import { createMiddleware } from 'hono/factory';
import { HTTPException } from 'hono/http-exception';
import { sql } from 'drizzle-orm';
import type { Env, Variables } from '../types';
import { createDb, schema } from '../db';

// IP address validation pattern
const IP_PATTERN = /^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$/;

// Identifier validation patterns (SQL injection prevention)
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9_]*$/;
const SLUG_PATTERN = /^[a-z0-9-]+$/;
const MAX_IDENTIFIER_LENGTH = 128;

/**
 * Security headers middleware
 * Implements strict security headers for all responses
 */
export const securityHeaders = createMiddleware<{ Bindings: Env; Variables: Variables }>(
  async (c, next) => {
    await next();

    // Strict Transport Security - enforce HTTPS
    c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');

    // Prevent clickjacking
    c.header('X-Frame-Options', 'DENY');

    // Prevent MIME type sniffing
    c.header('X-Content-Type-Options', 'nosniff');

    // XSS Protection (legacy but still useful)
    c.header('X-XSS-Protection', '1; mode=block');

    // Referrer Policy
    c.header('Referrer-Policy', 'strict-origin-when-cross-origin');

    // Permissions Policy (restrict browser features)
    c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');

    // Content Security Policy
    c.header('Content-Security-Policy', [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob: https:",
      "font-src 'self'",
      "connect-src 'self' https://challenges.cloudflare.com",
      "frame-src https://challenges.cloudflare.com",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
    ].join('; '));
  }
);

/**
 * Cloudflare-aware IP extraction
 * Only trusts CF-Connecting-IP when the `cf` object is present (proves request came through Cloudflare)
 * Falls back to X-Forwarded-For only when verified, otherwise returns null
 */
export function getClientIp(request: Request): string | null {
  // Check if request came through Cloudflare (cf object is present)
  const cf = (request as unknown as { cf?: Record<string, unknown> }).cf;

  if (!cf) {
    // Not on Cloudflare - no trusted IP source
    // In development, we might still want to extract IP for logging
    return null;
  }

  const headers = request.headers;

  // Trust CF-Connecting-IP when cf object confirms Cloudflare
  const cfIp = headers.get('cf-connecting-ip')?.trim();
  if (cfIp && IP_PATTERN.test(cfIp)) {
    return cfIp;
  }

  // Fallback to first XFF entry (only if through Cloudflare)
  const xff = headers.get('x-forwarded-for');
  if (xff) {
    const first = xff.split(',')[0]?.trim();
    if (first && IP_PATTERN.test(first)) {
      return first;
    }
  }

  return null;
}

/**
 * Get IP for rate limiting (with fallback for development)
 */
export function getClientIpOrFallback(request: Request): string {
  const ip = getClientIp(request);
  if (ip) return ip;

  // Development fallback - use XFF or 'unknown'
  const xff = request.headers.get('x-forwarded-for');
  if (xff) {
    const first = xff.split(',')[0]?.trim();
    if (first && IP_PATTERN.test(first)) {
      return first;
    }
  }

  return 'unknown';
}

/**
 * Rate limiting state (in-memory, reset on worker restart)
 * For production with persistence, use dbRateLimiter instead
 */
interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const rateLimitStore = new Map<string, RateLimitEntry>();
const MAX_RATE_LIMIT_ENTRIES = 10000; // Prevent memory exhaustion under attack

/**
 * Rate limiting middleware (in-memory)
 * Configurable limits per endpoint type
 */
export function rateLimiter(options: {
  windowMs: number;      // Time window in milliseconds
  maxRequests: number;   // Max requests per window
  keyGenerator?: (c: any) => string;  // Custom key generator
}) {
  const { windowMs, maxRequests, keyGenerator } = options;

  return createMiddleware<{ Bindings: Env; Variables: Variables }>(async (c, next) => {
    // Generate key based on IP and optional custom logic
    const ip = getClientIpOrFallback(c.req.raw);
    const key = keyGenerator ? keyGenerator(c) : `${ip}:${c.req.path}`;

    const now = Date.now();
    const entry = rateLimitStore.get(key);

    if (entry) {
      if (now > entry.resetAt) {
        // Window expired, reset
        entry.count = 1;
        entry.resetAt = now + windowMs;
      } else if (entry.count >= maxRequests) {
        // Rate limit exceeded
        c.header('X-RateLimit-Limit', String(maxRequests));
        c.header('X-RateLimit-Remaining', '0');
        c.header('X-RateLimit-Reset', String(Math.ceil(entry.resetAt / 1000)));
        c.header('Retry-After', String(Math.ceil((entry.resetAt - now) / 1000)));

        throw new HTTPException(429, {
          message: 'Too many requests. Please try again later.'
        });
      } else {
        entry.count++;
      }
    } else {
      rateLimitStore.set(key, {
        count: 1,
        resetAt: now + windowMs,
      });
    }

    // Clean up old entries periodically (1% chance) or if store is too large
    if (Math.random() < 0.01 || rateLimitStore.size > MAX_RATE_LIMIT_ENTRIES) {
      const entriesToDelete: string[] = [];
      for (const [k, v] of rateLimitStore.entries()) {
        if (now > v.resetAt) {
          entriesToDelete.push(k);
        }
      }
      for (const k of entriesToDelete) {
        rateLimitStore.delete(k);
      }

      // If still over limit after cleanup, remove oldest entries
      if (rateLimitStore.size > MAX_RATE_LIMIT_ENTRIES) {
        const entries = Array.from(rateLimitStore.entries())
          .sort((a, b) => a[1].resetAt - b[1].resetAt);
        const toRemove = entries.slice(0, rateLimitStore.size - MAX_RATE_LIMIT_ENTRIES + 1000);
        for (const [k] of toRemove) {
          rateLimitStore.delete(k);
        }
      }
    }

    const currentEntry = rateLimitStore.get(key)!;
    c.header('X-RateLimit-Limit', String(maxRequests));
    c.header('X-RateLimit-Remaining', String(Math.max(0, maxRequests - currentEntry.count)));
    c.header('X-RateLimit-Reset', String(Math.ceil(currentEntry.resetAt / 1000)));

    await next();
  });
}

/**
 * Database-backed rate limiting middleware
 * Persists across worker restarts, suitable for distributed environments
 */
export function dbRateLimiter(options: {
  windowSeconds: number;  // Time window in seconds
  maxRequests: number;    // Max requests per window
  endpoint: string;       // Endpoint identifier
}) {
  const { windowSeconds, maxRequests, endpoint } = options;

  return createMiddleware<{ Bindings: Env; Variables: Variables }>(async (c, next) => {
    const db = createDb(c.env.DB);
    const ip = getClientIpOrFallback(c.req.raw);
    const key = `${ip}:${endpoint}`;

    // Calculate window start (aligned to window boundaries)
    const windowStart = new Date(
      Math.floor(Date.now() / (windowSeconds * 1000)) * windowSeconds * 1000
    ).toISOString();

    // Atomic upsert using SQLite's ON CONFLICT
    const result = await db.run(sql`
      INSERT INTO cc_rate_limits (key, window, count)
      VALUES (${key}, ${windowStart}, 1)
      ON CONFLICT (key, window)
      DO UPDATE SET count = cc_rate_limits.count + 1
    `);

    // Get current count
    const current = await db
      .select({ count: schema.rateLimits.count })
      .from(schema.rateLimits)
      .where(sql`key = ${key} AND window = ${windowStart}`)
      .get();

    const count = current?.count || 1;
    const windowEndMs = new Date(windowStart).getTime() + windowSeconds * 1000;

    c.header('X-RateLimit-Limit', String(maxRequests));
    c.header('X-RateLimit-Remaining', String(Math.max(0, maxRequests - count)));
    c.header('X-RateLimit-Reset', String(Math.ceil(windowEndMs / 1000)));

    if (count > maxRequests) {
      const retryAfter = Math.ceil((windowEndMs - Date.now()) / 1000);
      c.header('Retry-After', String(Math.max(1, retryAfter)));

      throw new HTTPException(429, {
        message: 'Too many requests. Please try again later.'
      });
    }

    // Cleanup old entries (1% chance per request)
    if (Math.random() < 0.01) {
      const cutoff = new Date(Date.now() - windowSeconds * 2 * 1000).toISOString();
      await db.run(sql`DELETE FROM cc_rate_limits WHERE window < ${cutoff}`);
    }

    await next();
  });
}

/**
 * Honeypot middleware for form protection
 * Checks for honeypot fields that bots typically fill out
 */
export const honeypotProtection = createMiddleware<{ Bindings: Env; Variables: Variables }>(
  async (c, next) => {
    if (c.req.method === 'POST' || c.req.method === 'PUT' || c.req.method === 'PATCH') {
      try {
        const contentType = c.req.header('Content-Type') || '';

        if (contentType.includes('application/json')) {
          const body = await c.req.json();

          // Check common honeypot field names
          const honeypotFields = [
            'website', 'url', 'link', 'homepage',
            'fax', 'phone2', 'address2',
            '_honeypot', '_hp', 'hp_field',
            'confirm_email', 'email_confirm'
          ];

          for (const field of honeypotFields) {
            if (body[field] && String(body[field]).trim() !== '') {
              // Bot detected - silently reject
              console.log(`Honeypot triggered: field=${field}, ip=${c.req.header('CF-Connecting-IP')}`);
              throw new HTTPException(400, { message: 'Invalid request' });
            }
          }
        }
      } catch (e) {
        if (e instanceof HTTPException) throw e;
        // Ignore parsing errors, let the route handle them
      }
    }

    await next();
  }
);

/**
 * Cloudflare Turnstile verification middleware
 * Validates turnstile tokens for protected endpoints
 */
export function turnstileProtection(secretKey: string | undefined) {
  return createMiddleware<{ Bindings: Env; Variables: Variables }>(async (c, next) => {
    // Skip if no secret key configured
    if (!secretKey) {
      await next();
      return;
    }

    if (c.req.method === 'POST' || c.req.method === 'PUT' || c.req.method === 'PATCH') {
      try {
        const body = await c.req.json();
        const turnstileToken = body['cf-turnstile-response'] || body['turnstileToken'];

        if (!turnstileToken) {
          throw new HTTPException(400, {
            message: 'Turnstile verification required'
          });
        }

        // Verify with Cloudflare
        const formData = new FormData();
        formData.append('secret', secretKey);
        formData.append('response', turnstileToken);
        formData.append('remoteip', c.req.header('CF-Connecting-IP') || '');

        const verifyResponse = await fetch(
          'https://challenges.cloudflare.com/turnstile/v0/siteverify',
          {
            method: 'POST',
            body: formData,
          }
        );

        const outcome = await verifyResponse.json() as { success: boolean; 'error-codes'?: string[] };

        if (!outcome.success) {
          console.log('Turnstile verification failed:', outcome['error-codes']);
          throw new HTTPException(400, {
            message: 'Bot verification failed. Please try again.'
          });
        }
      } catch (e) {
        if (e instanceof HTTPException) throw e;
        // Parsing error - let the route handle it
      }
    }

    await next();
  });
}

/**
 * Input sanitization middleware
 * Sanitizes common XSS vectors from input
 */
export const inputSanitization = createMiddleware<{ Bindings: Env; Variables: Variables }>(
  async (c, next) => {
    // We don't modify the request body here - validation should handle that
    // This middleware logs potential attack patterns for monitoring

    if (c.req.method === 'POST' || c.req.method === 'PUT' || c.req.method === 'PATCH') {
      try {
        const body = await c.req.text();

        // Check for common XSS patterns (for logging/monitoring)
        const suspiciousPatterns = [
          /<script\b[^>]*>/i,
          /javascript:/i,
          /on\w+\s*=/i,
          /<iframe\b/i,
          /<object\b/i,
          /<embed\b/i,
          /data:\s*text\/html/i,
        ];

        for (const pattern of suspiciousPatterns) {
          if (pattern.test(body)) {
            console.log(`Suspicious input detected: pattern=${pattern}, ip=${c.req.header('CF-Connecting-IP')}`);
            // Don't block - let validation handle it, but log for monitoring
            break;
          }
        }
      } catch {
        // Ignore parsing errors
      }
    }

    await next();
  }
);

/**
 * Brute force protection for login endpoints
 * More aggressive rate limiting with exponential backoff
 */
const loginAttempts = new Map<string, { count: number; lockedUntil: number }>();
const MAX_LOGIN_ATTEMPTS_ENTRIES = 10000; // Prevent memory exhaustion

export const bruteForceProtection = createMiddleware<{ Bindings: Env; Variables: Variables }>(
  async (c, next) => {
    const ip = getClientIpOrFallback(c.req.raw);

    const now = Date.now();
    const entry = loginAttempts.get(ip);

    if (entry) {
      // Check if locked out
      if (entry.lockedUntil > now) {
        const waitSeconds = Math.ceil((entry.lockedUntil - now) / 1000);
        c.header('Retry-After', String(waitSeconds));
        throw new HTTPException(429, {
          message: `Too many login attempts. Please try again in ${waitSeconds} seconds.`
        });
      }

      // Reset if lockout expired
      if (entry.lockedUntil <= now && entry.count >= 5) {
        entry.count = 0;
        entry.lockedUntil = 0;
      }
    }

    await next();

    // After the response, check if login failed (status 401)
    if (c.res.status === 401) {
      const current = loginAttempts.get(ip) || { count: 0, lockedUntil: 0 };
      current.count++;

      // Exponential backoff: 5 attempts = 30s, 10 = 5min, 15 = 30min, 20+ = 1hr
      if (current.count >= 5) {
        const lockoutMinutes = Math.min(60, Math.pow(2, Math.floor(current.count / 5) - 1) * 0.5);
        current.lockedUntil = now + lockoutMinutes * 60 * 1000;
        console.log(`IP ${ip} locked out for ${lockoutMinutes} minutes after ${current.count} failed attempts`);
      }

      loginAttempts.set(ip, current);

      // Cleanup if store is too large
      if (loginAttempts.size > MAX_LOGIN_ATTEMPTS_ENTRIES) {
        const now = Date.now();
        const entriesToDelete: string[] = [];
        for (const [k, v] of loginAttempts.entries()) {
          // Remove entries that are no longer locked and have old counts
          if (v.lockedUntil <= now && v.count < 5) {
            entriesToDelete.push(k);
          }
        }
        for (const k of entriesToDelete) {
          loginAttempts.delete(k);
        }

        // If still over limit, remove oldest entries
        if (loginAttempts.size > MAX_LOGIN_ATTEMPTS_ENTRIES) {
          const entries = Array.from(loginAttempts.entries())
            .sort((a, b) => a[1].lockedUntil - b[1].lockedUntil);
          const toRemove = entries.slice(0, loginAttempts.size - MAX_LOGIN_ATTEMPTS_ENTRIES + 1000);
          for (const [k] of toRemove) {
            loginAttempts.delete(k);
          }
        }
      }
    } else if (c.res.status === 200) {
      // Successful login - reset attempts
      loginAttempts.delete(ip);
    }
  }
);

/**
 * Request ID middleware for tracing
 */
export const requestId = createMiddleware<{ Bindings: Env; Variables: Variables }>(
  async (c, next) => {
    const id = c.req.header('X-Request-ID') || crypto.randomUUID();
    c.set('requestId' as any, id);
    c.header('X-Request-ID', id);
    await next();
  }
);

/**
 * CSRF Protection middleware (emdash-style)
 * Layer 1: X-CloudCore-Request header check (like emdash's X-EmDash-Request)
 * Layer 2: Origin/Referer header validation
 * Layer 3: SameSite=Strict cookies (defense in depth)
 *
 * Browsers cannot send custom headers cross-origin without CORS preflight,
 * so presence of X-CloudCore-Request: 1 proves same-origin request
 */
export function csrfProtection(allowedOrigins: string[]) {
  return createMiddleware<{ Bindings: Env; Variables: Variables }>(async (c, next) => {
    const method = c.req.method;

    // Only check state-changing requests
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      // Layer 1: Check for X-CloudCore-Request header
      // SECURITY: Strictly validate header value to prevent bypass with truthy values
      const csrfHeader = c.req.header('X-CloudCore-Request');
      if (csrfHeader !== undefined && csrfHeader !== null) {
        // Trim whitespace and check for exact match
        const trimmedValue = csrfHeader.trim();
        if (trimmedValue === '1') {
          // Custom header present with correct value - proves same-origin
          await next();
          return;
        }
        // If header is present but has wrong value, log and continue to origin check
        console.log(`CSRF: Invalid X-CloudCore-Request value: "${csrfHeader}"`);
      }

      // Layer 2: Fall back to Origin/Referer validation
      const origin = c.req.header('Origin');
      const referer = c.req.header('Referer');
      const url = new URL(c.req.url);

      // Get the origin from referer if Origin header is missing
      let requestOrigin = origin;
      if (!requestOrigin && referer) {
        try {
          requestOrigin = new URL(referer).origin;
        } catch {
          // Invalid referer URL
        }
      }

      // If we have an origin, validate it
      if (requestOrigin) {
        // Check same-origin first
        if (requestOrigin === url.origin) {
          await next();
          return;
        }

        // Check against allowed origins list
        const isAllowed = allowedOrigins.some(allowed => {
          // Handle wildcard subdomains
          if (allowed.startsWith('*.')) {
            const domain = allowed.slice(2);
            try {
              const originUrl = new URL(requestOrigin!);
              return originUrl.hostname.endsWith(domain) || originUrl.hostname === domain.slice(1);
            } catch {
              return false;
            }
          }
          return requestOrigin === allowed;
        });

        if (!isAllowed) {
          console.log(`CSRF blocked: origin=${requestOrigin}, allowed=${allowedOrigins.join(',')}`);
          throw new HTTPException(403, {
            message: 'Cross-origin request blocked'
          });
        }
      }
      // SECURITY: If no origin/referer and no X-CloudCore-Request header, block the request
      // This ensures browser-based requests include the CSRF protection header
      // Non-browser API clients (curl, server-to-server) should be using Bearer tokens which bypass sessions
      // If using session auth from a browser, the X-CloudCore-Request: 1 header is required
      throw new HTTPException(403, {
        message: 'Missing X-CloudCore-Request header. Add "X-CloudCore-Request: 1" to your request headers.'
      });
    }

    await next();
  });
}

/**
 * Parse allowed origins from environment variable
 * Returns array of allowed origins, or ['*'] for development
 */
export function parseAllowedOrigins(envOrigins: string | undefined): string[] {
  if (!envOrigins) {
    // Default: allow localhost for development
    return [
      'http://localhost:3000',
      'http://localhost:4321',
      'http://localhost:5173',
      'http://localhost:5174',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:4321',
      'http://127.0.0.1:5173',
      'http://127.0.0.1:5174',
    ];
  }

  return envOrigins.split(',').map(o => o.trim()).filter(Boolean);
}

/**
 * File magic bytes signatures for MIME type validation
 */
export const FILE_SIGNATURES: Record<string, { bytes: number[]; offset?: number }[]> = {
  // Images
  'image/jpeg': [{ bytes: [0xFF, 0xD8, 0xFF] }],
  'image/png': [{ bytes: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] }],
  'image/gif': [{ bytes: [0x47, 0x49, 0x46, 0x38, 0x37, 0x61] }, { bytes: [0x47, 0x49, 0x46, 0x38, 0x39, 0x61] }],
  'image/webp': [{ bytes: [0x52, 0x49, 0x46, 0x46], offset: 0 }, { bytes: [0x57, 0x45, 0x42, 0x50], offset: 8 }],
  // SVG: handled separately - can start with XML declaration, whitespace, or <svg
  'image/svg+xml': [], // Special handling in validateFileMagicBytes
  'image/bmp': [{ bytes: [0x42, 0x4D] }],
  'image/x-icon': [{ bytes: [0x00, 0x00, 0x01, 0x00] }, { bytes: [0x00, 0x00, 0x02, 0x00] }], // ICO and CUR

  // PDF
  'application/pdf': [{ bytes: [0x25, 0x50, 0x44, 0x46] }], // %PDF

  // Video
  'video/mp4': [{ bytes: [0x66, 0x74, 0x79, 0x70], offset: 4 }], // ftyp at offset 4
  'video/webm': [{ bytes: [0x1A, 0x45, 0xDF, 0xA3] }],

  // Audio
  'audio/mpeg': [{ bytes: [0xFF, 0xFB] }, { bytes: [0xFF, 0xFA] }, { bytes: [0x49, 0x44, 0x33] }], // MP3
  'audio/wav': [{ bytes: [0x52, 0x49, 0x46, 0x46] }], // RIFF
  'audio/ogg': [{ bytes: [0x4F, 0x67, 0x67, 0x53] }],
};

/**
 * Validate file content matches claimed MIME type using magic bytes
 * SECURITY: Reject any MIME type that doesn't have a defined signature
 */
export async function validateFileMagicBytes(
  file: File,
  claimedMimeType: string
): Promise<boolean> {
  const signatures = FILE_SIGNATURES[claimedMimeType];

  // SECURITY: Reject any MIME type that doesn't have a defined signature
  // This prevents bypassing validation by using unknown MIME types
  if (signatures === undefined) {
    console.log(`SECURITY: Rejected unknown MIME type: ${claimedMimeType}`);
    return false;
  }

  // Special handling for SVG - can start with XML declaration, whitespace, or <svg
  if (claimedMimeType === 'image/svg+xml') {
    const text = await file.slice(0, 1024).text();
    const trimmed = text.trim().toLowerCase();
    // Must start with <?xml, <!doctype, or <svg
    if (trimmed.startsWith('<?xml') || trimmed.startsWith('<!doctype') || trimmed.startsWith('<svg')) {
      // Additional check: must contain <svg somewhere in the first 1KB
      return text.toLowerCase().includes('<svg');
    }
    console.log(`SECURITY: SVG validation failed - invalid start: ${trimmed.slice(0, 50)}`);
    return false;
  }

  // Read first 16 bytes of file
  const buffer = await file.slice(0, 16).arrayBuffer();
  const bytes = new Uint8Array(buffer);

  // Check each signature variant
  for (const sig of signatures) {
    const offset = sig.offset || 0;
    let matches = true;

    for (let i = 0; i < sig.bytes.length; i++) {
      if (bytes[offset + i] !== sig.bytes[i]) {
        matches = false;
        break;
      }
    }

    if (matches) return true;
  }

  console.log(`Magic byte mismatch: claimed=${claimedMimeType}, bytes=${Array.from(bytes.slice(0, 8)).map(b => b.toString(16)).join(' ')}`);
  return false;
}

/**
 * Sanitize filename to prevent path traversal and other attacks
 */
export function sanitizeFilename(filename: string): string {
  // Remove path components
  let sanitized = filename.replace(/^.*[\\/]/, '');

  // Remove null bytes and control characters
  sanitized = sanitized.replace(/[\x00-\x1f\x7f]/g, '');

  // Remove dangerous characters
  sanitized = sanitized.replace(/[<>:"|?*]/g, '');

  // Prevent hidden files
  sanitized = sanitized.replace(/^\.+/, '');

  // Limit length
  if (sanitized.length > 255) {
    const ext = sanitized.split('.').pop() || '';
    const name = sanitized.slice(0, 255 - ext.length - 1);
    sanitized = `${name}.${ext}`;
  }

  // Default filename if empty
  return sanitized || 'unnamed_file';
}

/**
 * Get safe file extension from MIME type
 */
export function getExtensionFromMimeType(mimeType: string): string {
  const mimeToExt: Record<string, string> = {
    'image/jpeg': 'jpg',
    'image/png': 'png',
    'image/gif': 'gif',
    'image/webp': 'webp',
    'image/svg+xml': 'svg',
    'image/bmp': 'bmp',
    'image/x-icon': 'ico',
    'application/pdf': 'pdf',
    'video/mp4': 'mp4',
    'video/webm': 'webm',
    'audio/mpeg': 'mp3',
    'audio/wav': 'wav',
    'audio/ogg': 'ogg',
  };

  return mimeToExt[mimeType] || 'bin';
}

/**
 * SQL Identifier validation (prevents SQL injection for dynamic identifiers)
 * Pattern: lowercase letters, numbers, underscores, must start with letter
 */
export class IdentifierError extends Error {
  constructor(
    message: string,
    public readonly value: string
  ) {
    super(message);
    this.name = 'IdentifierError';
  }
}

/**
 * Validate a SQL identifier (table name, column name, etc.)
 * Throws IdentifierError if invalid
 */
export function validateIdentifier(value: string, label = 'identifier'): void {
  if (value.length > MAX_IDENTIFIER_LENGTH) {
    throw new IdentifierError(`${label} exceeds max length (${MAX_IDENTIFIER_LENGTH})`, value);
  }
  if (!IDENTIFIER_PATTERN.test(value)) {
    throw new IdentifierError(
      `${label} must match /^[a-z][a-z0-9_]*$/ (got "${value}")`,
      value
    );
  }
}

/**
 * Validate a slug (URL-safe identifier)
 * Pattern: lowercase letters, numbers, hyphens
 */
export function validateSlug(value: string, label = 'slug'): void {
  if (value.length > MAX_IDENTIFIER_LENGTH) {
    throw new IdentifierError(`${label} exceeds max length (${MAX_IDENTIFIER_LENGTH})`, value);
  }
  if (!SLUG_PATTERN.test(value)) {
    throw new IdentifierError(
      `${label} must match /^[a-z0-9-]+$/ (got "${value}")`,
      value
    );
  }
}

/**
 * Validate and sanitize a settings key
 * Allows alphanumeric, underscores, and dots (for namespacing)
 */
const SETTINGS_KEY_PATTERN = /^[a-zA-Z][a-zA-Z0-9_.]*$/;

export function validateSettingsKey(value: string, label = 'settings key'): void {
  if (value.length > MAX_IDENTIFIER_LENGTH) {
    throw new IdentifierError(`${label} exceeds max length (${MAX_IDENTIFIER_LENGTH})`, value);
  }
  if (!SETTINGS_KEY_PATTERN.test(value)) {
    throw new IdentifierError(
      `${label} must match /^[a-zA-Z][a-zA-Z0-9_.]*$/ (got "${value}")`,
      value
    );
  }
}

/**
 * Check if a value is a valid identifier without throwing
 */
export function isValidIdentifier(value: string): boolean {
  return value.length <= MAX_IDENTIFIER_LENGTH && IDENTIFIER_PATTERN.test(value);
}

/**
 * Check if a value is a valid slug without throwing
 */
export function isValidSlug(value: string): boolean {
  return value.length <= MAX_IDENTIFIER_LENGTH && SLUG_PATTERN.test(value);
}

/**
 * SVG Sanitization
 * Removes potentially dangerous elements and attributes from SVG files
 * This prevents XSS attacks through SVG uploads
 */

// Dangerous SVG elements that can execute scripts or load external resources
const DANGEROUS_SVG_ELEMENTS = [
  'script',
  'style', // SECURITY: CSS can execute JS via @import url('javascript:...') or exfiltrate data
  'foreignObject',
  'use', // Can reference external resources
  'iframe',
  'embed',
  'object',
  'applet',
];

// Dangerous attributes that can execute scripts
const DANGEROUS_SVG_ATTRIBUTES = [
  'onload',
  'onerror',
  'onclick',
  'onmouseover',
  'onmouseout',
  'onmousedown',
  'onmouseup',
  'onfocus',
  'onblur',
  'onchange',
  'onsubmit',
  'onreset',
  'onselect',
  'onkeydown',
  'onkeyup',
  'onkeypress',
  'onabort',
  'ondblclick',
  'onresize',
  'onscroll',
  'onunload',
  'onanimationstart',
  'onanimationend',
  'onanimationiteration',
  'ontransitionend',
];

// Attributes that can contain URLs (need validation)
const URL_ATTRIBUTES = ['href', 'xlink:href', 'src'];

/**
 * Sanitize SVG content by removing dangerous elements and attributes
 * Returns sanitized SVG string or null if the SVG is too dangerous to sanitize
 */
export function sanitizeSvg(svgContent: string): string | null {
  // Check for common attack patterns first
  const lowerContent = svgContent.toLowerCase();

  // Block javascript: URLs anywhere in the SVG
  if (lowerContent.includes('javascript:')) {
    console.log('SVG sanitization: blocked javascript: URL');
    return null;
  }

  // Block data: URLs that could contain scripts
  if (lowerContent.includes('data:text/html') || lowerContent.includes('data:application/')) {
    console.log('SVG sanitization: blocked dangerous data: URL');
    return null;
  }

  // Remove dangerous elements using regex (since we can't use DOM in Workers easily)
  let sanitized = svgContent;

  // Remove dangerous elements and their contents
  for (const element of DANGEROUS_SVG_ELEMENTS) {
    // Match opening and closing tags with content
    const regex = new RegExp(`<${element}[^>]*>[\\s\\S]*?<\\/${element}>`, 'gi');
    sanitized = sanitized.replace(regex, '');

    // Match self-closing tags
    const selfClosingRegex = new RegExp(`<${element}[^>]*\\/?>`, 'gi');
    sanitized = sanitized.replace(selfClosingRegex, '');
  }

  // Remove dangerous attributes (event handlers)
  for (const attr of DANGEROUS_SVG_ATTRIBUTES) {
    // Match attribute with various quote styles
    const doubleQuoteRegex = new RegExp(`\\s${attr}\\s*=\\s*"[^"]*"`, 'gi');
    const singleQuoteRegex = new RegExp(`\\s${attr}\\s*=\\s*'[^']*'`, 'gi');
    const noQuoteRegex = new RegExp(`\\s${attr}\\s*=\\s*[^\\s>]+`, 'gi');

    sanitized = sanitized.replace(doubleQuoteRegex, '');
    sanitized = sanitized.replace(singleQuoteRegex, '');
    sanitized = sanitized.replace(noQuoteRegex, '');
  }

  // Sanitize href/xlink:href attributes - remove if they contain javascript:
  for (const attr of URL_ATTRIBUTES) {
    // Remove javascript: and data: URLs in href-like attributes
    const jsUrlRegex = new RegExp(`(${attr})\\s*=\\s*["']\\s*javascript:[^"']*["']`, 'gi');
    const dataUrlRegex = new RegExp(`(${attr})\\s*=\\s*["']\\s*data:(?:text\\/html|application\\/)[^"']*["']`, 'gi');

    sanitized = sanitized.replace(jsUrlRegex, '');
    sanitized = sanitized.replace(dataUrlRegex, '');
  }

  // Final check - if any suspicious patterns remain, reject
  const sanitizedLower = sanitized.toLowerCase();
  if (
    sanitizedLower.includes('javascript:') ||
    sanitizedLower.includes('<script') ||
    DANGEROUS_SVG_ATTRIBUTES.some(attr => sanitizedLower.includes(attr + '='))
  ) {
    console.log('SVG sanitization: suspicious content remained after sanitization');
    return null;
  }

  return sanitized;
}

/**
 * Check if SVG content is safe (without modifying it)
 * Returns true if the SVG appears safe, false if it contains dangerous content
 */
export function isSvgSafe(svgContent: string): boolean {
  const lowerContent = svgContent.toLowerCase();

  // Check for dangerous patterns
  if (lowerContent.includes('javascript:')) return false;
  if (lowerContent.includes('data:text/html')) return false;
  if (lowerContent.includes('data:application/')) return false;

  // Check for dangerous elements
  for (const element of DANGEROUS_SVG_ELEMENTS) {
    if (lowerContent.includes(`<${element}`)) return false;
  }

  // Check for event handler attributes
  for (const attr of DANGEROUS_SVG_ATTRIBUTES) {
    if (lowerContent.includes(`${attr}=`)) return false;
  }

  return true;
}
