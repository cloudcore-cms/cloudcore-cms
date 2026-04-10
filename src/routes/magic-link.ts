import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { setCookie } from 'hono/cookie';
import { eq, lt, and, sql } from 'drizzle-orm';
import { z } from 'zod';
import type { Env, Variables } from '../types';
import { createDb, schema } from '../db';
import { generateId, now } from '../lib/utils';
import {
  generateSecureToken,
  hashSessionToken,
  generateBase64UrlToken,
  timingSafeDelay,
} from '../lib/crypto';
import { getClientIpOrFallback, rateLimiter } from '../middleware/security';

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// Session duration: 30 days
const SESSION_DURATION_MS = 30 * 24 * 60 * 60 * 1000;
// Magic link expiry: 15 minutes
const MAGIC_LINK_TTL_MS = 15 * 60 * 1000;

// Per-email rate limiting for magic link requests
const emailRateLimits = new Map<string, { count: number; resetAt: number }>();
const MAX_EMAIL_REQUESTS = 3; // Max 3 magic link requests per email per hour
const EMAIL_WINDOW_MS = 60 * 60 * 1000; // 1 hour window
const MAX_EMAIL_ENTRIES = 10000; // Prevent memory exhaustion
let lastEmailCleanup = 0;
const EMAIL_CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // Cleanup expired entries every 5 minutes

// Helper to log audit events
async function logAudit(
  db: ReturnType<typeof createDb>,
  userId: string | null,
  userEmail: string | null,
  action: string,
  resourceType: string | null,
  resourceId: string | null,
  details: Record<string, unknown> | null,
  ipAddress: string | null,
  userAgent: string | null
) {
  await db.insert(schema.auditLog).values({
    id: generateId(),
    userId,
    userEmail,
    action,
    resourceType,
    resourceId,
    details: details ? JSON.stringify(details) : null,
    ipAddress,
    userAgent,
    createdAt: now(),
  });
}

// Hash magic link token for storage
async function hashMagicToken(token: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(token);
  const hash = await crypto.subtle.digest('SHA-256', data);
  const hashArray = new Uint8Array(hash);
  let hexString = '';
  for (let i = 0; i < hashArray.length; i++) {
    hexString += hashArray[i].toString(16).padStart(2, '0');
  }
  return hexString;
}

// Cleanup expired magic link tokens
async function cleanupExpiredTokens(db: ReturnType<typeof createDb>) {
  const nowStr = now();
  await db.delete(schema.magicLinkTokens).where(lt(schema.magicLinkTokens.expiresAt, nowStr));
}

// Send email via SMTP (using Cloudflare Email Workers or external SMTP)
async function sendMagicLinkEmail(
  env: Env,
  to: string,
  magicLinkUrl: string
): Promise<{ success: boolean; error?: string }> {
  // Check if SMTP is configured
  if (!env.SMTP_HOST || !env.SMTP_USER || !env.SMTP_PASS) {
    console.warn('SMTP not configured, magic link would be sent to:', to);
    console.warn('Magic link URL:', magicLinkUrl);
    // In development, return success and log the URL
    return { success: true };
  }

  const fromEmail = env.SMTP_FROM || 'noreply@example.com';
  const fromName = env.SMTP_FROM_NAME || 'Cloudcore CMS';
  const port = parseInt(env.SMTP_PORT || '587', 10);

  // For Cloudflare Workers, we need to use the Email Workers binding or external API
  // Here's a generic SMTP approach using fetch to a mail service
  // In production, you'd use Cloudflare Email Workers, SendGrid, Mailgun, etc.

  try {
    // Example using a generic mail API (you'd replace this with your actual provider)
    // For SendGrid:
    if (env.SMTP_HOST?.includes('sendgrid')) {
      const response = await fetch('https://api.sendgrid.com/v3/mail/send', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.SMTP_PASS}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          personalizations: [{ to: [{ email: to }] }],
          from: { email: fromEmail, name: fromName },
          subject: 'Sign in to Cloudcore CMS',
          content: [
            {
              type: 'text/plain',
              value: `Click this link to sign in to Cloudcore CMS:\n\n${magicLinkUrl}\n\nThis link expires in 15 minutes.\n\nIf you didn't request this, you can safely ignore this email.`,
            },
            {
              type: 'text/html',
              value: `
                <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                  <h2 style="color: #333;">Sign in to Cloudcore CMS</h2>
                  <p style="color: #666; font-size: 16px;">Click the button below to sign in:</p>
                  <a href="${magicLinkUrl}" style="display: inline-block; background: #4F46E5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 500; margin: 20px 0;">Sign In</a>
                  <p style="color: #999; font-size: 14px;">This link expires in 15 minutes.</p>
                  <p style="color: #999; font-size: 14px;">If you didn't request this email, you can safely ignore it.</p>
                  <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                  <p style="color: #999; font-size: 12px;">Or copy and paste this URL: ${magicLinkUrl}</p>
                </div>
              `,
            },
          ],
        }),
      });

      if (!response.ok) {
        const error = await response.text();
        return { success: false, error };
      }
      return { success: true };
    }

    // For Mailgun:
    if (env.SMTP_HOST?.includes('mailgun')) {
      const domain = env.SMTP_HOST.replace('smtp.mailgun.org', '').replace('smtp.', '') || 'example.com';
      const response = await fetch(`https://api.mailgun.net/v3/${domain}/messages`, {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${btoa(`api:${env.SMTP_PASS}`)}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          from: `${fromName} <${fromEmail}>`,
          to,
          subject: 'Sign in to Cloudcore CMS',
          text: `Click this link to sign in to Cloudcore CMS:\n\n${magicLinkUrl}\n\nThis link expires in 15 minutes.`,
          html: `
            <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
              <h2 style="color: #333;">Sign in to Cloudcore CMS</h2>
              <p style="color: #666; font-size: 16px;">Click the button below to sign in:</p>
              <a href="${magicLinkUrl}" style="display: inline-block; background: #4F46E5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 500; margin: 20px 0;">Sign In</a>
              <p style="color: #999; font-size: 14px;">This link expires in 15 minutes.</p>
              <p style="color: #999; font-size: 14px;">If you didn't request this email, you can safely ignore it.</p>
            </div>
          `,
        }),
      });

      if (!response.ok) {
        const error = await response.text();
        return { success: false, error };
      }
      return { success: true };
    }

    // For Resend:
    if (env.SMTP_HOST?.includes('resend')) {
      const response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.SMTP_PASS}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: `${fromName} <${fromEmail}>`,
          to: [to],
          subject: 'Sign in to Cloudcore CMS',
          html: `
            <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
              <h2 style="color: #333;">Sign in to Cloudcore CMS</h2>
              <p style="color: #666; font-size: 16px;">Click the button below to sign in:</p>
              <a href="${magicLinkUrl}" style="display: inline-block; background: #4F46E5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 500; margin: 20px 0;">Sign In</a>
              <p style="color: #999; font-size: 14px;">This link expires in 15 minutes.</p>
              <p style="color: #999; font-size: 14px;">If you didn't request this email, you can safely ignore it.</p>
            </div>
          `,
        }),
      });

      if (!response.ok) {
        const error = await response.text();
        return { success: false, error };
      }
      return { success: true };
    }

    // Default: log that SMTP needs to be configured with a supported provider
    console.warn('SMTP provider not recognized. Supported: SendGrid, Mailgun, Resend');
    console.warn('Magic link for', to, ':', magicLinkUrl);
    return { success: true }; // Return success in dev mode
  } catch (error) {
    console.error('Failed to send magic link email:', error);
    return { success: false, error: String(error) };
  }
}

// Request magic link
app.post('/', rateLimiter({ windowMs: 60000, maxRequests: 5 }), zValidator('json', z.object({
  email: z.string().email(),
})), async (c) => {
  const db = createDb(c.env.DB);
  const { email } = c.req.valid('json');
  const ip = getClientIpOrFallback(c.req.raw);
  const userAgent = c.req.header('User-Agent') || null;
  const normalizedEmail = email.toLowerCase();
  const currentTime = Date.now();

  // Per-email rate limiting (in addition to IP-based)
  const emailEntry = emailRateLimits.get(normalizedEmail);
  if (emailEntry && currentTime < emailEntry.resetAt && emailEntry.count >= MAX_EMAIL_REQUESTS) {
    // Don't reveal rate limit to prevent email enumeration
    // Just return success without sending another email
    await logAudit(db, null, normalizedEmail, 'magic_link_rate_limited', 'user', null, {
      reason: 'email_rate_limit',
    }, ip, userAgent);
    return c.json({
      success: true,
      message: 'If an account exists with this email, you will receive a magic link shortly.',
    });
  }

  // Update email rate limit counter
  if (emailEntry && currentTime < emailEntry.resetAt) {
    emailEntry.count++;
  } else {
    emailRateLimits.set(normalizedEmail, { count: 1, resetAt: currentTime + EMAIL_WINDOW_MS });
  }

  // SECURITY: Time-based cleanup prevents memory exhaustion while maintaining rate limits
  // Run cleanup periodically OR if store exceeds size limit (as a safety net)
  if (currentTime - lastEmailCleanup > EMAIL_CLEANUP_INTERVAL_MS || emailRateLimits.size > MAX_EMAIL_ENTRIES) {
    lastEmailCleanup = currentTime;
    for (const [k, v] of emailRateLimits.entries()) {
      if (currentTime > v.resetAt) {
        emailRateLimits.delete(k);
      }
    }
  }

  await cleanupExpiredTokens(db);

  // Check if user exists
  const user = await db
    .select({
      id: schema.users.id,
      email: schema.users.email,
      isActive: schema.users.isActive,
    })
    .from(schema.users)
    .where(eq(schema.users.email, email.toLowerCase()))
    .get();

  // Always return success to prevent email enumeration
  // But only send email if user exists and is active
  if (user && user.isActive) {
    // Generate raw token and hash for storage
    const rawToken = generateBase64UrlToken(32);
    const hashedToken = await hashMagicToken(rawToken);
    const timestamp = now();
    const expiresAt = new Date(Date.now() + MAGIC_LINK_TTL_MS).toISOString();

    // Store hashed token
    await db.insert(schema.magicLinkTokens).values({
      token: hashedToken,
      email: email.toLowerCase(),
      userId: user.id,
      expiresAt,
      createdAt: timestamp,
    });

    // Build magic link URL
    const baseUrl = c.env.MAGIC_LINK_BASE_URL || c.env.OAUTH_CALLBACK_URL || new URL(c.req.url).origin;
    const magicLinkUrl = `${baseUrl}/login?magic_token=${rawToken}`;

    // Send email
    const emailResult = await sendMagicLinkEmail(c.env, email, magicLinkUrl);

    if (!emailResult.success) {
      console.error('Failed to send magic link email:', emailResult.error);
    }

    await logAudit(db, user.id, user.email, 'magic_link_requested', 'user', user.id, {
      emailSent: emailResult.success,
    }, ip, userAgent);
  } else {
    // Add timing-safe delay to match the time spent when user exists
    // This prevents email enumeration via timing attacks
    await timingSafeDelay();

    // Log attempt for non-existent user (for security monitoring)
    await logAudit(db, null, email, 'magic_link_requested_unknown', 'user', null, {
      reason: user ? 'account_deactivated' : 'user_not_found',
    }, ip, userAgent);
  }

  // Always return success to prevent enumeration
  return c.json({
    success: true,
    message: 'If an account exists with this email, you will receive a magic link shortly.',
  });
});

// Verify magic link
app.post('/verify', rateLimiter({ windowMs: 60000, maxRequests: 10 }), zValidator('json', z.object({
  token: z.string().min(1),
})), async (c) => {
  const db = createDb(c.env.DB);
  const { token } = c.req.valid('json');
  const ip = getClientIpOrFallback(c.req.raw);
  const userAgent = c.req.header('User-Agent') || null;

  // Hash the provided token
  const hashedToken = await hashMagicToken(token);

  // SECURITY: Use consistent error message and timing to prevent token enumeration
  const invalidResponse = { error: 'Invalid or expired magic link' };
  const timestamp = now();

  // SECURITY: Generate a unique consumption marker per request
  // This prevents race conditions where two requests in the same millisecond
  // could both succeed the timestamp comparison check
  const consumptionMarker = `${now()}:${crypto.randomUUID()}`;

  // SECURITY: Atomic token consumption to prevent race conditions
  // Use UPDATE with usedAt IS NULL condition - only succeeds for unused tokens
  // This prevents concurrent requests from both consuming the same token
  const updateResult = await db
    .update(schema.magicLinkTokens)
    .set({ usedAt: consumptionMarker })
    .where(
      and(
        eq(schema.magicLinkTokens.token, hashedToken),
        sql`${schema.magicLinkTokens.usedAt} IS NULL`
      )
    );

  // Check if update succeeded (token existed and was unused)
  // D1/SQLite doesn't return affected rows directly, so we need to verify
  const storedToken = await db
    .select()
    .from(schema.magicLinkTokens)
    .where(eq(schema.magicLinkTokens.token, hashedToken))
    .get();

  if (!storedToken) {
    // SECURITY: Add timing-safe delay to normalize response time with valid token paths
    await timingSafeDelay();
    await logAudit(db, null, null, 'magic_link_invalid', 'user', null, {
      reason: 'token_not_found',
    }, ip, userAgent);
    return c.json(invalidResponse, 400);
  }

  // Check if we were the ones who consumed it (our unique marker matches)
  // The UUID makes this impossible to collide even with concurrent requests
  if (storedToken.usedAt !== consumptionMarker) {
    // Token was already used by another request (race condition prevented)
    await logAudit(db, storedToken.userId, storedToken.email, 'magic_link_reused', 'user', storedToken.userId, null, ip, userAgent);
    return c.json({ error: 'Magic link has already been used' }, 400);
  }

  // Check if expired
  if (new Date(storedToken.expiresAt) < new Date()) {
    await db.delete(schema.magicLinkTokens).where(eq(schema.magicLinkTokens.token, hashedToken));
    await logAudit(db, storedToken.userId, storedToken.email, 'magic_link_expired', 'user', storedToken.userId, null, ip, userAgent);
    // SECURITY: Return same error message as invalid token to prevent enumeration
    return c.json(invalidResponse, 400);
  }

  // Get user
  const user = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.email, storedToken.email))
    .get();

  if (!user) {
    return c.json({ error: 'User not found' }, 400);
  }

  if (!user.isActive) {
    await logAudit(db, user.id, user.email, 'magic_link_login_failed', 'user', user.id, {
      reason: 'account_deactivated',
    }, ip, userAgent);
    return c.json({ error: 'Account is deactivated' }, 401);
  }

  // Create session
  const rawSessionToken = generateSecureToken(32);
  const sessionId = await hashSessionToken(rawSessionToken);
  const expiresAt = new Date(Date.now() + SESSION_DURATION_MS).toISOString();

  await db.insert(schema.sessions).values({
    id: sessionId,
    userId: user.id,
    userAgent,
    ipAddress: ip,
    expiresAt,
    createdAt: timestamp,
  });

  // Update last login
  await db
    .update(schema.users)
    .set({ lastLoginAt: timestamp })
    .where(eq(schema.users.id, user.id));

  // Log successful login
  await logAudit(db, user.id, user.email, 'magic_link_login', 'user', user.id, null, ip, userAgent);

  // Set session cookie
  const isSecure = c.env.SECURE_COOKIES === 'true' ||
                   (c.env.SECURE_COOKIES !== 'false' && new URL(c.req.url).protocol === 'https:');
  setCookie(c, 'session', rawSessionToken, {
    httpOnly: true,
    secure: isSecure,
    sameSite: 'Strict',
    path: '/',
    maxAge: SESSION_DURATION_MS / 1000,
  });

  return c.json({
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      avatar: user.avatar,
      isActive: user.isActive,
    },
  });
});

export default app;
