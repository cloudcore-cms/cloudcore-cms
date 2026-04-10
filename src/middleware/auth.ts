import { createMiddleware } from 'hono/factory';
import { HTTPException } from 'hono/http-exception';
import { getCookie, setCookie } from 'hono/cookie';
import { eq, and, gt } from 'drizzle-orm';
import type { Env, Variables, UserRole, Permission } from '../types';
import { hasPermission } from '../types';
import { createDb, schema } from '../db';
import { now } from '../lib/utils';
import { hashSessionToken, timingSafeEqual, timingSafeDelay } from '../lib/crypto';

// Session duration: 30 days
const SESSION_DURATION_MS = 30 * 24 * 60 * 60 * 1000;
// Sliding window threshold: extend session if less than 15 days remain
const SLIDING_WINDOW_THRESHOLD_MS = 15 * 24 * 60 * 60 * 1000;
// SECURITY: Maximum absolute session lifetime - sessions cannot live forever via sliding window
// Set to 90 days to allow 3 full extensions but prevent infinite session lifetime
const MAX_SESSION_LIFETIME_MS = 90 * 24 * 60 * 60 * 1000;

// Rate limiting for Bearer token authentication (prevents brute force)
const bearerTokenAttempts = new Map<string, { count: number; resetAt: number }>();
const MAX_BEARER_ATTEMPTS = 10; // Max attempts per minute
const BEARER_WINDOW_MS = 60 * 1000; // 1 minute window
const MAX_BEARER_ENTRIES = 10000; // Prevent memory exhaustion
let lastBearerCleanup = 0;
const BEARER_CLEANUP_INTERVAL_MS = 60 * 1000; // Cleanup expired entries every minute

// Auth middleware - requires valid session
export const authMiddleware = createMiddleware<{ Bindings: Env; Variables: Variables }>(
  async (c, next) => {
    const db = createDb(c.env.DB);

    // Check for session cookie (raw token)
    const rawSessionToken = getCookie(c, 'session');

    // Also check for Bearer token (for API access) - case-insensitive per RFC 7235
    const authHeader = c.req.header('Authorization');
    const bearerToken = authHeader?.toLowerCase().startsWith('bearer ') ? authHeader.slice(7) : null;

    // Check admin token with rate limiting and timing-safe comparison
    if (bearerToken && c.env.ADMIN_TOKEN) {
      // Get client IP for rate limiting
      const ip = c.req.header('CF-Connecting-IP') ||
                 c.req.header('X-Forwarded-For')?.split(',')[0]?.trim() ||
                 'unknown';
      const currentTime = Date.now();

      // Check rate limit
      const entry = bearerTokenAttempts.get(ip);
      if (entry && currentTime < entry.resetAt && entry.count >= MAX_BEARER_ATTEMPTS) {
        throw new HTTPException(429, { message: 'Too many authentication attempts. Try again later.' });
      }

      const isValidToken = timingSafeEqual(bearerToken, c.env.ADMIN_TOKEN);

      if (isValidToken) {
        // Success - clear rate limit entry
        bearerTokenAttempts.delete(ip);

        // SECURITY: Log every ADMIN_TOKEN usage with IP for audit trail
        // This is a shared secret with no identity — log aggressively
        console.warn(
          `SECURITY: ADMIN_TOKEN used from IP=${ip} ` +
          `path=${c.req.method} ${c.req.path} ` +
          `ua=${c.req.header('User-Agent')?.substring(0, 100) || 'none'}. ` +
          `Consider migrating to database-backed user accounts for better traceability.`
        );

        // Admin token auth - create a virtual admin user
        // NOTE: This is a shared secret — all requests appear as the same user.
        // For production, create real admin accounts and use session auth instead.
        c.set('user', {
          id: `admin-token:${ip}`,
          email: 'admin-token@cloudcore.local',
          name: `Admin Token (${ip})`,
          role: 'admin' as UserRole,
          isActive: true,
          createdAt: now(),
        });
        c.set('session', null);
        return next();
      } else {
        // Failed attempt - update rate limit
        if (entry && currentTime < entry.resetAt) {
          entry.count++;
        } else {
          bearerTokenAttempts.set(ip, { count: 1, resetAt: currentTime + BEARER_WINDOW_MS });
        }

        // SECURITY: Time-based cleanup prevents memory exhaustion while maintaining rate limits
        // Run cleanup periodically OR if store exceeds size limit (as a safety net)
        if (currentTime - lastBearerCleanup > BEARER_CLEANUP_INTERVAL_MS || bearerTokenAttempts.size > MAX_BEARER_ENTRIES) {
          lastBearerCleanup = currentTime;
          for (const [k, v] of bearerTokenAttempts.entries()) {
            if (currentTime > v.resetAt) {
              bearerTokenAttempts.delete(k);
            }
          }
        }

        // Don't reveal invalid token - fall through to session check
      }
    }

    if (!rawSessionToken) {
      throw new HTTPException(401, { message: 'Unauthorized - no session' });
    }

    // Hash the raw token to find the session in DB
    const sessionId = await hashSessionToken(rawSessionToken);

    // Get session and check expiry
    const session = await db
      .select()
      .from(schema.sessions)
      .where(
        and(
          eq(schema.sessions.id, sessionId),
          gt(schema.sessions.expiresAt, now())
        )
      )
      .get();

    if (!session) {
      // SECURITY: Add timing-safe delay to normalize response times
      // This prevents timing attacks that could enumerate valid session IDs
      await timingSafeDelay();
      throw new HTTPException(401, { message: 'Unauthorized - invalid or expired session' });
    }

    // Get user
    const user = await db
      .select()
      .from(schema.users)
      .where(eq(schema.users.id, session.userId))
      .get();

    if (!user) {
      throw new HTTPException(401, { message: 'Unauthorized - user not found' });
    }

    // Check if user is active
    if (!user.isActive) {
      throw new HTTPException(403, { message: 'Account is deactivated' });
    }

    c.set('user', {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role as UserRole,
      avatar: user.avatar,
      bio: user.bio,
      isActive: user.isActive,
      lastLoginAt: user.lastLoginAt,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    });
    c.set('session', {
      id: session.id,
      userId: session.userId,
      userAgent: session.userAgent,
      ipAddress: session.ipAddress,
      expiresAt: session.expiresAt,
      createdAt: session.createdAt,
    });

    // Sliding session: extend session if less than half the time remains
    // This keeps active users logged in while inactive sessions expire
    // SECURITY: Maximum absolute lifetime cap prevents sessions from living forever
    if (c.env.SESSION_SLIDING_WINDOW === 'true') {
      const expiresAt = new Date(session.expiresAt);
      const timeRemaining = expiresAt.getTime() - Date.now();
      const sessionCreatedAt = new Date(session.createdAt);
      const sessionAge = Date.now() - sessionCreatedAt.getTime();

      // SECURITY: Only extend if session hasn't exceeded maximum lifetime cap
      // This prevents infinite session lifetime via sliding window
      if (timeRemaining < SLIDING_WINDOW_THRESHOLD_MS && sessionAge < MAX_SESSION_LIFETIME_MS) {
        // Calculate new expiry, but cap it at maximum lifetime from creation
        const maxAllowedExpiry = sessionCreatedAt.getTime() + MAX_SESSION_LIFETIME_MS;
        const requestedExpiry = Date.now() + SESSION_DURATION_MS;
        const newExpiresAt = new Date(Math.min(requestedExpiry, maxAllowedExpiry)).toISOString();

        // SECURITY: Use optimistic locking to prevent race conditions
        // Only update if the expiry hasn't changed since we read it (another request didn't beat us)
        await db
          .update(schema.sessions)
          .set({ expiresAt: newExpiresAt })
          .where(
            and(
              eq(schema.sessions.id, session.id),
              eq(schema.sessions.expiresAt, session.expiresAt)
            )
          );

        // Also refresh the cookie
        const isSecure = c.env.SECURE_COOKIES === 'true' ||
                         (c.env.SECURE_COOKIES !== 'false' && new URL(c.req.url).protocol === 'https:');
        const remainingLifetime = maxAllowedExpiry - Date.now();
        setCookie(c, 'session', rawSessionToken, {
          httpOnly: true,
          secure: isSecure,
          sameSite: 'Strict',
          path: '/',
          maxAge: Math.min(SESSION_DURATION_MS, remainingLifetime) / 1000,
        });
      }
    }

    return next();
  }
);

// Optional auth - doesn't fail if not authenticated
export const optionalAuthMiddleware = createMiddleware<{ Bindings: Env; Variables: Variables }>(
  async (c, next) => {
    const db = createDb(c.env.DB);
    const rawSessionToken = getCookie(c, 'session');

    c.set('user', null);
    c.set('session', null);

    if (!rawSessionToken) {
      return next();
    }

    // Hash the raw token to find the session in DB
    const sessionId = await hashSessionToken(rawSessionToken);

    const session = await db
      .select()
      .from(schema.sessions)
      .where(
        and(
          eq(schema.sessions.id, sessionId),
          gt(schema.sessions.expiresAt, now())
        )
      )
      .get();

    if (session) {
      const user = await db
        .select()
        .from(schema.users)
        .where(eq(schema.users.id, session.userId))
        .get();

      if (user && user.isActive) {
        c.set('user', {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role as UserRole,
          avatar: user.avatar,
          bio: user.bio,
          isActive: user.isActive,
          lastLoginAt: user.lastLoginAt,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
        });
        c.set('session', {
          id: session.id,
          userId: session.userId,
          userAgent: session.userAgent,
          ipAddress: session.ipAddress,
          expiresAt: session.expiresAt,
          createdAt: session.createdAt,
        });
      }
    }

    return next();
  }
);

// Admin only middleware
export const adminMiddleware = createMiddleware<{ Bindings: Env; Variables: Variables }>(
  async (c, next) => {
    const user = c.get('user');
    if (!user) {
      throw new HTTPException(401, { message: 'Unauthorized' });
    }
    if (user.role !== 'admin') {
      throw new HTTPException(403, { message: 'Forbidden - admin access required' });
    }
    return next();
  }
);

// Editor or admin middleware (can publish)
export const editorMiddleware = createMiddleware<{ Bindings: Env; Variables: Variables }>(
  async (c, next) => {
    const user = c.get('user');
    if (!user) {
      throw new HTTPException(401, { message: 'Unauthorized' });
    }
    if (user.role !== 'admin' && user.role !== 'editor') {
      throw new HTTPException(403, { message: 'Forbidden - editor access required' });
    }
    return next();
  }
);

// Permission-based middleware factory
export function requirePermission(permission: Permission) {
  return createMiddleware<{ Bindings: Env; Variables: Variables }>(async (c, next) => {
    const user = c.get('user');
    if (!user) {
      throw new HTTPException(401, { message: 'Unauthorized' });
    }
    if (!hasPermission(user.role, permission)) {
      throw new HTTPException(403, { message: `Forbidden - requires ${permission} permission` });
    }
    return next();
  });
}

// Role-based middleware factory
export function requireRole(...roles: UserRole[]) {
  return createMiddleware<{ Bindings: Env; Variables: Variables }>(async (c, next) => {
    const user = c.get('user');
    if (!user) {
      throw new HTTPException(401, { message: 'Unauthorized' });
    }
    if (!roles.includes(user.role)) {
      throw new HTTPException(403, { message: `Forbidden - requires one of: ${roles.join(', ')}` });
    }
    return next();
  });
}
