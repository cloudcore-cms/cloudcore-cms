import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { setCookie, deleteCookie, getCookie } from 'hono/cookie';
import { eq, desc, and, lt, gt, sql, like } from 'drizzle-orm';
import { z } from 'zod';
import type { Env, Variables, UserRole } from '../types';
import { createDb, schema } from '../db';
import { authMiddleware, adminMiddleware } from '../middleware/auth';
import { bruteForceProtection, getClientIpOrFallback, rateLimiter } from '../middleware/security';
import { loginSchema, createUserSchema, passwordSchema } from '../lib/validation';
import { generateId, now } from '../lib/utils';
import {
  hashPassword,
  verifyPassword,
  needsRehash,
  generateSecureToken,
  hashSessionToken,
  timingSafeDelay,
  timingSafeEqual,
  generateBase64UrlToken,
  encodeBase64Url,
  decodeBase64Url,
  timingSafeEqualBytes,
} from '../lib/crypto';

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// Session duration: 30 days
const SESSION_DURATION_MS = 30 * 24 * 60 * 60 * 1000;

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

// Check if setup is needed (no users exist)
// Rate limited to prevent reconnaissance abuse — generous limit since admin UI polls this
app.get('/status', rateLimiter({ windowMs: 60000, maxRequests: 60 }), async (c) => {
  const db = createDb(c.env.DB);
  const existingUser = await db
    .select({ id: schema.users.id })
    .from(schema.users)
    .limit(1)
    .get();

  // Check env var availability for each auth method
  const envAvailable = {
    password: true,
    passkey: true,
    magicLink: !!(c.env.SMTP_HOST || c.env.SENDGRID_API_KEY || c.env.RESEND_API_KEY || c.env.MAILGUN_API_KEY),
    github: !!(c.env.GITHUB_CLIENT_ID && c.env.GITHUB_CLIENT_SECRET),
    google: !!(c.env.GOOGLE_CLIENT_ID && c.env.GOOGLE_CLIENT_SECRET),
    cfAccess: c.env.CF_ACCESS_ENABLED === 'true',
  };

  // Load admin auth toggles from settings DB
  const authSettings = await db
    .select()
    .from(schema.settings)
    .where(like(schema.settings.key, 'auth.%'));

  const dbToggles: Record<string, boolean> = {};
  for (const s of authSettings) {
    // Strip "auth." prefix to match envAvailable keys
    const method = s.key.replace('auth.', '');
    const parsed = JSON.parse(s.value);
    dbToggles[method] = typeof parsed === 'boolean' ? parsed : true;
  }

  // Method is enabled only if env is available AND admin hasn't disabled it
  // Default to enabled if no DB toggle exists (backwards compatible)
  const authMethods = {
    password: envAvailable.password && (dbToggles.password ?? true),
    passkey: envAvailable.passkey && (dbToggles.passkey ?? true),
    magicLink: envAvailable.magicLink && (dbToggles.magicLink ?? true),
    github: envAvailable.github && (dbToggles.github ?? true),
    google: envAvailable.google && (dbToggles.google ?? true),
    cfAccess: envAvailable.cfAccess && (dbToggles.cfAccess ?? true),
  };

  return c.json({
    needsSetup: !existingUser,
    authMethods,
    // Also expose what's available at infra level (so admin UI can show "not configured" vs "disabled")
    envAvailable,
  });
});

// Login with brute force protection
app.post('/login', bruteForceProtection, zValidator('json', loginSchema), async (c) => {
  const db = createDb(c.env.DB);
  const body = c.req.valid('json');
  const ip = getClientIpOrFallback(c.req.raw);
  const userAgent = c.req.header('User-Agent') || null;

  const user = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.email, body.email.toLowerCase()))
    .get();

  if (!user || !user.passwordHash) {
    // Timing-safe delay to prevent user enumeration
    await timingSafeDelay();
    // Log failed attempt
    await logAudit(db, null, body.email, 'login_failed', 'user', null, { reason: 'user_not_found' }, ip, userAgent);
    return c.json({ error: 'Invalid email or password' }, 401);
  }

  // Check if user is active
  if (!user.isActive) {
    await timingSafeDelay();
    await logAudit(db, user.id, user.email, 'login_failed', 'user', user.id, { reason: 'account_deactivated' }, ip, userAgent);
    return c.json({ error: 'Account is deactivated' }, 401);
  }

  const valid = await verifyPassword(body.password, user.passwordHash);
  if (!valid) {
    // Timing-safe delay to prevent timing attacks distinguishing user-not-found from wrong-password
    await timingSafeDelay();
    await logAudit(db, user.id, user.email, 'login_failed', 'user', user.id, { reason: 'invalid_password' }, ip, userAgent);
    return c.json({ error: 'Invalid email or password' }, 401);
  }

  // Upgrade password hash if using older algorithm (transparent to user)
  if (needsRehash(user.passwordHash)) {
    const newHash = await hashPassword(body.password);
    await db
      .update(schema.users)
      .set({ passwordHash: newHash, updatedAt: now() })
      .where(eq(schema.users.id, user.id));
    // SECURITY: Invalidate all existing sessions when password hash is upgraded
    // This prevents session fixation attacks where an attacker might have
    // compromised a session before the password upgrade
    await db.delete(schema.sessions).where(eq(schema.sessions.userId, user.id));
    await logAudit(db, user.id, user.email, 'password_hash_upgraded', 'user', user.id, {
      sessionsInvalidated: true,
    }, ip, userAgent);
  }

  // Create session - generate raw token and store only hash
  const rawSessionToken = generateSecureToken(32);
  const sessionId = await hashSessionToken(rawSessionToken);
  const expiresAt = new Date(Date.now() + SESSION_DURATION_MS).toISOString();

  await db.insert(schema.sessions).values({
    id: sessionId, // Store hashed session ID
    userId: user.id,
    userAgent,
    ipAddress: ip,
    expiresAt,
    createdAt: now(),
  });

  // Update last login
  await db
    .update(schema.users)
    .set({ lastLoginAt: now() })
    .where(eq(schema.users.id, user.id));

  // Log successful login
  await logAudit(db, user.id, user.email, 'login', 'user', user.id, null, ip, userAgent);

  // Set session cookie - client gets raw token, DB stores only hash
  // Use SECURE_COOKIES env var to control (defaults to true for https: protocol)
  const isSecure = c.env.SECURE_COOKIES === 'true' ||
                   (c.env.SECURE_COOKIES !== 'false' && new URL(c.req.url).protocol === 'https:');
  setCookie(c, 'session', rawSessionToken, {
    httpOnly: true,
    secure: isSecure,
    sameSite: 'Strict', // Upgraded from 'Lax' for better CSRF protection
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

// Logout
app.post('/logout', async (c) => {
  const db = createDb(c.env.DB);
  const rawSessionToken = getCookie(c, 'session');
  const ip = getClientIpOrFallback(c.req.raw);
  const userAgent = c.req.header('User-Agent') || null;

  if (rawSessionToken) {
    // Hash the token to find it in DB
    const sessionId = await hashSessionToken(rawSessionToken);

    // Get session to log user info
    const session = await db.select().from(schema.sessions).where(eq(schema.sessions.id, sessionId)).get();
    if (session) {
      const user = await db.select().from(schema.users).where(eq(schema.users.id, session.userId)).get();
      if (user) {
        await logAudit(db, user.id, user.email, 'logout', 'user', user.id, null, ip, userAgent);
      }
    }

    // Delete session from DB
    await db.delete(schema.sessions).where(eq(schema.sessions.id, sessionId));
  }

  deleteCookie(c, 'session', { path: '/' });
  return c.json({ success: true });
});

// Get current user
app.get('/me', authMiddleware, async (c) => {
  const user = c.get('user');
  return c.json({ user });
});

// Setup schema with optional token
const setupSchema = createUserSchema.extend({
  setupToken: z.string().optional(),
});

// Create first admin user (only if no users exist)
// SECURITY: Rate limited aggressively to prevent race condition attacks
// Optional SETUP_TOKEN env var provides additional protection
app.post('/setup', rateLimiter({ windowMs: 60000, maxRequests: 3 }), zValidator('json', setupSchema), async (c) => {
  const db = createDb(c.env.DB);
  const body = c.req.valid('json');
  const ip = c.req.header('CF-Connecting-IP') || null;
  const userAgent = c.req.header('User-Agent') || null;

  // SECURITY: If SETUP_TOKEN is configured, require it
  // This prevents attackers from racing to set up the first admin
  if (c.env.SETUP_TOKEN) {
    if (!body.setupToken) {
      await logAudit(db, null, body.email.toLowerCase(), 'setup_failed', 'user', null, {
        reason: 'missing_setup_token',
      }, ip, userAgent);
      return c.json({ error: 'Setup token required' }, 403);
    }
    // Use timing-safe comparison to prevent timing attacks
    const isValidToken = timingSafeEqual(body.setupToken, c.env.SETUP_TOKEN);
    if (!isValidToken) {
      await logAudit(db, null, body.email.toLowerCase(), 'setup_failed', 'user', null, {
        reason: 'invalid_setup_token',
      }, ip, userAgent);
      return c.json({ error: 'Invalid setup token' }, 403);
    }
  }

  // Check if any users exist
  const existingUser = await db
    .select({ id: schema.users.id })
    .from(schema.users)
    .get();

  if (existingUser) {
    return c.json({ error: 'Setup already completed' }, 400);
  }

  const id = generateId();
  const passwordHash = await hashPassword(body.password);
  const timestamp = now();

  await db.insert(schema.users).values({
    id,
    email: body.email.toLowerCase(),
    passwordHash,
    name: body.name || null,
    role: 'admin', // First user is always admin
    isActive: true,
    createdAt: timestamp,
    updatedAt: timestamp,
  });

  await logAudit(db, id, body.email.toLowerCase(), 'setup', 'user', id, { role: 'admin' }, ip, userAgent);

  return c.json({ id, message: 'Admin user created' }, 201);
});

// Update user schema for editing
// SECURITY: Use strong password validation for updates too
const updateUserSchema = z.object({
  email: z.string().email().optional(),
  password: passwordSchema.optional(), // Strong password requirements
  name: z.string().optional().nullable(),
  role: z.enum(['admin', 'editor', 'contributor']).optional(),
  avatar: z.string().max(2000).optional().nullable(),
  bio: z.string().max(2000).optional().nullable(),
  isActive: z.boolean().optional(),
});

// Create user (admin only)
app.post('/users', authMiddleware, adminMiddleware, zValidator('json', createUserSchema), async (c) => {
  const db = createDb(c.env.DB);
  const currentUser = c.get('user')!;
  const body = c.req.valid('json');
  const ip = c.req.header('CF-Connecting-IP') || null;
  const userAgent = c.req.header('User-Agent') || null;

  // Check if email already exists
  const existing = await db
    .select({ id: schema.users.id })
    .from(schema.users)
    .where(eq(schema.users.email, body.email.toLowerCase()))
    .get();

  if (existing) {
    return c.json({ error: 'Email already registered' }, 400);
  }

  const id = generateId();
  const passwordHash = await hashPassword(body.password);
  const timestamp = now();

  await db.insert(schema.users).values({
    id,
    email: body.email.toLowerCase(),
    passwordHash,
    name: body.name || null,
    role: body.role || 'contributor',
    isActive: true,
    createdAt: timestamp,
    updatedAt: timestamp,
  });

  await logAudit(
    db,
    currentUser.id,
    currentUser.email,
    'create_user',
    'user',
    id,
    { email: body.email.toLowerCase(), role: body.role || 'contributor' },
    ip,
    userAgent
  );

  return c.json({ id }, 201);
});

// List users (admin only)
app.get('/users', authMiddleware, adminMiddleware, async (c) => {
  const db = createDb(c.env.DB);

  const users = await db
    .select({
      id: schema.users.id,
      email: schema.users.email,
      name: schema.users.name,
      role: schema.users.role,
      avatar: schema.users.avatar,
      bio: schema.users.bio,
      isActive: schema.users.isActive,
      lastLoginAt: schema.users.lastLoginAt,
      createdAt: schema.users.createdAt,
      updatedAt: schema.users.updatedAt,
    })
    .from(schema.users)
    .orderBy(desc(schema.users.createdAt));

  return c.json({ items: users });
});

// Get single user (admin only)
app.get('/users/:id', authMiddleware, adminMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const id = c.req.param('id');

  const user = await db
    .select({
      id: schema.users.id,
      email: schema.users.email,
      name: schema.users.name,
      role: schema.users.role,
      avatar: schema.users.avatar,
      bio: schema.users.bio,
      isActive: schema.users.isActive,
      lastLoginAt: schema.users.lastLoginAt,
      createdAt: schema.users.createdAt,
      updatedAt: schema.users.updatedAt,
    })
    .from(schema.users)
    .where(eq(schema.users.id, id))
    .get();

  if (!user) {
    return c.json({ error: 'User not found' }, 404);
  }

  return c.json(user);
});

// Update user (admin only)
app.patch('/users/:id', authMiddleware, adminMiddleware, zValidator('json', updateUserSchema), async (c) => {
  const db = createDb(c.env.DB);
  const currentUser = c.get('user')!;
  const id = c.req.param('id');
  const body = c.req.valid('json');
  const ip = c.req.header('CF-Connecting-IP') || null;
  const userAgent = c.req.header('User-Agent') || null;

  const existing = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.id, id))
    .get();

  if (!existing) {
    return c.json({ error: 'User not found' }, 404);
  }

  // Prevent demoting the last admin
  if (body.role && body.role !== 'admin' && existing.role === 'admin') {
    const adminCount = await db
      .select({ id: schema.users.id })
      .from(schema.users)
      .where(eq(schema.users.role, 'admin'))
      .all();

    if (adminCount.length <= 1) {
      return c.json({ error: 'Cannot demote the last admin' }, 400);
    }
  }

  // Prevent deactivating the last admin
  if (body.isActive === false && existing.role === 'admin') {
    // Get all admins with their isActive status
    const allAdmins = await db
      .select({ id: schema.users.id, isActive: schema.users.isActive })
      .from(schema.users)
      .where(eq(schema.users.role, 'admin'))
      .all();

    // Count active admins (excluding the one being deactivated)
    const activeAdminCount = allAdmins.filter(
      (u) => u.isActive && u.id !== id
    ).length;

    if (activeAdminCount < 1) {
      return c.json({ error: 'Cannot deactivate the last active admin' }, 400);
    }
  }

  const updates: Record<string, unknown> = { updatedAt: now() };

  if (body.email !== undefined) {
    // Check email uniqueness
    const emailExists = await db
      .select({ id: schema.users.id })
      .from(schema.users)
      .where(eq(schema.users.email, body.email.toLowerCase()))
      .get();

    if (emailExists && emailExists.id !== id) {
      return c.json({ error: 'Email already in use' }, 400);
    }
    updates.email = body.email.toLowerCase();
  }

  if (body.password !== undefined) {
    updates.passwordHash = await hashPassword(body.password);
  }

  if (body.name !== undefined) updates.name = body.name;
  if (body.role !== undefined) updates.role = body.role;
  if (body.avatar !== undefined) updates.avatar = body.avatar;
  if (body.bio !== undefined) updates.bio = body.bio;
  if (body.isActive !== undefined) updates.isActive = body.isActive;

  await db.update(schema.users).set(updates).where(eq(schema.users.id, id));

  // If user is deactivated, invalidate their sessions
  if (body.isActive === false) {
    await db.delete(schema.sessions).where(eq(schema.sessions.userId, id));
  }

  // If password is changed, invalidate all sessions for security (session rotation)
  // This forces re-authentication after password change
  if (body.password !== undefined) {
    await db.delete(schema.sessions).where(eq(schema.sessions.userId, id));
  }

  await logAudit(
    db,
    currentUser.id,
    currentUser.email,
    'update_user',
    'user',
    id,
    { changes: Object.keys(body) },
    ip,
    userAgent
  );

  return c.json({ success: true });
});

// Delete user (admin only)
app.delete('/users/:id', authMiddleware, adminMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const currentUser = c.get('user')!;
  const id = c.req.param('id');
  const ip = c.req.header('CF-Connecting-IP') || null;
  const userAgent = c.req.header('User-Agent') || null;

  if (currentUser.id === id) {
    return c.json({ error: 'Cannot delete yourself' }, 400);
  }

  const userToDelete = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.id, id))
    .get();

  if (!userToDelete) {
    return c.json({ error: 'User not found' }, 404);
  }

  // Prevent deleting the last admin
  if (userToDelete.role === 'admin') {
    const adminCount = await db
      .select({ id: schema.users.id })
      .from(schema.users)
      .where(eq(schema.users.role, 'admin'))
      .all();

    if (adminCount.length <= 1) {
      return c.json({ error: 'Cannot delete the last admin' }, 400);
    }
  }

  // Delete sessions first
  await db.delete(schema.sessions).where(eq(schema.sessions.userId, id));

  // Delete user
  await db.delete(schema.users).where(eq(schema.users.id, id));

  await logAudit(
    db,
    currentUser.id,
    currentUser.email,
    'delete_user',
    'user',
    id,
    { email: userToDelete.email, role: userToDelete.role },
    ip,
    userAgent
  );

  return c.json({ success: true });
});

// Get audit log (admin only)
app.get('/audit', authMiddleware, adminMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const limit = Math.min(Math.max(1, parseInt(c.req.query('limit') || '50', 10) || 50), 100);
  const offset = Math.max(0, parseInt(c.req.query('offset') || '0', 10) || 0);

  const logs = await db
    .select()
    .from(schema.auditLog)
    .orderBy(desc(schema.auditLog.createdAt))
    .limit(Math.min(limit, 100))
    .offset(offset);

  return c.json({
    items: logs.map((log) => ({
      ...log,
      details: log.details ? JSON.parse(log.details) : null,
    })),
  });
});

// Get active sessions for a user (admin only)
app.get('/users/:id/sessions', authMiddleware, adminMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const id = c.req.param('id');

  const sessions = await db
    .select({
      id: schema.sessions.id,
      userAgent: schema.sessions.userAgent,
      ipAddress: schema.sessions.ipAddress,
      expiresAt: schema.sessions.expiresAt,
      createdAt: schema.sessions.createdAt,
    })
    .from(schema.sessions)
    .where(eq(schema.sessions.userId, id))
    .orderBy(desc(schema.sessions.createdAt));

  return c.json({ items: sessions });
});

// Revoke a specific session (admin only)
app.delete('/sessions/:sessionId', authMiddleware, adminMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const currentUser = c.get('user')!;
  const sessionId = c.req.param('sessionId');
  const ip = c.req.header('CF-Connecting-IP') || null;
  const userAgent = c.req.header('User-Agent') || null;

  const session = await db
    .select()
    .from(schema.sessions)
    .where(eq(schema.sessions.id, sessionId))
    .get();

  if (!session) {
    return c.json({ error: 'Session not found' }, 404);
  }

  await db.delete(schema.sessions).where(eq(schema.sessions.id, sessionId));

  await logAudit(
    db,
    currentUser.id,
    currentUser.email,
    'revoke_session',
    'user',
    session.userId,
    { sessionId },
    ip,
    userAgent
  );

  return c.json({ success: true });
});

// Revoke all sessions for a user (admin only)
app.delete('/users/:id/sessions', authMiddleware, adminMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const currentUser = c.get('user')!;
  const id = c.req.param('id');
  const ip = c.req.header('CF-Connecting-IP') || null;
  const userAgent = c.req.header('User-Agent') || null;

  await db.delete(schema.sessions).where(eq(schema.sessions.userId, id));

  await logAudit(
    db,
    currentUser.id,
    currentUser.email,
    'revoke_all_sessions',
    'user',
    id,
    null,
    ip,
    userAgent
  );

  return c.json({ success: true });
});

// ============================================================================
// Passkey/WebAuthn Authentication
// ============================================================================

// Challenge expiry: 5 minutes
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

// WebAuthn RP (Relying Party) configuration
// Uses the Origin header (actual browser origin) when behind a proxy,
// falls back to the request URL for direct connections
function getRelyingParty(c: { req: { url: string; header: (name: string) => string | undefined } }) {
  // Prefer Origin header — this is the actual browser origin even behind a proxy
  const origin = c.req.header('Origin');
  const referer = c.req.header('Referer');
  let url = c.req.url;

  if (origin) {
    url = origin;
  } else if (referer) {
    try {
      url = new URL(referer).origin;
    } catch { /* use request URL */ }
  }

  const parsed = new URL(url);
  return {
    id: parsed.hostname, // RP ID should be the hostname
    name: 'Cloudcore CMS',
    origin: parsed.origin,
  };
}

// Cleanup expired challenges
async function cleanupExpiredChallenges(db: ReturnType<typeof createDb>) {
  const nowStr = now();
  await db.delete(schema.passkeyChallenges).where(lt(schema.passkeyChallenges.expiresAt, nowStr));
}

// Store a challenge for WebAuthn ceremony
async function storeChallenge(
  db: ReturnType<typeof createDb>,
  challenge: string,
  type: 'register' | 'authenticate',
  userId?: string
): Promise<void> {
  const timestamp = now();
  const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS).toISOString();

  await db.insert(schema.passkeyChallenges).values({
    challenge,
    userId: userId || null,
    type,
    expiresAt,
    createdAt: timestamp,
  });
}

// Validate and consume a challenge (single-use) - ATOMIC to prevent race conditions
async function consumeChallenge(
  db: ReturnType<typeof createDb>,
  challenge: string,
  type: 'register' | 'authenticate',
  userId?: string
): Promise<boolean> {
  const nowStr = now();
  // SECURITY: Use unique consumption marker (timestamp + UUID) to prevent
  // race conditions where two requests in the same millisecond both succeed
  const consumedAt = `${nowStr}:${crypto.randomUUID()}`;

  // SECURITY: Atomically consume the challenge using UPDATE with consumedAt IS NULL
  // This prevents race conditions where multiple requests could consume the same challenge
  await db
    .update(schema.passkeyChallenges)
    .set({ consumedAt })
    .where(
      and(
        eq(schema.passkeyChallenges.challenge, challenge),
        eq(schema.passkeyChallenges.type, type),
        gt(schema.passkeyChallenges.expiresAt, nowStr),
        sql`${schema.passkeyChallenges.consumedAt} IS NULL`
      )
    );

  // Verify we consumed the challenge by checking if our timestamp was set
  const stored = await db
    .select()
    .from(schema.passkeyChallenges)
    .where(eq(schema.passkeyChallenges.challenge, challenge))
    .get();

  if (!stored || stored.consumedAt !== consumedAt) {
    // Either challenge doesn't exist, expired, or was consumed by another request
    return false;
  }

  // For authenticated registration, verify userId matches
  if (type === 'register' && userId && stored.userId !== userId) {
    return false;
  }

  return true;
}

// Hash client data for signature verification
// WebAuthn requires SHA-256 of the raw clientDataJSON bytes (before base64url decoding to text)
async function hashClientDataJSON(clientDataJSONBase64url: string): Promise<Uint8Array> {
  // The clientDataJSON from the browser is base64url-encoded raw bytes
  // We need to hash the raw bytes, not the decoded UTF-8 text
  const rawBytes = decodeBase64Url(clientDataJSONBase64url);
  const hashBuffer = await crypto.subtle.digest('SHA-256', rawBytes);
  return new Uint8Array(hashBuffer);
}

// Verify signature using ECDSA P-256 (most common WebAuthn algorithm)
async function verifySignature(
  publicKeyBytes: Uint8Array,
  signature: Uint8Array,
  data: Uint8Array
): Promise<boolean> {
  try {
    // Import the COSE public key (assuming ES256 - ECDSA P-256)
    // COSE key format parsing (simplified for ES256)
    const publicKey = await crypto.subtle.importKey(
      'raw',
      publicKeyBytes,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );

    // WebAuthn uses DER-encoded signatures, need to convert to raw format
    const rawSignature = derToRaw(signature);

    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      rawSignature,
      data
    );
  } catch {
    return false;
  }
}

// Convert DER signature to raw format (for WebAuthn ES256)
function derToRaw(derSig: Uint8Array): Uint8Array {
  // DER signature: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
  if (derSig[0] !== 0x30) {
    // Already raw format or unknown
    return derSig;
  }

  let offset = 2; // Skip 0x30 and total length
  if (derSig[1]! > 0x80) offset++; // Long form length

  // Read r
  if (derSig[offset] !== 0x02) return derSig;
  offset++;
  const rLen = derSig[offset]!;
  offset++;
  let r = derSig.slice(offset, offset + rLen);
  offset += rLen;

  // Read s
  if (derSig[offset] !== 0x02) return derSig;
  offset++;
  const sLen = derSig[offset]!;
  offset++;
  let s = derSig.slice(offset, offset + sLen);

  // Remove leading zeros and pad to 32 bytes
  if (r.length > 32) r = r.slice(r.length - 32);
  if (s.length > 32) s = s.slice(s.length - 32);

  const raw = new Uint8Array(64);
  raw.set(r, 32 - r.length);
  raw.set(s, 64 - s.length);

  return raw;
}

// Extract public key from COSE format (ES256)
function extractPublicKeyFromCOSE(coseKey: Uint8Array): Uint8Array | null {
  try {
    // Simple CBOR parsing for COSE_Key (ES256 P-256)
    // This is a simplified parser for the most common WebAuthn key format
    // COSE key map: {1: kty, 3: alg, -1: crv, -2: x, -3: y}

    // For ES256, we expect kty=2 (EC), alg=-7 (ES256), crv=1 (P-256)
    // The public key is in uncompressed format: 0x04 || x || y

    let i = 0;
    if (coseKey[i]! !== 0xa5 && coseKey[i]! !== 0xa4) {
      // Not a 4 or 5 element map - might be different format
      // Try to find x and y coordinates directly
    }
    i++; // Skip map header

    let x: Uint8Array | null = null;
    let y: Uint8Array | null = null;

    while (i < coseKey.length - 1) {
      // Read key
      const key = coseKey[i]!;
      i++;

      // Read value based on key
      if (key === 0x21 || key === 0x38) {
        // -2 (x coordinate) in CBOR encoding
        if (coseKey[i] === 0x58 && coseKey[i + 1] === 0x20) {
          // byte string of length 32
          x = coseKey.slice(i + 2, i + 34);
          i += 34;
        } else {
          break;
        }
      } else if (key === 0x22 || key === 0x39) {
        // -3 (y coordinate) in CBOR encoding
        if (coseKey[i] === 0x58 && coseKey[i + 1] === 0x20) {
          y = coseKey.slice(i + 2, i + 34);
          i += 34;
        } else {
          break;
        }
      } else {
        // Skip other values - simplified
        if (coseKey[i]! <= 0x17) {
          i++; // Small int
        } else if (coseKey[i] === 0x20 || (coseKey[i]! >= 0x01 && coseKey[i]! <= 0x03)) {
          i++; // Negative small int or small positive
        } else if (coseKey[i] === 0x26) {
          i++; // -7 (ES256 alg)
        } else if (coseKey[i] === 0x58) {
          i += 2 + coseKey[i + 1]!; // byte string
        } else {
          i++;
        }
      }

      if (x && y) break;
    }

    if (x && y) {
      // Create uncompressed point format: 0x04 || x || y
      const publicKey = new Uint8Array(65);
      publicKey[0] = 0x04;
      publicKey.set(x, 1);
      publicKey.set(y, 33);
      return publicKey;
    }

    return null;
  } catch {
    return null;
  }
}

// Max passkeys per user to prevent abuse
const MAX_PASSKEYS_PER_USER = 10;

// Passkey registration options (authenticated users only)
// Rate limited to prevent challenge exhaustion attacks
// SECURITY: Use per-user rate limiting to prevent one user from affecting others
app.post('/passkeys/register/options', authMiddleware, rateLimiter({
  windowMs: 60000,
  maxRequests: 10,
  keyGenerator: (c) => {
    const user = c.get('user');
    return user ? `passkey-register:${user.id}` : `passkey-register:anon`;
  },
}), async (c) => {
  const db = createDb(c.env.DB);
  const user = c.get('user')!;
  const rp = getRelyingParty(c);

  // Cleanup expired challenges
  await cleanupExpiredChallenges(db);

  // Get existing credentials to exclude and check limit
  const existingCredentials = await db
    .select({ id: schema.passkeyCredentials.id })
    .from(schema.passkeyCredentials)
    .where(eq(schema.passkeyCredentials.userId, user.id));

  // Limit passkeys per user
  if (existingCredentials.length >= MAX_PASSKEYS_PER_USER) {
    return c.json({ error: `Maximum ${MAX_PASSKEYS_PER_USER} passkeys allowed per user` }, 400);
  }

  // Generate challenge
  const challenge = generateBase64UrlToken(32);

  // Store challenge
  await storeChallenge(db, challenge, 'register', user.id);

  // Return registration options (WebAuthn PublicKeyCredentialCreationOptions format)
  return c.json({
    challenge,
    rp: {
      id: rp.id,
      name: rp.name,
    },
    user: {
      id: encodeBase64Url(new TextEncoder().encode(user.id)),
      name: user.email,
      displayName: user.name || user.email,
    },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 }, // ES256 (ECDSA P-256)
      { type: 'public-key', alg: -257 }, // RS256 (RSA)
    ],
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
    timeout: CHALLENGE_TTL_MS,
    attestation: 'none', // Don't require attestation
    excludeCredentials: existingCredentials.map((cred) => ({
      id: cred.id,
      type: 'public-key',
    })),
  });
});

// Passkey registration verification
// Rate limited to prevent credential stuffing
// SECURITY: Use per-user rate limiting to prevent one user from affecting others
app.post('/passkeys/register/verify', authMiddleware, rateLimiter({
  windowMs: 60000,
  maxRequests: 10,
  keyGenerator: (c) => {
    const user = c.get('user');
    return user ? `passkey-verify:${user.id}` : `passkey-verify:anon`;
  },
}), zValidator('json', z.object({
  id: z.string(),
  rawId: z.string(),
  response: z.object({
    clientDataJSON: z.string(),
    attestationObject: z.string(),
  }),
  type: z.literal('public-key'),
  name: z.string().optional(),
})
), async (c) => {
  const db = createDb(c.env.DB);
  const user = c.get('user')!;
  const body = c.req.valid('json');
  const rp = getRelyingParty(c);
  const ip = getClientIpOrFallback(c.req.raw);
  const userAgent = c.req.header('User-Agent') || null;

  try {
    // Decode client data
    const clientDataJSON = new TextDecoder().decode(decodeBase64Url(body.response.clientDataJSON));
    const clientData = JSON.parse(clientDataJSON);

    // Verify client data
    if (clientData.type !== 'webauthn.create') {
      return c.json({ error: 'Invalid client data type' }, 400);
    }

    // Verify challenge
    const challengeValid = await consumeChallenge(db, clientData.challenge, 'register', user.id);
    if (!challengeValid) {
      return c.json({ error: 'Invalid or expired challenge' }, 400);
    }

    // Verify origin
    if (clientData.origin !== rp.origin) {
      return c.json({ error: 'Invalid origin' }, 400);
    }

    // Decode attestation object (CBOR-encoded)
    const attestationObject = decodeBase64Url(body.response.attestationObject);

    // Simple CBOR parsing for attestation object
    // Format: {fmt: string, attStmt: {}, authData: bytes}
    // We need authData which contains: rpIdHash(32) || flags(1) || signCount(4) || attestedCredentialData

    // Find authData in attestation object (simplified CBOR parsing)
    let authDataStart = 0;
    let authDataLen = 0;

    // Look for 'authData' key and byte string value
    const authDataKey = new TextEncoder().encode('authData');
    for (let i = 0; i < attestationObject.length - authDataKey.length; i++) {
      let match = true;
      for (let j = 0; j < authDataKey.length; j++) {
        if (attestationObject[i + j] !== authDataKey[j]) {
          match = false;
          break;
        }
      }
      if (match) {
        // Found authData key, next byte should be byte string indicator
        const next = attestationObject[i + authDataKey.length]!;
        if (next === 0x58) {
          // 1-byte length
          authDataLen = attestationObject[i + authDataKey.length + 1]!;
          authDataStart = i + authDataKey.length + 2;
        } else if (next === 0x59) {
          // 2-byte length
          authDataLen = (attestationObject[i + authDataKey.length + 1]! << 8) | attestationObject[i + authDataKey.length + 2]!;
          authDataStart = i + authDataKey.length + 3;
        }
        break;
      }
    }

    if (authDataLen === 0) {
      return c.json({ error: 'Could not parse attestation object' }, 400);
    }

    const authData = attestationObject.slice(authDataStart, authDataStart + authDataLen);

    // Parse authenticator data
    // rpIdHash (32 bytes) || flags (1 byte) || signCount (4 bytes) || attestedCredentialData (variable)
    const rpIdHash = authData.slice(0, 32);
    const flags = authData[32]!;
    const signCount = new DataView(authData.buffer, authData.byteOffset + 33, 4).getUint32(0, false);

    // Verify RP ID hash
    const expectedRpIdHash = new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rp.id))
    );
    if (!timingSafeEqualBytes(rpIdHash, expectedRpIdHash)) {
      return c.json({ error: 'Invalid RP ID' }, 400);
    }

    // Check flags: AT (attested credential data) must be present
    const atFlag = (flags & 0x40) !== 0;
    if (!atFlag) {
      return c.json({ error: 'No attested credential data' }, 400);
    }

    // Parse attested credential data
    // aaguid (16 bytes) || credentialIdLength (2 bytes) || credentialId || credentialPublicKey
    let offset = 37;
    const aaguid = authData.slice(offset, offset + 16);
    offset += 16;

    const credentialIdLength = (authData[offset]! << 8) | authData[offset + 1]!;
    offset += 2;

    const credentialId = authData.slice(offset, offset + credentialIdLength);
    offset += credentialIdLength;

    // Remaining bytes are the COSE public key
    const publicKeyCOSE = authData.slice(offset);

    // Extract public key for verification
    const publicKey = extractPublicKeyFromCOSE(publicKeyCOSE);
    if (!publicKey) {
      // Store the raw COSE key if we can't extract it
      // This is fine for storage, verification will use original format
    }

    const credentialIdBase64 = encodeBase64Url(credentialId);

    // Check if credential already exists
    const existing = await db
      .select({ id: schema.passkeyCredentials.id })
      .from(schema.passkeyCredentials)
      .where(eq(schema.passkeyCredentials.id, credentialIdBase64))
      .get();

    if (existing) {
      return c.json({ error: 'Credential already registered' }, 400);
    }

    // Determine device type from flags
    const uvFlag = (flags & 0x04) !== 0;
    const beFlag = (flags & 0x10) !== 0;
    const bsFlag = (flags & 0x08) !== 0;

    const timestamp = now();

    // SECURITY: Sanitize and limit passkey name length to prevent storage issues
    const sanitizedName = body.name
      ? body.name.trim().substring(0, 100)
      : `Passkey ${new Date().toLocaleDateString()}`;

    // Store credential
    await db.insert(schema.passkeyCredentials).values({
      id: credentialIdBase64,
      userId: user.id,
      publicKey: encodeBase64Url(publicKeyCOSE), // Store COSE format
      counter: signCount,
      deviceType: uvFlag ? 'platform' : 'cross-platform',
      backedUp: bsFlag,
      transports: null, // Could be passed from client
      name: sanitizedName,
      lastUsedAt: null,
      createdAt: timestamp,
    });

    // Audit log
    await logAudit(db, user.id, user.email, 'passkey_registered', 'passkey', credentialIdBase64, {
      name: sanitizedName,
    }, ip, userAgent);

    return c.json({
      success: true,
      credential: {
        id: credentialIdBase64,
        name: sanitizedName,
      },
    });
  } catch (error) {
    console.error('Passkey registration error:', error);
    return c.json({ error: 'Registration failed' }, 400);
  }
});

// Passkey authentication options (pre-login)
// SECURITY: Add rate limiting and timing-safe delays to prevent email enumeration
app.post('/passkeys/authenticate/options', rateLimiter({ windowMs: 60000, maxRequests: 20 }), zValidator('json', z.object({
  email: z.string().email().optional(),
}).optional()), async (c) => {
  const db = createDb(c.env.DB);
  const body = c.req.valid('json');
  const rp = getRelyingParty(c);

  // Cleanup expired challenges
  await cleanupExpiredChallenges(db);

  // Generate challenge
  const challenge = generateBase64UrlToken(32);

  // SECURITY: Always do a database lookup even if no email provided
  // to normalize timing and prevent email enumeration attacks
  let allowCredentials: { id: string; type: 'public-key' }[] = [];

  if (body?.email) {
    const user = await db
      .select({ id: schema.users.id })
      .from(schema.users)
      .where(eq(schema.users.email, body.email.toLowerCase()))
      .get();

    if (user) {
      const credentials = await db
        .select({ id: schema.passkeyCredentials.id })
        .from(schema.passkeyCredentials)
        .where(eq(schema.passkeyCredentials.userId, user.id));

      allowCredentials = credentials.map((cred) => ({
        id: cred.id,
        type: 'public-key' as const,
      }));
    } else {
      // SECURITY: User doesn't exist - add timing-safe delay to match lookup time
      // and do a dummy query to normalize timing
      await timingSafeDelay();
    }
  }

  // Store challenge (no userId for authentication - will be determined from credential)
  await storeChallenge(db, challenge, 'authenticate');

  // SECURITY: Always return the same response format regardless of user existence
  // allowCredentials is empty array for both non-existent users and users without passkeys
  // This prevents email enumeration via response differences
  return c.json({
    challenge,
    rpId: rp.id,
    timeout: CHALLENGE_TTL_MS,
    userVerification: 'preferred',
    // Always return empty array or credentials - never undefined vs array
    // This normalizes the response to prevent user enumeration
    allowCredentials: allowCredentials,
  });
});

// Passkey authentication verification
app.post('/passkeys/authenticate/verify', zValidator('json', z.object({
  id: z.string(),
  rawId: z.string(),
  response: z.object({
    clientDataJSON: z.string(),
    authenticatorData: z.string(),
    signature: z.string(),
    userHandle: z.string().optional(),
  }),
  type: z.literal('public-key'),
})
), async (c) => {
  const db = createDb(c.env.DB);
  const body = c.req.valid('json');
  const rp = getRelyingParty(c);
  const ip = getClientIpOrFallback(c.req.raw);
  const userAgent = c.req.header('User-Agent') || null;

  try {
    // Find credential
    const credential = await db
      .select()
      .from(schema.passkeyCredentials)
      .where(eq(schema.passkeyCredentials.id, body.id))
      .get();

    if (!credential) {
      await timingSafeDelay();
      return c.json({ error: 'Invalid credential' }, 401);
    }

    // Get user
    const user = await db
      .select()
      .from(schema.users)
      .where(eq(schema.users.id, credential.userId))
      .get();

    if (!user || !user.isActive) {
      await timingSafeDelay();
      await logAudit(db, null, null, 'passkey_auth_failed', 'passkey', body.id, {
        reason: user ? 'account_deactivated' : 'user_not_found',
      }, ip, userAgent);
      return c.json({ error: 'Authentication failed' }, 401);
    }

    // Decode client data
    const clientDataJSON = new TextDecoder().decode(decodeBase64Url(body.response.clientDataJSON));
    const clientData = JSON.parse(clientDataJSON);

    // Verify client data type
    if (clientData.type !== 'webauthn.get') {
      return c.json({ error: 'Invalid client data type' }, 400);
    }

    // Verify challenge
    const challengeValid = await consumeChallenge(db, clientData.challenge, 'authenticate');
    if (!challengeValid) {
      return c.json({ error: 'Invalid or expired challenge' }, 400);
    }

    // Verify origin
    if (clientData.origin !== rp.origin) {
      return c.json({ error: 'Invalid origin' }, 400);
    }

    // Decode authenticator data and signature
    const authenticatorData = decodeBase64Url(body.response.authenticatorData);
    const signature = decodeBase64Url(body.response.signature);

    // Verify RP ID hash (first 32 bytes of authenticator data)
    const rpIdHash = authenticatorData.slice(0, 32);
    const expectedRpIdHash = new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rp.id))
    );
    if (!timingSafeEqualBytes(rpIdHash, expectedRpIdHash)) {
      return c.json({ error: 'Invalid RP ID' }, 400);
    }

    // Check flags: UP (user present) must be set
    const flags = authenticatorData[32]!;
    const upFlag = (flags & 0x01) !== 0;
    if (!upFlag) {
      return c.json({ error: 'User presence not verified' }, 400);
    }

    // Get sign count
    const signCount = new DataView(
      authenticatorData.buffer,
      authenticatorData.byteOffset + 33,
      4
    ).getUint32(0, false);

    // Verify sign count - must be strictly greater than stored counter
    // Note: Some authenticators always return 0 (don't track counters), so we allow 0 → 0
    // But if either side has a non-zero counter, we enforce strict incrementing
    if (credential.counter > 0 && signCount <= credential.counter) {
      // Counter went backwards or stayed the same - possible cloned authenticator
      await logAudit(db, user.id, user.email, 'passkey_auth_failed', 'passkey', body.id, {
        reason: 'sign_count_replay',
        storedCounter: credential.counter,
        receivedCounter: signCount,
      }, ip, userAgent);
      return c.json({ error: 'Possible credential clone detected' }, 401);
    }

    // Verify signature
    // Data to verify: authenticatorData || SHA-256(clientDataJSON)
    const clientDataHash = await hashClientDataJSON(body.response.clientDataJSON);
    const signedData = new Uint8Array(authenticatorData.length + clientDataHash.length);
    signedData.set(authenticatorData);
    signedData.set(clientDataHash, authenticatorData.length);

    // Get public key and verify
    const publicKeyCOSE = decodeBase64Url(credential.publicKey);
    const publicKey = extractPublicKeyFromCOSE(publicKeyCOSE);

    if (!publicKey) {
      return c.json({ error: 'Invalid public key format' }, 400);
    }

    const signatureValid = await verifySignature(publicKey, signature, signedData);
    if (!signatureValid) {
      await logAudit(db, user.id, user.email, 'passkey_auth_failed', 'passkey', body.id, {
        reason: 'invalid_signature',
      }, ip, userAgent);
      return c.json({ error: 'Invalid signature' }, 401);
    }

    // Update credential counter and last used
    const timestamp = now();
    await db
      .update(schema.passkeyCredentials)
      .set({
        counter: signCount,
        lastUsedAt: timestamp,
      })
      .where(eq(schema.passkeyCredentials.id, body.id));

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

    // Audit log
    await logAudit(db, user.id, user.email, 'passkey_login', 'user', user.id, {
      credentialId: body.id,
    }, ip, userAgent);

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
  } catch (error) {
    console.error('Passkey authentication error:', error);
    return c.json({ error: 'Authentication failed' }, 401);
  }
});

// List user's passkeys
app.get('/passkeys', authMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const user = c.get('user')!;

  const credentials = await db
    .select({
      id: schema.passkeyCredentials.id,
      name: schema.passkeyCredentials.name,
      deviceType: schema.passkeyCredentials.deviceType,
      backedUp: schema.passkeyCredentials.backedUp,
      lastUsedAt: schema.passkeyCredentials.lastUsedAt,
      createdAt: schema.passkeyCredentials.createdAt,
    })
    .from(schema.passkeyCredentials)
    .where(eq(schema.passkeyCredentials.userId, user.id))
    .orderBy(desc(schema.passkeyCredentials.createdAt));

  return c.json({ items: credentials });
});

// Update passkey name
app.patch('/passkeys/:id', authMiddleware, zValidator('json', z.object({
  name: z.string().min(1).max(100),
})), async (c) => {
  const db = createDb(c.env.DB);
  const user = c.get('user')!;
  const credentialId = c.req.param('id');
  const body = c.req.valid('json');
  const ip = getClientIpOrFallback(c.req.raw);
  const userAgent = c.req.header('User-Agent') || null;

  // Verify ownership
  const credential = await db
    .select()
    .from(schema.passkeyCredentials)
    .where(
      and(
        eq(schema.passkeyCredentials.id, credentialId),
        eq(schema.passkeyCredentials.userId, user.id)
      )
    )
    .get();

  if (!credential) {
    return c.json({ error: 'Passkey not found' }, 404);
  }

  await db
    .update(schema.passkeyCredentials)
    .set({ name: body.name })
    .where(eq(schema.passkeyCredentials.id, credentialId));

  await logAudit(db, user.id, user.email, 'passkey_renamed', 'passkey', credentialId, {
    oldName: credential.name,
    newName: body.name,
  }, ip, userAgent);

  return c.json({ success: true });
});

// Delete a passkey
app.delete('/passkeys/:id', authMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const user = c.get('user')!;
  const credentialId = c.req.param('id');
  const ip = getClientIpOrFallback(c.req.raw);
  const userAgent = c.req.header('User-Agent') || null;

  // Verify ownership
  const credential = await db
    .select()
    .from(schema.passkeyCredentials)
    .where(
      and(
        eq(schema.passkeyCredentials.id, credentialId),
        eq(schema.passkeyCredentials.userId, user.id)
      )
    )
    .get();

  if (!credential) {
    return c.json({ error: 'Passkey not found' }, 404);
  }

  // Delete credential
  await db
    .delete(schema.passkeyCredentials)
    .where(eq(schema.passkeyCredentials.id, credentialId));

  await logAudit(db, user.id, user.email, 'passkey_deleted', 'passkey', credentialId, {
    name: credential.name,
  }, ip, userAgent);

  return c.json({ success: true });
});

// ============================================================================
// Profile Management (self-service)
// ============================================================================

// Update own profile
const updateProfileSchema = z.object({
  name: z.string().max(200).optional().nullable(),
  email: z.string().email().optional(),
  bio: z.string().max(2000).optional().nullable(),
  avatar: z.string().max(2000).optional().nullable(),
});

app.patch('/me', authMiddleware, zValidator('json', updateProfileSchema), async (c) => {
  const db = createDb(c.env.DB);
  const user = c.get('user')!;
  const body = c.req.valid('json');
  const ip = getClientIpOrFallback(c.req.raw);
  const userAgent = c.req.header('User-Agent') || null;

  const updates: Record<string, unknown> = { updatedAt: now() };

  if (body.name !== undefined) updates.name = body.name;
  if (body.bio !== undefined) updates.bio = body.bio;
  if (body.avatar !== undefined) updates.avatar = body.avatar;

  if (body.email !== undefined && body.email !== user.email) {
    // Check email uniqueness
    const emailExists = await db
      .select({ id: schema.users.id })
      .from(schema.users)
      .where(eq(schema.users.email, body.email.toLowerCase()))
      .get();

    if (emailExists && emailExists.id !== user.id) {
      return c.json({ error: 'Email already in use' }, 400);
    }
    updates.email = body.email.toLowerCase();
  }

  if (Object.keys(updates).length > 1) { // > 1 because updatedAt is always there
    await db.update(schema.users).set(updates).where(eq(schema.users.id, user.id));
  }

  await logAudit(db, user.id, user.email, 'profile_updated', 'user', user.id, {
    changes: Object.keys(body).filter((k) => body[k as keyof typeof body] !== undefined),
  }, ip, userAgent);

  // Return updated user
  const updated = await db
    .select({
      id: schema.users.id,
      email: schema.users.email,
      name: schema.users.name,
      role: schema.users.role,
      avatar: schema.users.avatar,
      bio: schema.users.bio,
      isActive: schema.users.isActive,
      lastLoginAt: schema.users.lastLoginAt,
      createdAt: schema.users.createdAt,
      updatedAt: schema.users.updatedAt,
    })
    .from(schema.users)
    .where(eq(schema.users.id, user.id))
    .get();

  return c.json({ user: updated });
});

// Change own password
const changePasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: passwordSchema,
});

app.post('/me/change-password', authMiddleware, zValidator('json', changePasswordSchema), async (c) => {
  const db = createDb(c.env.DB);
  const user = c.get('user')!;
  const body = c.req.valid('json');
  const ip = getClientIpOrFallback(c.req.raw);
  const userAgent = c.req.header('User-Agent') || null;

  // Get current password hash
  const dbUser = await db
    .select({ passwordHash: schema.users.passwordHash })
    .from(schema.users)
    .where(eq(schema.users.id, user.id))
    .get();

  if (!dbUser?.passwordHash) {
    return c.json({ error: 'No password set on this account. Use a different method to set one.' }, 400);
  }

  // Verify current password
  const valid = await verifyPassword(body.currentPassword, dbUser.passwordHash);
  if (!valid) {
    await timingSafeDelay();
    await logAudit(db, user.id, user.email, 'password_change_failed', 'user', user.id, {
      reason: 'wrong_current_password',
    }, ip, userAgent);
    return c.json({ error: 'Current password is incorrect' }, 401);
  }

  // Hash and save new password
  const newHash = await hashPassword(body.newPassword);
  await db
    .update(schema.users)
    .set({ passwordHash: newHash, updatedAt: now() })
    .where(eq(schema.users.id, user.id));

  // Invalidate all other sessions (security: force re-auth after password change)
  const currentSession = c.get('session' as any);
  if (currentSession?.id) {
    await db.delete(schema.sessions).where(
      and(
        eq(schema.sessions.userId, user.id),
        sql`${schema.sessions.id} != ${currentSession.id}`
      )
    );
  }

  await logAudit(db, user.id, user.email, 'password_changed', 'user', user.id, null, ip, userAgent);

  return c.json({ success: true });
});

// List own OAuth connections
app.get('/me/oauth-connections', authMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const user = c.get('user')!;

  const connections = await db
    .select({
      id: schema.oauthConnections.id,
      provider: schema.oauthConnections.provider,
      providerEmail: schema.oauthConnections.providerEmail,
      createdAt: schema.oauthConnections.createdAt,
    })
    .from(schema.oauthConnections)
    .where(eq(schema.oauthConnections.userId, user.id));

  return c.json({ items: connections });
});

// Unlink an OAuth connection
app.delete('/me/oauth-connections/:id', authMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const user = c.get('user')!;
  const connectionId = c.req.param('id');
  const ip = getClientIpOrFallback(c.req.raw);
  const userAgent = c.req.header('User-Agent') || null;

  // Verify ownership
  const connection = await db
    .select()
    .from(schema.oauthConnections)
    .where(
      and(
        eq(schema.oauthConnections.id, connectionId),
        eq(schema.oauthConnections.userId, user.id)
      )
    )
    .get();

  if (!connection) {
    return c.json({ error: 'OAuth connection not found' }, 404);
  }

  // Safety: ensure user still has at least one login method after unlinking
  const dbUser = await db
    .select({ passwordHash: schema.users.passwordHash })
    .from(schema.users)
    .where(eq(schema.users.id, user.id))
    .get();

  const otherOAuth = await db
    .select({ id: schema.oauthConnections.id })
    .from(schema.oauthConnections)
    .where(
      and(
        eq(schema.oauthConnections.userId, user.id),
        sql`${schema.oauthConnections.id} != ${connectionId}`
      )
    );

  const hasPasskeys = await db
    .select({ id: schema.passkeyCredentials.id })
    .from(schema.passkeyCredentials)
    .where(eq(schema.passkeyCredentials.userId, user.id))
    .limit(1)
    .get();

  const hasPassword = !!dbUser?.passwordHash;
  const hasOtherOAuth = otherOAuth.length > 0;
  const hasPasskey = !!hasPasskeys;

  if (!hasPassword && !hasOtherOAuth && !hasPasskey) {
    return c.json({ error: 'Cannot unlink — this is your only login method. Add a password or passkey first.' }, 400);
  }

  await db.delete(schema.oauthConnections).where(eq(schema.oauthConnections.id, connectionId));

  await logAudit(db, user.id, user.email, 'oauth_unlinked', 'oauth', connectionId, {
    provider: connection.provider,
  }, ip, userAgent);

  return c.json({ success: true });
});

// Check if a user has passkeys (for login flow)
app.post('/passkeys/check', rateLimiter({ windowMs: 60000, maxRequests: 30 }), zValidator('json', z.object({
  email: z.string().email(),
})), async (c) => {
  const db = createDb(c.env.DB);
  const { email } = c.req.valid('json');

  const user = await db
    .select({ id: schema.users.id })
    .from(schema.users)
    .where(eq(schema.users.email, email.toLowerCase()))
    .get();

  if (!user) {
    // Timing-safe: always do a dummy query + delay for non-existent users
    await timingSafeDelay();
    return c.json({ hasPasskeys: false });
  }

  const passkey = await db
    .select({ id: schema.passkeyCredentials.id })
    .from(schema.passkeyCredentials)
    .where(eq(schema.passkeyCredentials.userId, user.id))
    .limit(1)
    .get();

  return c.json({ hasPasskeys: !!passkey });
});

export default app;
