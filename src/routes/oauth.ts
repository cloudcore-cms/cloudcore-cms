import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { setCookie } from 'hono/cookie';
import { eq, and, lt, sql } from 'drizzle-orm';
import { z } from 'zod';
import type { Env, Variables } from '../types';
import { createDb, schema } from '../db';
import { generateId, now } from '../lib/utils';
import {
  generateSecureToken,
  hashSessionToken,
  generateBase64UrlToken,
} from '../lib/crypto';
import { getClientIpOrFallback, rateLimiter } from '../middleware/security';
import { authMiddleware } from '../middleware/auth';

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// Session duration: 30 days
const SESSION_DURATION_MS = 30 * 24 * 60 * 60 * 1000;
// OAuth state expiry: 10 minutes
const STATE_TTL_MS = 10 * 60 * 1000;

// Validate redirect URL to prevent open redirect attacks
// Only allows configured URLs (MAGIC_LINK_BASE_URL, OAUTH_CALLBACK_URL) or same-origin paths
function validateRedirectUrl(url: string, env: Env, requestOrigin: string): string {
  // If empty, default to root path
  if (!url) return '/';

  // Parse the URL to check if it's valid
  try {
    const parsedUrl = new URL(url);
    const allowedHosts: string[] = [];

    // Add configured base URLs as allowed hosts
    if (env.MAGIC_LINK_BASE_URL) {
      try {
        allowedHosts.push(new URL(env.MAGIC_LINK_BASE_URL).host);
      } catch { /* ignore invalid URLs */ }
    }
    if (env.OAUTH_CALLBACK_URL) {
      try {
        allowedHosts.push(new URL(env.OAUTH_CALLBACK_URL).host);
      } catch { /* ignore invalid URLs */ }
    }

    // Add request origin as allowed
    try {
      allowedHosts.push(new URL(requestOrigin).host);
    } catch { /* ignore invalid URLs */ }

    // Check if the URL host is in the allowlist
    if (allowedHosts.includes(parsedUrl.host)) {
      return url;
    }

    // Not allowed - return safe default
    return '/';
  } catch {
    // Not a valid absolute URL - check if it's a relative path
    // Only allow paths starting with / and not containing protocol markers
    if (url.startsWith('/') && !url.startsWith('//') && !url.includes(':')) {
      return url;
    }
    return '/';
  }
}

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

// Generate PKCE code verifier and challenge
async function generatePKCE(): Promise<{ codeVerifier: string; codeChallenge: string }> {
  const codeVerifier = generateBase64UrlToken(64);

  // SHA-256 hash of code verifier
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const hash = await crypto.subtle.digest('SHA-256', data);

  // Base64url encode
  const hashArray = new Uint8Array(hash);
  let binary = '';
  for (let i = 0; i < hashArray.length; i++) {
    binary += String.fromCharCode(hashArray[i]);
  }
  const codeChallenge = btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  return { codeVerifier, codeChallenge };
}

// Cleanup expired OAuth states
async function cleanupExpiredStates(db: ReturnType<typeof createDb>) {
  const nowStr = now();
  await db.delete(schema.oauthStates).where(lt(schema.oauthStates.expiresAt, nowStr));
}

// Get available OAuth providers
app.get('/providers', async (c) => {
  const providers = [];

  if (c.env.GITHUB_CLIENT_ID && c.env.GITHUB_CLIENT_SECRET) {
    providers.push({ name: 'github', enabled: true });
  }

  if (c.env.GOOGLE_CLIENT_ID && c.env.GOOGLE_CLIENT_SECRET) {
    providers.push({ name: 'google', enabled: true });
  }

  return c.json({ providers });
});

// GitHub OAuth authorize
app.post('/github/authorize', rateLimiter({ windowMs: 60000, maxRequests: 10 }), async (c) => {
  if (!c.env.GITHUB_CLIENT_ID || !c.env.GITHUB_CLIENT_SECRET) {
    return c.json({ error: 'GitHub OAuth not configured' }, 400);
  }

  const db = createDb(c.env.DB);
  await cleanupExpiredStates(db);

  const { codeVerifier, codeChallenge } = await generatePKCE();
  const state = generateBase64UrlToken(32);
  const callbackUrl = c.env.OAUTH_CALLBACK_URL || new URL(c.req.url).origin;
  const redirectUri = `${callbackUrl}/api/v1/auth/oauth/github/callback`;

  // Store state for verification
  await db.insert(schema.oauthStates).values({
    state,
    provider: 'github',
    codeVerifier,
    redirectUri,
    expiresAt: new Date(Date.now() + STATE_TTL_MS).toISOString(),
    createdAt: now(),
  });

  // Build GitHub authorization URL
  const params = new URLSearchParams({
    client_id: c.env.GITHUB_CLIENT_ID,
    redirect_uri: redirectUri,
    scope: 'read:user user:email',
    state,
    // Note: GitHub doesn't support PKCE, but we store verifier for consistency
  });

  const url = `https://github.com/login/oauth/authorize?${params}`;
  return c.json({ url });
});

// GitHub OAuth callback
app.get('/github/callback', async (c) => {
  const code = c.req.query('code');
  const state = c.req.query('state');
  const error = c.req.query('error');
  const errorDescription = c.req.query('error_description');

  if (error) {
    const baseUrl = c.env.MAGIC_LINK_BASE_URL || c.env.OAUTH_CALLBACK_URL || '';
    const redirectUrl = validateRedirectUrl(`${baseUrl}/login`, c.env, new URL(c.req.url).origin);
    return c.redirect(`${redirectUrl}?error=${encodeURIComponent(error)}&error_description=${encodeURIComponent(errorDescription || '')}`);
  }

  if (!code || !state) {
    return c.json({ error: 'Missing code or state' }, 400);
  }

  const db = createDb(c.env.DB);
  const ip = getClientIpOrFallback(c.req.raw);
  const userAgent = c.req.header('User-Agent') || null;

  // SECURITY: Use unique consumption marker (timestamp + UUID) to prevent
  // race conditions where two requests in the same millisecond both succeed
  const consumedAt = `${now()}:${crypto.randomUUID()}`;

  // SECURITY: Atomic state consumption using UPDATE with condition
  // This prevents race conditions where two concurrent requests both try to use the same state
  // We mark the state as consumed (with consumedAt) before processing
  await db
    .update(schema.oauthStates)
    .set({ consumedAt })
    .where(
      and(
        eq(schema.oauthStates.state, state),
        eq(schema.oauthStates.provider, 'github'),
        sql`${schema.oauthStates.consumedAt} IS NULL`
      )
    );

  // Now fetch the state - only proceed if WE were the ones who consumed it
  const storedState = await db
    .select()
    .from(schema.oauthStates)
    .where(
      and(
        eq(schema.oauthStates.state, state),
        eq(schema.oauthStates.provider, 'github')
      )
    )
    .get();

  if (!storedState) {
    return c.json({ error: 'Invalid or expired state' }, 400);
  }

  // Verify we were the ones who consumed this state (our timestamp matches)
  if (storedState.consumedAt !== consumedAt) {
    // Another request already consumed this state - race condition prevented
    return c.json({ error: 'State already used' }, 400);
  }

  if (new Date(storedState.expiresAt) < new Date()) {
    // Cleanup the expired state
    await db.delete(schema.oauthStates).where(eq(schema.oauthStates.state, state));
    return c.json({ error: 'Invalid or expired state' }, 400);
  }

  // State is valid and we own it - delete it after use
  await db.delete(schema.oauthStates).where(eq(schema.oauthStates.state, state));

  try {
    // Exchange code for access token
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client_id: c.env.GITHUB_CLIENT_ID,
        client_secret: c.env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: storedState.redirectUri,
      }),
    });

    const tokenData = await tokenResponse.json() as {
      access_token?: string;
      error?: string;
      error_description?: string;
    };

    if (tokenData.error || !tokenData.access_token) {
      await logAudit(db, null, null, 'oauth_failed', 'oauth', null, {
        provider: 'github',
        error: tokenData.error,
      }, ip, userAgent);
      return c.json({ error: tokenData.error_description || 'Failed to get access token' }, 400);
    }

    // Get user info from GitHub
    const userResponse = await fetch('https://api.github.com/user', {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`,
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'Cloudcore-CMS',
      },
    });

    const githubUser = await userResponse.json() as {
      id: number;
      email?: string;
      name?: string;
      login: string;
      avatar_url?: string;
    };

    // Always fetch emails from API to ensure we get a verified email
    // The public email on the profile may not be verified
    const emailsResponse = await fetch('https://api.github.com/user/emails', {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`,
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'Cloudcore-CMS',
      },
    });
    const emails = await emailsResponse.json() as Array<{ email: string; primary: boolean; verified: boolean }>;

    // Find a verified email - prefer primary, but accept any verified email
    let email: string | undefined;
    const primaryVerified = emails.find(e => e.primary && e.verified);
    if (primaryVerified) {
      email = primaryVerified.email;
    } else {
      // Fall back to any verified email
      const anyVerified = emails.find(e => e.verified);
      email = anyVerified?.email;
    }

    if (!email) {
      return c.json({ error: 'No verified email found on GitHub account' }, 400);
    }

    // Find user (does NOT create new users)
    const result = await findOAuthUser(
      db,
      'github',
      String(githubUser.id),
      email
    );

    if (!result) {
      // No existing user - reject login
      await logAudit(db, null, email, 'oauth_login_rejected', 'user', null, {
        provider: 'github',
        reason: 'no_account',
      }, ip, userAgent);
      const baseUrl = c.env.MAGIC_LINK_BASE_URL || c.env.OAUTH_CALLBACK_URL || '';
      const redirectUrl = validateRedirectUrl(`${baseUrl}/login`, c.env, new URL(c.req.url).origin);
      return c.redirect(`${redirectUrl}?error=${encodeURIComponent('no_account')}&error_description=${encodeURIComponent('No account exists with this email. Please contact an administrator.')}`);
    }

    const { user, linked } = result;

    if (!user.isActive) {
      await logAudit(db, user.id, user.email, 'oauth_login_failed', 'user', user.id, {
        provider: 'github',
        reason: 'account_deactivated',
      }, ip, userAgent);
      const baseUrl = c.env.MAGIC_LINK_BASE_URL || c.env.OAUTH_CALLBACK_URL || '';
      const redirectUrl = validateRedirectUrl(`${baseUrl}/login`, c.env, new URL(c.req.url).origin);
      return c.redirect(`${redirectUrl}?error=${encodeURIComponent('account_deactivated')}&error_description=${encodeURIComponent('Account is deactivated.')}`);
    }

    // Create session
    const rawSessionToken = generateSecureToken(32);
    const sessionId = await hashSessionToken(rawSessionToken);
    const expiresAt = new Date(Date.now() + SESSION_DURATION_MS).toISOString();
    const timestamp = now();

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

    // Log successful login (note if OAuth was just linked)
    await logAudit(db, user.id, user.email, linked ? 'oauth_login' : 'oauth_linked', 'user', user.id, {
      provider: 'github',
    }, ip, userAgent);

    // Set session cookie
    const isSecure = c.env.SECURE_COOKIES === 'true' ||
                     (c.env.SECURE_COOKIES !== 'false' && new URL(c.req.url).protocol === 'https:');
    setCookie(c, 'session', rawSessionToken, {
      httpOnly: true,
      secure: isSecure,
      sameSite: 'Lax', // Lax for OAuth redirects
      path: '/',
      maxAge: SESSION_DURATION_MS / 1000,
    });

    // Redirect to admin
    const baseUrl = c.env.MAGIC_LINK_BASE_URL || c.env.OAUTH_CALLBACK_URL || '';
    const redirectUrl = validateRedirectUrl(`${baseUrl}/`, c.env, new URL(c.req.url).origin);
    return c.redirect(redirectUrl);
  } catch (error) {
    console.error('GitHub OAuth error:', error);
    return c.json({ error: 'OAuth authentication failed' }, 500);
  }
});

// Google OAuth authorize
app.post('/google/authorize', rateLimiter({ windowMs: 60000, maxRequests: 10 }), async (c) => {
  if (!c.env.GOOGLE_CLIENT_ID || !c.env.GOOGLE_CLIENT_SECRET) {
    return c.json({ error: 'Google OAuth not configured' }, 400);
  }

  const db = createDb(c.env.DB);
  await cleanupExpiredStates(db);

  const { codeVerifier, codeChallenge } = await generatePKCE();
  const state = generateBase64UrlToken(32);
  const callbackUrl = c.env.OAUTH_CALLBACK_URL || new URL(c.req.url).origin;
  const redirectUri = `${callbackUrl}/api/v1/auth/oauth/google/callback`;

  // Store state for verification
  await db.insert(schema.oauthStates).values({
    state,
    provider: 'google',
    codeVerifier,
    redirectUri,
    expiresAt: new Date(Date.now() + STATE_TTL_MS).toISOString(),
    createdAt: now(),
  });

  // Build Google authorization URL with PKCE
  const params = new URLSearchParams({
    client_id: c.env.GOOGLE_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid email profile',
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    access_type: 'offline',
    prompt: 'select_account',
  });

  const url = `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
  return c.json({ url });
});

// Google OAuth callback
app.get('/google/callback', async (c) => {
  const code = c.req.query('code');
  const state = c.req.query('state');
  const error = c.req.query('error');

  if (error) {
    const baseUrl = c.env.MAGIC_LINK_BASE_URL || c.env.OAUTH_CALLBACK_URL || '';
    const redirectUrl = validateRedirectUrl(`${baseUrl}/login`, c.env, new URL(c.req.url).origin);
    return c.redirect(`${redirectUrl}?error=${encodeURIComponent(error)}`);
  }

  if (!code || !state) {
    return c.json({ error: 'Missing code or state' }, 400);
  }

  const db = createDb(c.env.DB);
  const ip = getClientIpOrFallback(c.req.raw);
  const userAgent = c.req.header('User-Agent') || null;

  // SECURITY: Use unique consumption marker (timestamp + UUID) to prevent
  // race conditions where two requests in the same millisecond both succeed
  const consumedAt = `${now()}:${crypto.randomUUID()}`;

  // SECURITY: Atomic state consumption using UPDATE with condition
  // This prevents race conditions where two concurrent requests both try to use the same state
  await db
    .update(schema.oauthStates)
    .set({ consumedAt })
    .where(
      and(
        eq(schema.oauthStates.state, state),
        eq(schema.oauthStates.provider, 'google'),
        sql`${schema.oauthStates.consumedAt} IS NULL`
      )
    );

  // Now fetch the state - only proceed if WE were the ones who consumed it
  const storedState = await db
    .select()
    .from(schema.oauthStates)
    .where(
      and(
        eq(schema.oauthStates.state, state),
        eq(schema.oauthStates.provider, 'google')
      )
    )
    .get();

  if (!storedState) {
    return c.json({ error: 'Invalid or expired state' }, 400);
  }

  // Verify we were the ones who consumed this state (our timestamp matches)
  if (storedState.consumedAt !== consumedAt) {
    // Another request already consumed this state - race condition prevented
    return c.json({ error: 'State already used' }, 400);
  }

  if (new Date(storedState.expiresAt) < new Date()) {
    // Cleanup the expired state
    await db.delete(schema.oauthStates).where(eq(schema.oauthStates.state, state));
    return c.json({ error: 'Invalid or expired state' }, 400);
  }

  // State is valid and we own it - delete it after use
  await db.delete(schema.oauthStates).where(eq(schema.oauthStates.state, state));

  try {
    // Exchange code for access token with PKCE
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        code,
        client_id: c.env.GOOGLE_CLIENT_ID!,
        client_secret: c.env.GOOGLE_CLIENT_SECRET!,
        redirect_uri: storedState.redirectUri,
        grant_type: 'authorization_code',
        code_verifier: storedState.codeVerifier,
      }),
    });

    const tokenData = await tokenResponse.json() as {
      access_token?: string;
      id_token?: string;
      error?: string;
      error_description?: string;
    };

    if (tokenData.error || !tokenData.access_token) {
      await logAudit(db, null, null, 'oauth_failed', 'oauth', null, {
        provider: 'google',
        error: tokenData.error,
      }, ip, userAgent);
      return c.json({ error: tokenData.error_description || 'Failed to get access token' }, 400);
    }

    // Get user info from Google
    const userResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`,
      },
    });

    const googleUser = await userResponse.json() as {
      id: string;
      email: string;
      name?: string;
      picture?: string;
      verified_email?: boolean;
    };

    if (!googleUser.email || !googleUser.verified_email) {
      return c.json({ error: 'Email not verified with Google' }, 400);
    }

    // Find user (does NOT create new users)
    const result = await findOAuthUser(
      db,
      'google',
      googleUser.id,
      googleUser.email
    );

    if (!result) {
      // No existing user - reject login
      await logAudit(db, null, googleUser.email, 'oauth_login_rejected', 'user', null, {
        provider: 'google',
        reason: 'no_account',
      }, ip, userAgent);
      const baseUrl = c.env.MAGIC_LINK_BASE_URL || c.env.OAUTH_CALLBACK_URL || '';
      const redirectUrl = validateRedirectUrl(`${baseUrl}/login`, c.env, new URL(c.req.url).origin);
      return c.redirect(`${redirectUrl}?error=${encodeURIComponent('no_account')}&error_description=${encodeURIComponent('No account exists with this email. Please contact an administrator.')}`);
    }

    const { user, linked } = result;

    if (!user.isActive) {
      await logAudit(db, user.id, user.email, 'oauth_login_failed', 'user', user.id, {
        provider: 'google',
        reason: 'account_deactivated',
      }, ip, userAgent);
      const baseUrl = c.env.MAGIC_LINK_BASE_URL || c.env.OAUTH_CALLBACK_URL || '';
      const redirectUrl = validateRedirectUrl(`${baseUrl}/login`, c.env, new URL(c.req.url).origin);
      return c.redirect(`${redirectUrl}?error=${encodeURIComponent('account_deactivated')}&error_description=${encodeURIComponent('Account is deactivated.')}`);
    }

    // Create session
    const rawSessionToken = generateSecureToken(32);
    const sessionId = await hashSessionToken(rawSessionToken);
    const expiresAt = new Date(Date.now() + SESSION_DURATION_MS).toISOString();
    const timestamp = now();

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

    // Log successful login (note if OAuth was just linked)
    await logAudit(db, user.id, user.email, linked ? 'oauth_login' : 'oauth_linked', 'user', user.id, {
      provider: 'google',
    }, ip, userAgent);

    // Set session cookie
    const isSecure = c.env.SECURE_COOKIES === 'true' ||
                     (c.env.SECURE_COOKIES !== 'false' && new URL(c.req.url).protocol === 'https:');
    setCookie(c, 'session', rawSessionToken, {
      httpOnly: true,
      secure: isSecure,
      sameSite: 'Lax',
      path: '/',
      maxAge: SESSION_DURATION_MS / 1000,
    });

    // Redirect to admin
    const baseUrl = c.env.MAGIC_LINK_BASE_URL || c.env.OAUTH_CALLBACK_URL || '';
    const redirectUrl = validateRedirectUrl(`${baseUrl}/`, c.env, new URL(c.req.url).origin);
    return c.redirect(redirectUrl);
  } catch (error) {
    console.error('Google OAuth error:', error);
    return c.json({ error: 'OAuth authentication failed' }, 500);
  }
});

// Helper to find user from OAuth (does NOT create new users)
async function findOAuthUser(
  db: ReturnType<typeof createDb>,
  provider: string,
  providerUserId: string,
  email: string
): Promise<{ user: { id: string; email: string; name: string | null; role: string; isActive: boolean }; linked: boolean } | null> {
  // First check if OAuth connection exists
  const existingConnection = await db
    .select()
    .from(schema.oauthConnections)
    .where(
      and(
        eq(schema.oauthConnections.provider, provider),
        eq(schema.oauthConnections.providerUserId, providerUserId)
      )
    )
    .get();

  if (existingConnection) {
    // User already linked, get user
    const user = await db
      .select({
        id: schema.users.id,
        email: schema.users.email,
        name: schema.users.name,
        role: schema.users.role,
        isActive: schema.users.isActive,
      })
      .from(schema.users)
      .where(eq(schema.users.id, existingConnection.userId))
      .get();

    if (user) {
      return { user, linked: true };
    }
  }

  // SECURITY: Do NOT auto-link OAuth accounts by email match
  // This prevents account takeover if:
  // 1. Admin changes a user's email
  // 2. Attacker creates OAuth account with the old email
  // 3. Attacker would gain access to victim's CMS account
  //
  // Users must link OAuth accounts manually from their settings page
  // while already authenticated via another method (password, magic link, passkey)

  // No existing OAuth connection found - return null
  // User must link OAuth from settings while authenticated
  return null;
}

// ============================================================================
// OAuth Account Linking (authenticated users only)
// These endpoints allow users to link OAuth accounts to their existing account
// ============================================================================

// Link GitHub account — initiate flow
app.post('/link/github/authorize', authMiddleware, rateLimiter({ windowMs: 60000, maxRequests: 5 }), async (c) => {
  if (!c.env.GITHUB_CLIENT_ID || !c.env.GITHUB_CLIENT_SECRET) {
    return c.json({ error: 'GitHub OAuth not configured' }, 400);
  }

  const db = createDb(c.env.DB);
  const user = c.get('user')!;
  await cleanupExpiredStates(db);

  const { codeVerifier, codeChallenge } = await generatePKCE();
  const state = generateBase64UrlToken(32);
  const callbackUrl = c.env.OAUTH_CALLBACK_URL || new URL(c.req.url).origin;
  const redirectUri = `${callbackUrl}/api/v1/auth/oauth/link/github/callback`;

  await db.insert(schema.oauthStates).values({
    state,
    provider: 'github-link',
    codeVerifier,
    redirectUri,
    expiresAt: new Date(Date.now() + STATE_TTL_MS).toISOString(),
    createdAt: now(),
  });

  const params = new URLSearchParams({
    client_id: c.env.GITHUB_CLIENT_ID,
    redirect_uri: redirectUri,
    scope: 'read:user user:email',
    state,
    allow_signup: 'false',
  });

  return c.json({ url: `https://github.com/login/oauth/authorize?${params}` });
});

// Link GitHub account — callback
app.get('/link/github/callback', authMiddleware, async (c) => {
  const code = c.req.query('code');
  const state = c.req.query('state');

  if (!code || !state) {
    return c.json({ error: 'Missing code or state' }, 400);
  }

  const db = createDb(c.env.DB);
  const user = c.get('user')!;
  const ip = getClientIpOrFallback(c.req.raw);
  const userAgent = c.req.header('User-Agent') || null;
  const consumedAt = `${now()}:${crypto.randomUUID()}`;

  await db
    .update(schema.oauthStates)
    .set({ consumedAt })
    .where(
      and(
        eq(schema.oauthStates.state, state),
        eq(schema.oauthStates.provider, 'github-link'),
        sql`${schema.oauthStates.consumedAt} IS NULL`
      )
    );

  const storedState = await db
    .select()
    .from(schema.oauthStates)
    .where(eq(schema.oauthStates.state, state))
    .get();

  if (!storedState || storedState.consumedAt !== consumedAt) {
    return c.json({ error: 'Invalid or expired state' }, 400);
  }

  if (new Date(storedState.expiresAt) < new Date()) {
    return c.json({ error: 'State expired' }, 400);
  }

  try {
    // Exchange code for token
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: c.env.GITHUB_CLIENT_ID,
        client_secret: c.env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: storedState.redirectUri,
      }),
    });

    const tokenData = await tokenResponse.json() as { access_token?: string; error?: string };
    if (!tokenData.access_token) {
      return c.json({ error: 'Failed to get GitHub access token' }, 400);
    }

    // Get GitHub user info
    const userResponse = await fetch('https://api.github.com/user', {
      headers: { 'Authorization': `Bearer ${tokenData.access_token}`, 'Accept': 'application/vnd.github+json', 'User-Agent': 'Cloudcore-CMS' },
    });
    const githubUser = await userResponse.json() as { id: number; login: string; email?: string };

    // Get verified email
    const emailsResponse = await fetch('https://api.github.com/user/emails', {
      headers: { 'Authorization': `Bearer ${tokenData.access_token}`, 'Accept': 'application/vnd.github+json', 'User-Agent': 'Cloudcore-CMS' },
    });
    const emails = await emailsResponse.json() as Array<{ email: string; primary: boolean; verified: boolean }>;
    const verifiedEmail = emails.find(e => e.primary && e.verified)?.email || emails.find(e => e.verified)?.email;

    // Check if this GitHub account is already linked to someone
    const existing = await db
      .select()
      .from(schema.oauthConnections)
      .where(and(eq(schema.oauthConnections.provider, 'github'), eq(schema.oauthConnections.providerUserId, String(githubUser.id))))
      .get();

    if (existing) {
      const baseUrl = c.env.MAGIC_LINK_BASE_URL || c.env.OAUTH_CALLBACK_URL || '';
      return c.redirect(`${baseUrl}/profile?error=${encodeURIComponent('This GitHub account is already linked to another user.')}`);
    }

    // Create the link
    await db.insert(schema.oauthConnections).values({
      id: generateId(),
      userId: user.id,
      provider: 'github',
      providerUserId: String(githubUser.id),
      providerEmail: verifiedEmail || null,
      createdAt: now(),
    });

    await logAudit(db, user.id, user.email, 'oauth_account_linked', 'oauth', null, {
      provider: 'github',
      providerUserId: String(githubUser.id),
    }, ip, userAgent);

    const baseUrl = c.env.MAGIC_LINK_BASE_URL || c.env.OAUTH_CALLBACK_URL || '';
    return c.redirect(`${baseUrl}/profile?linked=github`);
  } catch (error) {
    console.error('GitHub link error:', error);
    const baseUrl = c.env.MAGIC_LINK_BASE_URL || c.env.OAUTH_CALLBACK_URL || '';
    return c.redirect(`${baseUrl}/profile?error=${encodeURIComponent('Failed to link GitHub account.')}`);
  }
});

// Link Google account — initiate flow
app.post('/link/google/authorize', authMiddleware, rateLimiter({ windowMs: 60000, maxRequests: 5 }), async (c) => {
  if (!c.env.GOOGLE_CLIENT_ID || !c.env.GOOGLE_CLIENT_SECRET) {
    return c.json({ error: 'Google OAuth not configured' }, 400);
  }

  const db = createDb(c.env.DB);
  await cleanupExpiredStates(db);

  const { codeVerifier, codeChallenge } = await generatePKCE();
  const state = generateBase64UrlToken(32);
  const callbackUrl = c.env.OAUTH_CALLBACK_URL || new URL(c.req.url).origin;
  const redirectUri = `${callbackUrl}/api/v1/auth/oauth/link/google/callback`;

  await db.insert(schema.oauthStates).values({
    state,
    provider: 'google-link',
    codeVerifier,
    redirectUri,
    expiresAt: new Date(Date.now() + STATE_TTL_MS).toISOString(),
    createdAt: now(),
  });

  const params = new URLSearchParams({
    client_id: c.env.GOOGLE_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid email profile',
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    access_type: 'online',
    prompt: 'consent',
  });

  return c.json({ url: `https://accounts.google.com/o/oauth2/v2/auth?${params}` });
});

// Link Google account — callback
app.get('/link/google/callback', authMiddleware, async (c) => {
  const code = c.req.query('code');
  const state = c.req.query('state');

  if (!code || !state) {
    return c.json({ error: 'Missing code or state' }, 400);
  }

  const db = createDb(c.env.DB);
  const user = c.get('user')!;
  const ip = getClientIpOrFallback(c.req.raw);
  const userAgent = c.req.header('User-Agent') || null;
  const consumedAt = `${now()}:${crypto.randomUUID()}`;

  await db
    .update(schema.oauthStates)
    .set({ consumedAt })
    .where(
      and(
        eq(schema.oauthStates.state, state),
        eq(schema.oauthStates.provider, 'google-link'),
        sql`${schema.oauthStates.consumedAt} IS NULL`
      )
    );

  const storedState = await db
    .select()
    .from(schema.oauthStates)
    .where(eq(schema.oauthStates.state, state))
    .get();

  if (!storedState || storedState.consumedAt !== consumedAt) {
    return c.json({ error: 'Invalid or expired state' }, 400);
  }

  if (new Date(storedState.expiresAt) < new Date()) {
    return c.json({ error: 'State expired' }, 400);
  }

  try {
    // Exchange code for token with PKCE
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: c.env.GOOGLE_CLIENT_ID!,
        client_secret: c.env.GOOGLE_CLIENT_SECRET!,
        redirect_uri: storedState.redirectUri,
        grant_type: 'authorization_code',
        code_verifier: storedState.codeVerifier,
      }),
    });

    const tokenData = await tokenResponse.json() as { access_token?: string; error?: string };
    if (!tokenData.access_token) {
      return c.json({ error: 'Failed to get Google access token' }, 400);
    }

    // Get Google user info
    const userResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { 'Authorization': `Bearer ${tokenData.access_token}` },
    });
    const googleUser = await userResponse.json() as { id: string; email: string; verified_email: boolean };

    if (!googleUser.verified_email) {
      return c.json({ error: 'Google email not verified' }, 400);
    }

    // Check if already linked
    const existing = await db
      .select()
      .from(schema.oauthConnections)
      .where(and(eq(schema.oauthConnections.provider, 'google'), eq(schema.oauthConnections.providerUserId, googleUser.id)))
      .get();

    if (existing) {
      const baseUrl = c.env.MAGIC_LINK_BASE_URL || c.env.OAUTH_CALLBACK_URL || '';
      return c.redirect(`${baseUrl}/profile?error=${encodeURIComponent('This Google account is already linked to another user.')}`);
    }

    // Create the link
    await db.insert(schema.oauthConnections).values({
      id: generateId(),
      userId: user.id,
      provider: 'google',
      providerUserId: googleUser.id,
      providerEmail: googleUser.email,
      createdAt: now(),
    });

    await logAudit(db, user.id, user.email, 'oauth_account_linked', 'oauth', null, {
      provider: 'google',
      providerUserId: googleUser.id,
    }, ip, userAgent);

    const baseUrl = c.env.MAGIC_LINK_BASE_URL || c.env.OAUTH_CALLBACK_URL || '';
    return c.redirect(`${baseUrl}/profile?linked=google`);
  } catch (error) {
    console.error('Google link error:', error);
    const baseUrl = c.env.MAGIC_LINK_BASE_URL || c.env.OAUTH_CALLBACK_URL || '';
    return c.redirect(`${baseUrl}/profile?error=${encodeURIComponent('Failed to link Google account.')}`);
  }
});

export default app;
