import { Hono } from 'hono';
import { setCookie, getCookie } from 'hono/cookie';
import { eq, and } from 'drizzle-orm';
import type { Env, Variables } from '../types';
import { createDb, schema } from '../db';
import { generateId, now } from '../lib/utils';
import {
  generateSecureToken,
  hashSessionToken,
} from '../lib/crypto';
import { getClientIpOrFallback } from '../middleware/security';

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

// Cloudflare Access JWT payload type
interface CFAccessJWT {
  aud: string[];
  email: string;
  exp: number;
  iat: number;
  iss: string;
  type: string;
  identity_nonce: string;
  sub: string;
  custom?: {
    groups?: string[];
  };
}

// Extended JWK type with kid (key ID) field from JWKS
interface CFAccessJWK extends JsonWebKey {
  kid: string;
}

// Fetch Cloudflare Access public keys for JWT verification
async function getCFAccessPublicKeys(teamDomain: string): Promise<CFAccessJWK[]> {
  const response = await fetch(`https://${teamDomain}/cdn-cgi/access/certs`, {
    headers: { Accept: 'application/json' },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch Cloudflare Access public keys');
  }

  const data = await response.json() as { keys: CFAccessJWK[] };
  return data.keys;
}

// Verify Cloudflare Access JWT
async function verifyCFAccessToken(
  token: string,
  teamDomain: string,
  expectedAud: string
): Promise<CFAccessJWT | null> {
  try {
    // Parse JWT without verification first to get header
    const [headerB64, payloadB64, signatureB64] = token.split('.');
    if (!headerB64 || !payloadB64 || !signatureB64) {
      return null;
    }

    // SECURITY: Wrap header parsing in try-catch to handle malformed base64/JSON gracefully
    let header: { alg: string; kid: string };
    try {
      const headerJson = atob(headerB64.replace(/-/g, '+').replace(/_/g, '/'));
      header = JSON.parse(headerJson) as { alg: string; kid: string };
    } catch {
      console.warn('Failed to parse JWT header - malformed token');
      return null;
    }

    // Get public keys
    const publicKeys = await getCFAccessPublicKeys(teamDomain);

    // Find matching key
    const matchingKey = publicKeys.find((key) => key.kid === header.kid);
    if (!matchingKey) {
      console.warn('No matching public key found for kid:', header.kid);
      return null;
    }

    // Import public key
    const cryptoKey = await crypto.subtle.importKey(
      'jwk',
      matchingKey,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    );

    // Decode signature
    const signatureBuffer = Uint8Array.from(
      atob(signatureB64.replace(/-/g, '+').replace(/_/g, '/')),
      (c) => c.charCodeAt(0)
    );

    // Verify signature
    const dataToVerify = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const isValid = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      cryptoKey,
      signatureBuffer,
      dataToVerify
    );

    if (!isValid) {
      console.warn('JWT signature verification failed');
      return null;
    }

    // Decode payload
    const payloadJson = atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/'));
    const payload = JSON.parse(payloadJson) as CFAccessJWT;

    // Verify claims
    const nowSeconds = Math.floor(Date.now() / 1000);

    // Check expiration
    if (payload.exp < nowSeconds) {
      console.warn('JWT expired');
      return null;
    }

    // Check audience
    if (!payload.aud.includes(expectedAud)) {
      console.warn('JWT audience mismatch');
      return null;
    }

    // Check issuer
    const expectedIssuer = `https://${teamDomain}`;
    if (payload.iss !== expectedIssuer) {
      console.warn('JWT issuer mismatch');
      return null;
    }

    return payload;
  } catch (error) {
    console.error('JWT verification error:', error);
    return null;
  }
}

// Check if CF Access is enabled and verify JWT
app.get('/verify', async (c) => {
  if (c.env.CF_ACCESS_ENABLED !== 'true') {
    return c.json({ enabled: false });
  }

  if (!c.env.CF_ACCESS_TEAM_DOMAIN || !c.env.CF_ACCESS_AUD) {
    return c.json({ error: 'Cloudflare Access not properly configured' }, 400);
  }

  // Get CF Access JWT from header or cookie
  const cfAccessJwt =
    c.req.header('Cf-Access-Jwt-Assertion') ||
    getCookie(c, 'CF_Authorization');

  if (!cfAccessJwt) {
    return c.json({
      enabled: true,
      authenticated: false,
      message: 'No Cloudflare Access token found',
    });
  }

  const payload = await verifyCFAccessToken(
    cfAccessJwt,
    c.env.CF_ACCESS_TEAM_DOMAIN,
    c.env.CF_ACCESS_AUD
  );

  if (!payload) {
    return c.json({
      enabled: true,
      authenticated: false,
      message: 'Invalid Cloudflare Access token',
    });
  }

  return c.json({
    enabled: true,
    authenticated: true,
    email: payload.email,
    sub: payload.sub,
    groups: payload.custom?.groups || [],
    exp: payload.exp,
  });
});

// Login via Cloudflare Access
app.post('/login', async (c) => {
  if (c.env.CF_ACCESS_ENABLED !== 'true') {
    return c.json({ error: 'Cloudflare Access is not enabled' }, 400);
  }

  if (!c.env.CF_ACCESS_TEAM_DOMAIN || !c.env.CF_ACCESS_AUD) {
    return c.json({ error: 'Cloudflare Access not properly configured' }, 400);
  }

  const db = createDb(c.env.DB);
  const ip = getClientIpOrFallback(c.req.raw);
  const userAgent = c.req.header('User-Agent') || null;

  // Get CF Access JWT from header or cookie
  const cfAccessJwt =
    c.req.header('Cf-Access-Jwt-Assertion') ||
    getCookie(c, 'CF_Authorization');

  if (!cfAccessJwt) {
    return c.json({ error: 'No Cloudflare Access token found' }, 401);
  }

  const payload = await verifyCFAccessToken(
    cfAccessJwt,
    c.env.CF_ACCESS_TEAM_DOMAIN,
    c.env.CF_ACCESS_AUD
  );

  if (!payload) {
    await logAudit(db, null, null, 'cf_access_login_failed', 'user', null, {
      reason: 'invalid_token',
    }, ip, userAgent);
    return c.json({ error: 'Invalid Cloudflare Access token' }, 401);
  }

  // SECURITY: Do NOT auto-create users from CF Access
  // This prevents privilege escalation where an attacker with CF Access could become admin
  // Users must be created by an admin first, then they can login via CF Access
  const user = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.email, payload.email.toLowerCase()))
    .get();

  if (!user) {
    await logAudit(db, null, payload.email, 'cf_access_login_rejected', 'user', null, {
      reason: 'no_account',
      cfIdentityId: payload.sub,
    }, ip, userAgent);
    return c.json({ error: 'No account exists with this email. Please contact an administrator.' }, 401);
  }

  if (!user.isActive) {
    await logAudit(db, user.id, user.email, 'cf_access_login_failed', 'user', user.id, {
      reason: 'account_deactivated',
    }, ip, userAgent);
    return c.json({ error: 'Account is deactivated' }, 401);
  }

  const timestamp = now();

  // Store CF Access session info
  await db.insert(schema.cfAccessSessions).values({
    id: generateId(),
    userId: user.id,
    cfIdentityId: payload.sub,
    cfEmail: payload.email,
    cfGroups: payload.custom?.groups ? JSON.stringify(payload.custom.groups) : null,
    cfAud: c.env.CF_ACCESS_AUD,
    expiresAt: new Date(payload.exp * 1000).toISOString(),
    createdAt: timestamp,
  });

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
  await logAudit(db, user.id, user.email, 'cf_access_login', 'user', user.id, {
    cfIdentityId: payload.sub,
    groups: payload.custom?.groups,
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
});

// Get CF Access status
app.get('/status', async (c) => {
  const enabled = c.env.CF_ACCESS_ENABLED === 'true' &&
                  !!c.env.CF_ACCESS_TEAM_DOMAIN &&
                  !!c.env.CF_ACCESS_AUD;

  return c.json({
    enabled,
    teamDomain: enabled ? c.env.CF_ACCESS_TEAM_DOMAIN : undefined,
  });
});

export default app;
