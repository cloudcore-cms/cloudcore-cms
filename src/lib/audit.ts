import type { Context } from 'hono';
import type { Env, Variables } from '../types';
import { createDb, schema } from '../db';
import { generateId, now } from './utils';

// SECURITY: Maximum length for User-Agent to prevent storage abuse
const MAX_USER_AGENT_LENGTH = 500;

// SECURITY: Sensitive fields that should be redacted from audit logs
// These could leak credentials, tokens, or other sensitive data
const SENSITIVE_FIELDS = [
  'password',
  'passwordHash',
  'token',
  'secret',
  'apiKey',
  'accessToken',
  'refreshToken',
  'sessionToken',
  'privateKey',
  'credential',
  'authorization',
];

/**
 * Recursively sanitize an object by redacting sensitive fields
 */
function sanitizeDetails(obj: Record<string, unknown>): Record<string, unknown> {
  const sanitized: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(obj)) {
    // Check if key contains any sensitive field name (case-insensitive)
    const isSensitive = SENSITIVE_FIELDS.some(
      (field) => key.toLowerCase().includes(field.toLowerCase())
    );

    if (isSensitive) {
      // Redact sensitive values - show that something was there but not the value
      sanitized[key] = '[REDACTED]';
    } else if (value && typeof value === 'object' && !Array.isArray(value)) {
      // Recursively sanitize nested objects
      sanitized[key] = sanitizeDetails(value as Record<string, unknown>);
    } else if (Array.isArray(value)) {
      // Handle arrays - sanitize any objects within
      sanitized[key] = value.map((item) =>
        item && typeof item === 'object' && !Array.isArray(item)
          ? sanitizeDetails(item as Record<string, unknown>)
          : item
      );
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
}

/**
 * Truncate User-Agent to prevent storage abuse
 */
function truncateUserAgent(userAgent: string | null): string | null {
  if (!userAgent) return null;
  if (userAgent.length <= MAX_USER_AGENT_LENGTH) return userAgent;
  return userAgent.substring(0, MAX_USER_AGENT_LENGTH) + '...[truncated]';
}

/**
 * Log an audit event for security tracking
 */
export async function logAudit(
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
  // SECURITY: Sanitize details to remove sensitive data
  const sanitizedDetails = details ? sanitizeDetails(details) : null;
  // SECURITY: Truncate User-Agent to prevent storage abuse
  const truncatedUserAgent = truncateUserAgent(userAgent);

  await db.insert(schema.auditLog).values({
    id: generateId(),
    userId,
    userEmail,
    action,
    resourceType,
    resourceId,
    details: sanitizedDetails ? JSON.stringify(sanitizedDetails) : null,
    ipAddress,
    userAgent: truncatedUserAgent,
    createdAt: now(),
  });
}

/**
 * Helper to extract IP and User-Agent from request context
 */
export function getRequestMeta(c: Context<{ Bindings: Env; Variables: Variables }>) {
  const ip = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For')?.split(',')[0] || null;
  const userAgent = c.req.header('User-Agent') || null;
  return { ip, userAgent };
}

/**
 * Convenience function to log audit from route handler context
 */
export async function auditLog(
  c: Context<{ Bindings: Env; Variables: Variables }>,
  action: string,
  resourceType: string,
  resourceId: string | null,
  details?: Record<string, unknown>
) {
  const db = createDb(c.env.DB);
  const user = c.get('user');
  const { ip, userAgent } = getRequestMeta(c);

  await logAudit(
    db,
    user?.id || null,
    user?.email || null,
    action,
    resourceType,
    resourceId,
    details || null,
    ip,
    userAgent
  );
}
