import { Hono } from 'hono';
import { eq, desc, and, like, sql, or } from 'drizzle-orm';
import type { Env, Variables } from '../types';
import { createDb, schema } from '../db';
import { authMiddleware, adminMiddleware } from '../middleware/auth';
import { parseJson } from '../lib/utils';

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// List audit log entries (admin only)
app.get('/', authMiddleware, adminMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const limit = Math.min(Math.max(1, parseInt(c.req.query('limit') || '50') || 50), 100);
  const offset = Math.max(0, parseInt(c.req.query('offset') || '0') || 0);
  const action = c.req.query('action'); // Filter by action type
  const userId = c.req.query('userId'); // Filter by user
  const resourceType = c.req.query('resourceType'); // Filter by resource type

  // Build conditions array
  const conditions = [];

  if (action) {
    // Sanitize action to prevent SQL injection - only allow alphanumeric and underscore
    const sanitizedAction = action.replace(/[^a-zA-Z0-9_]/g, '');
    conditions.push(eq(schema.auditLog.action, sanitizedAction));
  }

  if (userId) {
    // Sanitize userId - only allow ULID characters
    const sanitizedUserId = userId.replace(/[^A-Z0-9]/g, '');
    conditions.push(eq(schema.auditLog.userId, sanitizedUserId));
  }

  if (resourceType) {
    // Sanitize resourceType
    const sanitizedResourceType = resourceType.replace(/[^a-zA-Z0-9_]/g, '');
    conditions.push(eq(schema.auditLog.resourceType, sanitizedResourceType));
  }

  const items = conditions.length > 0
    ? await db
        .select()
        .from(schema.auditLog)
        .where(and(...conditions))
        .orderBy(desc(schema.auditLog.createdAt))
        .limit(limit)
        .offset(offset)
    : await db
        .select()
        .from(schema.auditLog)
        .orderBy(desc(schema.auditLog.createdAt))
        .limit(limit)
        .offset(offset);

  // Get total count with same filters
  const countQuery = conditions.length > 0
    ? await db
        .select({ count: sql<number>`count(*)` })
        .from(schema.auditLog)
        .where(and(...conditions))
        .get()
    : await db
        .select({ count: sql<number>`count(*)` })
        .from(schema.auditLog)
        .get();

  return c.json({
    items: items.map((item) => ({
      ...item,
      details: item.details ? parseJson(item.details, {}) : null,
    })),
    pagination: {
      total: countQuery?.count ?? 0,
      limit,
      offset,
    },
  });
});

// Get login audit log (admin only) - specifically for login/logout/auth events
app.get('/logins', authMiddleware, adminMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const limit = Math.min(Math.max(1, parseInt(c.req.query('limit') || '50') || 50), 100);
  const offset = Math.max(0, parseInt(c.req.query('offset') || '0') || 0);
  const userId = c.req.query('userId'); // Optional filter by user

  const conditions = [
    or(
      eq(schema.auditLog.action, 'login'),
      eq(schema.auditLog.action, 'logout'),
      eq(schema.auditLog.action, 'login_failed'),
      eq(schema.auditLog.action, 'passkey_login'),
      eq(schema.auditLog.action, 'passkey_register'),
      eq(schema.auditLog.action, 'session_expired')
    ),
  ];

  if (userId) {
    const sanitizedUserId = userId.replace(/[^A-Z0-9]/g, '');
    conditions.push(eq(schema.auditLog.userId, sanitizedUserId));
  }

  const items = await db
    .select()
    .from(schema.auditLog)
    .where(and(...conditions))
    .orderBy(desc(schema.auditLog.createdAt))
    .limit(limit)
    .offset(offset);

  // Get total count
  const countResult = await db
    .select({ count: sql<number>`count(*)` })
    .from(schema.auditLog)
    .where(and(...conditions))
    .get();

  return c.json({
    items: items.map((item) => ({
      ...item,
      details: item.details ? parseJson(item.details, {}) : null,
    })),
    pagination: {
      total: countResult?.count ?? 0,
      limit,
      offset,
    },
  });
});

// Get audit log for a specific user (admin only)
app.get('/user/:userId', authMiddleware, adminMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const userId = c.req.param('userId');
  const limit = Math.min(Math.max(1, parseInt(c.req.query('limit') || '50') || 50), 100);
  const offset = Math.max(0, parseInt(c.req.query('offset') || '0') || 0);

  // Sanitize userId
  const sanitizedUserId = userId.replace(/[^A-Z0-9]/g, '');

  const items = await db
    .select()
    .from(schema.auditLog)
    .where(eq(schema.auditLog.userId, sanitizedUserId))
    .orderBy(desc(schema.auditLog.createdAt))
    .limit(limit)
    .offset(offset);

  const countResult = await db
    .select({ count: sql<number>`count(*)` })
    .from(schema.auditLog)
    .where(eq(schema.auditLog.userId, sanitizedUserId))
    .get();

  return c.json({
    items: items.map((item) => ({
      ...item,
      details: item.details ? parseJson(item.details, {}) : null,
    })),
    pagination: {
      total: countResult?.count ?? 0,
      limit,
      offset,
    },
  });
});

// Get single audit log entry (admin only)
app.get('/:id', authMiddleware, adminMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const id = c.req.param('id');

  const item = await db
    .select()
    .from(schema.auditLog)
    .where(eq(schema.auditLog.id, id))
    .get();

  if (!item) {
    return c.json({ error: 'Audit log entry not found' }, 404);
  }

  return c.json({
    ...item,
    details: item.details ? parseJson(item.details, {}) : null,
  });
});

export default app;
