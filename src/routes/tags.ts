import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { eq, desc } from 'drizzle-orm';
import type { Env, Variables } from '../types';
import { createDb, schema } from '../db';
import { authMiddleware, editorMiddleware } from '../middleware/auth';
import { createTagSchema, updateTagSchema } from '../lib/validation';
import { generateId, now, slugify } from '../lib/utils';
import { rateLimiter } from '../middleware/security';

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// List tags
// SECURITY: Rate limited to prevent enumeration
app.get('/', rateLimiter({ windowMs: 60000, maxRequests: 30 }), async (c) => {
  const db = createDb(c.env.DB);

  const tags = await db
    .select()
    .from(schema.tags)
    .orderBy(desc(schema.tags.createdAt));

  return c.json({ items: tags });
});

// Get single tag
app.get('/:id', rateLimiter({ windowMs: 60000, maxRequests: 30 }), async (c) => {
  const db = createDb(c.env.DB);
  const id = c.req.param('id');

  const tag = await db
    .select()
    .from(schema.tags)
    .where(eq(schema.tags.id, id))
    .get();

  if (!tag) {
    return c.json({ error: 'Tag not found' }, 404);
  }

  return c.json(tag);
});

// Create tag (editors/admins only per taxonomy:manage policy)
app.post('/', authMiddleware, editorMiddleware, zValidator('json', createTagSchema), async (c) => {
  const db = createDb(c.env.DB);
  const body = c.req.valid('json');

  const id = generateId();
  const slug = body.slug || slugify(body.name);
  const timestamp = now();

  // Check slug uniqueness
  const existing = await db
    .select({ id: schema.tags.id })
    .from(schema.tags)
    .where(eq(schema.tags.slug, slug))
    .get();

  if (existing) {
    return c.json({ error: 'Slug already exists' }, 400);
  }

  await db.insert(schema.tags).values({
    id,
    slug,
    name: body.name,
    createdAt: timestamp,
  });

  return c.json({ id, slug }, 201);
});

// Update tag (editors/admins only per taxonomy:manage policy)
app.patch('/:id', authMiddleware, editorMiddleware, zValidator('json', updateTagSchema), async (c) => {
  const db = createDb(c.env.DB);
  const id = c.req.param('id');
  const body = c.req.valid('json');

  const existing = await db
    .select()
    .from(schema.tags)
    .where(eq(schema.tags.id, id))
    .get();

  if (!existing) {
    return c.json({ error: 'Tag not found' }, 404);
  }

  const updates: Record<string, unknown> = {};

  if (body.name !== undefined) updates.name = body.name;
  if (body.slug !== undefined) {
    // Check slug uniqueness
    const slugExists = await db
      .select({ id: schema.tags.id })
      .from(schema.tags)
      .where(eq(schema.tags.slug, body.slug))
      .get();

    if (slugExists && slugExists.id !== id) {
      return c.json({ error: 'Slug already exists' }, 400);
    }
    updates.slug = body.slug;
  }

  if (Object.keys(updates).length > 0) {
    await db
      .update(schema.tags)
      .set(updates)
      .where(eq(schema.tags.id, id));
  }

  return c.json({ success: true });
});

// Delete tag (editors/admins only per taxonomy:manage policy)
app.delete('/:id', authMiddleware, editorMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const id = c.req.param('id');

  // Remove tag from content
  await db.delete(schema.contentTags).where(eq(schema.contentTags.tagId, id));

  // Delete tag
  await db.delete(schema.tags).where(eq(schema.tags.id, id));

  return c.json({ success: true });
});

export default app;
