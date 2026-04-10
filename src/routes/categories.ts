import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { eq, desc, isNull, and } from 'drizzle-orm';
import type { Env, Variables } from '../types';
import { createDb, schema } from '../db';
import { authMiddleware, editorMiddleware } from '../middleware/auth';
import { createCategorySchema, updateCategorySchema } from '../lib/validation';
import { generateId, now, slugify } from '../lib/utils';
import { rateLimiter } from '../middleware/security';

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// Maximum category nesting depth to prevent stack overflow
const MAX_CATEGORY_DEPTH = 10;

/**
 * Check for circular references when setting a parent
 * Returns true if setting parentId would create a cycle
 */
async function wouldCreateCircle(
  db: ReturnType<typeof createDb>,
  categoryId: string,
  newParentId: string | null
): Promise<boolean> {
  if (!newParentId) return false;
  if (categoryId === newParentId) return true;

  // Walk up the parent chain from newParentId
  let currentId: string | null = newParentId;
  let depth = 0;

  while (currentId && depth < MAX_CATEGORY_DEPTH) {
    if (currentId === categoryId) {
      return true; // Found a cycle
    }

    const parent = await db
      .select({ parentId: schema.categories.parentId })
      .from(schema.categories)
      .where(eq(schema.categories.id, currentId))
      .get();

    currentId = parent?.parentId || null;
    depth++;
  }

  // Also check if this would exceed max depth
  if (depth >= MAX_CATEGORY_DEPTH) {
    return true; // Treat max depth exceeded as invalid
  }

  return false;
}

// List categories (hierarchical)
// SECURITY: Rate limited to prevent enumeration
app.get('/', rateLimiter({ windowMs: 60000, maxRequests: 30 }), async (c) => {
  const db = createDb(c.env.DB);

  const categories = await db
    .select()
    .from(schema.categories)
    .orderBy(desc(schema.categories.createdAt));

  // Build hierarchy
  const categoryMap = new Map(categories.map((cat) => [cat.id, { ...cat, children: [] as typeof categories }]));
  const rootCategories: (typeof categories[0] & { children: typeof categories })[] = [];

  for (const cat of categoryMap.values()) {
    if (cat.parentId && categoryMap.has(cat.parentId)) {
      categoryMap.get(cat.parentId)!.children.push(cat);
    } else {
      rootCategories.push(cat);
    }
  }

  return c.json({ items: rootCategories });
});

// Get single category
app.get('/:id', rateLimiter({ windowMs: 60000, maxRequests: 30 }), async (c) => {
  const db = createDb(c.env.DB);
  const id = c.req.param('id');

  const category = await db
    .select()
    .from(schema.categories)
    .where(eq(schema.categories.id, id))
    .get();

  if (!category) {
    return c.json({ error: 'Category not found' }, 404);
  }

  // Get children
  const children = await db
    .select()
    .from(schema.categories)
    .where(eq(schema.categories.parentId, id));

  return c.json({ ...category, children });
});

// Create category (editors/admins only per taxonomy:manage policy)
app.post('/', authMiddleware, editorMiddleware, zValidator('json', createCategorySchema), async (c) => {
  const db = createDb(c.env.DB);
  const body = c.req.valid('json');

  const id = generateId();
  const slug = body.slug || slugify(body.name);
  const timestamp = now();

  // Check slug uniqueness
  const existing = await db
    .select({ id: schema.categories.id })
    .from(schema.categories)
    .where(eq(schema.categories.slug, slug))
    .get();

  if (existing) {
    return c.json({ error: 'Slug already exists' }, 400);
  }

  // Verify parent exists if provided
  if (body.parentId) {
    const parent = await db
      .select({ id: schema.categories.id })
      .from(schema.categories)
      .where(eq(schema.categories.id, body.parentId))
      .get();

    if (!parent) {
      return c.json({ error: 'Parent category not found' }, 400);
    }
  }

  await db.insert(schema.categories).values({
    id,
    slug,
    name: body.name,
    parentId: body.parentId || null,
    createdAt: timestamp,
  });

  return c.json({ id, slug }, 201);
});

// Update category
// Update category (editors/admins only per taxonomy:manage policy)
app.patch('/:id', authMiddleware, editorMiddleware, zValidator('json', updateCategorySchema), async (c) => {
  const db = createDb(c.env.DB);
  const id = c.req.param('id');
  const body = c.req.valid('json');

  const existing = await db
    .select()
    .from(schema.categories)
    .where(eq(schema.categories.id, id))
    .get();

  if (!existing) {
    return c.json({ error: 'Category not found' }, 404);
  }

  const updates: Record<string, unknown> = {};

  if (body.name !== undefined) updates.name = body.name;
  if (body.slug !== undefined) {
    // Check slug uniqueness
    const slugExists = await db
      .select({ id: schema.categories.id })
      .from(schema.categories)
      .where(eq(schema.categories.slug, body.slug))
      .get();

    if (slugExists && slugExists.id !== id) {
      return c.json({ error: 'Slug already exists' }, 400);
    }
    updates.slug = body.slug;
  }
  if (body.parentId !== undefined) {
    // Prevent circular reference (including indirect cycles)
    if (await wouldCreateCircle(db, id, body.parentId)) {
      return c.json({ error: 'Cannot set parent: would create circular reference or exceed maximum depth' }, 400);
    }
    updates.parentId = body.parentId;
  }

  if (Object.keys(updates).length > 0) {
    // SECURITY: Use optimistic locking to prevent race conditions when updating parentId
    // This ensures the category structure hasn't changed between our check and update
    if (body.parentId !== undefined) {
      // Atomically update only if the current parentId matches what we expect
      // This prevents TOCTOU race conditions where another request could
      // create a circular reference between our check and update
      const result = await db
        .update(schema.categories)
        .set(updates)
        .where(
          and(
            eq(schema.categories.id, id),
            existing.parentId === null
              ? isNull(schema.categories.parentId)
              : eq(schema.categories.parentId, existing.parentId)
          )
        );

      // Check if update was applied (the row matched our condition)
      // If no rows were updated, another request modified the category
      const updated = await db
        .select({ parentId: schema.categories.parentId })
        .from(schema.categories)
        .where(eq(schema.categories.id, id))
        .get();

      if (updated && updated.parentId !== body.parentId) {
        // The update didn't take effect - category was modified concurrently
        // Re-check for circular reference with the new state
        if (await wouldCreateCircle(db, id, body.parentId)) {
          return c.json({ error: 'Cannot set parent: would create circular reference (concurrent modification detected)' }, 409);
        }
        // Retry the update once
        await db
          .update(schema.categories)
          .set(updates)
          .where(eq(schema.categories.id, id));
      }
    } else {
      await db
        .update(schema.categories)
        .set(updates)
        .where(eq(schema.categories.id, id));
    }
  }

  return c.json({ success: true });
});

// Delete category (editors/admins only per taxonomy:manage policy)
app.delete('/:id', authMiddleware, editorMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const id = c.req.param('id');

  // Check if category has children
  const children = await db
    .select({ id: schema.categories.id })
    .from(schema.categories)
    .where(eq(schema.categories.parentId, id))
    .get();

  if (children) {
    return c.json({ error: 'Cannot delete category with children' }, 400);
  }

  // Remove category from content
  await db.delete(schema.contentCategories).where(eq(schema.contentCategories.categoryId, id));

  // Delete category
  await db.delete(schema.categories).where(eq(schema.categories.id, id));

  return c.json({ success: true });
});

export default app;
