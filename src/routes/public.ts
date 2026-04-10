import { Hono } from 'hono';
import { eq, and, desc, asc, sql } from 'drizzle-orm';
import type { Env, Variables, ContentBlock } from '../types';
import { createDb, schema } from '../db';
import { rateLimiter } from '../middleware/security';
import { parseJson } from '../lib/utils';

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// Public content API — no auth required, only returns published content
// Rate limited to prevent scraping

// List published content
app.get('/content', rateLimiter({ windowMs: 60000, maxRequests: 60 }), async (c) => {
  const db = createDb(c.env.DB);
  const type = c.req.query('type') as 'page' | 'post' | undefined;
  const limit = Math.min(Math.max(1, parseInt(c.req.query('limit') || '20') || 20), 100);
  const offset = Math.max(0, parseInt(c.req.query('offset') || '0') || 0);

  const conditions = [eq(schema.content.status, 'published')];
  if (type) {
    conditions.push(eq(schema.content.type, type));
  }

  const items = await db
    .select({
      id: schema.content.id,
      type: schema.content.type,
      title: schema.content.title,
      slug: schema.content.slug,
      status: schema.content.status,
      blocks: schema.content.blocks,
      authorId: schema.content.authorId,
      publishedAt: schema.content.publishedAt,
      createdAt: schema.content.createdAt,
      updatedAt: schema.content.updatedAt,
    })
    .from(schema.content)
    .where(and(...conditions))
    .orderBy(desc(schema.content.publishedAt))
    .limit(limit)
    .offset(offset);

  const countResult = await db
    .select({ count: sql<number>`count(*)` })
    .from(schema.content)
    .where(and(...conditions))
    .get();

  const total = countResult?.count ?? 0;

  // Get author info
  const authorIds = [...new Set(items.map((i) => i.authorId).filter(Boolean))];
  const authors = authorIds.length > 0
    ? await db
        .select({ id: schema.users.id, name: schema.users.name })
        .from(schema.users)
        .where(sql`${schema.users.id} IN ${authorIds}`)
    : [];
  const authorMap = new Map(authors.map((a) => [a.id, a]));

  return c.json({
    items: items.map((item) => ({
      ...item,
      blocks: parseJson<ContentBlock[]>(item.blocks, []),
      author: item.authorId ? authorMap.get(item.authorId) || null : null,
    })),
    pagination: { total, limit, offset, hasMore: offset + items.length < total },
  });
});

// Get single published content by slug
app.get('/content/:type/:slug', rateLimiter({ windowMs: 60000, maxRequests: 60 }), async (c) => {
  const db = createDb(c.env.DB);
  const type = c.req.param('type');
  const slug = c.req.param('slug');

  if (type !== 'page' && type !== 'post') {
    return c.json({ error: 'Invalid content type' }, 400);
  }

  const item = await db
    .select()
    .from(schema.content)
    .where(
      and(
        eq(schema.content.type, type),
        eq(schema.content.slug, slug),
        eq(schema.content.status, 'published')
      )
    )
    .get();

  if (!item) {
    return c.json({ error: 'Content not found' }, 404);
  }

  // Get author
  let author = null;
  if (item.authorId) {
    author = await db
      .select({ id: schema.users.id, name: schema.users.name })
      .from(schema.users)
      .where(eq(schema.users.id, item.authorId))
      .get();
  }

  // Get categories and tags for posts
  let categories: { id: string; slug: string; name: string }[] = [];
  let tags: { id: string; slug: string; name: string }[] = [];

  if (item.type === 'post') {
    const categoryLinks = await db
      .select({ categoryId: schema.contentCategories.categoryId })
      .from(schema.contentCategories)
      .where(eq(schema.contentCategories.contentId, item.id));

    if (categoryLinks.length > 0) {
      categories = await db
        .select({ id: schema.categories.id, slug: schema.categories.slug, name: schema.categories.name })
        .from(schema.categories)
        .where(sql`${schema.categories.id} IN ${categoryLinks.map((l) => l.categoryId)}`);
    }

    const tagLinks = await db
      .select({ tagId: schema.contentTags.tagId })
      .from(schema.contentTags)
      .where(eq(schema.contentTags.contentId, item.id));

    if (tagLinks.length > 0) {
      tags = await db
        .select({ id: schema.tags.id, slug: schema.tags.slug, name: schema.tags.name })
        .from(schema.tags)
        .where(sql`${schema.tags.id} IN ${tagLinks.map((l) => l.tagId)}`);
    }
  }

  return c.json({
    ...item,
    blocks: parseJson<ContentBlock[]>(item.blocks, []),
    author,
    categories,
    tags,
  });
});

// Public categories list
app.get('/categories', rateLimiter({ windowMs: 60000, maxRequests: 30 }), async (c) => {
  const db = createDb(c.env.DB);
  const categories = await db.select().from(schema.categories).orderBy(asc(schema.categories.name));
  return c.json({ items: categories });
});

// Public tags list
app.get('/tags', rateLimiter({ windowMs: 60000, maxRequests: 30 }), async (c) => {
  const db = createDb(c.env.DB);
  const tags = await db.select().from(schema.tags).orderBy(asc(schema.tags.name));
  return c.json({ items: tags });
});

export default app;
