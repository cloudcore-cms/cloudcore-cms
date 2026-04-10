import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { eq, and, desc, asc, sql } from 'drizzle-orm';
import type { Env, Variables, ContentBlock, UserRole } from '../types';
import { canEditContent, canPublishContent, canDeleteContent } from '../types';
import { createDb, schema } from '../db';
import { authMiddleware, editorMiddleware } from '../middleware/auth';
import {
  createContentSchema,
  updateContentSchema,
  listQuerySchema,
  submitForReviewSchema,
} from '../lib/validation';
import { generateId, now, slugify, parseJson } from '../lib/utils';
import { rateLimiter } from '../middleware/security';

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// Helper to create revision with author info
async function createRevision(
  db: ReturnType<typeof createDb>,
  contentId: string,
  title: string,
  blocks: string,
  status: string,
  userId: string,
  userName: string | null,
  userEmail: string,
  changeType: string,
  changeSummary?: string
) {
  await db.insert(schema.revisions).values({
    id: generateId(),
    contentId,
    title,
    blocks,
    status,
    authorId: userId,
    authorName: userName,
    authorEmail: userEmail,
    changeType,
    changeSummary: changeSummary || null,
    createdAt: now(),
  });
}

// List content (requires auth to prevent enumeration)
// For public access to published content, use the public API endpoints
app.get('/', authMiddleware, zValidator('query', listQuerySchema), async (c) => {
  const db = createDb(c.env.DB);
  const query = c.req.valid('query');

  const conditions = [];
  if (query.type) {
    conditions.push(eq(schema.content.type, query.type));
  }
  if (query.status) {
    conditions.push(eq(schema.content.status, query.status));
  }
  if (query.authorId) {
    conditions.push(eq(schema.content.authorId, query.authorId));
  }

  const orderColumn = {
    createdAt: schema.content.createdAt,
    updatedAt: schema.content.updatedAt,
    title: schema.content.title,
    publishedAt: schema.content.publishedAt,
  }[query.orderBy];

  const orderFn = query.order === 'asc' ? asc : desc;

  const items = await db
    .select()
    .from(schema.content)
    .where(conditions.length > 0 ? and(...conditions) : undefined)
    .orderBy(orderFn(orderColumn))
    .limit(query.limit)
    .offset(query.offset);

  // Get total count
  const countResult = await db
    .select({ count: sql<number>`count(*)` })
    .from(schema.content)
    .where(conditions.length > 0 ? and(...conditions) : undefined)
    .get();

  const total = countResult?.count ?? 0;

  // Get author info for each item
  const authorIds = [...new Set(items.map((i) => i.authorId).filter(Boolean))];
  const authors = authorIds.length > 0
    ? await db
        .select({ id: schema.users.id, name: schema.users.name, email: schema.users.email })
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
    pagination: {
      total,
      limit: query.limit,
      offset: query.offset,
      hasMore: query.offset + items.length < total,
    },
  });
});

// Get single content by ID
// SECURITY: Rate limited to prevent content enumeration/scraping
// SECURITY: Unauthenticated requests can only see published content
// Authenticated users can see all content (for CMS editing)
app.get('/:id', rateLimiter({ windowMs: 60000, maxRequests: 60 }), async (c) => {
  const db = createDb(c.env.DB);
  const id = c.req.param('id');

  const item = await db
    .select()
    .from(schema.content)
    .where(eq(schema.content.id, id))
    .get();

  if (!item) {
    return c.json({ error: 'Content not found' }, 404);
  }

  // SECURITY: Check if the request is authenticated
  // If not authenticated, only published content is accessible
  const user = c.get('user' as any);
  if (!user && item.status !== 'published') {
    // Return 404 instead of 403 to avoid leaking existence of draft content
    return c.json({ error: 'Content not found' }, 404);
  }

  // Get author info
  let author = null;
  if (item.authorId) {
    author = await db
      .select({ id: schema.users.id, name: schema.users.name, email: schema.users.email })
      .from(schema.users)
      .where(eq(schema.users.id, item.authorId))
      .get();
  }

  // Get last editor info
  let lastEditor = null;
  if (item.lastEditedBy) {
    lastEditor = await db
      .select({ id: schema.users.id, name: schema.users.name, email: schema.users.email })
      .from(schema.users)
      .where(eq(schema.users.id, item.lastEditedBy))
      .get();
  }

  // Get categories and tags if it's a post
  let categories: { id: string; slug: string; name: string }[] = [];
  let tags: { id: string; slug: string; name: string }[] = [];

  if (item.type === 'post') {
    const categoryLinks = await db
      .select({ categoryId: schema.contentCategories.categoryId })
      .from(schema.contentCategories)
      .where(eq(schema.contentCategories.contentId, id));

    if (categoryLinks.length > 0) {
      const categoryIds = categoryLinks.map((l) => l.categoryId);
      categories = await db
        .select({ id: schema.categories.id, slug: schema.categories.slug, name: schema.categories.name })
        .from(schema.categories)
        .where(sql`${schema.categories.id} IN ${categoryIds}`);
    }

    const tagLinks = await db
      .select({ tagId: schema.contentTags.tagId })
      .from(schema.contentTags)
      .where(eq(schema.contentTags.contentId, id));

    if (tagLinks.length > 0) {
      const tagIds = tagLinks.map((l) => l.tagId);
      tags = await db
        .select({ id: schema.tags.id, slug: schema.tags.slug, name: schema.tags.name })
        .from(schema.tags)
        .where(sql`${schema.tags.id} IN ${tagIds}`);
    }
  }

  return c.json({
    ...item,
    blocks: parseJson<ContentBlock[]>(item.blocks, []),
    author,
    lastEditor,
    categories,
    tags,
  });
});

// Create content (requires auth)
app.post('/', authMiddleware, zValidator('json', createContentSchema), async (c) => {
  const db = createDb(c.env.DB);
  const user = c.get('user')!;
  const body = c.req.valid('json');

  // Contributors can only create drafts
  if (user.role === 'contributor' && body.status !== 'draft') {
    return c.json({ error: 'Contributors can only create drafts' }, 403);
  }

  // Only editors/admins can publish directly
  if (body.status === 'published' && !canPublishContent(user)) {
    return c.json({ error: 'You do not have permission to publish' }, 403);
  }

  const id = generateId();
  const timestamp = now();

  // Auto-generate slug from title if not provided
  let slug = body.slug || slugify(body.title);

  // SECURITY: Enforce maximum slug length to prevent database issues
  // Slugs are used in URLs, so keeping them reasonable length is important
  const MAX_SLUG_LENGTH = 200;
  if (slug.length > MAX_SLUG_LENGTH) {
    slug = slug.substring(0, MAX_SLUG_LENGTH);
    // Ensure we don't cut in the middle of a word/hyphen sequence
    const lastHyphen = slug.lastIndexOf('-');
    if (lastHyphen > MAX_SLUG_LENGTH - 20) {
      slug = slug.substring(0, lastHyphen);
    }
  }

  // Ensure all blocks have IDs and validate uniqueness
  const blockIds = new Set<string>();
  const blocksWithIds = body.blocks.map(block => {
    const blockId = block.id || generateId();
    // SECURITY: Check for duplicate block IDs to prevent potential issues
    if (blockIds.has(blockId)) {
      // If duplicate found, generate a new unique ID
      return { ...block, id: generateId() };
    }
    blockIds.add(blockId);
    return { ...block, id: blockId };
  });

  // Check slug uniqueness for this type
  const existing = await db
    .select({ id: schema.content.id })
    .from(schema.content)
    .where(and(eq(schema.content.type, body.type), eq(schema.content.slug, slug)))
    .get();

  if (existing) {
    return c.json({ error: 'Slug already exists' }, 400);
  }

  const blocksJson = JSON.stringify(blocksWithIds);

  await db.insert(schema.content).values({
    id,
    type: body.type,
    title: body.title,
    slug,
    status: body.status,
    blocks: blocksJson,
    authorId: user.id,
    lastEditedBy: user.id,
    publishedAt: body.status === 'published' ? timestamp : null,
    createdAt: timestamp,
    updatedAt: timestamp,
  });

  // Create initial revision
  await createRevision(
    db,
    id,
    body.title,
    blocksJson,
    body.status,
    user.id,
    user.name,
    user.email,
    'create'
  );

  // Handle categories and tags for posts
  if (body.type === 'post') {
    if (body.categoryIds && body.categoryIds.length > 0) {
      await db.insert(schema.contentCategories).values(
        body.categoryIds.map((categoryId) => ({
          contentId: id,
          categoryId,
        }))
      );
    }
    if (body.tagIds && body.tagIds.length > 0) {
      await db.insert(schema.contentTags).values(
        body.tagIds.map((tagId) => ({
          contentId: id,
          tagId,
        }))
      );
    }
  }

  return c.json({ id, slug }, 201);
});

// Update content (requires auth and permission)
app.patch('/:id', authMiddleware, zValidator('json', updateContentSchema), async (c) => {
  const db = createDb(c.env.DB);
  const user = c.get('user')!;
  const id = c.req.param('id');
  const body = c.req.valid('json');

  const existing = await db
    .select()
    .from(schema.content)
    .where(eq(schema.content.id, id))
    .get();

  if (!existing) {
    return c.json({ error: 'Content not found' }, 404);
  }

  // Check edit permissions
  const contentForCheck = {
    ...existing,
    blocks: parseJson<ContentBlock[]>(existing.blocks, []),
    type: existing.type as 'page' | 'post',
    status: existing.status as 'draft' | 'pending_review' | 'published',
  };

  if (!canEditContent(user, contentForCheck)) {
    return c.json({ error: 'You do not have permission to edit this content' }, 403);
  }

  // Contributors can't change status to published
  if (body.status === 'published' && !canPublishContent(user)) {
    return c.json({ error: 'You do not have permission to publish' }, 403);
  }

  // Contributors can only set status to draft or pending_review
  if (user.role === 'contributor' && body.status && body.status !== 'draft' && body.status !== 'pending_review') {
    return c.json({ error: 'Contributors can only save as draft or submit for review' }, 403);
  }

  // Create revision before updating
  await createRevision(
    db,
    id,
    existing.title,
    existing.blocks,
    existing.status,
    user.id,
    user.name,
    user.email,
    'update'
  );

  const timestamp = now();
  const updates: Record<string, unknown> = {
    updatedAt: timestamp,
    lastEditedBy: user.id,
  };

  if (body.title !== undefined) updates.title = body.title;
  if (body.slug !== undefined) {
    // Check slug uniqueness
    const slugExists = await db
      .select({ id: schema.content.id })
      .from(schema.content)
      .where(
        and(
          eq(schema.content.type, existing.type),
          eq(schema.content.slug, body.slug),
          sql`${schema.content.id} != ${id}`
        )
      )
      .get();

    if (slugExists) {
      return c.json({ error: 'Slug already exists' }, 400);
    }
    updates.slug = body.slug;
  }
  if (body.status !== undefined) {
    updates.status = body.status;
    if (body.status === 'published' && !existing.publishedAt) {
      updates.publishedAt = timestamp;
    }
  }
  if (body.blocks !== undefined) {
    updates.blocks = JSON.stringify(body.blocks);
  }

  await db
    .update(schema.content)
    .set(updates)
    .where(eq(schema.content.id, id));

  // Update categories and tags for posts
  if (existing.type === 'post') {
    if (body.categoryIds !== undefined) {
      await db.delete(schema.contentCategories).where(eq(schema.contentCategories.contentId, id));
      if (body.categoryIds.length > 0) {
        await db.insert(schema.contentCategories).values(
          body.categoryIds.map((categoryId) => ({
            contentId: id,
            categoryId,
          }))
        );
      }
    }
    if (body.tagIds !== undefined) {
      await db.delete(schema.contentTags).where(eq(schema.contentTags.contentId, id));
      if (body.tagIds.length > 0) {
        await db.insert(schema.contentTags).values(
          body.tagIds.map((tagId) => ({
            contentId: id,
            tagId,
          }))
        );
      }
    }
  }

  return c.json({ success: true });
});

// Delete content (requires auth and permission)
app.delete('/:id', authMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const user = c.get('user')!;
  const id = c.req.param('id');

  const existing = await db
    .select()
    .from(schema.content)
    .where(eq(schema.content.id, id))
    .get();

  if (!existing) {
    return c.json({ error: 'Content not found' }, 404);
  }

  // Check delete permissions
  const contentForCheck = {
    ...existing,
    blocks: parseJson<ContentBlock[]>(existing.blocks, []),
    type: existing.type as 'page' | 'post',
    status: existing.status as 'draft' | 'pending_review' | 'published',
  };

  if (!canDeleteContent(user, contentForCheck)) {
    return c.json({ error: 'You do not have permission to delete this content' }, 403);
  }

  // Delete related records
  await db.delete(schema.contentCategories).where(eq(schema.contentCategories.contentId, id));
  await db.delete(schema.contentTags).where(eq(schema.contentTags.contentId, id));
  await db.delete(schema.revisions).where(eq(schema.revisions.contentId, id));
  await db.delete(schema.content).where(eq(schema.content.id, id));

  return c.json({ success: true });
});

// Submit for review (contributors submit their drafts)
app.post('/:id/submit-review', authMiddleware, zValidator('json', submitForReviewSchema), async (c) => {
  const db = createDb(c.env.DB);
  const user = c.get('user')!;
  const id = c.req.param('id');
  const body = c.req.valid('json');

  const existing = await db
    .select()
    .from(schema.content)
    .where(eq(schema.content.id, id))
    .get();

  if (!existing) {
    return c.json({ error: 'Content not found' }, 404);
  }

  // Only the author can submit for review
  if (existing.authorId !== user.id && user.role === 'contributor') {
    return c.json({ error: 'You can only submit your own content for review' }, 403);
  }

  // Can only submit drafts
  if (existing.status !== 'draft') {
    return c.json({ error: 'Only drafts can be submitted for review' }, 400);
  }

  // Create revision
  await createRevision(
    db,
    id,
    existing.title,
    existing.blocks,
    existing.status,
    user.id,
    user.name,
    user.email,
    'update',
    body.message || 'Submitted for review'
  );

  await db
    .update(schema.content)
    .set({
      status: 'pending_review',
      updatedAt: now(),
      lastEditedBy: user.id,
    })
    .where(eq(schema.content.id, id));

  return c.json({ success: true });
});

// Publish content (editors/admins only)
app.post('/:id/publish', authMiddleware, editorMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const user = c.get('user')!;
  const id = c.req.param('id');

  const existing = await db
    .select()
    .from(schema.content)
    .where(eq(schema.content.id, id))
    .get();

  if (!existing) {
    return c.json({ error: 'Content not found' }, 404);
  }

  // Create revision
  await createRevision(
    db,
    id,
    existing.title,
    existing.blocks,
    existing.status,
    user.id,
    user.name,
    user.email,
    'publish'
  );

  const timestamp = now();
  await db
    .update(schema.content)
    .set({
      status: 'published',
      publishedAt: existing.publishedAt || timestamp,
      updatedAt: timestamp,
      lastEditedBy: user.id,
    })
    .where(eq(schema.content.id, id));

  return c.json({ success: true });
});

// Unpublish content (back to draft, editors/admins only)
app.post('/:id/unpublish', authMiddleware, editorMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const user = c.get('user')!;
  const id = c.req.param('id');

  const existing = await db
    .select()
    .from(schema.content)
    .where(eq(schema.content.id, id))
    .get();

  if (!existing) {
    return c.json({ error: 'Content not found' }, 404);
  }

  // Create revision
  await createRevision(
    db,
    id,
    existing.title,
    existing.blocks,
    existing.status,
    user.id,
    user.name,
    user.email,
    'unpublish'
  );

  await db
    .update(schema.content)
    .set({
      status: 'draft',
      updatedAt: now(),
      lastEditedBy: user.id,
    })
    .where(eq(schema.content.id, id));

  return c.json({ success: true });
});

// Reject review (send back to draft with feedback)
app.post('/:id/reject-review', authMiddleware, editorMiddleware, zValidator('json', submitForReviewSchema), async (c) => {
  const db = createDb(c.env.DB);
  const user = c.get('user')!;
  const id = c.req.param('id');
  const body = c.req.valid('json');

  const existing = await db
    .select()
    .from(schema.content)
    .where(eq(schema.content.id, id))
    .get();

  if (!existing) {
    return c.json({ error: 'Content not found' }, 404);
  }

  if (existing.status !== 'pending_review') {
    return c.json({ error: 'Content is not pending review' }, 400);
  }

  // Create revision with feedback
  await createRevision(
    db,
    id,
    existing.title,
    existing.blocks,
    existing.status,
    user.id,
    user.name,
    user.email,
    'update',
    body.message || 'Review rejected - sent back to draft'
  );

  await db
    .update(schema.content)
    .set({
      status: 'draft',
      updatedAt: now(),
      lastEditedBy: user.id,
    })
    .where(eq(schema.content.id, id));

  return c.json({ success: true });
});

// List revisions for content
// SECURITY: Contributors can only see revisions for their own content
app.get('/:id/revisions', authMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const user = c.get('user')!;
  const id = c.req.param('id');

  // Check content exists and verify access
  const content = await db
    .select({ authorId: schema.content.authorId })
    .from(schema.content)
    .where(eq(schema.content.id, id))
    .get();

  if (!content) {
    return c.json({ error: 'Content not found' }, 404);
  }

  // Contributors can only see revisions for their own content
  if (user.role === 'contributor' && content.authorId !== user.id) {
    return c.json({ error: 'You do not have permission to view these revisions' }, 403);
  }

  const revisions = await db
    .select()
    .from(schema.revisions)
    .where(eq(schema.revisions.contentId, id))
    .orderBy(desc(schema.revisions.createdAt))
    .limit(50);

  return c.json({
    items: revisions.map((r) => ({
      ...r,
      blocks: parseJson<ContentBlock[]>(r.blocks, []),
    })),
  });
});

// Restore revision (editors/admins only)
app.post('/:id/revisions/:revisionId/restore', authMiddleware, editorMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const user = c.get('user')!;
  const id = c.req.param('id');
  const revisionId = c.req.param('revisionId');

  const content = await db
    .select()
    .from(schema.content)
    .where(eq(schema.content.id, id))
    .get();

  if (!content) {
    return c.json({ error: 'Content not found' }, 404);
  }

  const revision = await db
    .select()
    .from(schema.revisions)
    .where(eq(schema.revisions.id, revisionId))
    .get();

  if (!revision || revision.contentId !== id) {
    return c.json({ error: 'Revision not found' }, 404);
  }

  // Create new revision with current content before restoring
  await createRevision(
    db,
    id,
    content.title,
    content.blocks,
    content.status,
    user.id,
    user.name,
    user.email,
    'restore',
    `Restored from revision ${revisionId}`
  );

  // Restore from revision
  await db
    .update(schema.content)
    .set({
      title: revision.title,
      blocks: revision.blocks,
      updatedAt: now(),
      lastEditedBy: user.id,
    })
    .where(eq(schema.content.id, id));

  return c.json({ success: true });
});

export default app;
