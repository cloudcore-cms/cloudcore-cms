# AGENTS.md - AI Assistant Instructions for Cloudcore CMS

This file provides guidance for AI coding assistants working with this codebase.

## Project Overview

Cloudcore CMS is a headless content management system with ACF-style content blocks. It runs on Cloudflare Workers (free tier) or any environment that supports Hono.

**Tech stack:**
- Runtime: Hono (web framework)
- Database: Drizzle ORM with D1/SQLite
- Auth: Session-based with SHA-256 password hashing
- Storage: Cloudflare R2 (S3-compatible)
- Validation: Zod

## Directory Structure

```
packages/cms/
├── src/
│   ├── index.ts              # Hono app entry point
│   ├── types.ts              # TypeScript types
│   ├── routes/
│   │   ├── content.ts        # Content CRUD (pages/posts)
│   │   ├── media.ts          # Media upload/management
│   │   ├── categories.ts     # Category management
│   │   ├── tags.ts           # Tag management
│   │   ├── auth.ts           # Authentication
│   │   ├── settings.ts       # Site settings
│   │   └── blocks.ts         # Block type definitions
│   ├── db/
│   │   ├── schema.ts         # Drizzle schema
│   │   ├── index.ts          # Database connection
│   │   └── migrations/       # SQL migrations
│   ├── blocks/
│   │   └── types.ts          # Block type definitions
│   ├── middleware/
│   │   └── auth.ts           # Auth middleware
│   └── lib/
│       ├── validation.ts     # Zod schemas
│       └── utils.ts          # Utilities (generateId, slugify, etc.)
├── admin/                    # React admin UI (separate)
├── wrangler.toml             # Cloudflare config
└── package.json
```

## Core Concepts

### Content Blocks

Content is stored as an array of typed blocks. Each block has:
- `id`: Unique block ID
- `type`: Block type (paragraph, heading, image, etc.)
- `value`: The content value
- `options`: Type-specific options (heading level, image size, etc.)
- `mediaId` / `mediaIds`: Reference to media items

Block types are defined in `src/blocks/types.ts`. They are hardcoded - no dynamic schema.

### Content Model

```typescript
{
  id: string;           // ULID
  type: 'page' | 'post';
  title: string;
  slug: string;
  status: 'draft' | 'published';
  blocks: ContentBlock[];
  authorId: string | null;
  publishedAt: string | null;
  createdAt: string;
  updatedAt: string;
}
```

Posts can have categories and tags. Pages cannot.

## Common Tasks

### Adding a New Block Type

1. Add to `src/blocks/types.ts`:

```typescript
export const BLOCK_TYPES = {
  // ... existing types
  myNewBlock: {
    label: 'My New Block',
    input: 'text',  // or 'textarea', 'richtext', 'media', 'url', 'code', 'none'
    options: {
      someOption: { type: 'select', values: ['a', 'b'], default: 'a' },
    },
    description: 'Description for the admin UI',
  },
};
```

2. Update frontend to render the new block type.

### Adding a New API Endpoint

1. Create or update route file in `src/routes/`:

```typescript
import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import type { Env, Variables } from '../types';
import { authMiddleware } from '../middleware/auth';

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// Define validation schema
const mySchema = z.object({
  field: z.string().min(1),
});

// Create endpoint with auth
app.post('/my-endpoint', authMiddleware, zValidator('json', mySchema), async (c) => {
  const body = c.req.valid('json');
  const user = c.get('user');

  // ... do something

  return c.json({ success: true });
});

export default app;
```

2. Mount in `src/index.ts`:

```typescript
import myRoutes from './routes/my-routes';
app.route('/api/v1/my-routes', myRoutes);
```

### Adding a Database Table

1. Add to `src/db/schema.ts`:

```typescript
export const myTable = sqliteTable('cc_my_table', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  createdAt: text('created_at').notNull(),
});
```

2. Create migration in `src/db/migrations/`:

```sql
-- 0002_add_my_table.sql
CREATE TABLE IF NOT EXISTS cc_my_table (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);
```

3. Run migration:

```bash
npx wrangler d1 execute cloudcore-cms --local --file=./src/db/migrations/0002_add_my_table.sql
```

## Security Rules

### Always Validate Input

```typescript
// WRONG - no validation
app.post('/', async (c) => {
  const body = await c.req.json();
  // body could be anything!
});

// RIGHT - validate with Zod
app.post('/', zValidator('json', mySchema), async (c) => {
  const body = c.req.valid('json');
  // body is typed and validated
});
```

### Use Drizzle for Database Queries

```typescript
// WRONG - SQL injection risk
const result = db.run(`SELECT * FROM cc_content WHERE slug = '${slug}'`);

// RIGHT - parameterized via Drizzle
const result = await db
  .select()
  .from(schema.content)
  .where(eq(schema.content.slug, slug))
  .get();
```

### Check Authentication

```typescript
// Protected route
app.post('/protected', authMiddleware, async (c) => {
  const user = c.get('user'); // Guaranteed to exist
  // ...
});

// Admin only
app.post('/admin-only', authMiddleware, async (c) => {
  const user = c.get('user')!;
  if (user.role !== 'admin') {
    return c.json({ error: 'Admin required' }, 403);
  }
  // ...
});
```

### Validate Slugs and IDs

```typescript
// Slug validation - only lowercase letters, numbers, hyphens
const slugSchema = z.string().min(1).max(200).regex(/^[a-z0-9-]+$/);

// ID validation - ULID format
const idSchema = z.string().min(26).max(26);
```

## Deployment

### Local Development

```bash
npm run dev
```

### Cloudflare Workers

```bash
npx wrangler deploy
```

### Environment-Specific

```bash
# Staging
npx wrangler deploy --env staging

# Production
npx wrangler deploy --env production
```

## Testing API

```bash
# Health check
curl http://localhost:8787/health

# Create admin user
curl -X POST http://localhost:8787/api/v1/auth/setup \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@test.com", "password": "password123"}'

# Login
curl -X POST http://localhost:8787/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@test.com", "password": "password123"}' \
  -c cookies.txt

# Create content (with session cookie)
curl -X POST http://localhost:8787/api/v1/content \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "type": "page",
    "title": "Test Page",
    "slug": "test-page",
    "blocks": [
      {"id": "1", "type": "paragraph", "value": "Hello world"}
    ]
  }'
```

## Key Files to Understand

1. `src/index.ts` - Main app, route mounting, error handling
2. `src/routes/content.ts` - Content CRUD with revisions
3. `src/blocks/types.ts` - Block type definitions
4. `src/middleware/auth.ts` - Session and token authentication
5. `src/lib/validation.ts` - Zod schemas for all inputs
