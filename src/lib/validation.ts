import { z } from 'zod';

// SECURITY: Maximum number of keys allowed in block options to prevent memory exhaustion
const MAX_OPTIONS_KEYS = 50;

// Content block schema
export const blockSchema = z.object({
  id: z.string().max(100).optional(),
  type: z.string().min(1).max(100),
  value: z.string().max(100_000).default(''), // ~100KB per block value
  options: z.record(z.unknown()).optional().refine(
    (val) => {
      if (!val) return true;
      // SECURITY: Limit number of keys and serialized size to prevent DoS
      const keys = Object.keys(val);
      if (keys.length > MAX_OPTIONS_KEYS) return false;
      // Limit total serialized size to ~50KB
      try {
        const serialized = JSON.stringify(val);
        return serialized.length <= 50_000;
      } catch {
        return false;
      }
    },
    { message: `Options must have at most ${MAX_OPTIONS_KEYS} keys and be under 50KB serialized` }
  ),
  mediaId: z.string().max(100).optional(),
  mediaIds: z.array(z.string().max(100)).max(50).optional(),
});

// Create content
export const createContentSchema = z.object({
  type: z.enum(['page', 'post']),
  title: z.string().min(1).max(500),
  slug: z.string().min(1).max(200).regex(/^[a-z0-9-]+$/).optional(),
  status: z.enum(['draft', 'pending_review', 'published']).default('draft'),
  blocks: z.array(blockSchema).max(500).default([]),
  categoryIds: z.array(z.string().max(100)).max(100).optional(),
  tagIds: z.array(z.string().max(100)).max(100).optional(),
});

// Update content
export const updateContentSchema = z.object({
  title: z.string().min(1).max(500).optional(),
  slug: z.string().min(1).max(200).regex(/^[a-z0-9-]+$/).optional(),
  status: z.enum(['draft', 'pending_review', 'published']).optional(),
  blocks: z.array(blockSchema).max(500).optional(),
  categoryIds: z.array(z.string().max(100)).max(100).optional(),
  tagIds: z.array(z.string().max(100)).max(100).optional(),
});

// Create category
export const createCategorySchema = z.object({
  name: z.string().min(1).max(100),
  slug: z.string().min(1).max(100).regex(/^[a-z0-9-]+$/).optional(),
  parentId: z.string().optional(),
});

// Update category
export const updateCategorySchema = z.object({
  name: z.string().min(1).max(100).optional(),
  slug: z.string().min(1).max(100).regex(/^[a-z0-9-]+$/).optional(),
  parentId: z.string().nullable().optional(),
});

// Create tag
export const createTagSchema = z.object({
  name: z.string().min(1).max(100),
  slug: z.string().min(1).max(100).regex(/^[a-z0-9-]+$/).optional(),
});

// Update tag
export const updateTagSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  slug: z.string().min(1).max(100).regex(/^[a-z0-9-]+$/).optional(),
});

// Create media
export const createMediaSchema = z.object({
  filename: z.string().min(1).max(500),
  mimeType: z.string().min(1).max(100),
  size: z.number().nonnegative().optional(),
  width: z.number().nonnegative().int().optional(),
  height: z.number().nonnegative().int().optional(),
  alt: z.string().max(1000).optional(),
});

// Update media
export const updateMediaSchema = z.object({
  alt: z.string().max(1000).optional(),
  filename: z.string().max(500).optional(),
});

// Login with optional Turnstile token
export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
  turnstileToken: z.string().optional(), // Cloudflare Turnstile token
  'cf-turnstile-response': z.string().optional(), // Alternative Turnstile field name
});

/**
 * Strong password validation schema
 * Requirements (OWASP aligned):
 * - Minimum 12 characters (increased from 8)
 * - Maximum 128 characters (prevent DoS via long passwords)
 * - At least one uppercase letter
 * - At least one lowercase letter
 * - At least one number
 * - At least one special character
 */
export const passwordSchema = z.string()
  .min(12, 'Password must be at least 12 characters')
  .max(128, 'Password must be at most 128 characters')
  .regex(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{}|;':",.<>?/\\`~])/,
    'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
  );

// Create user - supports all three roles
export const createUserSchema = z.object({
  email: z.string().email().toLowerCase(),
  password: passwordSchema,
  name: z.string().max(100).optional(),
  role: z.enum(['admin', 'editor', 'contributor']).default('contributor'),
});

// Update settings
export const updateSettingSchema = z.object({
  value: z.unknown(),
});

// Query params for listing content
export const listQuerySchema = z.object({
  type: z.enum(['page', 'post']).optional(),
  status: z.enum(['draft', 'pending_review', 'published']).optional(),
  authorId: z.string().optional(), // Filter by author
  limit: z.coerce.number().min(1).max(100).default(20),
  offset: z.coerce.number().min(0).default(0),
  orderBy: z.enum(['createdAt', 'updatedAt', 'title', 'publishedAt']).default('updatedAt'),
  order: z.enum(['asc', 'desc']).default('desc'),
});

// Submit for review schema (contributors)
export const submitForReviewSchema = z.object({
  message: z.string().max(500).optional(), // Optional message to editors
});
