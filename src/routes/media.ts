import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { eq, desc, like, sql } from 'drizzle-orm';
import type { Env, Variables } from '../types';
import { createDb, schema } from '../db';
import { authMiddleware, optionalAuthMiddleware, editorMiddleware } from '../middleware/auth';
import { createMediaSchema, updateMediaSchema } from '../lib/validation';
import { generateId, now } from '../lib/utils';
import { auditLog } from '../lib/audit';
import { z } from 'zod';
import {
  validateFileMagicBytes,
  sanitizeFilename,
  getExtensionFromMimeType,
  sanitizeSvg,
  rateLimiter,
} from '../middleware/security';

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// RFC 5987 compliant Content-Disposition header encoding
// This prevents header injection attacks by properly encoding filenames
function encodeContentDisposition(disposition: 'inline' | 'attachment', filename: string): string {
  // First check if filename is ASCII-safe (no special chars that need escaping)
  const asciiSafe = /^[\x20-\x7E]*$/.test(filename) && !filename.includes('"') && !filename.includes('\\');

  if (asciiSafe) {
    // Simple case - just quote the filename
    return `${disposition}; filename="${filename}"`;
  }

  // Use RFC 5987 encoding for non-ASCII or special characters
  // This uses UTF-8 encoding with percent-encoding
  const encodedFilename = encodeURIComponent(filename)
    .replace(/['()]/g, escape) // escape these per RFC 5987
    .replace(/\*/g, '%2A');    // escape asterisk

  // Provide both filename (ASCII fallback) and filename* (UTF-8 encoded)
  const asciiFallback = filename.replace(/[^\x20-\x7E]/g, '_').replace(/["\\]/g, '_');
  return `${disposition}; filename="${asciiFallback}"; filename*=UTF-8''${encodedFilename}`;
}

// SECURITY: Allowed MIME type prefixes for filtering
// Only allow filtering by known, safe MIME type categories
const ALLOWED_MIME_PREFIXES = ['image/', 'video/', 'audio/', 'application/pdf'];

// List media (requires auth to prevent enumeration)
app.get('/', authMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const limit = Math.min(Math.max(1, parseInt(c.req.query('limit') || '50') || 50), 100);
  const offset = Math.max(0, parseInt(c.req.query('offset') || '0') || 0);
  const mimeType = c.req.query('mimeType'); // Filter by type (image, video, etc.)

  // SECURITY: Validate mimeType against whitelist to prevent arbitrary queries
  // Only allow specific prefixes, not arbitrary user input
  let filterMimeType: string | null = null;
  if (mimeType) {
    // Check if the provided filter matches one of our allowed prefixes
    const matchedPrefix = ALLOWED_MIME_PREFIXES.find(
      (prefix) => mimeType === prefix || prefix.startsWith(mimeType + '/') || mimeType === prefix.split('/')[0]
    );
    if (matchedPrefix) {
      // Use the prefix for filtering (e.g., "image" becomes "image/")
      filterMimeType = mimeType.includes('/') ? mimeType : mimeType + '/';
    }
    // If mimeType doesn't match any allowed prefix, ignore it (don't filter)
  }

  const items = filterMimeType
    ? await db
        .select()
        .from(schema.media)
        .where(like(schema.media.mimeType, `${filterMimeType}%`))
        .orderBy(desc(schema.media.createdAt))
        .limit(limit)
        .offset(offset)
    : await db
        .select()
        .from(schema.media)
        .orderBy(desc(schema.media.createdAt))
        .limit(limit)
        .offset(offset);

  // Get total count
  const countResult = await db
    .select({ count: sql<number>`count(*)` })
    .from(schema.media)
    .get();

  return c.json({
    items: items.map((item) => ({
      ...item,
      url: `/api/v1/media/${item.id}/file`,
    })),
    pagination: {
      total: countResult?.count ?? 0,
      limit,
      offset,
    },
  });
});

// Get single media item (requires auth to prevent enumeration)
app.get('/:id', authMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const id = c.req.param('id');

  const item = await db
    .select()
    .from(schema.media)
    .where(eq(schema.media.id, id))
    .get();

  if (!item) {
    return c.json({ error: 'Media not found' }, 404);
  }

  return c.json({
    ...item,
    url: `/api/v1/media/${item.id}/file`,
  });
});

// Serve media file from R2
// SECURITY: Uses optional auth — authenticated users can access any media,
// unauthenticated users are aggressively rate-limited to prevent enumeration.
// Media IDs are unguessable ULIDs (128-bit random), so brute force is infeasible
// at 30 req/min, but defense in depth is applied.
app.get('/:id/file', optionalAuthMiddleware, rateLimiter({
  windowMs: 60000,
  maxRequests: 30, // Tight limit for unauthenticated access
  keyGenerator: (c) => {
    const user = c.get('user');
    // Authenticated users get a generous limit; anonymous users get a tight one
    return user ? `media-file-auth:${user.id}` : `media-file-anon:${c.req.header('CF-Connecting-IP') || 'unknown'}`;
  },
}), async (c) => {
  const db = createDb(c.env.DB);
  const id = c.req.param('id');

  const item = await db
    .select()
    .from(schema.media)
    .where(eq(schema.media.id, id))
    .get();

  if (!item) {
    return c.json({ error: 'Media not found' }, 404);
  }

  const object = await c.env.BUCKET.get(item.storageKey);
  if (!object) {
    return c.json({ error: 'File not found in storage' }, 404);
  }

  const headers = new Headers();
  headers.set('Content-Type', item.mimeType);
  headers.set('Cache-Control', 'public, max-age=2592000'); // 30 days (reduced from 1 year)
  headers.set('X-Content-Type-Options', 'nosniff'); // Prevent MIME sniffing
  // SECURITY: Strict CSP to prevent XSS via uploaded files
  // This blocks JavaScript execution even if attacker uploads malicious HTML/SVG
  headers.set('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; media-src 'self'");
  headers.set('X-Frame-Options', 'DENY'); // Prevent framing
  if (item.size) {
    headers.set('Content-Length', item.size.toString());
  }

  // Force download for non-image/video/audio types to prevent script execution
  if (!item.mimeType.startsWith('image/') &&
      !item.mimeType.startsWith('video/') &&
      !item.mimeType.startsWith('audio/')) {
    headers.set('Content-Disposition', encodeContentDisposition('attachment', item.filename));
  }

  return new Response(object.body, { headers });
});

// Allowed MIME types whitelist
const ALLOWED_MIME_TYPES = [
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp',
  'image/svg+xml',
  'image/bmp',
  'image/x-icon',
  'video/mp4',
  'video/webm',
  'audio/mpeg',
  'audio/wav',
  'audio/ogg',
  'application/pdf',
];

// Upload media (direct upload) - rate limited to prevent abuse
app.post('/upload', authMiddleware, rateLimiter({ windowMs: 60000, maxRequests: 20 }), async (c) => {
  const db = createDb(c.env.DB);
  const user = c.get('user')!;
  const formData = await c.req.formData();
  const file = formData.get('file') as File | null;

  if (!file) {
    return c.json({ error: 'No file provided' }, 400);
  }

  // Validate file type against whitelist (not just prefix matching)
  const isAllowed = ALLOWED_MIME_TYPES.includes(file.type) ||
                    ALLOWED_MIME_TYPES.some(t => file.type.startsWith(t.split('/')[0] + '/'));
  if (!isAllowed) {
    return c.json({ error: 'File type not allowed' }, 400);
  }

  // Validate file size (50MB max)
  const maxSize = 50 * 1024 * 1024;
  if (file.size > maxSize) {
    return c.json({ error: 'File too large (max 50MB)' }, 400);
  }

  // Validate magic bytes match claimed MIME type
  const validMagic = await validateFileMagicBytes(file, file.type);
  if (!validMagic) {
    return c.json({ error: 'File content does not match declared type' }, 400);
  }

  const id = generateId();

  // Use extension from whitelist based on MIME type (not from user-provided filename)
  const ext = getExtensionFromMimeType(file.type);
  const storageKey = `media/${id}.${ext}`;

  // Sanitize the original filename for display purposes
  const safeFilename = sanitizeFilename(file.name);

  // For SVG files, sanitize content to prevent XSS attacks
  let uploadContent: ReadableStream | Blob = file.stream();
  let finalSize = file.size;

  if (file.type === 'image/svg+xml') {
    const svgText = await file.text();
    const sanitizedSvg = sanitizeSvg(svgText);

    if (sanitizedSvg === null) {
      return c.json({ error: 'SVG contains potentially dangerous content' }, 400);
    }

    // Use sanitized content for upload
    const sanitizedBlob = new Blob([sanitizedSvg], { type: 'image/svg+xml' });
    uploadContent = sanitizedBlob;
    finalSize = sanitizedBlob.size;
  }

  // Upload to R2
  await c.env.BUCKET.put(storageKey, uploadContent, {
    httpMetadata: {
      contentType: file.type,
      // Force download for non-image types to prevent script execution
      contentDisposition: file.type.startsWith('image/')
        ? 'inline'
        : encodeContentDisposition('attachment', safeFilename),
    },
  });

  // Get image dimensions if it's an image
  let width: number | null = null;
  let height: number | null = null;

  // Note: Getting image dimensions in Workers requires additional processing
  // For now, we skip this - the admin UI can send dimensions from client

  const timestamp = now();

  await db.insert(schema.media).values({
    id,
    filename: safeFilename,
    mimeType: file.type,
    size: finalSize,
    width,
    height,
    alt: null,
    storageKey,
    uploadedBy: user.id,
    createdAt: timestamp,
  });

  // Audit log the upload
  await auditLog(c, 'upload', 'media', id, {
    filename: safeFilename,
    mimeType: file.type,
    size: finalSize,
    sanitized: file.type === 'image/svg+xml',
  });

  return c.json({
    id,
    filename: safeFilename,
    mimeType: file.type,
    size: finalSize,
    url: `/api/v1/media/${id}/file`,
  }, 201);
});

// Create media record (for pre-signed URL workflow)
app.post('/', authMiddleware, zValidator('json', createMediaSchema), async (c) => {
  const db = createDb(c.env.DB);
  const user = c.get('user')!;
  const body = c.req.valid('json');

  // SECURITY: Validate MIME type against whitelist
  const isAllowed = ALLOWED_MIME_TYPES.includes(body.mimeType) ||
                    ALLOWED_MIME_TYPES.some(t => body.mimeType.startsWith(t.split('/')[0] + '/'));
  if (!isAllowed) {
    return c.json({ error: 'File type not allowed' }, 400);
  }

  const id = generateId();
  // SECURITY: Use extension from MIME type whitelist, not from user-provided filename
  // This prevents path traversal and extension spoofing attacks
  const ext = getExtensionFromMimeType(body.mimeType);
  const storageKey = `media/${id}.${ext}`;
  // SECURITY: Sanitize filename to prevent header injection and path traversal
  const safeFilename = sanitizeFilename(body.filename);
  const timestamp = now();

  await db.insert(schema.media).values({
    id,
    filename: safeFilename,
    mimeType: body.mimeType,
    size: body.size || null,
    width: body.width || null,
    height: body.height || null,
    alt: body.alt || null,
    storageKey,
    uploadedBy: user.id,
    createdAt: timestamp,
  });

  return c.json({
    id,
    storageKey,
    url: `/api/v1/media/${id}/file`,
  }, 201);
});

// Generate signed upload token
async function generateSignedUploadToken(
  secret: string,
  mediaId: string,
  mimeType: string,
  expiresAt: number
): Promise<string> {
  const payload = `${mediaId}:${mimeType}:${expiresAt}`;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  const sigBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  return `${btoa(payload).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}.${sigBase64}`;
}

// Verify signed upload token
async function verifySignedUploadToken(
  secret: string,
  token: string
): Promise<{ mediaId: string; mimeType: string; expiresAt: number } | null> {
  try {
    const [payloadB64, sigB64] = token.split('.');
    if (!payloadB64 || !sigB64) return null;

    const payload = atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/'));
    const [mediaId, mimeType, expiresAtStr] = payload.split(':');
    const expiresAt = parseInt(expiresAtStr, 10);

    // Check expiry
    if (Date.now() > expiresAt) return null;

    // Verify signature
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    const sigBytes = Uint8Array.from(
      atob(sigB64.replace(/-/g, '+').replace(/_/g, '/')),
      (c) => c.charCodeAt(0)
    );
    const isValid = await crypto.subtle.verify('HMAC', key, sigBytes, encoder.encode(payload));

    if (!isValid) return null;

    return { mediaId, mimeType, expiresAt };
  } catch {
    return null;
  }
}

// Get signed upload URL (for secure client-side uploads)
// Returns a time-limited signed URL that allows upload without session
app.post('/upload-url', authMiddleware, rateLimiter({ windowMs: 60000, maxRequests: 20 }), zValidator('json', z.object({
  filename: z.string(),
  mimeType: z.string(),
  size: z.number().optional(),
})), async (c) => {
  const body = c.req.valid('json');
  const user = c.get('user')!;

  // Validate MIME type
  const isAllowed = ALLOWED_MIME_TYPES.includes(body.mimeType) ||
                    ALLOWED_MIME_TYPES.some(t => body.mimeType.startsWith(t.split('/')[0] + '/'));
  if (!isAllowed) {
    return c.json({ error: 'File type not allowed' }, 400);
  }

  const id = generateId();
  const ext = getExtensionFromMimeType(body.mimeType);
  const storageKey = `media/${id}.${ext}`;
  const safeFilename = sanitizeFilename(body.filename);

  // SECURITY: Require a configured secret for upload token signing
  // Refuse to generate signed URLs without a proper secret — the hardcoded
  // default is publicly visible in source code and trivially forgeable
  const signingSecret = c.env.ADMIN_TOKEN;
  if (!signingSecret) {
    console.error('SECURITY: ADMIN_TOKEN not set — signed upload URLs are disabled');
    return c.json({ error: 'Signed uploads not available — server misconfiguration' }, 503);
  }
  const effectiveSecret = signingSecret;

  // Token expires in 15 minutes
  const expiresAt = Date.now() + 15 * 60 * 1000;
  const token = await generateSignedUploadToken(effectiveSecret, id, body.mimeType, expiresAt);

  // Pre-create the media record (will be updated after upload)
  const timestamp = now();
  await createDb(c.env.DB).insert(schema.media).values({
    id,
    filename: safeFilename,
    mimeType: body.mimeType,
    size: body.size || null,
    width: null,
    height: null,
    alt: null,
    storageKey,
    uploadedBy: user.id,
    createdAt: timestamp,
  });

  return c.json({
    id,
    storageKey,
    uploadUrl: `/api/v1/media/signed-upload`,
    token,
    expiresAt: new Date(expiresAt).toISOString(),
    method: 'PUT',
  });
});

// Signed upload endpoint - accepts uploads with valid token
app.put('/signed-upload', rateLimiter({ windowMs: 60000, maxRequests: 20 }), async (c) => {
  const token = c.req.header('X-Upload-Token') || c.req.query('token');

  if (!token) {
    return c.json({ error: 'Missing upload token' }, 401);
  }

  // SECURITY: Refuse to verify tokens without a proper signing secret
  const verifySecret = c.env.ADMIN_TOKEN;
  if (!verifySecret) {
    return c.json({ error: 'Signed uploads not available — server misconfiguration' }, 503);
  }
  const tokenData = await verifySignedUploadToken(verifySecret, token);

  if (!tokenData) {
    return c.json({ error: 'Invalid or expired upload token' }, 401);
  }

  const { mediaId, mimeType } = tokenData;

  // Get existing media record
  const db = createDb(c.env.DB);
  const existing = await db
    .select()
    .from(schema.media)
    .where(eq(schema.media.id, mediaId))
    .get();

  if (!existing) {
    return c.json({ error: 'Media record not found' }, 404);
  }

  // Get file from request body
  const contentType = c.req.header('Content-Type') || mimeType;

  // SECURITY: Validate content type matches expected (case-insensitive)
  if (!contentType.toLowerCase().startsWith(mimeType.split('/')[0].toLowerCase())) {
    return c.json({ error: 'Content type mismatch' }, 400);
  }

  const body = await c.req.arrayBuffer();
  const file = new Uint8Array(body);

  // Validate file size (50MB max)
  const maxSize = 50 * 1024 * 1024;
  if (file.length > maxSize) {
    return c.json({ error: 'File too large (max 50MB)' }, 400);
  }

  // Validate magic bytes
  const blob = new Blob([file], { type: mimeType });
  const blobFile = new File([blob], existing.filename, { type: mimeType });
  const validMagic = await validateFileMagicBytes(blobFile, mimeType);
  if (!validMagic) {
    return c.json({ error: 'File content does not match declared type' }, 400);
  }

  // For SVG files, sanitize content
  let uploadContent: Uint8Array | Blob = file;
  let finalSize = file.length;

  if (mimeType === 'image/svg+xml') {
    const decoder = new TextDecoder();
    const svgText = decoder.decode(file);
    const sanitizedSvg = sanitizeSvg(svgText);

    if (sanitizedSvg === null) {
      return c.json({ error: 'SVG contains potentially dangerous content' }, 400);
    }

    const encoder = new TextEncoder();
    uploadContent = encoder.encode(sanitizedSvg);
    finalSize = uploadContent.length;
  }

  // Upload to R2
  await c.env.BUCKET.put(existing.storageKey, uploadContent, {
    httpMetadata: {
      contentType: mimeType,
      contentDisposition: mimeType.startsWith('image/')
        ? 'inline'
        : encodeContentDisposition('attachment', existing.filename),
    },
  });

  // Update media record with final size
  await db
    .update(schema.media)
    .set({ size: finalSize })
    .where(eq(schema.media.id, mediaId));

  return c.json({
    id: mediaId,
    filename: existing.filename,
    mimeType,
    size: finalSize,
    url: `/api/v1/media/${mediaId}/file`,
  });
});

// Update media metadata (editors/admins only per media:update policy)
app.patch('/:id', authMiddleware, editorMiddleware, zValidator('json', updateMediaSchema), async (c) => {
  const db = createDb(c.env.DB);
  const id = c.req.param('id');
  const body = c.req.valid('json');

  const existing = await db
    .select()
    .from(schema.media)
    .where(eq(schema.media.id, id))
    .get();

  if (!existing) {
    return c.json({ error: 'Media not found' }, 404);
  }

  const updates: Record<string, unknown> = {};
  if (body.alt !== undefined) updates.alt = body.alt;
  if (body.filename !== undefined) updates.filename = body.filename;

  if (Object.keys(updates).length > 0) {
    await db
      .update(schema.media)
      .set(updates)
      .where(eq(schema.media.id, id));

    // Audit log the update
    await auditLog(c, 'update', 'media', id, {
      changes: updates,
      filename: existing.filename,
    });
  }

  return c.json({ success: true });
});

// Delete media (editors/admins only per media:delete policy)
app.delete('/:id', authMiddleware, editorMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const id = c.req.param('id');

  const item = await db
    .select()
    .from(schema.media)
    .where(eq(schema.media.id, id))
    .get();

  if (!item) {
    return c.json({ error: 'Media not found' }, 404);
  }

  // Delete from R2
  await c.env.BUCKET.delete(item.storageKey);

  // Delete from database
  await db.delete(schema.media).where(eq(schema.media.id, id));

  // Audit log the deletion
  await auditLog(c, 'delete', 'media', id, {
    filename: item.filename,
    mimeType: item.mimeType,
  });

  return c.json({ success: true });
});

export default app;
