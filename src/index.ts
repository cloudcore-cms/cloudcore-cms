import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { bodyLimit } from 'hono/body-limit';
import { HTTPException } from 'hono/http-exception';
import type { Env, Variables } from './types';

// Import security middleware
import {
  securityHeaders,
  rateLimiter,
  requestId,
  csrfProtection,
  parseAllowedOrigins,
} from './middleware/security';

// Import routes
import contentRoutes from './routes/content';
import mediaRoutes from './routes/media';
import categoriesRoutes from './routes/categories';
import tagsRoutes from './routes/tags';
import authRoutes from './routes/auth';
import settingsRoutes from './routes/settings';
import blocksRoutes from './routes/blocks';
import auditRoutes from './routes/audit';
import oauthRoutes from './routes/oauth';
import magicLinkRoutes from './routes/magic-link';
import cfAccessRoutes from './routes/cf-access';
import publicRoutes from './routes/public';

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// Security middleware - applied to all routes
app.use('*', requestId);
app.use('*', securityHeaders);

// SECURITY: Global request body size limit to prevent memory exhaustion DoS
// 10MB for general API requests; media upload endpoints have their own 50MB limit
app.use('/api/*', bodyLimit({
  maxSize: 10 * 1024 * 1024, // 10MB
  onError: (c) => c.json({ error: 'Request body too large (max 10MB)' }, 413),
}));

// Rate limiting - different limits for different endpoints
// General API: 100 requests per minute
app.use('/api/*', rateLimiter({ windowMs: 60000, maxRequests: 100 }));
// Auth endpoints: stricter limits (handled by bruteForceProtection in auth routes)

// Standard middleware
app.use('*', logger());

// CORS configuration - uses environment variable for allowed origins
// Set ALLOWED_ORIGINS env var to comma-separated origins (e.g., "https://admin.example.com,https://example.com")
app.use('*', async (c, next) => {
  const allowedOrigins = parseAllowedOrigins(c.env.ALLOWED_ORIGINS);

  const corsMiddleware = cors({
    origin: (origin) => {
      // No origin (same-origin request or non-browser client)
      if (!origin) return origin;

      // Check if origin is in allowed list
      const isAllowed = allowedOrigins.some(allowed => {
        if (allowed.startsWith('*.')) {
          // Wildcard subdomain matching
          const domain = allowed.slice(1); // Remove *
          try {
            const originUrl = new URL(origin);
            return originUrl.hostname.endsWith(domain) || originUrl.hostname === domain.slice(1);
          } catch {
            return false;
          }
        }
        return origin === allowed;
      });

      // SECURITY: Reject disallowed origins by returning undefined
      // This prevents the Access-Control-Allow-Origin header from being set,
      // causing the browser to block the cross-origin response
      if (!isAllowed) {
        return undefined;
      }
      return origin;
    },
    credentials: true,
    allowHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'X-CloudCore-Request', 'X-Upload-Token'],
    allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    exposeHeaders: ['X-Request-ID', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
  });

  return corsMiddleware(c, next);
});

// CSRF Protection - validates Origin header on state-changing requests
app.use('/api/*', async (c, next) => {
  const allowedOrigins = parseAllowedOrigins(c.env.ALLOWED_ORIGINS);
  const csrfMiddleware = csrfProtection(allowedOrigins);
  return csrfMiddleware(c, next);
});

// Health check (no rate limiting)
app.get('/health', (c) => {
  return c.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// API info
app.get('/api/v1', (c) => {
  return c.json({
    name: 'Cloudcore CMS',
    version: '0.2.0',
    security: {
      rateLimit: '100 requests/minute',
      bruteForceProtection: 'enabled',
      turnstile: c.env.TURNSTILE_SECRET ? 'enabled' : 'disabled',
    },
    endpoints: {
      content: '/api/v1/content',
      media: '/api/v1/media',
      categories: '/api/v1/categories',
      tags: '/api/v1/tags',
      auth: '/api/v1/auth',
      settings: '/api/v1/settings',
      blocks: '/api/v1/blocks',
      audit: '/api/v1/audit',
    },
  });
});

// Mount routes
app.route('/api/v1/content', contentRoutes);
app.route('/api/v1/media', mediaRoutes);
app.route('/api/v1/categories', categoriesRoutes);
app.route('/api/v1/tags', tagsRoutes);
app.route('/api/v1/auth', authRoutes);
app.route('/api/v1/settings', settingsRoutes);
app.route('/api/v1/blocks', blocksRoutes);
app.route('/api/v1/audit', auditRoutes);
app.route('/api/v1/auth/oauth', oauthRoutes);
app.route('/api/v1/auth/magic-link', magicLinkRoutes);
app.route('/api/v1/auth/cf-access', cfAccessRoutes);
app.route('/api/v1/public', publicRoutes);

// Global error handler
app.onError((err, c) => {
  console.error('Error:', err);

  // Don't expose internal error details in production
  const isProduction = new URL(c.req.url).protocol === 'https:';

  if (err instanceof HTTPException) {
    return c.json(
      {
        error: err.message,
        ...(err.cause && !isProduction ? { details: err.cause } : {}),
      },
      err.status
    );
  }

  return c.json(
    {
      error: isProduction ? 'Internal server error' : err.message,
    },
    500
  );
});

// 404 handler
app.notFound((c) => {
  return c.json({ error: 'Not found' }, 404);
});

export default app;
