# Cloudcore CMS

A headless CMS built on Cloudflare Workers. Block-based content model, admin dashboard, 5 auth methods, enterprise-grade security. Runs on Cloudflare's free tier.

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/cloudcore-cms/cloudcore-cms)

## Quick Start

```bash
npm install
npx wrangler d1 migrations apply cloudcore-cms --local
npm run dev:local
# API at http://localhost:8787

# Start admin UI
cd admin && npm install && npm run dev
# Admin at http://localhost:5173
```

## Deploy

```bash
npx wrangler d1 create cloudcore-cms
npx wrangler r2 bucket create cloudcore-cms
npx wrangler secret put ADMIN_TOKEN
npx wrangler deploy
npx wrangler d1 migrations apply cloudcore-cms --remote
```

For production, deploy the [Public API](https://github.com/cloudcore-cms/cloudcore-api) as your internet-facing endpoint and lock this CMS behind Cloudflare Access.

## Features

- **Block-based content** — 13 block types including WYSIWYG rich text editor
- **Pages and posts** — with categories, tags, and revision history
- **Media library** — upload to R2 with magic byte validation and SVG sanitization
- **Admin dashboard** — React + Vite + TailwindCSS with Tiptap editor
- **5 auth methods** — Password, Passkeys (WebAuthn), Magic Links, GitHub OAuth, Google OAuth
- **RBAC** — Admin, Editor, Contributor roles with granular permissions
- **Public API** — built-in read-only routes at `/api/v1/public/*`, or deploy the [standalone Public API](https://github.com/cloudcore-cms/cloudcore-api)

## Security

- PBKDF2-SHA512 (210k iterations) password hashing
- SHA-256 hashed session tokens
- Timing-safe comparisons on all auth paths
- CSRF protection (custom header + Origin + SameSite=Strict)
- Rate limiting on every endpoint with brute force protection
- File upload validation (magic bytes + MIME whitelist)
- SVG sanitization (blocks script, style, event handlers)
- 10MB request body limit
- Comprehensive audit logging with sensitive field redaction
- 0 npm audit vulnerabilities

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ADMIN_TOKEN` | Yes | Bearer token for API access |
| `SETUP_TOKEN` | Recommended | Required for initial admin setup |
| `SECURE_COOKIES` | Recommended | `"true"` for production |
| `ALLOWED_ORIGINS` | Recommended | CORS origins (comma-separated) |

See the [full environment variable reference](https://cloudcore-cms.github.io/docs/environment) for OAuth, SMTP, and Cloudflare Access configuration.

## License

MIT
