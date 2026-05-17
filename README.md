# Cloudcore CMS — Open-Source Headless CMS for Cloudflare Workers

![CI](https://github.com/cloudcore-cms/cloudcore-cms/actions/workflows/ci.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**Cloudcore CMS is a free, open-source, self-hosted headless CMS built on Cloudflare Workers.** Block-based content, a React admin dashboard, 5 built-in auth methods, and enterprise-grade security — running entirely on Cloudflare's free tier. A modern, MIT-licensed alternative to Strapi, Sanity, Contentful, Payload, and Directus for teams already on Cloudflare.

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/cloudcore-cms/cloudcore-cms)

## Why Cloudcore CMS?

- **Free forever** — runs on Cloudflare's free tier (Workers, D1, R2). No per-seat pricing, no usage caps until you scale.
- **Self-hosted and MIT licensed** — own your data, your auth, your content. No vendor lock-in.
- **Cloudflare-native** — D1 (SQLite at the edge), R2 (S3-compatible storage), Workers. No AWS account, no Heroku, no Postgres to manage.
- **TypeScript end-to-end** — Hono on the backend, React + Vite + TailwindCSS on the admin UI.
- **Production-grade auth out of the box** — passwords, passkeys (WebAuthn), magic links, GitHub OAuth, Google OAuth, and Cloudflare Access JWT, all without extra services.
- **Block-based content model** — ACF-style typed blocks instead of free-form markdown or proprietary rich-text JSON.
- **Edge-first performance** — every request runs at the closest Cloudflare PoP.

## Use Cases

- **Blogs and publications** — multi-author posts with categories, tags, and full revision history
- **Marketing sites** — pages with reusable content blocks
- **Documentation** — structured content with a rich text editor
- **Headless backends for Next.js, Astro, SvelteKit, Nuxt, Remix, Hugo, 11ty** — consume the public REST API from any frontend
- **Multi-site content hubs** — one CMS, many consumers via the public API
- **Internal tools and dashboards** — RBAC + audit logging built in

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

## Deploy to Cloudflare

```bash
npx wrangler d1 create cloudcore-cms
npx wrangler r2 bucket create cloudcore-cms
npx wrangler secret put ADMIN_TOKEN
npx wrangler deploy
npx wrangler d1 migrations apply cloudcore-cms --remote
```

For production, deploy the [Public API](https://github.com/cloudcore-cms/cloudcore-api) as your internet-facing endpoint and lock this CMS behind Cloudflare Access.

## Features

- **Block-based content model** — 13 typed block types including a WYSIWYG rich text editor (Tiptap)
- **Pages and posts** — with categories, tags, draft/published workflow, and complete revision history
- **Media library** — upload to Cloudflare R2 with magic-byte validation and SVG sanitization
- **React admin dashboard** — React 18 + Vite + TailwindCSS + Tiptap, deployable as static assets
- **5 authentication methods** — Password (PBKDF2-SHA512), Passkeys / WebAuthn, Magic Links, GitHub OAuth, Google OAuth, plus Cloudflare Access JWT
- **Role-based access control (RBAC)** — Admin, Editor, Contributor roles with granular permissions
- **Public REST API** — built-in read-only routes at `/api/v1/public/*`, or deploy the [standalone Public API](https://github.com/cloudcore-cms/cloudcore-api) for an internet-facing read layer
- **Comprehensive audit log** — every state change tracked with actor, IP, and user agent

## Cloudcore CMS vs Alternatives

How Cloudcore CMS positions against other popular headless CMS options:

| | Cloudcore CMS | Strapi | Sanity | Contentful | Payload | Directus |
|---|---|---|---|---|---|---|
| **License** | MIT | SSPL | Commercial | Commercial | MIT | BSL |
| **Self-hosted** | ✅ | ✅ | ❌ (SaaS) | ❌ (SaaS) | ✅ | ✅ |
| **Free tier (hosted)** | ✅ Cloudflare free tier | Cloud paid | Limited free | Limited free | Self-host only | Self-host only |
| **Runtime** | Cloudflare Workers (edge) | Node.js | Hosted | Hosted | Node.js | Node.js |
| **Database** | Cloudflare D1 (SQLite) | Postgres/MySQL/SQLite | Proprietary | Proprietary | Postgres/MongoDB | Postgres/MySQL |
| **Built-in passkeys** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Stack** | TypeScript / Hono / React | JavaScript / Koa | JavaScript | Closed | TypeScript / Express | JavaScript / Express |

Cloudcore CMS is the right pick if: you're already on Cloudflare, you want an open-source self-hosted CMS without managing a Node server or a database, and you care about modern auth (passkeys / WebAuthn) being available without bolting on extra services.

## Security

- **Password hashing** — PBKDF2-SHA512 with 210,000 iterations (OWASP 2023 recommended)
- **Session tokens** — SHA-256 hashed at rest; raw tokens only in HttpOnly + SameSite=Strict cookies
- **Timing-safe comparisons** on all authentication paths
- **CSRF protection** — custom header check + Origin validation + SameSite=Strict cookies (defense in depth)
- **Rate limiting** on every endpoint, with exponential-backoff brute force protection on login
- **File upload validation** — magic-byte signatures + MIME-type whitelist (not extension-based)
- **SVG sanitization** — strips `<script>`, `<style>`, event handlers, and `javascript:` URLs
- **Strict CSP, HSTS, X-Frame-Options DENY** on every response
- **10MB request body limit** to prevent memory exhaustion
- **Comprehensive audit logging** with sensitive field redaction
- **0 npm audit vulnerabilities** in dependencies

## Tech Stack

- **Runtime**: [Cloudflare Workers](https://workers.cloudflare.com/) (edge serverless)
- **Web framework**: [Hono](https://hono.dev/)
- **Database**: [Cloudflare D1](https://developers.cloudflare.com/d1/) (SQLite) via [Drizzle ORM](https://orm.drizzle.team/)
- **Object storage**: [Cloudflare R2](https://developers.cloudflare.com/r2/) (S3-compatible)
- **Admin UI**: React 18, Vite, TailwindCSS, Tiptap, React Query, React Router
- **Validation**: [Zod](https://zod.dev/)
- **Testing**: [Vitest](https://vitest.dev/)

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ADMIN_TOKEN` | Yes | Bearer token for API access |
| `SETUP_TOKEN` | Recommended | Required for initial admin setup |
| `SECURE_COOKIES` | Recommended | `"true"` for production |
| `ALLOWED_ORIGINS` | Recommended | CORS origins (comma-separated) |

See the [full environment variable reference](https://cloudcore-cms.github.io/docs/environment) for OAuth, SMTP, and Cloudflare Access configuration.

## FAQ

**Is Cloudcore CMS really free?**
Yes — MIT licensed and built to run on Cloudflare's free tier (Workers, D1, R2). You only pay if your traffic exceeds the free tier's generous limits.

**How does Cloudcore CMS compare to Strapi, Sanity, or Contentful?**
Cloudcore CMS is a Cloudflare-native, self-hosted alternative. Unlike Sanity and Contentful (SaaS only), you own and host everything. Unlike Strapi (Node.js server + your own database), Cloudcore CMS deploys as a single Worker with D1 and R2 — no server to manage. See the [comparison table](#cloudcore-cms-vs-alternatives) above.

**Can I use Cloudcore CMS with Next.js, Astro, SvelteKit, or other frontends?**
Yes. The public REST API at `/api/v1/public/*` is framework-agnostic — call it from any frontend that can `fetch()`. For higher traffic, deploy the dedicated [Public API worker](https://github.com/cloudcore-cms/cloudcore-api).

**Can I self-host Cloudcore CMS without Cloudflare?**
Not currently. The CMS is built on Cloudflare-specific primitives (D1, R2, Workers). Porting to Node.js + Postgres + S3 is possible but unsupported.

**Does Cloudcore CMS support passkeys / WebAuthn?**
Yes — passkeys are first-class, alongside password, magic links, GitHub OAuth, Google OAuth, and Cloudflare Access JWT. No third-party auth service required.

**Is Cloudcore CMS production-ready?**
Cloudcore CMS is at v0.1.0. The security model and feature set are solid, but the codebase is young and test coverage is light. Recommended for personal projects, blogs, and pre-launch products today; evaluate carefully for mission-critical workloads.

**Where do I report bugs or request features?**
[Open an issue on GitHub](https://github.com/cloudcore-cms/cloudcore-cms/issues).

## Contributing

Contributions welcome — please open an issue first for non-trivial changes. See [AGENTS.md](AGENTS.md) for an architectural overview.

## License

MIT — see [LICENSE](LICENSE).

---

**Keywords:** open source headless CMS, Cloudflare Workers CMS, self-hosted CMS, free CMS, MIT licensed CMS, Strapi alternative, Sanity alternative, Contentful alternative, Payload CMS alternative, Directus alternative, Ghost alternative, headless CMS with passkeys, WebAuthn CMS, TypeScript CMS, D1 CMS, R2 CMS, edge CMS, block-based CMS, JAMstack CMS.
