// Cloudflare bindings
export interface Env {
  DB: D1Database;
  BUCKET: R2Bucket;
  ADMIN_TOKEN?: string;
  SETUP_TOKEN?: string; // Optional token required for initial admin setup (prevents setup race attacks)
  TURNSTILE_SECRET?: string; // Cloudflare Turnstile secret key
  ALLOWED_ORIGINS?: string; // Comma-separated list of allowed origins (e.g., "https://admin.example.com,https://example.com")
  SECURE_COOKIES?: string; // 'true' to force secure cookies (recommended for production)

  // OAuth Configuration
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  OAUTH_CALLBACK_URL?: string; // Base URL for OAuth callbacks (e.g., "https://cms.example.com")

  // SMTP / Email Configuration (for magic links)
  SMTP_HOST?: string;
  SMTP_PORT?: string;
  SMTP_USER?: string;
  SMTP_PASS?: string;
  SMTP_FROM?: string; // Sender email (e.g., "noreply@example.com")
  SMTP_FROM_NAME?: string; // Sender name (e.g., "Cloudcore CMS")
  MAGIC_LINK_BASE_URL?: string; // Base URL for magic links (e.g., "https://admin.example.com")
  SENDGRID_API_KEY?: string; // SendGrid API key (alternative to SMTP)
  RESEND_API_KEY?: string; // Resend API key (alternative to SMTP)
  MAILGUN_API_KEY?: string; // Mailgun API key (alternative to SMTP)

  // Cloudflare Access Configuration
  CF_ACCESS_TEAM_DOMAIN?: string; // e.g., "yourteam.cloudflareaccess.com"
  CF_ACCESS_AUD?: string; // Application Audience (AUD) tag
  CF_ACCESS_ENABLED?: string; // 'true' to enable CF Access authentication

  // Session Configuration
  SESSION_SLIDING_WINDOW?: string; // 'true' to enable sliding sessions (extend on activity)
}

// User roles
export type UserRole = 'admin' | 'editor' | 'contributor';

// Content status
export type ContentStatus = 'draft' | 'pending_review' | 'published';

// Context variables set by middleware
export interface Variables {
  user: User | null;
  session: Session | null;
  requestId?: string;
}

// User type
export interface User {
  id: string;
  email: string;
  name: string | null;
  role: UserRole;
  avatar?: string | null;
  bio?: string | null;
  isActive: boolean;
  lastLoginAt?: string | null;
  createdAt: string;
  updatedAt?: string | null;
}

// Session type
export interface Session {
  id: string;
  userId: string;
  userAgent?: string | null;
  ipAddress?: string | null;
  expiresAt: string;
  createdAt: string;
}

// Content block
export interface ContentBlock {
  id: string;
  type: string;
  value: string;
  options?: Record<string, unknown>;
  mediaId?: string;
  mediaIds?: string[];
}

// Content item (page or post)
export interface Content {
  id: string;
  type: 'page' | 'post';
  title: string;
  slug: string;
  status: ContentStatus;
  blocks: ContentBlock[];
  authorId: string | null;
  lastEditedBy?: string | null;
  publishedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

// Revision with author info
export interface Revision {
  id: string;
  contentId: string;
  title: string;
  blocks: ContentBlock[];
  status?: ContentStatus | null;
  authorId: string | null;
  authorName?: string | null;
  authorEmail?: string | null;
  changeType?: 'create' | 'update' | 'publish' | 'unpublish' | 'restore' | null;
  changeSummary?: string | null;
  createdAt: string;
}

// Media item
export interface Media {
  id: string;
  filename: string;
  mimeType: string;
  size: number | null;
  width: number | null;
  height: number | null;
  alt: string | null;
  storageKey: string;
  uploadedBy?: string | null;
  createdAt: string;
}

// Category
export interface Category {
  id: string;
  slug: string;
  name: string;
  parentId: string | null;
  createdAt: string;
}

// Tag
export interface Tag {
  id: string;
  slug: string;
  name: string;
  createdAt: string;
}

// Audit log entry
export interface AuditLogEntry {
  id: string;
  userId: string | null;
  userEmail: string | null;
  action: string;
  resourceType: 'content' | 'user' | 'media' | 'settings' | null;
  resourceId: string | null;
  details: Record<string, unknown> | null;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: string;
}

// Permission definitions
export const PERMISSIONS = {
  // Content permissions
  'content:create': ['admin', 'editor', 'contributor'],
  'content:read': ['admin', 'editor', 'contributor'],
  'content:update': ['admin', 'editor', 'contributor'], // Contributors can only update their own drafts
  'content:delete': ['admin', 'editor'],
  'content:publish': ['admin', 'editor'],
  'content:unpublish': ['admin', 'editor'],

  // User management
  'users:create': ['admin'],
  'users:read': ['admin'],
  'users:update': ['admin'],
  'users:delete': ['admin'],

  // Media
  'media:upload': ['admin', 'editor', 'contributor'],
  'media:delete': ['admin', 'editor'],

  // Categories/Tags
  'taxonomy:manage': ['admin', 'editor'],

  // Settings
  'settings:read': ['admin'],
  'settings:update': ['admin'],

  // Audit
  'audit:read': ['admin'],
} as const;

export type Permission = keyof typeof PERMISSIONS;

// Check if a role has a permission
export function hasPermission(role: UserRole, permission: Permission): boolean {
  const allowedRoles = PERMISSIONS[permission] as readonly UserRole[];
  return allowedRoles.includes(role);
}

// Check if user can edit content
export function canEditContent(user: User, content: Content): boolean {
  if (user.role === 'admin' || user.role === 'editor') {
    return true;
  }
  // Contributors can only edit their own drafts
  if (user.role === 'contributor') {
    return content.authorId === user.id && content.status === 'draft';
  }
  return false;
}

// Check if user can publish content
export function canPublishContent(user: User): boolean {
  return user.role === 'admin' || user.role === 'editor';
}

// Check if user can delete content
export function canDeleteContent(user: User, content: Content): boolean {
  if (user.role === 'admin') return true;
  if (user.role === 'editor') return true;
  // Contributors can delete their own unpublished content
  if (user.role === 'contributor') {
    return content.authorId === user.id && content.status === 'draft';
  }
  return false;
}
