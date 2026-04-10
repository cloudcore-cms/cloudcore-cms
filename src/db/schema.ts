import { sqliteTable, text, integer, primaryKey, index } from 'drizzle-orm/sqlite-core';

// Content (Pages and Posts)
// Status: 'draft', 'pending_review', 'published'
export const content = sqliteTable('cc_content', {
  id: text('id').primaryKey(),
  type: text('type').notNull(), // 'page' or 'post'
  title: text('title').notNull(),
  slug: text('slug').notNull(),
  status: text('status').default('draft').notNull(), // 'draft', 'pending_review', 'published'
  blocks: text('blocks').notNull(), // JSON array of blocks
  authorId: text('author_id'),
  publishedAt: text('published_at'),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at').notNull(),
  lastEditedBy: text('last_edited_by'), // Track who last edited
}, (table) => ({
  typeIdx: index('idx_content_type').on(table.type),
  statusIdx: index('idx_content_status').on(table.status),
  slugIdx: index('idx_content_slug').on(table.slug),
  authorIdx: index('idx_content_author').on(table.authorId),
}));

// Revisions (Version History) - Enhanced with change tracking
export const revisions = sqliteTable('cc_revisions', {
  id: text('id').primaryKey(),
  contentId: text('content_id').notNull(),
  title: text('title').notNull(),
  blocks: text('blocks').notNull(), // JSON snapshot
  status: text('status'), // Status at time of revision
  authorId: text('author_id'), // Who made this change
  authorName: text('author_name'), // Denormalized for history display
  authorEmail: text('author_email'), // Denormalized for history display
  changeType: text('change_type'), // 'create', 'update', 'publish', 'unpublish', 'restore'
  changeSummary: text('change_summary'), // Optional description of changes
  createdAt: text('created_at').notNull(),
}, (table) => ({
  contentIdx: index('idx_revisions_content').on(table.contentId),
  authorIdx: index('idx_revisions_author').on(table.authorId),
  createdIdx: index('idx_revisions_created').on(table.createdAt),
}));

// Media Library
export const media = sqliteTable('cc_media', {
  id: text('id').primaryKey(),
  filename: text('filename').notNull(),
  mimeType: text('mime_type').notNull(),
  size: integer('size'),
  width: integer('width'),
  height: integer('height'),
  alt: text('alt'),
  storageKey: text('storage_key').notNull(),
  uploadedBy: text('uploaded_by'), // Track who uploaded
  createdAt: text('created_at').notNull(),
});

// Categories (Posts only)
export const categories = sqliteTable('cc_categories', {
  id: text('id').primaryKey(),
  slug: text('slug').notNull().unique(),
  name: text('name').notNull(),
  parentId: text('parent_id'),
  createdAt: text('created_at').notNull(),
});

// Tags (Posts only)
export const tags = sqliteTable('cc_tags', {
  id: text('id').primaryKey(),
  slug: text('slug').notNull().unique(),
  name: text('name').notNull(),
  createdAt: text('created_at').notNull(),
});

// Content-Category mapping
export const contentCategories = sqliteTable('cc_content_categories', {
  contentId: text('content_id').notNull(),
  categoryId: text('category_id').notNull(),
}, (table) => ({
  pk: primaryKey({ columns: [table.contentId, table.categoryId] }),
}));

// Content-Tag mapping
export const contentTags = sqliteTable('cc_content_tags', {
  contentId: text('content_id').notNull(),
  tagId: text('tag_id').notNull(),
}, (table) => ({
  pk: primaryKey({ columns: [table.contentId, table.tagId] }),
}));

// Users
// Roles: 'admin', 'editor', 'contributor'
// - admin: Full access, can manage users, publish anything
// - editor: Can create/edit/publish content
// - contributor: Can create/edit drafts, submit for review, cannot publish
export const users = sqliteTable('cc_users', {
  id: text('id').primaryKey(),
  email: text('email').notNull().unique(),
  passwordHash: text('password_hash'), // PBKDF2 hashed
  name: text('name'),
  role: text('role').default('contributor').notNull(), // 'admin', 'editor', 'contributor'
  avatar: text('avatar'), // URL or media ID
  bio: text('bio'),
  isActive: integer('is_active', { mode: 'boolean' }).default(true).notNull(),
  lastLoginAt: text('last_login_at'),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at'),
}, (table) => ({
  emailIdx: index('idx_users_email').on(table.email),
  roleIdx: index('idx_users_role').on(table.role),
}));

// Sessions
export const sessions = sqliteTable('cc_sessions', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull(),
  userAgent: text('user_agent'), // Track device/browser
  ipAddress: text('ip_address'), // Track IP for security
  expiresAt: text('expires_at').notNull(),
  createdAt: text('created_at').notNull(),
}, (table) => ({
  userIdx: index('idx_sessions_user').on(table.userId),
  expiresIdx: index('idx_sessions_expires').on(table.expiresAt),
}));

// Audit Log - Track all important actions
export const auditLog = sqliteTable('cc_audit_log', {
  id: text('id').primaryKey(),
  userId: text('user_id'),
  userEmail: text('user_email'), // Denormalized for history
  action: text('action').notNull(), // 'login', 'logout', 'create', 'update', 'delete', 'publish', etc.
  resourceType: text('resource_type'), // 'content', 'user', 'media', 'settings'
  resourceId: text('resource_id'),
  details: text('details'), // JSON with additional context
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  createdAt: text('created_at').notNull(),
}, (table) => ({
  userIdx: index('idx_audit_user').on(table.userId),
  actionIdx: index('idx_audit_action').on(table.action),
  resourceIdx: index('idx_audit_resource').on(table.resourceType, table.resourceId),
  createdIdx: index('idx_audit_created').on(table.createdAt),
}));

// Settings (Key-value store)
export const settings = sqliteTable('cc_settings', {
  key: text('key').primaryKey(),
  value: text('value').notNull(), // JSON
});

// Login Attempts - For brute force tracking (persisted)
export const loginAttempts = sqliteTable('cc_login_attempts', {
  id: text('id').primaryKey(),
  identifier: text('identifier').notNull(), // IP or email
  success: integer('success', { mode: 'boolean' }).notNull(),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  createdAt: text('created_at').notNull(),
}, (table) => ({
  identifierIdx: index('idx_login_identifier').on(table.identifier),
  createdIdx: index('idx_login_created').on(table.createdAt),
}));

// Rate Limits - Database-backed rate limiting (persisted across restarts)
export const rateLimits = sqliteTable('cc_rate_limits', {
  key: text('key').notNull(), // IP:endpoint composite key
  window: text('window').notNull(), // Window start timestamp (ISO)
  count: integer('count').notNull().default(1),
}, (table) => ({
  pk: primaryKey({ columns: [table.key, table.window] }),
  keyIdx: index('idx_rate_limits_key').on(table.key),
  windowIdx: index('idx_rate_limits_window').on(table.window),
}));

// Passkey Credentials - WebAuthn/FIDO2 authentication
export const passkeyCredentials = sqliteTable('cc_passkey_credentials', {
  id: text('id').primaryKey(), // Credential ID (base64url)
  userId: text('user_id').notNull(),
  publicKey: text('public_key').notNull(), // COSE public key (base64)
  counter: integer('counter').notNull().default(0), // Signature counter
  deviceType: text('device_type'), // 'platform' or 'cross-platform'
  backedUp: integer('backed_up', { mode: 'boolean' }).default(false),
  transports: text('transports'), // JSON array of transports
  name: text('name'), // User-friendly name for the passkey
  lastUsedAt: text('last_used_at'),
  createdAt: text('created_at').notNull(),
}, (table) => ({
  userIdx: index('idx_passkey_user').on(table.userId),
}));

// Passkey Challenges - Single-use challenges for WebAuthn ceremonies
export const passkeyChallenges = sqliteTable('cc_passkey_challenges', {
  challenge: text('challenge').primaryKey(), // Random challenge (base64url)
  userId: text('user_id'), // Null for registration, set for authentication
  type: text('type').notNull(), // 'register' or 'authenticate'
  expiresAt: text('expires_at').notNull(),
  consumedAt: text('consumed_at'), // Set when challenge is consumed (race condition protection)
  createdAt: text('created_at').notNull(),
}, (table) => ({
  expiresIdx: index('idx_passkey_challenges_expires').on(table.expiresAt),
}));

// OAuth States - PKCE state storage for OAuth flows
export const oauthStates = sqliteTable('cc_oauth_states', {
  state: text('state').primaryKey(), // Random state token
  provider: text('provider').notNull(), // 'github', 'google'
  codeVerifier: text('code_verifier').notNull(), // PKCE code verifier
  redirectUri: text('redirect_uri').notNull(),
  expiresAt: text('expires_at').notNull(),
  consumedAt: text('consumed_at'), // Set when state is consumed (race condition protection)
  createdAt: text('created_at').notNull(),
}, (table) => ({
  expiresIdx: index('idx_oauth_states_expires').on(table.expiresAt),
}));

// OAuth Connections - Link OAuth accounts to users
export const oauthConnections = sqliteTable('cc_oauth_connections', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull(),
  provider: text('provider').notNull(), // 'github', 'google'
  providerUserId: text('provider_user_id').notNull(), // External user ID
  providerEmail: text('provider_email'), // Email from OAuth provider
  accessToken: text('access_token'), // Encrypted access token (optional)
  refreshToken: text('refresh_token'), // Encrypted refresh token (optional)
  tokenExpiresAt: text('token_expires_at'),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at'),
}, (table) => ({
  userIdx: index('idx_oauth_user').on(table.userId),
  providerIdx: index('idx_oauth_provider').on(table.provider, table.providerUserId),
}));

// Magic Link Tokens - Single-use email authentication tokens
export const magicLinkTokens = sqliteTable('cc_magic_link_tokens', {
  token: text('token').primaryKey(), // Hashed token (SHA-256)
  email: text('email').notNull(), // Target email
  userId: text('user_id'), // Null for new users, set for existing
  expiresAt: text('expires_at').notNull(),
  usedAt: text('used_at'), // Set when token is consumed
  createdAt: text('created_at').notNull(),
}, (table) => ({
  emailIdx: index('idx_magic_link_email').on(table.email),
  expiresIdx: index('idx_magic_link_expires').on(table.expiresAt),
}));

// Cloudflare Access Tokens - Store CF Access JWT claims
export const cfAccessSessions = sqliteTable('cc_cf_access_sessions', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull(),
  cfIdentityId: text('cf_identity_id').notNull(), // Cloudflare identity ID
  cfEmail: text('cf_email').notNull(), // Email from CF Access
  cfGroups: text('cf_groups'), // JSON array of groups
  cfAud: text('cf_aud').notNull(), // Application AUD tag
  expiresAt: text('expires_at').notNull(),
  createdAt: text('created_at').notNull(),
}, (table) => ({
  userIdx: index('idx_cf_access_user').on(table.userId),
  cfIdIdx: index('idx_cf_access_identity').on(table.cfIdentityId),
}));
