-- Cloudcore CMS Initial Schema
-- Version: 1.0.0
-- This is the complete initial schema for v1.0
-- Future migrations will be created by developers after this release

-- Content (Pages and Posts)
CREATE TABLE IF NOT EXISTS cc_content (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    slug TEXT NOT NULL,
    status TEXT DEFAULT 'draft' NOT NULL,
    blocks TEXT NOT NULL,
    author_id TEXT,
    published_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_edited_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_content_type ON cc_content(type);
CREATE INDEX IF NOT EXISTS idx_content_status ON cc_content(status);
CREATE INDEX IF NOT EXISTS idx_content_slug ON cc_content(slug);
CREATE INDEX IF NOT EXISTS idx_content_author ON cc_content(author_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_content_type_slug ON cc_content(type, slug);

-- Revisions (Version History)
CREATE TABLE IF NOT EXISTS cc_revisions (
    id TEXT PRIMARY KEY,
    content_id TEXT NOT NULL,
    title TEXT NOT NULL,
    blocks TEXT NOT NULL,
    status TEXT,
    author_id TEXT,
    author_name TEXT,
    author_email TEXT,
    change_type TEXT,
    change_summary TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (content_id) REFERENCES cc_content(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_revisions_content ON cc_revisions(content_id);
CREATE INDEX IF NOT EXISTS idx_revisions_author ON cc_revisions(author_id);
CREATE INDEX IF NOT EXISTS idx_revisions_created ON cc_revisions(created_at);

-- Media Library
CREATE TABLE IF NOT EXISTS cc_media (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size INTEGER,
    width INTEGER,
    height INTEGER,
    alt TEXT,
    storage_key TEXT NOT NULL,
    uploaded_by TEXT,
    created_at TEXT NOT NULL
);

-- Categories (Posts only)
CREATE TABLE IF NOT EXISTS cc_categories (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    parent_id TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (parent_id) REFERENCES cc_categories(id) ON DELETE SET NULL
);

-- Tags (Posts only)
CREATE TABLE IF NOT EXISTS cc_tags (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Content-Category mapping
CREATE TABLE IF NOT EXISTS cc_content_categories (
    content_id TEXT NOT NULL,
    category_id TEXT NOT NULL,
    PRIMARY KEY (content_id, category_id),
    FOREIGN KEY (content_id) REFERENCES cc_content(id) ON DELETE CASCADE,
    FOREIGN KEY (category_id) REFERENCES cc_categories(id) ON DELETE CASCADE
);

-- Content-Tag mapping
CREATE TABLE IF NOT EXISTS cc_content_tags (
    content_id TEXT NOT NULL,
    tag_id TEXT NOT NULL,
    PRIMARY KEY (content_id, tag_id),
    FOREIGN KEY (content_id) REFERENCES cc_content(id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id) REFERENCES cc_tags(id) ON DELETE CASCADE
);

-- Users
CREATE TABLE IF NOT EXISTS cc_users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT,
    name TEXT,
    role TEXT DEFAULT 'contributor' NOT NULL,
    avatar TEXT,
    bio TEXT,
    is_active INTEGER DEFAULT 1 NOT NULL,
    last_login_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_users_email ON cc_users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON cc_users(role);

-- Sessions (stores SHA-256 hash of session token, not raw token)
CREATE TABLE IF NOT EXISTS cc_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    user_agent TEXT,
    ip_address TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES cc_users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON cc_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON cc_sessions(expires_at);

-- Settings (Key-value store)
CREATE TABLE IF NOT EXISTS cc_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Audit Log - Track all important actions
CREATE TABLE IF NOT EXISTS cc_audit_log (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    user_email TEXT,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    details TEXT,
    ip_address TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_user ON cc_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON cc_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON cc_audit_log(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON cc_audit_log(created_at);

-- Login Attempts - For brute force tracking
CREATE TABLE IF NOT EXISTS cc_login_attempts (
    id TEXT PRIMARY KEY,
    identifier TEXT NOT NULL,
    success INTEGER NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_login_identifier ON cc_login_attempts(identifier);
CREATE INDEX IF NOT EXISTS idx_login_created ON cc_login_attempts(created_at);

-- Rate Limits - Database-backed rate limiting (persisted across restarts)
CREATE TABLE IF NOT EXISTS cc_rate_limits (
    key TEXT NOT NULL,
    window TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (key, window)
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_key ON cc_rate_limits(key);
CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON cc_rate_limits(window);

-- Passkey Credentials - WebAuthn/FIDO2 authentication
CREATE TABLE IF NOT EXISTS cc_passkey_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    device_type TEXT,
    backed_up INTEGER DEFAULT 0,
    transports TEXT,
    name TEXT,
    last_used_at TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES cc_users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_passkey_user ON cc_passkey_credentials(user_id);

-- Passkey Challenges - Single-use challenges for WebAuthn ceremonies
CREATE TABLE IF NOT EXISTS cc_passkey_challenges (
    challenge TEXT PRIMARY KEY,
    user_id TEXT,
    type TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_passkey_challenges_expires ON cc_passkey_challenges(expires_at);

-- OAuth States for PKCE flow
CREATE TABLE IF NOT EXISTS cc_oauth_states (
  state TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  code_verifier TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oauth_states_expires ON cc_oauth_states(expires_at);

-- OAuth Connections (link OAuth accounts to users)
CREATE TABLE IF NOT EXISTS cc_oauth_connections (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  provider_user_id TEXT NOT NULL,
  provider_email TEXT,
  access_token TEXT,
  refresh_token TEXT,
  token_expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT,
  FOREIGN KEY (user_id) REFERENCES cc_users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_oauth_user ON cc_oauth_connections(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_provider ON cc_oauth_connections(provider, provider_user_id);

-- Magic Link Tokens
CREATE TABLE IF NOT EXISTS cc_magic_link_tokens (
  token TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  user_id TEXT,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_magic_link_email ON cc_magic_link_tokens(email);
CREATE INDEX IF NOT EXISTS idx_magic_link_expires ON cc_magic_link_tokens(expires_at);

-- Cloudflare Access Sessions
CREATE TABLE IF NOT EXISTS cc_cf_access_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  cf_identity_id TEXT NOT NULL,
  cf_email TEXT NOT NULL,
  cf_groups TEXT,
  cf_aud TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES cc_users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_cf_access_user ON cc_cf_access_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_cf_access_identity ON cc_cf_access_sessions(cf_identity_id);
