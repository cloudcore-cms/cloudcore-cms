const API_BASE = '/api/v1';

export interface ApiError {
  error: string;
  details?: unknown;
}

async function request<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'X-CloudCore-Request': '1', // CSRF protection header
      ...options.headers,
    },
    credentials: 'include',
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({
      error: `Request failed with status ${response.status}`,
    }));

    // Handle Zod validation errors (from @hono/zod-validator)
    if (errorData.success === false && errorData.error?.issues) {
      const firstIssue = errorData.error.issues[0];
      throw new Error(firstIssue?.message || 'Validation failed');
    }

    // Handle standard error format
    const errorMessage = typeof errorData.error === 'string'
      ? errorData.error
      : 'Request failed';
    throw new Error(errorMessage);
  }

  return response.json();
}

// Auth
export const auth = {
  login: (email: string, password: string) =>
    request<{ user: User }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    }),

  logout: () =>
    request<{ success: boolean }>('/auth/logout', { method: 'POST' }),

  me: () => request<{ user: User }>('/auth/me'),

  setup: (email: string, password: string, name?: string) =>
    request<{ id: string }>('/auth/setup', {
      method: 'POST',
      body: JSON.stringify({ email, password, name }),
    }),

  status: () => request<{
    needsSetup: boolean;
    authMethods: {
      password: boolean;
      passkey: boolean;
      magicLink: boolean;
      github: boolean;
      google: boolean;
      cfAccess: boolean;
    };
    envAvailable: {
      password: boolean;
      passkey: boolean;
      magicLink: boolean;
      github: boolean;
      google: boolean;
      cfAccess: boolean;
    };
  }>('/auth/status'),
};

// Content
export interface ContentBlock {
  id: string;
  type: string;
  value: string;
  options?: Record<string, unknown>;
  mediaId?: string;
  mediaIds?: string[];
}

export interface ContentAuthor {
  id: string;
  name: string | null;
  email: string;
}

export interface Content {
  id: string;
  type: 'page' | 'post';
  title: string;
  slug: string;
  status: 'draft' | 'published';
  blocks: ContentBlock[];
  authorId: string | null;
  author?: ContentAuthor | null;
  lastEditor?: ContentAuthor | null;
  publishedAt: string | null;
  createdAt: string;
  updatedAt: string;
  categories?: { id: string; slug: string; name: string }[];
  tags?: { id: string; slug: string; name: string }[];
}

export interface ListResponse<T> {
  items: T[];
  pagination: {
    total: number;
    limit: number;
    offset: number;
    hasMore?: boolean;
  };
}

export const content = {
  list: (params?: {
    type?: 'page' | 'post';
    status?: 'draft' | 'published';
    limit?: number;
    offset?: number;
  }) => {
    const searchParams = new URLSearchParams();
    if (params?.type) searchParams.set('type', params.type);
    if (params?.status) searchParams.set('status', params.status);
    if (params?.limit) searchParams.set('limit', params.limit.toString());
    if (params?.offset) searchParams.set('offset', params.offset.toString());
    return request<ListResponse<Content>>(`/content?${searchParams}`);
  },

  get: (id: string) => request<Content>(`/content/${id}`),

  create: (data: {
    type: 'page' | 'post';
    title: string;
    slug: string;
    status?: 'draft' | 'published';
    blocks?: ContentBlock[];
    categoryIds?: string[];
    tagIds?: string[];
  }) =>
    request<{ id: string; slug: string }>('/content', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  update: (
    id: string,
    data: Partial<{
      title: string;
      slug: string;
      status: 'draft' | 'published';
      blocks: ContentBlock[];
      categoryIds: string[];
      tagIds: string[];
    }>
  ) =>
    request<{ success: boolean }>(`/content/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  delete: (id: string) =>
    request<{ success: boolean }>(`/content/${id}`, { method: 'DELETE' }),

  publish: (id: string) =>
    request<{ success: boolean }>(`/content/${id}/publish`, { method: 'POST' }),

  unpublish: (id: string) =>
    request<{ success: boolean }>(`/content/${id}/unpublish`, {
      method: 'POST',
    }),

  revisions: (id: string) =>
    request<{ items: Revision[] }>(`/content/${id}/revisions`),

  restoreRevision: (id: string, revisionId: string) =>
    request<{ success: boolean }>(`/content/${id}/revisions/${revisionId}/restore`, {
      method: 'POST',
    }),
};

export interface Revision {
  id: string;
  contentId: string;
  title: string;
  blocks: ContentBlock[];
  status: string | null;
  authorId: string | null;
  authorName: string | null;
  authorEmail: string | null;
  changeType: string | null;
  changeSummary: string | null;
  createdAt: string;
}

// Media
export interface MediaUploader {
  id: string;
  name: string | null;
  email: string;
}

export interface Media {
  id: string;
  filename: string;
  mimeType: string;
  size: number | null;
  width: number | null;
  height: number | null;
  alt: string | null;
  storageKey: string;
  url: string;
  uploadedBy?: MediaUploader | null;
  createdAt: string;
}

export const media = {
  list: (params?: { limit?: number; offset?: number; mimeType?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.set('limit', params.limit.toString());
    if (params?.offset) searchParams.set('offset', params.offset.toString());
    if (params?.mimeType) searchParams.set('mimeType', params.mimeType);
    return request<ListResponse<Media>>(`/media?${searchParams}`);
  },

  get: (id: string) => request<Media>(`/media/${id}`),

  upload: async (file: File) => {
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch(`${API_BASE}/media/upload`, {
      method: 'POST',
      body: formData,
      credentials: 'include',
    });

    if (!response.ok) {
      const error: ApiError = await response.json().catch(() => ({
        error: 'Upload failed',
      }));
      throw new Error(error.error);
    }

    return response.json() as Promise<Media>;
  },

  update: (id: string, data: { alt?: string; filename?: string }) =>
    request<{ success: boolean }>(`/media/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  delete: (id: string) =>
    request<{ success: boolean }>(`/media/${id}`, { method: 'DELETE' }),
};

// Categories
export interface Category {
  id: string;
  slug: string;
  name: string;
  parentId: string | null;
  createdAt: string;
  children?: Category[];
}

export const categories = {
  list: () => request<{ items: Category[] }>('/categories'),

  get: (id: string) => request<Category>(`/categories/${id}`),

  create: (data: { name: string; slug?: string; parentId?: string }) =>
    request<{ id: string; slug: string }>('/categories', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  update: (
    id: string,
    data: { name?: string; slug?: string; parentId?: string | null }
  ) =>
    request<{ success: boolean }>(`/categories/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  delete: (id: string) =>
    request<{ success: boolean }>(`/categories/${id}`, { method: 'DELETE' }),
};

// Tags
export interface Tag {
  id: string;
  slug: string;
  name: string;
  createdAt: string;
}

export const tags = {
  list: () => request<{ items: Tag[] }>('/tags'),

  get: (id: string) => request<Tag>(`/tags/${id}`),

  create: (data: { name: string; slug?: string }) =>
    request<{ id: string; slug: string }>('/tags', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  update: (id: string, data: { name?: string; slug?: string }) =>
    request<{ success: boolean }>(`/tags/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  delete: (id: string) =>
    request<{ success: boolean }>(`/tags/${id}`, { method: 'DELETE' }),
};

// Settings
export const settings = {
  getAll: () => request<Record<string, unknown>>('/settings'),

  get: (key: string) => request<{ key: string; value: unknown }>(`/settings/${key}`),

  set: (key: string, value: unknown) =>
    request<{ success: boolean }>(`/settings/${key}`, {
      method: 'PUT',
      body: JSON.stringify({ value }),
    }),
};

// Block types
export interface BlockType {
  type: string;
  label: string;
  input: string;
  options?: Record<string, unknown>;
  description?: string;
}

export const blocks = {
  list: () => request<{ items: BlockType[] }>('/blocks'),
};

// User
export interface User {
  id: string;
  email: string;
  name: string | null;
  role: 'admin' | 'editor' | 'contributor';
  avatar?: string | null;
  bio?: string | null;
  isActive?: boolean;
  lastLoginAt?: string | null;
  createdAt?: string;
  updatedAt?: string | null;
}

export const users = {
  list: () => request<{ items: User[] }>('/auth/users'),

  get: (id: string) => request<User>(`/auth/users/${id}`),

  create: (data: { email: string; password: string; name?: string; role?: 'admin' | 'editor' | 'contributor' }) =>
    request<{ id: string }>('/auth/users', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  update: (
    id: string,
    data: { name?: string; email?: string; role?: 'admin' | 'editor' | 'contributor'; isActive?: boolean; password?: string }
  ) =>
    request<{ success: boolean }>(`/auth/users/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  delete: (id: string) =>
    request<{ success: boolean }>(`/auth/users/${id}`, { method: 'DELETE' }),
};

// Audit Log
export interface AuditLogEntry {
  id: string;
  userId: string | null;
  userEmail: string | null;
  action: string;
  resourceType: string | null;
  resourceId: string | null;
  details: Record<string, unknown> | null;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: string;
}

export const audit = {
  list: (params?: { action?: string; userId?: string; resourceType?: string; limit?: number; offset?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.action) searchParams.set('action', params.action);
    if (params?.userId) searchParams.set('userId', params.userId);
    if (params?.resourceType) searchParams.set('resourceType', params.resourceType);
    if (params?.limit) searchParams.set('limit', params.limit.toString());
    if (params?.offset) searchParams.set('offset', params.offset.toString());
    return request<ListResponse<AuditLogEntry>>(`/audit?${searchParams}`);
  },

  logins: (params?: { userId?: string; limit?: number; offset?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.userId) searchParams.set('userId', params.userId);
    if (params?.limit) searchParams.set('limit', params.limit.toString());
    if (params?.offset) searchParams.set('offset', params.offset.toString());
    return request<ListResponse<AuditLogEntry>>(`/audit/logins?${searchParams}`);
  },

  userActivity: (userId: string, params?: { limit?: number; offset?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.set('limit', params.limit.toString());
    if (params?.offset) searchParams.set('offset', params.offset.toString());
    return request<ListResponse<AuditLogEntry>>(`/audit/user/${userId}?${searchParams}`);
  },
};

// Passkeys/WebAuthn
export interface PasskeyCredential {
  id: string;
  name: string;
  deviceType: 'platform' | 'cross-platform';
  backedUp: boolean;
  lastUsedAt: string | null;
  createdAt: string;
}

export interface PasskeyAuthOptions {
  challenge: string;
  rpId: string;
  timeout: number;
  userVerification: 'required' | 'preferred' | 'discouraged';
  allowCredentials?: { id: string; type: 'public-key' }[];
}

export interface PasskeyRegisterOptions {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: { type: 'public-key'; alg: number }[];
  authenticatorSelection: {
    residentKey: string;
    userVerification: string;
  };
  timeout: number;
  attestation: string;
  excludeCredentials: { id: string; type: 'public-key' }[];
}

export const passkeys = {
  // Check if user has passkeys registered (for login flow)
  checkForEmail: (email: string) =>
    request<{ hasPasskeys: boolean }>('/auth/passkeys/check', {
      method: 'POST',
      body: JSON.stringify({ email }),
    }),

  // Get authentication options (for login)
  getAuthOptions: (email?: string) =>
    request<PasskeyAuthOptions>('/auth/passkeys/authenticate/options', {
      method: 'POST',
      body: JSON.stringify(email ? { email } : {}),
    }),

  // Verify authentication (complete login)
  verifyAuth: (credential: {
    id: string;
    rawId: string;
    response: {
      clientDataJSON: string;
      authenticatorData: string;
      signature: string;
      userHandle?: string;
    };
    type: 'public-key';
  }) =>
    request<{ user: User }>('/auth/passkeys/authenticate/verify', {
      method: 'POST',
      body: JSON.stringify(credential),
    }),

  // Get registration options (requires auth)
  getRegisterOptions: () =>
    request<PasskeyRegisterOptions>('/auth/passkeys/register/options', {
      method: 'POST',
    }),

  // Verify registration (requires auth)
  verifyRegister: (credential: {
    id: string;
    rawId: string;
    response: {
      clientDataJSON: string;
      attestationObject: string;
    };
    type: 'public-key';
    name?: string;
  }) =>
    request<{ success: boolean; credential: { id: string; name: string } }>(
      '/auth/passkeys/register/verify',
      {
        method: 'POST',
        body: JSON.stringify(credential),
      }
    ),

  // List user's passkeys
  list: () => request<{ items: PasskeyCredential[] }>('/auth/passkeys'),

  // Update passkey name
  update: (id: string, data: { name: string }) =>
    request<{ success: boolean }>(`/auth/passkeys/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  // Delete passkey
  delete: (id: string) =>
    request<{ success: boolean }>(`/auth/passkeys/${id}`, { method: 'DELETE' }),
};

// OAuth
export interface OAuthProvider {
  name: string;
  enabled: boolean;
  authUrl?: string;
}

export const oauth = {
  // Get available OAuth providers
  providers: () => request<{ providers: OAuthProvider[] }>('/auth/oauth/providers'),

  // Start OAuth flow (returns redirect URL)
  authorize: (provider: 'github' | 'google') =>
    request<{ url: string }>(`/auth/oauth/${provider}/authorize`, {
      method: 'POST',
    }),

  // Handle OAuth callback (exchange code for session)
  callback: (provider: 'github' | 'google', code: string, state: string) =>
    request<{ user: User }>(`/auth/oauth/${provider}/callback`, {
      method: 'POST',
      body: JSON.stringify({ code, state }),
    }),

  // Link OAuth account to current user (returns redirect URL)
  link: (provider: 'github' | 'google') =>
    request<{ url: string }>(`/auth/oauth/link/${provider}/authorize`, {
      method: 'POST',
    }),
};

// Profile (self-service)
export interface OAuthConnection {
  id: string;
  provider: string;
  providerEmail: string | null;
  createdAt: string;
}

export const profile = {
  update: (data: { name?: string | null; email?: string; bio?: string | null; avatar?: string | null }) =>
    request<{ user: User }>('/auth/me', {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  changePassword: (currentPassword: string, newPassword: string) =>
    request<{ success: boolean }>('/auth/me/change-password', {
      method: 'POST',
      body: JSON.stringify({ currentPassword, newPassword }),
    }),

  getOAuthConnections: () =>
    request<{ items: OAuthConnection[] }>('/auth/me/oauth-connections'),

  unlinkOAuth: (id: string) =>
    request<{ success: boolean }>(`/auth/me/oauth-connections/${id}`, { method: 'DELETE' }),
};

// Magic Links
export const magicLinks = {
  // Request magic link (sends email)
  request: (email: string) =>
    request<{ success: boolean; message: string }>('/auth/magic-link', {
      method: 'POST',
      body: JSON.stringify({ email }),
    }),

  // Verify magic link token (from email URL)
  verify: (token: string) =>
    request<{ user: User }>('/auth/magic-link/verify', {
      method: 'POST',
      body: JSON.stringify({ token }),
    }),
};
