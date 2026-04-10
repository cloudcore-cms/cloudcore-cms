// ULID implementation using Web Crypto API (Cloudflare Workers compatible)
const ENCODING = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const ENCODING_LEN = ENCODING.length;

function encodeTime(now: number, len: number): string {
  let str = '';
  for (let i = len; i > 0; i--) {
    const mod = now % ENCODING_LEN;
    str = ENCODING[mod] + str;
    now = (now - mod) / ENCODING_LEN;
  }
  return str;
}

function encodeRandom(len: number): string {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  let str = '';
  for (let i = 0; i < len; i++) {
    str += ENCODING[bytes[i] % ENCODING_LEN];
  }
  return str;
}

// Generate ULID for IDs (sortable, unique)
export function generateId(): string {
  const time = encodeTime(Date.now(), 10);
  const random = encodeRandom(16);
  return time + random;
}

// Get current ISO timestamp
export function now(): string {
  return new Date().toISOString();
}

// Generate slug from title
export function slugify(text: string): string {
  return text
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '') // Remove non-word chars
    .replace(/[\s_-]+/g, '-') // Replace spaces/underscores with hyphens
    .replace(/^-+|-+$/g, ''); // Remove leading/trailing hyphens
}

// Parse JSON safely
export function parseJson<T>(json: string, fallback: T): T {
  try {
    return JSON.parse(json) as T;
  } catch {
    return fallback;
  }
}

// NOTE: Password hashing and verification functions are in crypto.ts
// Use hashPassword and verifyPassword from crypto.ts for secure PBKDF2-SHA512 hashing
