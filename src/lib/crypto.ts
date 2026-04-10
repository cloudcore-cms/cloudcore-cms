/**
 * Password hashing using PBKDF2-SHA512
 * Cloudflare Workers compatible using Web Crypto API
 *
 * Security standards met (OWASP 2023):
 * - PBKDF2-SHA512 with 210,000 iterations (OWASP minimum)
 * - 256-bit cryptographically random salt
 * - 512-bit derived key
 * - Constant-time comparison to prevent timing attacks
 * - Pepper support for defense in depth
 *
 * Note: Argon2id would be preferred but isn't available in Web Crypto API.
 * PBKDF2-SHA512 at 210k iterations provides equivalent security per OWASP.
 */

// OWASP 2023 recommendations for PBKDF2
const ITERATIONS = 210000; // OWASP minimum for SHA-512
const KEY_LENGTH = 64; // 512 bits
const SALT_LENGTH = 32; // 256 bits
const HASH_ALGORITHM = 'SHA-512';

// Version identifier for future algorithm upgrades
const HASH_VERSION = 'v2';

// Generate a cryptographically secure random salt
function generateSalt(): Uint8Array {
  const salt = new Uint8Array(SALT_LENGTH);
  crypto.getRandomValues(salt);
  return salt;
}

// Convert ArrayBuffer or Uint8Array to hex string
function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Convert hex string to Uint8Array
function hexToBuffer(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Constant-time string comparison to prevent timing attacks
 * Uses XOR to compare all characters regardless of early mismatches
 */
export function timingSafeEqual(a: string, b: string): boolean {
  // Pad shorter string to prevent length-based timing leaks
  const maxLen = Math.max(a.length, b.length);
  const aPadded = a.padEnd(maxLen, '\0');
  const bPadded = b.padEnd(maxLen, '\0');

  let result = a.length ^ b.length; // Length difference check
  for (let i = 0; i < maxLen; i++) {
    result |= aPadded.charCodeAt(i) ^ bPadded.charCodeAt(i);
  }
  return result === 0;
}

/**
 * Hash a password using PBKDF2-SHA512
 * Returns format: version$algorithm$iterations$salt$hash (all hex encoded)
 */
export async function hashPassword(password: string, pepper?: string): Promise<string> {
  const salt = generateSalt();
  const encoder = new TextEncoder();

  // Combine password with pepper if provided (defense in depth)
  const passwordWithPepper = pepper ? password + pepper : password;
  const passwordData = encoder.encode(passwordWithPepper);

  // Import password as key material
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordData,
    'PBKDF2',
    false,
    ['deriveBits']
  );

  // Derive key using PBKDF2-SHA512
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations: ITERATIONS,
      hash: HASH_ALGORITHM,
    },
    keyMaterial,
    KEY_LENGTH * 8 // bits
  );

  const saltHex = bufferToHex(salt);
  const hashHex = bufferToHex(derivedBits);

  // Version 2 format includes algorithm identifier for future upgrades
  return `${HASH_VERSION}$sha512$${ITERATIONS}$${saltHex}$${hashHex}`;
}

/**
 * Verify a password against a stored hash
 * Supports multiple formats for backward compatibility:
 * - v2: version$algorithm$iterations$salt$hash (current)
 * - v1: iterations$salt$hash (PBKDF2-SHA256)
 * - legacy: plain SHA-256 hash
 */
export async function verifyPassword(
  password: string,
  storedHash: string,
  pepper?: string
): Promise<boolean> {
  const encoder = new TextEncoder();
  const passwordWithPepper = pepper ? password + pepper : password;

  // V2 format: v2$sha512$iterations$salt$hash
  if (storedHash.startsWith('v2$')) {
    const parts = storedHash.split('$');
    if (parts.length !== 5) return false;

    const [, algorithm, iterationsStr, saltHex, hashHex] = parts;
    const iterations = parseInt(iterationsStr, 10);
    const salt = hexToBuffer(saltHex);

    // Determine hash algorithm and key length
    const hashAlgo = algorithm === 'sha512' ? 'SHA-512' : 'SHA-256';
    const keyLen = algorithm === 'sha512' ? 64 : 32;

    const passwordData = encoder.encode(passwordWithPepper);

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passwordData,
      'PBKDF2',
      false,
      ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations,
        hash: hashAlgo,
      },
      keyMaterial,
      keyLen * 8
    );

    const computedHash = bufferToHex(derivedBits);
    return timingSafeEqual(computedHash, hashHex);
  }

  // V1 format: iterations$salt$hash (PBKDF2-SHA256)
  if (storedHash.includes('$') && !storedHash.startsWith('v')) {
    const parts = storedHash.split('$');
    if (parts.length !== 3) return false;

    const [iterationsStr, saltHex, hashHex] = parts;
    const iterations = parseInt(iterationsStr, 10);
    const salt = hexToBuffer(saltHex);

    const passwordData = encoder.encode(passwordWithPepper);

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passwordData,
      'PBKDF2',
      false,
      ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations,
        hash: 'SHA-256',
      },
      keyMaterial,
      32 * 8 // 256 bits
    );

    const computedHash = bufferToHex(derivedBits);
    return timingSafeEqual(computedHash, hashHex);
  }

  // Legacy plain SHA-256 format (for backwards compatibility during migration)
  const data = encoder.encode(password); // No pepper for legacy
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const legacyHash = bufferToHex(hashBuffer);
  return timingSafeEqual(legacyHash, storedHash);
}

/**
 * Check if a password hash needs upgrading to current algorithm
 */
export function needsRehash(storedHash: string): boolean {
  // Current format starts with v2$sha512$210000
  return !storedHash.startsWith(`${HASH_VERSION}$sha512$${ITERATIONS}`);
}

/**
 * Generate a secure random token (for sessions, CSRF, etc.)
 * Uses 256 bits of entropy by default
 */
export function generateSecureToken(bytes: number = 32): string {
  const buffer = new Uint8Array(bytes);
  crypto.getRandomValues(buffer);
  return bufferToHex(buffer);
}

/**
 * Generate a CSRF token with embedded timestamp for expiry validation
 * Format: timestamp.random (base64url encoded)
 */
export function generateCsrfToken(ttlSeconds: number = 3600): string {
  const timestamp = Math.floor(Date.now() / 1000) + ttlSeconds;
  const random = generateSecureToken(24);
  const data = `${timestamp}.${random}`;
  return btoa(data).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Validate a CSRF token (check format and expiry)
 */
export function validateCsrfToken(token: string): boolean {
  try {
    // Decode from base64url
    const decoded = atob(token.replace(/-/g, '+').replace(/_/g, '/'));
    const [timestampStr] = decoded.split('.');
    const expiry = parseInt(timestampStr, 10);
    const now = Math.floor(Date.now() / 1000);
    return expiry > now;
  } catch {
    return false;
  }
}

/**
 * Hash a token for storage/comparison (using SHA-256)
 */
export async function hashToken(token: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(token);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return bufferToHex(hashBuffer);
}

/**
 * Generate a secure API key
 * Format: prefix_randomhex (e.g., cc_sk_abc123...)
 */
export function generateApiKey(prefix: string = 'cc_sk'): string {
  const random = generateSecureToken(32);
  return `${prefix}_${random}`;
}

/**
 * Timing-safe delay to prevent user enumeration attacks
 * Adds random jitter (100-250ms) to normalize response times
 */
export async function timingSafeDelay(): Promise<void> {
  const delay = 100 + Math.random() * 150; // 100-250ms jitter
  await new Promise((resolve) => setTimeout(resolve, delay));
}

/**
 * Constant-time byte array comparison
 * Uses XOR to compare all bytes regardless of early mismatches
 */
export function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i]! ^ b[i]!;
  }
  return result === 0;
}

/**
 * Hash a session token for storage
 * Uses SHA-256 to prevent session hijacking from DB breach
 */
export async function hashSessionToken(token: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(token);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return bufferToHex(hashBuffer);
}

/**
 * Generate base64url-encoded random bytes (URL-safe)
 */
export function generateBase64UrlToken(bytes: number = 32): string {
  const buffer = new Uint8Array(bytes);
  crypto.getRandomValues(buffer);
  // Convert to base64url
  const base64 = btoa(String.fromCharCode(...buffer));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Decode base64url to Uint8Array
 */
export function decodeBase64Url(str: string): Uint8Array {
  // Add padding if needed
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4);
  // Convert base64url to base64
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encode Uint8Array to base64url
 */
export function encodeBase64Url(bytes: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
