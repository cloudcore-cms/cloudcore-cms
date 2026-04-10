import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { eq, like } from 'drizzle-orm';
import type { Env, Variables } from '../types';
import { createDb, schema } from '../db';
import { authMiddleware, adminMiddleware } from '../middleware/auth';
import { updateSettingSchema } from '../lib/validation';
import { parseJson } from '../lib/utils';
import { auditLog } from '../lib/audit';

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// SECURITY: Whitelist of allowed settings keys
// This prevents arbitrary key creation/overwrites
const ALLOWED_SETTINGS_KEYS = [
  'siteName',
  'siteDescription',
  'siteUrl',
  'postsPerPage',
  'dateFormat',
  'timeFormat',
  'timezone',
  'language',
  'theme',
  'logo',
  'favicon',
  'socialLinks',
  'analytics',
  'seo',
  // Auth method toggles (admin-configurable)
  'auth.password',
  'auth.passkey',
  'auth.magicLink',
  'auth.github',
  'auth.google',
  'auth.cfAccess',
] as const;

// Auth setting keys for safety validation
const AUTH_SETTING_KEYS = [
  'auth.password',
  'auth.passkey',
  'auth.magicLink',
  'auth.github',
  'auth.google',
  'auth.cfAccess',
] as const;

// Maximum settings key length to prevent DoS
const MAX_KEY_LENGTH = 50;

// Validate settings key
function isValidSettingsKey(key: string): boolean {
  if (!key || key.length > MAX_KEY_LENGTH) return false;
  // Only allow alphanumeric, dots (for namespacing), underscores, and hyphens
  if (!/^[a-zA-Z][a-zA-Z0-9_.-]*$/.test(key)) return false;
  return true;
}

// Default settings
const DEFAULT_SETTINGS: Record<string, unknown> = {
  siteName: 'Cloudcore CMS',
  siteDescription: '',
  siteUrl: '',
  postsPerPage: 10,
  dateFormat: 'YYYY-MM-DD',
  timeFormat: 'HH:mm',
};

// Get all settings
app.get('/', authMiddleware, async (c) => {
  const db = createDb(c.env.DB);

  const settings = await db.select().from(schema.settings);

  const result: Record<string, unknown> = { ...DEFAULT_SETTINGS };
  for (const setting of settings) {
    result[setting.key] = parseJson(setting.value, setting.value);
  }

  return c.json(result);
});

// Get single setting (requires auth to prevent enumeration)
app.get('/:key', authMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const key = c.req.param('key');

  const setting = await db
    .select()
    .from(schema.settings)
    .where(eq(schema.settings.key, key))
    .get();

  if (!setting) {
    if (key in DEFAULT_SETTINGS) {
      return c.json({ key, value: DEFAULT_SETTINGS[key] });
    }
    return c.json({ error: 'Setting not found' }, 404);
  }

  return c.json({
    key: setting.key,
    value: parseJson(setting.value, setting.value),
  });
});

// Update setting (admin only)
app.put('/:key', authMiddleware, adminMiddleware, zValidator('json', updateSettingSchema), async (c) => {
  const db = createDb(c.env.DB);
  const key = c.req.param('key');
  const body = c.req.valid('json');

  // SECURITY: Validate settings key format and length
  if (!isValidSettingsKey(key)) {
    return c.json({ error: 'Invalid settings key format' }, 400);
  }

  // SECURITY: Enforce whitelist - only allow known settings keys
  if (!ALLOWED_SETTINGS_KEYS.includes(key as typeof ALLOWED_SETTINGS_KEYS[number])) {
    return c.json({ error: 'Unknown settings key' }, 400);
  }

  // SECURITY: Limit settings value size to prevent storage/memory DoS
  const serialized = JSON.stringify(body.value);
  const MAX_SETTINGS_VALUE_SIZE = 100_000; // 100KB
  if (serialized.length > MAX_SETTINGS_VALUE_SIZE) {
    return c.json({ error: `Settings value too large (max ${MAX_SETTINGS_VALUE_SIZE} bytes)` }, 400);
  }

  const value = serialized;

  // SECURITY: Safety check for auth settings — can't disable all auth methods
  if (AUTH_SETTING_KEYS.includes(key as typeof AUTH_SETTING_KEYS[number]) && body.value === false) {
    // Load all current auth settings from DB
    const authSettings = await db
      .select()
      .from(schema.settings)
      .where(like(schema.settings.key, 'auth.%'));

    const currentToggles: Record<string, boolean> = {};
    for (const s of authSettings) {
      currentToggles[s.key] = parseJson(s.value, true) as boolean;
    }

    // Simulate the change
    currentToggles[key] = false;

    // Check env var availability for each method
    const envAvailable: Record<string, boolean> = {
      'auth.password': true,
      'auth.passkey': true,
      'auth.magicLink': !!(c.env.SMTP_HOST || c.env.SENDGRID_API_KEY || c.env.RESEND_API_KEY || c.env.MAILGUN_API_KEY),
      'auth.github': !!(c.env.GITHUB_CLIENT_ID && c.env.GITHUB_CLIENT_SECRET),
      'auth.google': !!(c.env.GOOGLE_CLIENT_ID && c.env.GOOGLE_CLIENT_SECRET),
      'auth.cfAccess': c.env.CF_ACCESS_ENABLED === 'true',
    };

    // Count how many methods would remain enabled (both env available AND toggled on)
    const enabledCount = AUTH_SETTING_KEYS.filter(
      (k) => envAvailable[k] && (currentToggles[k] ?? true)
    ).length;

    if (enabledCount === 0) {
      return c.json({ error: 'Cannot disable all authentication methods. At least one must remain enabled.' }, 400);
    }
  }

  // Upsert setting
  const existing = await db
    .select()
    .from(schema.settings)
    .where(eq(schema.settings.key, key))
    .get();

  if (existing) {
    await db
      .update(schema.settings)
      .set({ value })
      .where(eq(schema.settings.key, key));
  } else {
    await db.insert(schema.settings).values({ key, value });
  }

  // Audit log the settings change
  await auditLog(c, existing ? 'update' : 'create', 'settings', key, {
    key,
    newValue: body.value,
    previousValue: existing ? parseJson(existing.value, existing.value) : null,
  });

  return c.json({ success: true });
});

// Delete setting (admin only)
app.delete('/:key', authMiddleware, adminMiddleware, async (c) => {
  const db = createDb(c.env.DB);
  const key = c.req.param('key');

  // Get the current value before deletion for audit log
  const existing = await db
    .select()
    .from(schema.settings)
    .where(eq(schema.settings.key, key))
    .get();

  await db.delete(schema.settings).where(eq(schema.settings.key, key));

  // Audit log the deletion
  await auditLog(c, 'delete', 'settings', key, {
    key,
    deletedValue: existing ? parseJson(existing.value, existing.value) : null,
  });

  return c.json({ success: true });
});

export default app;
