import { describe, it, expect } from 'vitest';
import app from '../index';

const env = { DB: {} as any, BUCKET: {} as any };

describe('Security Headers', () => {
  it('sets HSTS header', async () => {
    const res = await app.request('/health', {}, env);
    expect(res.headers.get('Strict-Transport-Security')).toContain('max-age=31536000');
  });

  it('sets X-Frame-Options DENY', async () => {
    const res = await app.request('/health', {}, env);
    expect(res.headers.get('X-Frame-Options')).toBe('DENY');
  });

  it('sets X-Content-Type-Options nosniff', async () => {
    const res = await app.request('/health', {}, env);
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
  });

  it('sets Content-Security-Policy', async () => {
    const res = await app.request('/health', {}, env);
    const csp = res.headers.get('Content-Security-Policy');
    expect(csp).toContain("default-src 'self'");
  });

  it('sets Referrer-Policy', async () => {
    const res = await app.request('/health', {}, env);
    expect(res.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
  });

  it('sets Permissions-Policy', async () => {
    const res = await app.request('/health', {}, env);
    const pp = res.headers.get('Permissions-Policy');
    expect(pp).toContain('camera=()');
    expect(pp).toContain('microphone=()');
  });
});
