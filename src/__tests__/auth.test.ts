import { describe, it, expect } from 'vitest';
import app from '../index';

const env = { DB: {} as any, BUCKET: {} as any };

describe('Auth', () => {
  describe('Protected endpoints', () => {
    it('GET /api/v1/content requires auth', async () => {
      const res = await app.request('/api/v1/content', {}, env);
      expect(res.status).toBe(401);
    });

    it('GET /api/v1/auth/me requires auth', async () => {
      const res = await app.request('/api/v1/auth/me', {}, env);
      expect(res.status).toBe(401);
    });

    it('GET /api/v1/settings requires auth', async () => {
      const res = await app.request('/api/v1/settings', {}, env);
      expect(res.status).toBe(401);
    });

    it('GET /api/v1/media requires auth', async () => {
      const res = await app.request('/api/v1/media', {}, env);
      expect(res.status).toBe(401);
    });

    it('GET /api/v1/audit requires auth', async () => {
      const res = await app.request('/api/v1/audit', {}, env);
      expect(res.status).toBe(401);
    });
  });

  describe('CSRF protection', () => {
    it('POST without X-CloudCore-Request header is blocked', async () => {
      const res = await app.request('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@test.com', password: 'test' }),
      }, env);
      expect(res.status).toBe(403);
    });
  });
});
