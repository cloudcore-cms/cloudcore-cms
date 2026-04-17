import { describe, it, expect } from 'vitest';
import app from '../index';

const env = { DB: {} as any, BUCKET: {} as any };

describe('Public API', () => {
  describe('GET /api/v1/public/content/:type/:slug', () => {
    it('rejects invalid content type', async () => {
      const res = await app.request('/api/v1/public/content/invalid/test', {}, env);
      expect(res.status).toBe(400);
    });
  });
});
