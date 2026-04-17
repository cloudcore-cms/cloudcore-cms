import { describe, it, expect } from 'vitest';
import app from '../index';

const env = { DB: {} as any, BUCKET: {} as any };

describe('HTTP Method Security', () => {
  describe('Write operations require auth', () => {
    const writeEndpoints = [
      { method: 'POST', path: '/api/v1/content' },
      { method: 'POST', path: '/api/v1/categories' },
      { method: 'POST', path: '/api/v1/tags' },
    ];

    for (const { method, path } of writeEndpoints) {
      it(`${method} ${path} requires auth`, async () => {
        const res = await app.request(path, {
          method,
          headers: {
            'Content-Type': 'application/json',
            'X-CloudCore-Request': '1',
          },
          body: JSON.stringify({}),
        }, env);
        expect(res.status).not.toBe(200);
        expect(res.status).not.toBe(201);
      });
    }
  });

  describe('Admin-only endpoints', () => {
    const adminEndpoints = [
      '/api/v1/auth/users',
      '/api/v1/audit',
    ];

    for (const path of adminEndpoints) {
      it(`GET ${path} requires auth`, async () => {
        const res = await app.request(path, {}, env);
        expect(res.status).toBe(401);
      });
    }
  });
});
