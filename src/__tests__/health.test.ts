import { describe, it, expect } from 'vitest';
import app from '../index';

const env = { DB: {} as any, BUCKET: {} as any };

describe('Health & Info', () => {
  it('GET /health returns ok', async () => {
    const res = await app.request('/health', {}, env);
    expect(res.status).toBe(200);
    const body = await res.json() as { status: string };
    expect(body.status).toBe('ok');
  });

  it('GET /api/v1 returns API info', async () => {
    const res = await app.request('/api/v1', {}, env);
    expect(res.status).toBe(200);
    const body = await res.json() as { name: string };
    expect(body.name).toBe('Cloudcore CMS');
  });

  it('404 for unknown routes', async () => {
    const res = await app.request('/nonexistent', {}, env);
    expect(res.status).toBe(404);
  });
});
