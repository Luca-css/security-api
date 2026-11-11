import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildTestApp } from '../helpers.js';

describe('system endpoints', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildTestApp();
  });
  afterAll(async () => {
    await app.close();
  });

  it('GET /health returns ok and security headers', async () => {
    const response = await app.inject({ method: 'GET', url: '/health' });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ status: 'ok' });
    expect(response.headers['x-content-type-options']).toBe('nosniff');
    expect(response.headers['x-request-id']).toBeDefined();
  });

  it('serves the OpenAPI document with all modules and the bearer scheme', async () => {
    const response = await app.inject({ method: 'GET', url: '/docs/json' });
    expect(response.statusCode).toBe(200);
    const spec = response.json<{
      openapi: string;
      paths: Record<string, unknown>;
      components: { securitySchemes: Record<string, unknown> };
    }>();
    expect(spec.openapi).toMatch(/^3\./);
    expect(Object.keys(spec.paths)).toEqual(
      expect.arrayContaining([
        '/api/v1/auth/login',
        '/api/v1/threats/',
        '/api/v1/alerts/',
        '/api/v1/blocklist/',
        '/api/v1/blocklist/check',
      ]),
    );
    expect(spec.components.securitySchemes).toHaveProperty('bearerAuth');
  });

  it('applies the global per-IP rate limit', async () => {
    const limited = await buildTestApp({ RATE_LIMIT_MAX: '2' });
    const call = () =>
      limited.inject({ method: 'GET', url: '/api/v1/threats', remoteAddress: '192.0.2.50' });
    expect((await call()).statusCode).toBe(401);
    expect((await call()).statusCode).toBe(401);
    expect((await call()).statusCode).toBe(429);
    // Another client is not affected.
    const other = await limited.inject({
      method: 'GET',
      url: '/api/v1/threats',
      remoteAddress: '192.0.2.51',
    });
    expect(other.statusCode).toBe(401);
    await limited.close();
  });
});
