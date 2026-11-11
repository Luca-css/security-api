import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN, bearer, buildTestApp, login } from '../helpers.js';

describe('auth flow', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildTestApp();
  });
  afterAll(async () => {
    await app.close();
  });

  it('logs in the seeded admin and returns a bearer token', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: ADMIN,
    });
    expect(response.statusCode).toBe(200);
    const body = response.json<{ accessToken: string; tokenType: string; expiresIn: string }>();
    expect(body.tokenType).toBe('Bearer');
    expect(body.expiresIn).toBe('15m');
    expect(body.accessToken.split('.')).toHaveLength(3);
  });

  it('returns the current user without the password hash', async () => {
    const token = await login(app, ADMIN);
    const response = await app.inject({
      method: 'GET',
      url: '/api/v1/auth/me',
      headers: bearer(token),
    });
    expect(response.statusCode).toBe(200);
    const body = response.json<Record<string, unknown>>();
    expect(body).toMatchObject({ username: 'admin', role: 'admin' });
    expect(body).not.toHaveProperty('passwordHash');
  });

  it('uses the same 401 for wrong password and unknown user', async () => {
    const wrongPassword = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { username: 'admin', password: 'nope' },
    });
    const unknownUser = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { username: 'ghost', password: 'nope' },
    });
    for (const response of [wrongPassword, unknownUser]) {
      expect(response.statusCode).toBe(401);
      expect(response.json()).toMatchObject({ code: 'INVALID_CREDENTIALS' });
    }
  });

  it('rejects requests without a token', async () => {
    const response = await app.inject({ method: 'GET', url: '/api/v1/threats' });
    expect(response.statusCode).toBe(401);
    expect(response.json()).toMatchObject({ statusCode: 401, code: 'INVALID_TOKEN' });
  });

  it('rejects tampered and foreign-signed tokens', async () => {
    const token = await login(app, ADMIN);
    const tampered = token.slice(0, -2) + (token.endsWith('AA') ? 'BB' : 'AA');
    // Token signed by another deployment (different secret).
    const other = await buildTestApp({ JWT_SECRET: 'another-secret-another-secret-123456' });
    const forged = await login(other, ADMIN);
    await other.close();
    for (const bad of [tampered, forged]) {
      const response = await app.inject({
        method: 'GET',
        url: '/api/v1/threats',
        headers: bearer(bad),
      });
      expect(response.statusCode).toBe(401);
    }
  });

  it('rejects unsigned "alg: none" tokens', async () => {
    const encode = (obj: object) => Buffer.from(JSON.stringify(obj)).toString('base64url');
    const unsigned = `${encode({ alg: 'none', typ: 'JWT' })}.${encode({ sub: 'x', username: 'admin', role: 'admin' })}.`;
    const response = await app.inject({
      method: 'GET',
      url: '/api/v1/threats',
      headers: bearer(unsigned),
    });
    expect(response.statusCode).toBe(401);
  });

  it('rejects duplicate usernames with 409', async () => {
    const token = await login(app, ADMIN);
    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/users',
      headers: bearer(token),
      payload: { username: 'admin', password: 'another-long-password', role: 'admin' },
    });
    expect(response.statusCode).toBe(409);
  });
});

describe('login rate limit', () => {
  it('returns 429 after LOGIN_RATE_LIMIT_MAX attempts per minute', async () => {
    const app = await buildTestApp({ LOGIN_RATE_LIMIT_MAX: '3' });
    const attempt = () =>
      app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { username: 'admin', password: 'wrong' },
      });

    for (let i = 0; i < 3; i++) {
      expect((await attempt()).statusCode).toBe(401);
    }
    const limited = await attempt();
    expect(limited.statusCode).toBe(429);
    expect(limited.json()).toMatchObject({ statusCode: 429, code: 'RATE_LIMITED' });
    expect(limited.headers['retry-after']).toBeDefined();
    await app.close();
  });
});
