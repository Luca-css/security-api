import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { bearer, buildTestApp, login, ADMIN } from '../helpers.js';

interface ValidationBody {
  statusCode: number;
  code: string;
  details: { location: string; issues: { path: string; message: string }[] };
}

describe('request validation', () => {
  let app: FastifyInstance;
  let token: string;

  beforeAll(async () => {
    app = await buildTestApp();
    token = await login(app, ADMIN);
  });
  afterAll(async () => {
    await app.close();
  });

  it('returns 400 with field-level issues for an invalid body', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/threats',
      headers: bearer(token),
      payload: { sourceIp: '999.1.1.1', type: '', severity: 'apocalyptic' },
    });
    expect(response.statusCode).toBe(400);
    const body = response.json<ValidationBody>();
    expect(body.code).toBe('VALIDATION_ERROR');
    expect(body.details.location).toBe('body');
    const paths = body.details.issues.map((i) => i.path);
    expect(paths).toEqual(expect.arrayContaining(['sourceIp', 'type', 'severity', 'description']));
  });

  it('returns 400 for an invalid query string', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/api/v1/alerts?limit=1000&resolved=maybe',
      headers: bearer(token),
    });
    expect(response.statusCode).toBe(400);
    const body = response.json<ValidationBody>();
    expect(body.details.location).toBe('querystring');
    expect(body.details.issues.map((i) => i.path)).toEqual(
      expect.arrayContaining(['limit', 'resolved']),
    );
  });

  it('returns 400 for a non-UUID path id', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/api/v1/threats/not-a-uuid',
      headers: bearer(token),
    });
    expect(response.statusCode).toBe(400);
    expect(response.json<ValidationBody>().details.location).toBe('params');
  });

  it('returns 400 for an invalid CIDR', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/blocklist',
      headers: bearer(token),
      payload: { cidr: '10.0.0.0/40', reason: 'bad prefix' },
    });
    expect(response.statusCode).toBe(400);
    expect(response.json<ValidationBody>().details.issues[0]?.path).toBe('cidr');
  });

  it('returns 400 for malformed JSON', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      headers: { 'content-type': 'application/json' },
      payload: '{"username": ',
    });
    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ statusCode: 400, error: 'Bad Request' });
  });

  it('checks auth before validation (401, not 400, without a token)', async () => {
    const response = await app.inject({ method: 'POST', url: '/api/v1/threats', payload: {} });
    expect(response.statusCode).toBe(401);
  });

  it('returns 404 in the standard format for unknown routes', async () => {
    const response = await app.inject({ method: 'GET', url: '/api/v1/nope' });
    expect(response.statusCode).toBe(404);
    expect(response.json()).toMatchObject({ code: 'NOT_FOUND' });
  });
});
