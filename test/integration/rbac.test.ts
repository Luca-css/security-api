import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { bearer, buildTestApp, setupUsers } from '../helpers.js';

describe('role-based access control', () => {
  let app: FastifyInstance;
  let adminToken: string;
  let analystToken: string;

  beforeAll(async () => {
    app = await buildTestApp();
    ({ adminToken, analystToken } = await setupUsers(app));
  });
  afterAll(async () => {
    await app.close();
  });

  const threat = {
    sourceIp: '198.51.100.23',
    type: 'Brute Force',
    severity: 'critical',
    description: 'RDP brute force',
  };

  it('lets analysts read and create threats', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/api/v1/threats',
      headers: bearer(analystToken),
      payload: threat,
    });
    expect(created.statusCode).toBe(201);
    expect(created.json()).toMatchObject({ ...threat, createdBy: 'analyst', resolved: false });

    const list = await app.inject({
      method: 'GET',
      url: '/api/v1/threats',
      headers: bearer(analystToken),
    });
    expect(list.statusCode).toBe(200);
    expect(list.json<{ meta: { total: number } }>().meta.total).toBeGreaterThanOrEqual(1);
  });

  it('lets analysts resolve but not delete threats', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/api/v1/threats',
      headers: bearer(analystToken),
      payload: threat,
    });
    const id = created.json<{ id: string }>().id;

    const resolved = await app.inject({
      method: 'PATCH',
      url: `/api/v1/threats/${id}/resolve`,
      headers: bearer(analystToken),
    });
    expect(resolved.statusCode).toBe(200);
    expect(resolved.json()).toMatchObject({ resolved: true, resolvedBy: 'analyst' });

    const forbidden = await app.inject({
      method: 'DELETE',
      url: `/api/v1/threats/${id}`,
      headers: bearer(analystToken),
    });
    expect(forbidden.statusCode).toBe(403);
    expect(forbidden.json()).toMatchObject({ code: 'FORBIDDEN' });

    const deleted = await app.inject({
      method: 'DELETE',
      url: `/api/v1/threats/${id}`,
      headers: bearer(adminToken),
    });
    expect(deleted.statusCode).toBe(204);
  });

  it.each([
    ['POST', '/api/v1/blocklist', { cidr: '192.0.2.0/24', reason: 'test' }],
    ['DELETE', '/api/v1/blocklist/00000000-0000-4000-8000-000000000000', undefined],
    ['DELETE', '/api/v1/alerts/00000000-0000-4000-8000-000000000000', undefined],
    ['POST', '/api/v1/auth/users', { username: 'eve', password: 'eve-password-123' }],
  ] as const)('returns 403 for analyst on %s %s', async (method, url, payload) => {
    const response = await app.inject({ method, url, headers: bearer(analystToken), payload });
    expect(response.statusCode).toBe(403);
  });

  it('lets analysts read the blocklist and check IPs', async () => {
    const list = await app.inject({
      method: 'GET',
      url: '/api/v1/blocklist',
      headers: bearer(analystToken),
    });
    expect(list.statusCode).toBe(200);
    const check = await app.inject({
      method: 'GET',
      url: '/api/v1/blocklist/check?ip=192.0.2.1',
      headers: bearer(analystToken),
    });
    expect(check.statusCode).toBe(200);
    expect(check.json()).toMatchObject({ ip: '192.0.2.1', blocked: false, matchedEntry: null });
  });

  it('manages the alert lifecycle and filters by severity/resolved', async () => {
    const create = (severity: string) =>
      app.inject({
        method: 'POST',
        url: '/api/v1/alerts',
        headers: bearer(analystToken),
        payload: { title: `${severity} alert`, severity, source: 'SIEM-01' },
      });
    const low = await create('low');
    await create('critical');
    expect(low.statusCode).toBe(201);

    await app.inject({
      method: 'PATCH',
      url: `/api/v1/alerts/${low.json<{ id: string }>().id}/resolve`,
      headers: bearer(analystToken),
    });

    const open = await app.inject({
      method: 'GET',
      url: '/api/v1/alerts?resolved=false',
      headers: bearer(analystToken),
    });
    const openAlerts = open.json<{ data: { severity: string; resolved: boolean }[] }>().data;
    expect(openAlerts.every((a) => !a.resolved)).toBe(true);
    expect(openAlerts.map((a) => a.severity)).toContain('critical');

    const all = await app.inject({
      method: 'GET',
      url: '/api/v1/alerts',
      headers: bearer(analystToken),
    });
    const severities = all.json<{ data: { severity: string }[] }>().data.map((a) => a.severity);
    expect(severities[0]).toBe('critical'); // most severe first
  });

  it('returns 404 with the standard error body for unknown ids', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/api/v1/threats/00000000-0000-4000-8000-000000000000',
      headers: bearer(adminToken),
    });
    expect(response.statusCode).toBe(404);
    expect(response.json()).toMatchObject({
      statusCode: 404,
      error: 'Not Found',
      code: 'NOT_FOUND',
      requestId: expect.any(String) as string,
    });
  });
});
