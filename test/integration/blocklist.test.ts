import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN, bearer, buildTestApp, login } from '../helpers.js';

describe('blocklist enforcement', () => {
  let app: FastifyInstance;
  let token: string;

  beforeAll(async () => {
    app = await buildTestApp();
    token = await login(app, ADMIN);
  });
  afterAll(async () => {
    await app.close();
  });

  const healthFrom = (remoteAddress: string) =>
    app.inject({ method: 'GET', url: '/health', remoteAddress });

  it('blocks every IP inside a CIDR rule with 403, on any route', async () => {
    expect((await healthFrom('203.0.113.77')).statusCode).toBe(200);

    const created = await app.inject({
      method: 'POST',
      url: '/api/v1/blocklist',
      headers: bearer(token),
      payload: { cidr: '203.0.113.0/24', reason: 'botnet range' },
    });
    expect(created.statusCode).toBe(201);
    expect(created.json()).toMatchObject({ cidr: '203.0.113.0/24', createdBy: 'admin', hits: 0 });

    const blocked = await healthFrom('203.0.113.77');
    expect(blocked.statusCode).toBe(403);
    expect(blocked.json()).toMatchObject({ statusCode: 403, code: 'IP_BLOCKED' });

    // A valid token does not bypass the blocklist.
    const withToken = await app.inject({
      method: 'GET',
      url: '/api/v1/threats',
      headers: bearer(token),
      remoteAddress: '203.0.113.1',
    });
    expect(withToken.statusCode).toBe(403);

    // IPv4-mapped IPv6 form of a blocked address is also blocked.
    expect((await healthFrom('::ffff:203.0.113.9')).statusCode).toBe(403);

    // Neighbouring range is not affected.
    expect((await healthFrom('203.0.114.1')).statusCode).toBe(200);
  });

  it('records hits and reports them via /check', async () => {
    const check = await app.inject({
      method: 'GET',
      url: '/api/v1/blocklist/check?ip=203.0.113.200',
      headers: bearer(token),
    });
    expect(check.statusCode).toBe(200);
    const body = check.json<{ blocked: boolean; matchedEntry: { hits: number } }>();
    expect(body.blocked).toBe(true);
    expect(body.matchedEntry.hits).toBeGreaterThanOrEqual(3);
  });

  it('supports IPv6 CIDR rules', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/api/v1/blocklist',
      headers: bearer(token),
      payload: { cidr: '2001:db8:abcd::/48', reason: 'v6 abuse' },
    });
    expect(created.statusCode).toBe(201);
    expect((await healthFrom('2001:db8:abcd:12::1')).statusCode).toBe(403);
    expect((await healthFrom('2001:db8:abce::1')).statusCode).toBe(200);
  });

  it('unblocks after the entry is deleted', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/api/v1/blocklist',
      headers: bearer(token),
      payload: { cidr: '198.51.100.10', reason: 'temporary' },
    });
    const { id, cidr } = created.json<{ id: string; cidr: string }>();
    expect(cidr).toBe('198.51.100.10/32');
    expect((await healthFrom('198.51.100.10')).statusCode).toBe(403);

    const deleted = await app.inject({
      method: 'DELETE',
      url: `/api/v1/blocklist/${id}`,
      headers: bearer(token),
    });
    expect(deleted.statusCode).toBe(204);
    expect((await healthFrom('198.51.100.10')).statusCode).toBe(200);
  });

  it('rejects duplicate rules with 409', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/blocklist',
      headers: bearer(token),
      payload: { cidr: '203.0.113.5/24', reason: 'same network, different spelling' },
    });
    expect(response.statusCode).toBe(409);
  });
});
