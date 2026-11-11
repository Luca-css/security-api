import type { FastifyInstance } from 'fastify';
import { buildApp } from '../src/app.js';
import { loadConfig, type AppConfig } from '../src/config/env.js';

export const ADMIN = { username: 'admin', password: 'admin-password-123' };
export const ANALYST = { username: 'analyst', password: 'analyst-password-123' };

export function testConfig(overrides: Partial<Record<keyof AppConfig, string>> = {}): AppConfig {
  return loadConfig({
    NODE_ENV: 'test',
    LOG_LEVEL: 'silent',
    DATABASE_PATH: ':memory:',
    JWT_SECRET: 'test-secret-that-is-long-enough-for-hs256-signing',
    ADMIN_USERNAME: ADMIN.username,
    ADMIN_PASSWORD: ADMIN.password,
    RATE_LIMIT_MAX: '1000',
    LOGIN_RATE_LIMIT_MAX: '1000',
    ...overrides,
  });
}

export async function buildTestApp(
  overrides: Partial<Record<keyof AppConfig, string>> = {},
): Promise<FastifyInstance> {
  const app = await buildApp(testConfig(overrides));
  await app.ready();
  return app;
}

export async function login(
  app: FastifyInstance,
  credentials: { username: string; password: string },
): Promise<string> {
  const response = await app.inject({
    method: 'POST',
    url: '/api/v1/auth/login',
    payload: credentials,
  });
  if (response.statusCode !== 200) {
    throw new Error(`login failed: ${response.statusCode} ${response.body}`);
  }
  return response.json<{ accessToken: string }>().accessToken;
}

/** Logs in as admin, creates the analyst user and returns both tokens. */
export async function setupUsers(app: FastifyInstance) {
  const adminToken = await login(app, ADMIN);
  const created = await app.inject({
    method: 'POST',
    url: '/api/v1/auth/users',
    headers: { authorization: `Bearer ${adminToken}` },
    payload: { ...ANALYST, role: 'analyst' },
  });
  if (created.statusCode !== 201) throw new Error(`create analyst failed: ${created.body}`);
  const analystToken = await login(app, ANALYST);
  return { adminToken, analystToken };
}

export const bearer = (token: string) => ({ authorization: `Bearer ${token}` });
