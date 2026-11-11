import { describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config/env.js';

const base = {
  JWT_SECRET: 'x'.repeat(32),
  ADMIN_PASSWORD: 'a-long-password',
};

describe('loadConfig', () => {
  it('applies defaults', () => {
    const config = loadConfig(base);
    expect(config.PORT).toBe(3000);
    expect(config.TRUST_PROXY).toBe(false);
    expect(config.JWT_EXPIRES_IN).toBe('15m');
  });

  it('parses "false" as false (not truthy string coercion)', () => {
    expect(loadConfig({ ...base, TRUST_PROXY: 'false' }).TRUST_PROXY).toBe(false);
    expect(loadConfig({ ...base, TRUST_PROXY: 'true' }).TRUST_PROXY).toBe(true);
  });

  it('fails fast on weak or missing secrets', () => {
    expect(() => loadConfig({ ...base, JWT_SECRET: 'short' })).toThrow(/JWT_SECRET/);
    expect(() => loadConfig({ JWT_SECRET: base.JWT_SECRET })).toThrow(/ADMIN_PASSWORD/);
  });
});
