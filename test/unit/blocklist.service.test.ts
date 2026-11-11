import { beforeEach, describe, expect, it } from 'vitest';
import { openDatabase } from '../../src/db/database.js';
import { runMigrations } from '../../src/db/migrate.js';
import { BadRequestError, ConflictError, NotFoundError } from '../../src/lib/errors.js';
import { SqliteBlocklistRepository } from '../../src/modules/blocklist/blocklist.repository.js';
import { BlocklistService } from '../../src/modules/blocklist/blocklist.service.js';

describe('BlocklistService', () => {
  let now: Date;
  let service: BlocklistService;

  beforeEach(async () => {
    const db = openDatabase(':memory:');
    runMigrations(db);
    now = new Date('2026-01-01T00:00:00.000Z');
    // Injected clock makes expiry deterministic.
    service = new BlocklistService(new SqliteBlocklistRepository(db), () => now);
    await service.reload();
  });

  it('matches IPs inside a CIDR rule and ignores others', async () => {
    await service.add({ cidr: '198.51.100.0/24', reason: 'scanner' }, 'tester');
    expect(service.findMatch('198.51.100.42')?.cidr).toBe('198.51.100.0/24');
    expect(service.findMatch('198.51.101.1')).toBeNull();
  });

  it('stores single IPs as host routes and normalizes CIDRs', async () => {
    const single = await service.add({ cidr: '192.0.2.10', reason: 'x' }, 'tester');
    const range = await service.add({ cidr: '10.20.30.40/16', reason: 'y' }, 'tester');
    expect(single.cidr).toBe('192.0.2.10/32');
    expect(range.cidr).toBe('10.20.0.0/16');
  });

  it('rejects duplicates after normalization', async () => {
    await service.add({ cidr: '10.0.0.0/8', reason: 'x' }, 'tester');
    await expect(
      service.add({ cidr: '10.9.9.9/8', reason: 'dup' }, 'tester'),
    ).rejects.toBeInstanceOf(ConflictError);
  });

  it('rejects an expiry in the past', async () => {
    await expect(
      service.add({ cidr: '10.0.0.1', reason: 'x', expiresAt: '2025-12-31T23:59:59Z' }, 'tester'),
    ).rejects.toBeInstanceOf(BadRequestError);
  });

  it('stops enforcing a rule once it expires', async () => {
    await service.add(
      { cidr: '203.0.113.0/24', reason: 'temp', expiresAt: '2026-01-01T01:00:00Z' },
      'tester',
    );
    expect(service.findMatch('203.0.113.5')).not.toBeNull();

    now = new Date('2026-01-01T01:00:01Z');
    expect(service.findMatch('203.0.113.5')).toBeNull();

    const active = await service.list({ limit: 20, offset: 0, includeExpired: false });
    const all = await service.list({ limit: 20, offset: 0, includeExpired: true });
    expect(active.total).toBe(0);
    expect(all.total).toBe(1);
  });

  it('removes rules and refreshes the matcher', async () => {
    const entry = await service.add({ cidr: '2001:db8::/32', reason: 'v6' }, 'tester');
    expect(service.findMatch('2001:db8::abcd')).not.toBeNull();
    await service.remove(entry.id);
    expect(service.findMatch('2001:db8::abcd')).toBeNull();
    await expect(service.remove(entry.id)).rejects.toBeInstanceOf(NotFoundError);
  });

  it('counts hits', async () => {
    const entry = await service.add({ cidr: '192.0.2.1', reason: 'x' }, 'tester');
    await service.recordHit(entry);
    await service.recordHit(entry);
    const result = await service.check('192.0.2.1');
    expect(result.blocked).toBe(true);
    expect(result.matchedEntry?.hits).toBe(2);
  });
});
