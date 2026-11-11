import { beforeEach, describe, expect, it } from 'vitest';
import { ConflictError, NotFoundError } from '../../src/lib/errors.js';
import type {
  ThreatFilters,
  ThreatRepository,
} from '../../src/modules/threats/threat.repository.js';
import type { Threat } from '../../src/modules/threats/threat.schemas.js';
import { ThreatService } from '../../src/modules/threats/threat.service.js';
import type { Page, Pagination } from '../../src/shared/schemas.js';

/**
 * In-memory fake: the service only depends on the ThreatRepository interface,
 * so it can be tested without SQLite.
 */
class InMemoryThreatRepository implements ThreatRepository {
  readonly items = new Map<string, Threat>();

  async list(filters: ThreatFilters, { limit, offset }: Pagination): Promise<Page<Threat>> {
    const matching = [...this.items.values()]
      .filter((t) => !filters.severity || t.severity === filters.severity)
      .filter((t) => filters.resolved === undefined || t.resolved === filters.resolved)
      .filter((t) => !filters.sourceIp || t.sourceIp === filters.sourceIp)
      .sort((a, b) => b.detectedAt.localeCompare(a.detectedAt));
    return { items: matching.slice(offset, offset + limit), total: matching.length };
  }
  async findById(id: string) {
    return this.items.get(id);
  }
  async create(threat: Threat) {
    this.items.set(threat.id, threat);
  }
  async markResolved(id: string, resolvedBy: string, resolvedAt: string) {
    const t = this.items.get(id);
    if (t) this.items.set(id, { ...t, resolved: true, resolvedBy, resolvedAt });
  }
  async delete(id: string) {
    return this.items.delete(id);
  }
}

describe('ThreatService', () => {
  const fixedNow = new Date('2026-03-01T12:00:00.000Z');
  let repo: InMemoryThreatRepository;
  let service: ThreatService;

  beforeEach(() => {
    repo = new InMemoryThreatRepository();
    service = new ThreatService(repo, () => fixedNow);
  });

  const input = {
    sourceIp: '198.51.100.7',
    type: 'Port Scan',
    severity: 'high' as const,
    description: 'SYN scan',
  };

  it('creates a threat with defaults and audit fields', async () => {
    const threat = await service.create(input, 'alice');
    expect(threat).toMatchObject({
      ...input,
      resolved: false,
      country: null,
      attackVector: null,
      createdBy: 'alice',
      detectedAt: fixedNow.toISOString(),
    });
    expect(repo.items.size).toBe(1);
  });

  it('normalizes detectedAt to UTC', async () => {
    const threat = await service.create({ ...input, detectedAt: '2026-03-01T09:00:00-03:00' }, 'a');
    expect(threat.detectedAt).toBe('2026-03-01T12:00:00.000Z');
  });

  it('resolves a threat once and rejects resolving twice', async () => {
    const threat = await service.create(input, 'alice');
    const resolved = await service.resolve(threat.id, 'bob');
    expect(resolved).toMatchObject({ resolved: true, resolvedBy: 'bob' });
    await expect(service.resolve(threat.id, 'bob')).rejects.toBeInstanceOf(ConflictError);
  });

  it('throws NotFoundError for unknown ids', async () => {
    await expect(service.getById('missing')).rejects.toBeInstanceOf(NotFoundError);
    await expect(service.delete('missing')).rejects.toBeInstanceOf(NotFoundError);
  });

  it('passes filters and pagination to the repository', async () => {
    await service.create({ ...input, severity: 'critical' }, 'a');
    await service.create({ ...input, severity: 'low' }, 'a');
    const page = await service.list({ limit: 10, offset: 0, severity: 'critical' });
    expect(page.total).toBe(1);
    expect(page.items[0]?.severity).toBe('critical');
  });
});
