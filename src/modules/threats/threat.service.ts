import { randomUUID } from 'node:crypto';
import { ConflictError, NotFoundError } from '../../lib/errors.js';
import type { Page } from '../../shared/schemas.js';
import type { ThreatRepository } from './threat.repository.js';
import type { CreateThreatInput, ListThreatsQuery, Threat } from './threat.schemas.js';

export class ThreatService {
  constructor(
    private readonly threats: ThreatRepository,
    private readonly now: () => Date = () => new Date(),
  ) {}

  list(query: ListThreatsQuery): Promise<Page<Threat>> {
    const { limit, offset, ...filters } = query;
    return this.threats.list(filters, { limit, offset });
  }

  async getById(id: string): Promise<Threat> {
    const threat = await this.threats.findById(id);
    if (!threat) throw new NotFoundError('Threat', id);
    return threat;
  }

  async create(input: CreateThreatInput, actor: string): Promise<Threat> {
    const now = this.now().toISOString();
    const threat: Threat = {
      id: randomUUID(),
      sourceIp: input.sourceIp,
      type: input.type,
      severity: input.severity,
      description: input.description,
      country: input.country ?? null,
      attackVector: input.attackVector ?? null,
      detectedAt: input.detectedAt ? new Date(input.detectedAt).toISOString() : now,
      resolved: false,
      resolvedAt: null,
      resolvedBy: null,
      createdBy: actor,
      createdAt: now,
    };
    await this.threats.create(threat);
    return threat;
  }

  async resolve(id: string, actor: string): Promise<Threat> {
    const threat = await this.getById(id);
    if (threat.resolved) throw new ConflictError(`Threat '${id}' is already resolved`);
    const resolvedAt = this.now().toISOString();
    await this.threats.markResolved(id, actor, resolvedAt);
    return { ...threat, resolved: true, resolvedAt, resolvedBy: actor };
  }

  async delete(id: string): Promise<void> {
    const deleted = await this.threats.delete(id);
    if (!deleted) throw new NotFoundError('Threat', id);
  }
}
