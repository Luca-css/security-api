import { randomUUID } from 'node:crypto';
import { BadRequestError, ConflictError, NotFoundError } from '../../lib/errors.js';
import { cidrContains, formatCidr, parseCidr, parseIp, type Cidr } from '../../lib/ip.js';
import type { Page } from '../../shared/schemas.js';
import type { BlocklistRepository } from './blocklist.repository.js';
import type {
  BlocklistEntry,
  CreateBlocklistEntryInput,
  ListBlocklistQuery,
} from './blocklist.schemas.js';

interface CompiledRule {
  entry: BlocklistEntry;
  cidr: Cidr;
}

/**
 * Owns blocklist rules and the matcher used by the request guard.
 *
 * Rules are kept in memory (parsed once) so checking an incoming IP does not hit the
 * database on every request. The cache is rebuilt whenever this service changes a rule.
 * Matching is a linear scan: fine for hundreds/thousands of rules; a radix tree would be
 * the next step for very large feeds.
 */
export class BlocklistService {
  private rules: CompiledRule[] = [];

  constructor(
    private readonly repository: BlocklistRepository,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async reload(): Promise<void> {
    const entries = await this.repository.findAll();
    this.rules = entries.flatMap((entry) => {
      const cidr = parseCidr(entry.cidr);
      return cidr ? [{ entry, cidr }] : [];
    });
  }

  private isActive(entry: BlocklistEntry): boolean {
    return entry.expiresAt === null || new Date(entry.expiresAt) > this.now();
  }

  /** Returns the first active rule covering `ip`, or null. Invalid IPs never match. */
  findMatch(ip: string): BlocklistEntry | null {
    const parsed = parseIp(ip);
    if (!parsed) return null;
    const rule = this.rules.find((r) => this.isActive(r.entry) && cidrContains(r.cidr, parsed));
    return rule?.entry ?? null;
  }

  async recordHit(entry: BlocklistEntry): Promise<void> {
    await this.repository.incrementHits(entry.id);
  }

  async list(query: ListBlocklistQuery): Promise<Page<BlocklistEntry>> {
    const { limit, offset, includeExpired } = query;
    return this.repository.list(
      { includeExpired, now: this.now().toISOString() },
      { limit, offset },
    );
  }

  async check(
    ip: string,
  ): Promise<{ ip: string; blocked: boolean; matchedEntry: BlocklistEntry | null }> {
    const match = this.findMatch(ip);
    // Re-read so the returned hit counter is current (the cache only holds rule definitions).
    const matchedEntry = match ? ((await this.repository.findById(match.id)) ?? match) : null;
    return { ip, blocked: matchedEntry !== null, matchedEntry };
  }

  async add(input: CreateBlocklistEntryInput, actor: string): Promise<BlocklistEntry> {
    const cidr = parseCidr(input.cidr);
    if (!cidr) throw new BadRequestError(`'${input.cidr}' is not a valid IP or CIDR block`);

    const expiresAt = input.expiresAt ? new Date(input.expiresAt) : null;
    if (expiresAt && expiresAt <= this.now()) {
      throw new BadRequestError('expiresAt must be in the future');
    }

    // Store the canonical form so "10.1.2.3/8" and "10.0.0.0/8" are the same rule.
    const normalized = formatCidr(cidr);
    if (await this.repository.findByCidr(normalized)) {
      throw new ConflictError(`${normalized} is already in the blocklist`);
    }

    const entry: BlocklistEntry = {
      id: randomUUID(),
      cidr: normalized,
      reason: input.reason,
      expiresAt: expiresAt?.toISOString() ?? null,
      hits: 0,
      createdBy: actor,
      createdAt: this.now().toISOString(),
    };
    await this.repository.create(entry);
    await this.reload();
    return entry;
  }

  async remove(id: string): Promise<void> {
    const deleted = await this.repository.delete(id);
    if (!deleted) throw new NotFoundError('Blocklist entry', id);
    await this.reload();
  }
}
