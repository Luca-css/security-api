import type { Database } from '../../db/database.js';
import type { Page, Pagination } from '../../shared/schemas.js';
import type { BlocklistEntry } from './blocklist.schemas.js';

export interface BlocklistRepository {
  /** All entries, used to build the in-memory matcher. */
  findAll(): Promise<BlocklistEntry[]>;
  list(
    options: { includeExpired: boolean; now: string },
    pagination: Pagination,
  ): Promise<Page<BlocklistEntry>>;
  findById(id: string): Promise<BlocklistEntry | undefined>;
  findByCidr(cidr: string): Promise<BlocklistEntry | undefined>;
  create(entry: BlocklistEntry): Promise<void>;
  delete(id: string): Promise<boolean>;
  incrementHits(id: string): Promise<void>;
}

interface BlocklistRow {
  id: string;
  cidr: string;
  reason: string;
  expires_at: string | null;
  hits: number;
  created_by: string;
  created_at: string;
}

const toEntry = (row: BlocklistRow): BlocklistEntry => ({
  id: row.id,
  cidr: row.cidr,
  reason: row.reason,
  expiresAt: row.expires_at,
  hits: row.hits,
  createdBy: row.created_by,
  createdAt: row.created_at,
});

export class SqliteBlocklistRepository implements BlocklistRepository {
  constructor(private readonly db: Database) {}

  findAll(): Promise<BlocklistEntry[]> {
    const rows = this.db.prepare('SELECT * FROM blocklist').all() as unknown as BlocklistRow[];
    return Promise.resolve(rows.map(toEntry));
  }

  list(
    { includeExpired, now }: { includeExpired: boolean; now: string },
    { limit, offset }: Pagination,
  ): Promise<Page<BlocklistEntry>> {
    // ISO-8601 UTC strings compare correctly as text.
    const whereSql = includeExpired ? '' : 'WHERE expires_at IS NULL OR expires_at > ?';
    const params = includeExpired ? [] : [now];

    const { total } = this.db
      .prepare(`SELECT COUNT(*) AS total FROM blocklist ${whereSql}`)
      .get(...params) as { total: number };
    const rows = this.db
      .prepare(`SELECT * FROM blocklist ${whereSql} ORDER BY created_at DESC LIMIT ? OFFSET ?`)
      .all(...params, limit, offset) as unknown as BlocklistRow[];

    return Promise.resolve({ items: rows.map(toEntry), total });
  }

  findById(id: string): Promise<BlocklistEntry | undefined> {
    const row = this.db.prepare('SELECT * FROM blocklist WHERE id = ?').get(id) as
      BlocklistRow | undefined;
    return Promise.resolve(row ? toEntry(row) : undefined);
  }

  findByCidr(cidr: string): Promise<BlocklistEntry | undefined> {
    const row = this.db.prepare('SELECT * FROM blocklist WHERE cidr = ?').get(cidr) as
      BlocklistRow | undefined;
    return Promise.resolve(row ? toEntry(row) : undefined);
  }

  create(e: BlocklistEntry): Promise<void> {
    this.db
      .prepare(
        `INSERT INTO blocklist (id, cidr, reason, expires_at, hits, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(e.id, e.cidr, e.reason, e.expiresAt, e.hits, e.createdBy, e.createdAt);
    return Promise.resolve();
  }

  delete(id: string): Promise<boolean> {
    const result = this.db.prepare('DELETE FROM blocklist WHERE id = ?').run(id);
    return Promise.resolve(Number(result.changes) > 0);
  }

  incrementHits(id: string): Promise<void> {
    this.db.prepare('UPDATE blocklist SET hits = hits + 1 WHERE id = ?').run(id);
    return Promise.resolve();
  }
}
