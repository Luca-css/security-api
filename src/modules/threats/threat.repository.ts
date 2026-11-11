import type { Database } from '../../db/database.js';
import type { Page, Pagination, Severity } from '../../shared/schemas.js';
import type { Threat } from './threat.schemas.js';

export interface ThreatFilters {
  severity?: Severity;
  resolved?: boolean;
  sourceIp?: string;
}

export interface ThreatRepository {
  list(filters: ThreatFilters, pagination: Pagination): Promise<Page<Threat>>;
  findById(id: string): Promise<Threat | undefined>;
  create(threat: Threat): Promise<void>;
  markResolved(id: string, resolvedBy: string, resolvedAt: string): Promise<void>;
  delete(id: string): Promise<boolean>;
}

interface ThreatRow {
  id: string;
  source_ip: string;
  type: string;
  severity: Severity;
  description: string;
  country: string | null;
  attack_vector: Threat['attackVector'];
  detected_at: string;
  resolved: number;
  resolved_at: string | null;
  resolved_by: string | null;
  created_by: string;
  created_at: string;
}

const toThreat = (row: ThreatRow): Threat => ({
  id: row.id,
  sourceIp: row.source_ip,
  type: row.type,
  severity: row.severity,
  description: row.description,
  country: row.country,
  attackVector: row.attack_vector,
  detectedAt: row.detected_at,
  resolved: row.resolved === 1,
  resolvedAt: row.resolved_at,
  resolvedBy: row.resolved_by,
  createdBy: row.created_by,
  createdAt: row.created_at,
});

export class SqliteThreatRepository implements ThreatRepository {
  constructor(private readonly db: Database) {}

  list(filters: ThreatFilters, { limit, offset }: Pagination): Promise<Page<Threat>> {
    // Filters are always bound as parameters, never concatenated into SQL.
    const where: string[] = [];
    const params: (string | number)[] = [];
    if (filters.severity) {
      where.push('severity = ?');
      params.push(filters.severity);
    }
    if (filters.resolved !== undefined) {
      where.push('resolved = ?');
      params.push(filters.resolved ? 1 : 0);
    }
    if (filters.sourceIp) {
      where.push('source_ip = ?');
      params.push(filters.sourceIp);
    }
    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const { total } = this.db
      .prepare(`SELECT COUNT(*) AS total FROM threats ${whereSql}`)
      .get(...params) as { total: number };
    const rows = this.db
      .prepare(`SELECT * FROM threats ${whereSql} ORDER BY detected_at DESC LIMIT ? OFFSET ?`)
      .all(...params, limit, offset) as unknown as ThreatRow[];

    return Promise.resolve({ items: rows.map(toThreat), total });
  }

  findById(id: string): Promise<Threat | undefined> {
    const row = this.db.prepare('SELECT * FROM threats WHERE id = ?').get(id) as
      ThreatRow | undefined;
    return Promise.resolve(row ? toThreat(row) : undefined);
  }

  create(t: Threat): Promise<void> {
    this.db
      .prepare(
        `INSERT INTO threats (id, source_ip, type, severity, description, country, attack_vector,
           detected_at, resolved, resolved_at, resolved_by, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        t.id,
        t.sourceIp,
        t.type,
        t.severity,
        t.description,
        t.country,
        t.attackVector,
        t.detectedAt,
        t.resolved ? 1 : 0,
        t.resolvedAt,
        t.resolvedBy,
        t.createdBy,
        t.createdAt,
      );
    return Promise.resolve();
  }

  markResolved(id: string, resolvedBy: string, resolvedAt: string): Promise<void> {
    this.db
      .prepare('UPDATE threats SET resolved = 1, resolved_by = ?, resolved_at = ? WHERE id = ?')
      .run(resolvedBy, resolvedAt, id);
    return Promise.resolve();
  }

  delete(id: string): Promise<boolean> {
    const result = this.db.prepare('DELETE FROM threats WHERE id = ?').run(id);
    return Promise.resolve(Number(result.changes) > 0);
  }
}
