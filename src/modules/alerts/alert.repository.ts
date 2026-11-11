import type { Database } from '../../db/database.js';
import type { Page, Pagination, Severity } from '../../shared/schemas.js';
import type { Alert } from './alert.schemas.js';

export interface AlertFilters {
  severity?: Severity;
  resolved?: boolean;
}

export interface AlertRepository {
  list(filters: AlertFilters, pagination: Pagination): Promise<Page<Alert>>;
  findById(id: string): Promise<Alert | undefined>;
  create(alert: Alert): Promise<void>;
  markResolved(id: string, resolvedBy: string, resolvedAt: string): Promise<void>;
  delete(id: string): Promise<boolean>;
}

interface AlertRow {
  id: string;
  title: string;
  severity: Severity;
  source: string;
  description: string | null;
  affected_host: string | null;
  resolved: number;
  resolved_at: string | null;
  resolved_by: string | null;
  created_by: string;
  created_at: string;
}

const toAlert = (row: AlertRow): Alert => ({
  id: row.id,
  title: row.title,
  severity: row.severity,
  source: row.source,
  description: row.description,
  affectedHost: row.affected_host,
  resolved: row.resolved === 1,
  resolvedAt: row.resolved_at,
  resolvedBy: row.resolved_by,
  createdBy: row.created_by,
  createdAt: row.created_at,
});

/** Most severe first, then newest first. */
const SEVERITY_ORDER_SQL = `CASE severity
  WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END`;

export class SqliteAlertRepository implements AlertRepository {
  constructor(private readonly db: Database) {}

  list(filters: AlertFilters, { limit, offset }: Pagination): Promise<Page<Alert>> {
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
    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const { total } = this.db
      .prepare(`SELECT COUNT(*) AS total FROM alerts ${whereSql}`)
      .get(...params) as { total: number };
    const rows = this.db
      .prepare(
        `SELECT * FROM alerts ${whereSql}
         ORDER BY ${SEVERITY_ORDER_SQL}, created_at DESC LIMIT ? OFFSET ?`,
      )
      .all(...params, limit, offset) as unknown as AlertRow[];

    return Promise.resolve({ items: rows.map(toAlert), total });
  }

  findById(id: string): Promise<Alert | undefined> {
    const row = this.db.prepare('SELECT * FROM alerts WHERE id = ?').get(id) as
      AlertRow | undefined;
    return Promise.resolve(row ? toAlert(row) : undefined);
  }

  create(a: Alert): Promise<void> {
    this.db
      .prepare(
        `INSERT INTO alerts (id, title, severity, source, description, affected_host,
           resolved, resolved_at, resolved_by, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        a.id,
        a.title,
        a.severity,
        a.source,
        a.description,
        a.affectedHost,
        a.resolved ? 1 : 0,
        a.resolvedAt,
        a.resolvedBy,
        a.createdBy,
        a.createdAt,
      );
    return Promise.resolve();
  }

  markResolved(id: string, resolvedBy: string, resolvedAt: string): Promise<void> {
    this.db
      .prepare('UPDATE alerts SET resolved = 1, resolved_by = ?, resolved_at = ? WHERE id = ?')
      .run(resolvedBy, resolvedAt, id);
    return Promise.resolve();
  }

  delete(id: string): Promise<boolean> {
    const result = this.db.prepare('DELETE FROM alerts WHERE id = ?').run(id);
    return Promise.resolve(Number(result.changes) > 0);
  }
}
