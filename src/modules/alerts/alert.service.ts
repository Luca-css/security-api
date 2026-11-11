import { randomUUID } from 'node:crypto';
import { ConflictError, NotFoundError } from '../../lib/errors.js';
import type { Page } from '../../shared/schemas.js';
import type { AlertRepository } from './alert.repository.js';
import type { Alert, CreateAlertInput, ListAlertsQuery } from './alert.schemas.js';

export class AlertService {
  constructor(
    private readonly alerts: AlertRepository,
    private readonly now: () => Date = () => new Date(),
  ) {}

  list(query: ListAlertsQuery): Promise<Page<Alert>> {
    const { limit, offset, ...filters } = query;
    return this.alerts.list(filters, { limit, offset });
  }

  async getById(id: string): Promise<Alert> {
    const alert = await this.alerts.findById(id);
    if (!alert) throw new NotFoundError('Alert', id);
    return alert;
  }

  async create(input: CreateAlertInput, actor: string): Promise<Alert> {
    const alert: Alert = {
      id: randomUUID(),
      title: input.title,
      severity: input.severity,
      source: input.source,
      description: input.description ?? null,
      affectedHost: input.affectedHost ?? null,
      resolved: false,
      resolvedAt: null,
      resolvedBy: null,
      createdBy: actor,
      createdAt: this.now().toISOString(),
    };
    await this.alerts.create(alert);
    return alert;
  }

  async resolve(id: string, actor: string): Promise<Alert> {
    const alert = await this.getById(id);
    if (alert.resolved) throw new ConflictError(`Alert '${id}' is already resolved`);
    const resolvedAt = this.now().toISOString();
    await this.alerts.markResolved(id, actor, resolvedAt);
    return { ...alert, resolved: true, resolvedAt, resolvedBy: actor };
  }

  async delete(id: string): Promise<void> {
    const deleted = await this.alerts.delete(id);
    if (!deleted) throw new NotFoundError('Alert', id);
  }
}
