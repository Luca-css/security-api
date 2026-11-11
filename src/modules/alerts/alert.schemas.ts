import { z } from 'zod';
import {
  booleanQuerySchema,
  paginatedSchema,
  paginationQuerySchema,
  severitySchema,
} from '../../shared/schemas.js';

export const alertSchema = z.object({
  id: z.string(),
  title: z.string(),
  severity: severitySchema,
  source: z.string(),
  description: z.string().nullable(),
  affectedHost: z.string().nullable(),
  resolved: z.boolean(),
  resolvedAt: z.string().nullable(),
  resolvedBy: z.string().nullable(),
  createdBy: z.string(),
  createdAt: z.string(),
});
export type Alert = z.infer<typeof alertSchema>;

export const createAlertBodySchema = z.object({
  title: z.string().trim().min(1).max(200),
  severity: severitySchema,
  source: z
    .string()
    .trim()
    .min(1)
    .max(100)
    .describe('Emitting system, e.g. SIEM-01, EDR, FIREWALL'),
  description: z.string().trim().max(2000).optional(),
  affectedHost: z.string().trim().max(255).optional(),
});
export type CreateAlertInput = z.infer<typeof createAlertBodySchema>;

export const listAlertsQuerySchema = paginationQuerySchema.extend({
  severity: severitySchema.optional(),
  resolved: booleanQuerySchema.optional(),
});
export type ListAlertsQuery = z.infer<typeof listAlertsQuerySchema>;

export const alertListResponseSchema = paginatedSchema(alertSchema);
