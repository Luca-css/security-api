import { z } from 'zod';
import {
  booleanQuerySchema,
  ipAddressSchema,
  paginatedSchema,
  paginationQuerySchema,
  severitySchema,
} from '../../shared/schemas.js';

/** CVSS-style attack vectors. */
export const attackVectorSchema = z.enum(['network', 'adjacent', 'local', 'physical']);

export const threatSchema = z.object({
  id: z.string(),
  sourceIp: z.string(),
  type: z.string(),
  severity: severitySchema,
  description: z.string(),
  country: z.string().nullable(),
  attackVector: attackVectorSchema.nullable(),
  detectedAt: z.string(),
  resolved: z.boolean(),
  resolvedAt: z.string().nullable(),
  resolvedBy: z.string().nullable(),
  createdBy: z.string(),
  createdAt: z.string(),
});
export type Threat = z.infer<typeof threatSchema>;

export const createThreatBodySchema = z.object({
  sourceIp: ipAddressSchema,
  type: z.string().trim().min(1).max(100),
  severity: severitySchema,
  description: z.string().trim().min(1).max(2000),
  country: z
    .string()
    .regex(/^[A-Z]{2}$/, 'Use an ISO 3166-1 alpha-2 code, e.g. BR')
    .optional(),
  attackVector: attackVectorSchema.optional(),
  detectedAt: z.iso.datetime({ offset: true }).optional(),
});
export type CreateThreatInput = z.infer<typeof createThreatBodySchema>;

export const listThreatsQuerySchema = paginationQuerySchema.extend({
  severity: severitySchema.optional(),
  resolved: booleanQuerySchema.optional(),
  sourceIp: ipAddressSchema.optional(),
});
export type ListThreatsQuery = z.infer<typeof listThreatsQuerySchema>;

export const threatListResponseSchema = paginatedSchema(threatSchema);
