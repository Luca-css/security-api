import { z } from 'zod';
import { isValidIp } from '../lib/ip.js';

export const severitySchema = z.enum(['critical', 'high', 'medium', 'low']);
export type Severity = z.infer<typeof severitySchema>;

/** Query strings are always strings: parse "true"/"false" explicitly. */
export const booleanQuerySchema = z.enum(['true', 'false']).transform((value) => value === 'true');

export const paginationQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(20),
  offset: z.coerce.number().int().min(0).default(0),
});
export type Pagination = z.infer<typeof paginationQuerySchema>;

export const idParamsSchema = z.object({
  id: z.uuid(),
});

export const ipAddressSchema = z
  .string()
  .trim()
  .refine(isValidIp, { message: 'Must be a valid IPv4 or IPv6 address' });

export const paginationMetaSchema = z.object({
  total: z.number().int(),
  limit: z.number().int(),
  offset: z.number().int(),
});

export function paginatedSchema<T extends z.ZodType>(item: T) {
  return z.object({ data: z.array(item), meta: paginationMetaSchema });
}

export const errorResponseSchema = z.object({
  statusCode: z.number().int(),
  error: z.string(),
  code: z.string(),
  message: z.string(),
  details: z.unknown().optional(),
  requestId: z.string(),
});

export interface Page<T> {
  items: T[];
  total: number;
}
