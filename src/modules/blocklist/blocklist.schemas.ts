import { z } from 'zod';
import { parseCidr } from '../../lib/ip.js';
import {
  booleanQuerySchema,
  ipAddressSchema,
  paginatedSchema,
  paginationQuerySchema,
} from '../../shared/schemas.js';

export const blocklistEntrySchema = z.object({
  id: z.string(),
  cidr: z.string().describe('Normalized CIDR, e.g. 203.0.113.0/24 or 2001:db8::/32'),
  reason: z.string(),
  expiresAt: z.string().nullable(),
  hits: z.number().int(),
  createdBy: z.string(),
  createdAt: z.string(),
});
export type BlocklistEntry = z.infer<typeof blocklistEntrySchema>;

export const createBlocklistEntryBodySchema = z.object({
  cidr: z
    .string()
    .trim()
    .refine((value) => parseCidr(value) !== null, {
      message:
        'Must be an IP address or CIDR block (e.g. 203.0.113.7, 203.0.113.0/24, 2001:db8::/32)',
    })
    .describe('Single IP (stored as /32 or /128) or CIDR block'),
  reason: z.string().trim().min(1).max(255),
  expiresAt: z.iso
    .datetime({ offset: true })
    .optional()
    .describe('Optional expiry (ISO 8601). Expired entries stop being enforced.'),
});
export type CreateBlocklistEntryInput = z.infer<typeof createBlocklistEntryBodySchema>;

export const listBlocklistQuerySchema = paginationQuerySchema.extend({
  includeExpired: booleanQuerySchema.default(false),
});
export type ListBlocklistQuery = z.infer<typeof listBlocklistQuerySchema>;

export const checkIpQuerySchema = z.object({ ip: ipAddressSchema });

export const checkIpResponseSchema = z.object({
  ip: z.string(),
  blocked: z.boolean(),
  matchedEntry: blocklistEntrySchema.nullable(),
});

export const blocklistListResponseSchema = paginatedSchema(blocklistEntrySchema);
