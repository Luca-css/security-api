import { z } from 'zod';

export const roleSchema = z.enum(['admin', 'analyst']);

export const loginBodySchema = z.object({
  username: z.string().trim().min(1).max(64),
  password: z.string().min(1).max(256),
});

export const loginResponseSchema = z.object({
  accessToken: z.string(),
  tokenType: z.literal('Bearer'),
  expiresIn: z.string().describe('Token lifetime, e.g. "15m"'),
});

export const createUserBodySchema = z.object({
  username: z
    .string()
    .trim()
    .min(3)
    .max(64)
    .regex(/^[a-zA-Z0-9._-]+$/, 'Only letters, numbers, ".", "_" and "-" are allowed'),
  password: z.string().min(12).max(256),
  role: roleSchema.default('analyst'),
});

export const publicUserSchema = z.object({
  id: z.string(),
  username: z.string(),
  role: roleSchema,
  createdAt: z.string(),
});
