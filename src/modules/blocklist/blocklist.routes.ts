import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { idParamsSchema } from '../../shared/schemas.js';
import type { BlocklistService } from './blocklist.service.js';
import {
  blocklistEntrySchema,
  blocklistListResponseSchema,
  checkIpQuerySchema,
  checkIpResponseSchema,
  createBlocklistEntryBodySchema,
  listBlocklistQuerySchema,
} from './blocklist.schemas.js';

export interface BlocklistRoutesOptions {
  blocklistService: BlocklistService;
}

export const blocklistRoutes: FastifyPluginAsyncZod<BlocklistRoutesOptions> = async (app, opts) => {
  const { blocklistService } = opts;
  const anyRole = app.requireRole('admin', 'analyst');
  const adminOnly = app.requireRole('admin');
  const common = { tags: ['blocklist'], security: [{ bearerAuth: [] }] };

  app.get(
    '/',
    {
      onRequest: anyRole,
      schema: {
        ...common,
        summary: 'List blocklist entries (active only unless includeExpired=true)',
        querystring: listBlocklistQuerySchema,
        response: { 200: blocklistListResponseSchema },
      },
    },
    async (request) => {
      const { limit, offset } = request.query;
      const page = await blocklistService.list(request.query);
      return { data: page.items, meta: { total: page.total, limit, offset } };
    },
  );

  app.get(
    '/check',
    {
      onRequest: anyRole,
      schema: {
        ...common,
        summary: 'Check whether an IP is covered by an active rule',
        querystring: checkIpQuerySchema,
        response: { 200: checkIpResponseSchema },
      },
    },
    async (request) => blocklistService.check(request.query.ip),
  );

  app.post(
    '/',
    {
      onRequest: adminOnly,
      schema: {
        ...common,
        summary: 'Block an IP or CIDR range (admin only)',
        body: createBlocklistEntryBodySchema,
        response: { 201: blocklistEntrySchema },
      },
    },
    async (request, reply) => {
      const entry = await blocklistService.add(request.body, request.user.username);
      request.log.warn({ cidr: entry.cidr, by: entry.createdBy }, 'blocklist entry added');
      return reply.code(201).send(entry);
    },
  );

  app.delete(
    '/:id',
    {
      onRequest: adminOnly,
      schema: {
        ...common,
        summary: 'Remove a blocklist entry (admin only)',
        params: idParamsSchema,
      },
    },
    async (request, reply) => {
      await blocklistService.remove(request.params.id);
      request.log.warn(
        { id: request.params.id, by: request.user.username },
        'blocklist entry removed',
      );
      return reply.code(204).send();
    },
  );
};
