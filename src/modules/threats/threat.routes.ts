import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { idParamsSchema } from '../../shared/schemas.js';
import type { ThreatService } from './threat.service.js';
import {
  createThreatBodySchema,
  listThreatsQuerySchema,
  threatListResponseSchema,
  threatSchema,
} from './threat.schemas.js';

export interface ThreatRoutesOptions {
  threatService: ThreatService;
}

export const threatRoutes: FastifyPluginAsyncZod<ThreatRoutesOptions> = async (app, opts) => {
  const { threatService } = opts;
  const anyRole = app.requireRole('admin', 'analyst');
  const adminOnly = app.requireRole('admin');
  const common = { tags: ['threats'], security: [{ bearerAuth: [] }] };

  app.get(
    '/',
    {
      onRequest: anyRole,
      schema: {
        ...common,
        summary: 'List threats (newest first)',
        querystring: listThreatsQuerySchema,
        response: { 200: threatListResponseSchema },
      },
    },
    async (request) => {
      const { limit, offset } = request.query;
      const page = await threatService.list(request.query);
      return { data: page.items, meta: { total: page.total, limit, offset } };
    },
  );

  app.get(
    '/:id',
    {
      onRequest: anyRole,
      schema: {
        ...common,
        summary: 'Get a threat by id',
        params: idParamsSchema,
        response: { 200: threatSchema },
      },
    },
    async (request) => threatService.getById(request.params.id),
  );

  app.post(
    '/',
    {
      onRequest: anyRole,
      schema: {
        ...common,
        summary: 'Register a new threat',
        body: createThreatBodySchema,
        response: { 201: threatSchema },
      },
    },
    async (request, reply) => {
      const threat = await threatService.create(request.body, request.user.username);
      return reply.code(201).send(threat);
    },
  );

  app.patch(
    '/:id/resolve',
    {
      onRequest: anyRole,
      schema: {
        ...common,
        summary: 'Mark a threat as resolved',
        params: idParamsSchema,
        response: { 200: threatSchema },
      },
    },
    async (request) => threatService.resolve(request.params.id, request.user.username),
  );

  app.delete(
    '/:id',
    {
      onRequest: adminOnly,
      schema: { ...common, summary: 'Delete a threat (admin only)', params: idParamsSchema },
    },
    async (request, reply) => {
      await threatService.delete(request.params.id);
      return reply.code(204).send();
    },
  );
};
