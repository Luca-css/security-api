import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { idParamsSchema } from '../../shared/schemas.js';
import type { AlertService } from './alert.service.js';
import {
  alertListResponseSchema,
  alertSchema,
  createAlertBodySchema,
  listAlertsQuerySchema,
} from './alert.schemas.js';

export interface AlertRoutesOptions {
  alertService: AlertService;
}

export const alertRoutes: FastifyPluginAsyncZod<AlertRoutesOptions> = async (app, opts) => {
  const { alertService } = opts;
  const anyRole = app.requireRole('admin', 'analyst');
  const adminOnly = app.requireRole('admin');
  const common = { tags: ['alerts'], security: [{ bearerAuth: [] }] };

  app.get(
    '/',
    {
      onRequest: anyRole,
      schema: {
        ...common,
        summary: 'List alerts (most severe first)',
        querystring: listAlertsQuerySchema,
        response: { 200: alertListResponseSchema },
      },
    },
    async (request) => {
      const { limit, offset } = request.query;
      const page = await alertService.list(request.query);
      return { data: page.items, meta: { total: page.total, limit, offset } };
    },
  );

  app.get(
    '/:id',
    {
      onRequest: anyRole,
      schema: {
        ...common,
        summary: 'Get an alert by id',
        params: idParamsSchema,
        response: { 200: alertSchema },
      },
    },
    async (request) => alertService.getById(request.params.id),
  );

  app.post(
    '/',
    {
      onRequest: anyRole,
      schema: {
        ...common,
        summary: 'Create an alert',
        body: createAlertBodySchema,
        response: { 201: alertSchema },
      },
    },
    async (request, reply) => {
      const alert = await alertService.create(request.body, request.user.username);
      return reply.code(201).send(alert);
    },
  );

  app.patch(
    '/:id/resolve',
    {
      onRequest: anyRole,
      schema: {
        ...common,
        summary: 'Mark an alert as resolved',
        params: idParamsSchema,
        response: { 200: alertSchema },
      },
    },
    async (request) => alertService.resolve(request.params.id, request.user.username),
  );

  app.delete(
    '/:id',
    {
      onRequest: adminOnly,
      schema: { ...common, summary: 'Delete an alert (admin only)', params: idParamsSchema },
    },
    async (request, reply) => {
      await alertService.delete(request.params.id);
      return reply.code(204).send();
    },
  );
};
