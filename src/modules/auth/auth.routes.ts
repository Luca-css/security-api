import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { NotFoundError } from '../../lib/errors.js';
import type { AuthService } from './auth.service.js';
import {
  createUserBodySchema,
  loginBodySchema,
  loginResponseSchema,
  publicUserSchema,
} from './auth.schemas.js';

export interface AuthRoutesOptions {
  authService: AuthService;
  tokenExpiresIn: string;
  loginRateLimitMax: number;
}

export const authRoutes: FastifyPluginAsyncZod<AuthRoutesOptions> = async (app, opts) => {
  const { authService, tokenExpiresIn } = opts;

  app.post(
    '/login',
    {
      // Stricter limit on login to slow down brute force / credential stuffing.
      config: { rateLimit: { max: opts.loginRateLimitMax, timeWindow: '1 minute' } },
      schema: {
        tags: ['auth'],
        summary: 'Exchange username/password for a JWT access token',
        body: loginBodySchema,
        response: { 200: loginResponseSchema },
      },
    },
    async (request) => {
      const user = await authService.authenticate(request.body.username, request.body.password);
      const accessToken = app.jwt.sign(
        { sub: user.id, username: user.username, role: user.role },
        { expiresIn: tokenExpiresIn },
      );
      request.log.info({ userId: user.id }, 'user logged in');
      return { accessToken, tokenType: 'Bearer' as const, expiresIn: tokenExpiresIn };
    },
  );

  app.get(
    '/me',
    {
      onRequest: app.requireRole('admin', 'analyst'),
      schema: {
        tags: ['auth'],
        summary: 'Current authenticated user',
        security: [{ bearerAuth: [] }],
        response: { 200: publicUserSchema },
      },
    },
    async (request) => {
      const user = await authService.getById(request.user.sub);
      if (!user) throw new NotFoundError('User', request.user.sub);
      return user;
    },
  );

  app.post(
    '/users',
    {
      onRequest: app.requireRole('admin'),
      schema: {
        tags: ['auth'],
        summary: 'Create a user (admin only)',
        security: [{ bearerAuth: [] }],
        body: createUserBodySchema,
        response: { 201: publicUserSchema },
      },
    },
    async (request, reply) => {
      const user = await authService.createUser(request.body);
      return reply.code(201).send(user);
    },
  );
};
