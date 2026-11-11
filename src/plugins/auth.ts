import fastifyJwt from '@fastify/jwt';
import type { FastifyInstance, FastifyRequest, onRequestAsyncHookHandler } from 'fastify';
import fp from 'fastify-plugin';
import { ForbiddenError, UnauthorizedError } from '../lib/errors.js';
import type { Role } from '../modules/auth/user.repository.js';

export interface TokenPayload {
  sub: string;
  username: string;
  role: Role;
}

declare module '@fastify/jwt' {
  interface FastifyJWT {
    payload: TokenPayload;
    user: TokenPayload;
  }
}

declare module 'fastify' {
  interface FastifyInstance {
    /**
     * Returns an onRequest hook that verifies the Bearer token and checks the role.
     * 401 = missing/invalid token, 403 = valid token but role not allowed.
     */
    requireRole(...roles: Role[]): onRequestAsyncHookHandler;
  }
}

export interface AuthPluginOptions {
  secret: string;
}

export const authPlugin = fp(async (app: FastifyInstance, opts: AuthPluginOptions) => {
  await app.register(fastifyJwt, {
    secret: opts.secret,
    sign: { algorithm: 'HS256' },
    // Pin the algorithm so tokens signed with anything else (e.g. "none") are rejected.
    verify: { algorithms: ['HS256'] },
  });

  app.decorate('requireRole', (...roles: Role[]): onRequestAsyncHookHandler => {
    return async (request: FastifyRequest) => {
      try {
        await request.jwtVerify();
      } catch {
        throw new UnauthorizedError('Missing, invalid or expired access token', 'INVALID_TOKEN');
      }
      if (!roles.includes(request.user.role)) {
        throw new ForbiddenError(`Requires role: ${roles.join(' or ')}`);
      }
    };
  });
});
