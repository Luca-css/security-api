import fastifyRateLimit from '@fastify/rate-limit';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import { TooManyRequestsError } from '../lib/errors.js';

export interface RateLimitPluginOptions {
  max: number;
  timeWindowMs: number;
}

/**
 * Per-IP rate limiting (key = request.ip).
 *
 * The limiter is added as an instance-level onRequest hook rather than the plugin's
 * per-route hook. Instance hooks run before route hooks, so requests are counted even
 * when they are later rejected by auth (401/403) or are unknown routes (404). Otherwise an
 * attacker could hammer protected endpoints without a token and never be limited.
 *
 * Routes can opt out with `config.rateLimit: false` (health check) or declare their own
 * limit via `config.rateLimit` (login). A route-specific limiter is attached by the plugin as
 * a route hook, so such routes must not have auth hooks that could reject first.
 *
 * The store is in-memory, so limits are per process: running several replicas would need
 * a shared store such as Redis.
 */
export const rateLimitPlugin = fp(async (app: FastifyInstance, opts: RateLimitPluginOptions) => {
  await app.register(fastifyRateLimit, {
    global: false,
    errorResponseBuilder: (_request, context) =>
      new TooManyRequestsError(`Rate limit exceeded, retry in ${context.after}`),
  });

  const globalLimiter = app.rateLimit({ max: opts.max, timeWindow: opts.timeWindowMs });

  app.addHook('onRequest', async (request: FastifyRequest, reply: FastifyReply) => {
    const routeLimit = request.routeOptions.config?.rateLimit;
    // false = opted out; object = the plugin attaches that route's own (stricter) limiter.
    if (routeLimit === false || typeof routeLimit === 'object') return;
    await globalLimiter.call(app, request, reply);
  });
});
