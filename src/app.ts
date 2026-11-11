import fastifyCors from '@fastify/cors';
import fastifyHelmet from '@fastify/helmet';
import Fastify, { type FastifyInstance } from 'fastify';
import {
  serializerCompiler,
  validatorCompiler,
  type ZodTypeProvider,
} from 'fastify-type-provider-zod';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { AppConfig } from './config/env.js';
import { openDatabase } from './db/database.js';
import { runMigrations } from './db/migrate.js';
import { seedDemoData } from './db/seed.js';
import { SqliteAlertRepository } from './modules/alerts/alert.repository.js';
import { alertRoutes } from './modules/alerts/alert.routes.js';
import { AlertService } from './modules/alerts/alert.service.js';
import { authRoutes } from './modules/auth/auth.routes.js';
import { AuthService } from './modules/auth/auth.service.js';
import { SqliteUserRepository } from './modules/auth/user.repository.js';
import { SqliteBlocklistRepository } from './modules/blocklist/blocklist.repository.js';
import { blocklistRoutes } from './modules/blocklist/blocklist.routes.js';
import { BlocklistService } from './modules/blocklist/blocklist.service.js';
import { SqliteThreatRepository } from './modules/threats/threat.repository.js';
import { threatRoutes } from './modules/threats/threat.routes.js';
import { ThreatService } from './modules/threats/threat.service.js';
import { authPlugin } from './plugins/auth.js';
import { blocklistGuardPlugin } from './plugins/blocklist-guard.js';
import { errorHandlerPlugin } from './plugins/error-handler.js';
import { rateLimitPlugin } from './plugins/rate-limit.js';
import { swaggerPlugin } from './plugins/swagger.js';

function loggerOptions(config: AppConfig) {
  return {
    level: config.LOG_LEVEL,
    // Never write credentials to logs.
    redact: ['req.headers.authorization', 'req.headers.cookie'],
    ...(config.NODE_ENV === 'development' && {
      transport: { target: 'pino-pretty', options: { translateTime: 'SYS:HH:MM:ss' } },
    }),
  };
}

/**
 * Composition root: wires database -> repositories -> services -> plugins/routes.
 * Tests call buildApp() with a config pointing at an in-memory database.
 */
export async function buildApp(config: AppConfig): Promise<FastifyInstance> {
  const app = Fastify({
    logger: loggerOptions(config),
    trustProxy: config.TRUST_PROXY,
    genReqId: () => randomUUID(),
  }).withTypeProvider<ZodTypeProvider>();

  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);

  // --- persistence ---------------------------------------------------------
  const db = openDatabase(config.DATABASE_PATH);
  runMigrations(db);
  app.addHook('onClose', () => db.close());

  // --- services --------------------------------------------------------------
  const authService = new AuthService(new SqliteUserRepository(db));
  const threatService = new ThreatService(new SqliteThreatRepository(db));
  const alertService = new AlertService(new SqliteAlertRepository(db));
  const blocklistService = new BlocklistService(new SqliteBlocklistRepository(db));
  await blocklistService.reload();

  if (await authService.ensureAdminUser(config.ADMIN_USERNAME, config.ADMIN_PASSWORD)) {
    app.log.info({ username: config.ADMIN_USERNAME }, 'initial admin user created');
  }
  if (
    config.SEED_DEMO_DATA &&
    (await seedDemoData({ threatService, alertService, blocklistService }))
  ) {
    app.log.info('demo data seeded');
  }

  // --- cross-cutting plugins (order matters: guard runs before rate limit) ---
  await app.register(errorHandlerPlugin);
  await app.register(fastifyHelmet);
  if (config.CORS_ORIGIN) {
    await app.register(fastifyCors, {
      origin: config.CORS_ORIGIN.split(',').map((origin) => origin.trim()),
    });
  }
  await app.register(blocklistGuardPlugin, { blocklistService });
  await app.register(rateLimitPlugin, {
    max: config.RATE_LIMIT_MAX,
    timeWindowMs: config.RATE_LIMIT_WINDOW_MS,
  });
  await app.register(authPlugin, { secret: config.JWT_SECRET });
  await app.register(swaggerPlugin);

  app.addHook('onSend', async (request, reply) => {
    reply.header('x-request-id', request.id);
  });

  // --- routes ------------------------------------------------------------------
  app.get(
    '/health',
    {
      config: { rateLimit: false },
      schema: {
        tags: ['system'],
        summary: 'Liveness/readiness check (also verifies the database)',
        response: {
          200: z.object({ status: z.literal('ok'), uptime: z.number(), timestamp: z.string() }),
        },
      },
    },
    async () => {
      db.prepare('SELECT 1').get();
      return {
        status: 'ok' as const,
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
      };
    },
  );

  await app.register(authRoutes, {
    prefix: '/api/v1/auth',
    authService,
    tokenExpiresIn: config.JWT_EXPIRES_IN,
    loginRateLimitMax: config.LOGIN_RATE_LIMIT_MAX,
  });
  await app.register(threatRoutes, { prefix: '/api/v1/threats', threatService });
  await app.register(alertRoutes, { prefix: '/api/v1/alerts', alertService });
  await app.register(blocklistRoutes, { prefix: '/api/v1/blocklist', blocklistService });

  return app;
}
