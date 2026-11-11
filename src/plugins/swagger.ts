import fastifySwagger from '@fastify/swagger';
import fastifySwaggerUi from '@fastify/swagger-ui';
import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import { jsonSchemaTransform } from 'fastify-type-provider-zod';

/** OpenAPI 3 document generated from the zod route schemas; UI served at /docs. */
export const swaggerPlugin = fp(async (app: FastifyInstance) => {
  await app.register(fastifySwagger, {
    openapi: {
      info: {
        title: 'Security API',
        description:
          'Threats, alerts and IP blocklist management with JWT auth, RBAC and rate limiting.',
        version: '2.0.0',
      },
      components: {
        securitySchemes: {
          bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
        },
      },
      tags: [
        { name: 'auth', description: 'Login and user management' },
        { name: 'threats', description: 'Detected threats' },
        { name: 'alerts', description: 'Operational/security alerts' },
        { name: 'blocklist', description: 'IP / CIDR blocklist (enforced on every request)' },
        { name: 'system', description: 'Health' },
      ],
    },
    transform: jsonSchemaTransform,
  });

  await app.register(fastifySwaggerUi, {
    routePrefix: '/docs',
    staticCSP: true,
  });
});
