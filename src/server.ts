import { existsSync } from 'node:fs';
import { buildApp } from './app.js';
import { loadConfig } from './config/env.js';

// Load .env for local development (Node >= 21.7). In containers, env vars come from the runtime.
if (existsSync('.env')) {
  process.loadEnvFile('.env');
}

const config = loadConfig();
const app = await buildApp(config);

const shutdown = (signal: string) => {
  app.log.info({ signal }, 'shutting down');
  app.close().then(
    () => process.exit(0),
    (error: unknown) => {
      app.log.error({ err: error }, 'error during shutdown');
      process.exit(1);
    },
  );
};
process.once('SIGINT', shutdown);
process.once('SIGTERM', shutdown);

try {
  await app.listen({ host: config.HOST, port: config.PORT });
  app.log.info(`API docs available at http://localhost:${config.PORT}/docs`);
} catch (error) {
  app.log.fatal({ err: error }, 'failed to start');
  process.exit(1);
}
