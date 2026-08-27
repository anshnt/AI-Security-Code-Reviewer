import { loadConfig, validateConfig } from './config';
import { createServer } from './server';
import { logger } from './util/logger';

function main(): void {
  const config = loadConfig();
  const problems = validateConfig(config);

  for (const problem of problems) logger.warn('configuration problem', { problem });
  // Refusing to start without a webhook secret is deliberate: an unauthenticated
  // webhook endpoint would let anyone make this service post comments as the
  // configured token holder.
  if (!config.github.webhookSecret && process.env.ALLOW_INSECURE_WEBHOOK !== 'true') {
    logger.error(
      'refusing to start without GITHUB_WEBHOOK_SECRET; set it, or set ALLOW_INSECURE_WEBHOOK=true to run the dashboard alone',
    );
    process.exit(1);
  }

  const { app, store } = createServer(config);

  const server = app.listen(config.port, () => {
    logger.info('listening', {
      port: config.port,
      dashboard: `${config.publicUrl}/`,
      webhook: `${config.publicUrl}/webhook`,
      failOnSeverity: config.review.failOnSeverity,
      minSeverity: config.review.minSeverity,
    });
  });

  const shutdown = (signal: string): void => {
    logger.info('shutting down', { signal });
    server.close(() => {
      store.close();
      process.exit(0);
    });
    // Do not hang forever on a stuck connection.
    setTimeout(() => process.exit(1), 10_000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('unhandledRejection', (reason) => {
    logger.error('unhandled rejection', { reason: String(reason) });
  });
}

main();
