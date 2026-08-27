import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    reporters: ['default'],
    env: {
      // The structured logger writes to stdout, so a suite that exercises the
      // advisory lookup or the webhook path buries the test report in JSON log
      // lines. Raising the threshold keeps the report readable; set
      // LOG_LEVEL=debug when a test needs the log output to diagnose something.
      LOG_LEVEL: 'error',
    },
  },
});
