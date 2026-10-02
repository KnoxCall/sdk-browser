import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      // Resolve the workspace peer against its source so tests run without a
      // prior `@knoxcall/browser` build (mirrors tsconfig.test.json paths).
      '@knoxcall/browser': fileURLToPath(new URL('../knoxcall-browser/src/index.ts', import.meta.url)),
    },
  },
  test: {
    include: ['test/**/*.test.{ts,tsx}'],
    environment: 'jsdom',
    // See the root vitest.config.ts: vitest's 5s default is a wall-clock bound
    // that measures the runner, not the code. 30s matches every other config in
    // the repo; no assertion is relaxed, only the hang-detector moves.
    // Guard: tests/coverage/vitest-timeout-parity-coverage.test.ts.
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
