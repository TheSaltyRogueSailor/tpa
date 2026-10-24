import { defineConfig } from "vitest/config";

export default defineConfig({
  // The opt-in database suites share one disposable schema and reset it per test, so files run one at a time.
  test: { include: ["tests/**/*.test.ts"], environment: "node", globals: false, testTimeout: 10_000, fileParallelism: false },
});
