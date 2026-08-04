import path from "node:path";

import { defineConfig } from "vitest/config";

// Mirrors apps/backend/vitest.config.ts — same shape, same `@/` alias
// resolution as tsconfig.json `paths`, so a frontend unit test can import
// modules that use the `@/` prefix.
export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./"),
    },
  },
  test: {
    globals: true,
    environment: "node",
  },
});
