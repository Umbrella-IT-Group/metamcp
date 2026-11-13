import path from "node:path";

import { defineConfig } from "vitest/config";

// The loopback-socket tests of the conformance harness. They are excluded from
// the default `vitest run` (see vitest.config.ts) so the required unit job keeps
// only the pure tests; the conformance workflow runs these before the suite.
export default defineConfig({
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  test: {
    include: ["src/conformance/**/*.net.test.ts"],
    environment: "node",
  },
});
