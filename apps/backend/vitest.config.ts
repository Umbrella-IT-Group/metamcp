import path from "node:path";

import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      // Mirror the tsconfig.json `paths` mapping so unit tests can
      // import modules that use the `@/` prefix without each test
      // having to hand-mock every transitive logger / utils import.
      "@": path.resolve(__dirname, "./src"),
    },
  },
  test: {
    globals: true,
    environment: "node",
    // The conformance harness's loopback-socket tests (SDK client and server
    // pairs, a streaming proxy) run in the conformance job through
    // `pnpm test:conformance`, so a flake there cannot block an unrelated merge
    // in this required job. Its pure tests stay in the default run.
    exclude: [...configDefaults.exclude, "src/conformance/**/*.net.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      exclude: [
        "node_modules/",
        "dist/",
        "**/*.config.ts",
        "**/*.spec.ts",
        "**/*.test.ts",
      ],
    },
  },
});
