// Export tRPC setup
export {
  protectedProcedure,
  adminProcedure,
  requireAdmin,
  publicProcedure,
  router,
  baseProcedure,
  createTRPCRouter,
} from "./trpc";
export type { BaseContext } from "./trpc";

// Export router creators
export { createAppRouter, createFrontendRouter } from "./router";
export { createMcpServersRouter } from "./routers/frontend";
// Additional router-creator exports so backend RBAC tests can drive the real
// routers (with a mocked implementations stub) through a real tRPC caller —
// same pattern the pre-existing createMcpServersRouter export enables,
// rather than re-deriving each gate against a synthetic router.
export {
  createNamespacesRouter,
  createConfigRouter,
  createToolsRouter,
  createLogsRouter,
  createOAuthRouter,
} from "./routers/frontend";

// Export all zod types for convenience
export * from "@repo/zod-types";
