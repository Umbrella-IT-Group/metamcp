// Export tRPC setup
export {
  protectedProcedure,
  adminProcedure,
  requireAdmin,
  publicProcedure,
  router,
  baseProcedure,
  createTRPCRouter,
  auditActor,
  setTrpcAuditSink,
  ADMIN_PLANE_FORBIDDEN_MESSAGE,
  ADMIN_PLANE_HUMAN_ONLY_PROCEDURES,
  ADMIN_PLANE_OPERATOR_CONFIRMATIONS,
  ADMIN_PLANE_OPERATOR_CONTRACT_VERSION,
  ADMIN_PLANE_OPERATOR_MUTATIONS,
  ADMIN_PLANE_OPERATOR_PROCEDURES,
  ADMIN_PLANE_SYNC_PROCEDURES,
  adminPlaneOrigin,
  adminPlaneScopeOf,
  assertAdminPlaneProcedureAllowed,
  CHANGE_CONTEXT_REFUSALS,
  CHANGE_REASON_MAX_LENGTH,
  CHANGE_RUN_ID_MAX_LENGTH,
  changeContextForCall,
  changeContextOf,
} from "./trpc";
export type {
  AdminPlaneAuthOrigin,
  AdminPlaneScope,
  AuditActor,
  AuditRequestContext,
  BaseContext,
  ChangeContext,
  TrpcAuditSink,
  TrpcDenialEvent,
} from "./trpc";

// Export router creators
export { createAppRouter, createFrontendRouter } from "./router";
export { createMcpServersRouter } from "./routers/frontend";
// Additional router-creator exports so backend RBAC tests can drive the real
// routers (with a mocked implementations stub) through a real tRPC caller —
// same pattern the pre-existing createMcpServersRouter export enables,
// rather than re-deriving each gate against a synthetic router.
export {
  createAccessGroupsRouter,
  createApiKeysRouter,
  createAuditRouter,
  createEndpointPresentationRouter,
  createEndpointsRouter,
  createNamespacesRouter,
  createConfigRouter,
  createToolsRouter,
  createLogsRouter,
  createOAuthRouter,
  createOAuthClientsRouter,
  createOAuthTokensRouter,
  createUsersRouter,
} from "./routers/frontend";

// Export all zod types for convenience
export * from "@repo/zod-types";
