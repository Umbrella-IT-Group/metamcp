import {
  CreateToolRequestSchema,
  GetToolsByMcpServerUuidRequestSchema,
} from "@repo/zod-types";

import {
  adminProcedure,
  type AuditActor,
  auditActor,
  protectedProcedure,
  router,
} from "../../trpc";

export const createToolsRouter = <
  TImplementations extends {
    // `userId` is threaded from `ctx.user.id` so the impl can scope the tool
    // catalog to servers the caller owns or public servers, the same
    // own-plus-public contract as `mcpServers.get`. Without it any member who
    // learns a private server's UUID could read that server's full tool
    // catalog.
    getByMcpServerUuid: (input: any, userId: string) => Promise<any>;
    create: (input: any, actor: AuditActor) => Promise<any>;
    sync: (input: any, actor: AuditActor) => Promise<any>;
  },
>(
  implementations: TImplementations,
) => {
  return router({
    // Protected: Get tools by MCP server UUID, scoped to the caller in the impl.
    getByMcpServerUuid: protectedProcedure
      .input(GetToolsByMcpServerUuidRequestSchema)
      .query(async ({ input, ctx }) => {
        return implementations.getByMcpServerUuid(input, ctx.user.id);
      }),

    // Admin only: Save tools to database (upsert only, no cleanup). Curation
    // class, same rationale as namespaces.updateToolStatus — writes to the
    // shared tools catalog. NOTE: namespaces.refreshTools does NOT route
    // through this procedure — it calls toolsRepository.bulkUpsert directly
    // from namespaces.impl.ts, bypassing tRPC entirely, so this gate never
    // covers that path. It no longer has to for the case that mattered: the
    // impl now requires admin to refresh a PUBLIC namespace, so the only
    // caller reaching those writes without this gate is a namespace's own
    // (possibly non-admin) OWNER, on their own namespace.
    create: adminProcedure
      .input(CreateToolRequestSchema)
      .mutation(async ({ input, ctx }) => {
        return implementations.create(input, auditActor(ctx));
      }),

    // Admin only: Sync tools with cleanup (removes obsolete tools). Same
    // rationale and refreshTools independence as create() above.
    sync: adminProcedure
      .input(CreateToolRequestSchema)
      .mutation(async ({ input, ctx }) => {
        return implementations.sync(input, auditActor(ctx));
      }),
  });
};
