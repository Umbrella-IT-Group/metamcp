import {
  CreateNamespaceRequestSchema,
  CreateNamespaceResponseSchema,
  DeleteNamespaceResponseSchema,
  GetNamespaceResponseSchema,
  GetNamespaceToolsRequestSchema,
  GetNamespaceToolsResponseSchema,
  ListNamespacesResponseSchema,
  RefreshNamespaceToolsRequestSchema,
  RefreshNamespaceToolsResponseSchema,
  UpdateNamespaceRequestSchema,
  UpdateNamespaceResponseSchema,
  UpdateNamespaceServerStatusRequestSchema,
  UpdateNamespaceServerStatusResponseSchema,
  UpdateNamespaceToolOverridesRequestSchema,
  UpdateNamespaceToolOverridesResponseSchema,
  UpdateNamespaceToolStatusRequestSchema,
  UpdateNamespaceToolStatusResponseSchema,
} from "@repo/zod-types";
import { z } from "zod";

import {
  adminProcedure,
  type AuditActor,
  auditActor,
  protectedProcedure,
  router,
} from "../../trpc";

// Define the namespaces router with procedure definitions
// The actual implementation will be provided by the backend
export const createNamespacesRouter = (
  // These are the implementation functions that the backend will provide
  implementations: {
    create: (
      input: z.infer<typeof CreateNamespaceRequestSchema>,
      userId: string,
      actor: AuditActor,
    ) => Promise<z.infer<typeof CreateNamespaceResponseSchema>>;
    list: (
      userId: string,
    ) => Promise<z.infer<typeof ListNamespacesResponseSchema>>;
    // `isAdmin`: the namespace response embeds full server objects, so it
    // carries the same connection-URL / credential redaction contract as the
    // mcpServers router. Threaded from `ctx.user.role` at the call site.
    get: (
      input: {
        uuid: string;
      },
      userId: string,
      isAdmin: boolean,
    ) => Promise<z.infer<typeof GetNamespaceResponseSchema>>;
    getTools: (
      input: z.infer<typeof GetNamespaceToolsRequestSchema>,
      userId: string,
    ) => Promise<z.infer<typeof GetNamespaceToolsResponseSchema>>;
    delete: (
      input: {
        uuid: string;
      },
      userId: string,
      actor: AuditActor,
    ) => Promise<z.infer<typeof DeleteNamespaceResponseSchema>>;
    update: (
      input: z.infer<typeof UpdateNamespaceRequestSchema>,
      userId: string,
      actor: AuditActor,
    ) => Promise<z.infer<typeof UpdateNamespaceResponseSchema>>;
    updateServerStatus: (
      input: z.infer<typeof UpdateNamespaceServerStatusRequestSchema>,
      userId: string,
      actor: AuditActor,
    ) => Promise<z.infer<typeof UpdateNamespaceServerStatusResponseSchema>>;
    updateToolStatus: (
      input: z.infer<typeof UpdateNamespaceToolStatusRequestSchema>,
      userId: string,
      actor: AuditActor,
    ) => Promise<z.infer<typeof UpdateNamespaceToolStatusResponseSchema>>;
    updateToolOverrides: (
      input: z.infer<typeof UpdateNamespaceToolOverridesRequestSchema>,
      userId: string,
      actor: AuditActor,
    ) => Promise<z.infer<typeof UpdateNamespaceToolOverridesResponseSchema>>;
    // `isAdmin` decides whether a PUBLIC (unowned) namespace may be
    // refreshed, for the reason spelled out at the procedure below. Threaded
    // from `ctx.user.role` at the call site, like `get`'s flag above.
    refreshTools: (
      input: z.infer<typeof RefreshNamespaceToolsRequestSchema>,
      userId: string,
      isAdmin: boolean,
    ) => Promise<z.infer<typeof RefreshNamespaceToolsResponseSchema>>;
  },
) => {
  return router({
    // Protected: List all namespaces
    list: protectedProcedure
      .output(ListNamespacesResponseSchema)
      .query(async ({ ctx }) => {
        return await implementations.list(ctx.user.id);
      }),

    // Protected: Get single namespace by UUID
    get: protectedProcedure
      .input(z.object({ uuid: z.string() }))
      .output(GetNamespaceResponseSchema)
      .query(async ({ input, ctx }) => {
        return await implementations.get(
          input,
          ctx.user.id,
          ctx.user.role === "admin",
        );
      }),

    // Protected: Get tools for namespace from mapping table
    getTools: protectedProcedure
      .input(GetNamespaceToolsRequestSchema)
      .output(GetNamespaceToolsResponseSchema)
      .query(async ({ input, ctx }) => {
        return await implementations.getTools(input, ctx.user.id);
      }),

    // Admin only: Create namespace
    create: adminProcedure
      .input(CreateNamespaceRequestSchema)
      .output(CreateNamespaceResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return await implementations.create(
          input,
          ctx.user.id,
          auditActor(ctx),
        );
      }),

    // Admin only: Delete namespace
    delete: adminProcedure
      .input(z.object({ uuid: z.string() }))
      .output(DeleteNamespaceResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return await implementations.delete(
          input,
          ctx.user.id,
          auditActor(ctx),
        );
      }),

    // Admin only: Update namespace
    update: adminProcedure
      .input(UpdateNamespaceRequestSchema)
      .output(UpdateNamespaceResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return await implementations.update(
          input,
          ctx.user.id,
          auditActor(ctx),
        );
      }),

    // Admin only: Update server status within namespace. This is namespace
    // CURATION — it changes which servers' tools an agent sees through the
    // namespace, the same "destructive update" class as create/update/delete
    // above, so it gets the same gate.
    updateServerStatus: adminProcedure
      .input(UpdateNamespaceServerStatusRequestSchema)
      .output(UpdateNamespaceServerStatusResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return await implementations.updateServerStatus(
          input,
          ctx.user.id,
          auditActor(ctx),
        );
      }),

    // Admin only: Update tool status within namespace. Curation, same
    // reasoning as updateServerStatus.
    updateToolStatus: adminProcedure
      .input(UpdateNamespaceToolStatusRequestSchema)
      .output(UpdateNamespaceToolStatusResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return await implementations.updateToolStatus(
          input,
          ctx.user.id,
          auditActor(ctx),
        );
      }),

    // Admin only: Update tool overrides within namespace. Curation, same
    // reasoning as updateServerStatus.
    updateToolOverrides: adminProcedure
      .input(UpdateNamespaceToolOverridesRequestSchema)
      .output(UpdateNamespaceToolOverridesResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return await implementations.updateToolOverrides(
          input,
          ctx.user.id,
          auditActor(ctx),
        );
      }),

    // Protected (deliberate) at the PROCEDURE level so a non-admin owner can
    // still refresh a namespace they own — but the "not a config mutation"
    // half of the old note here was wrong, and the impl now enforces the
    // correction. The tools in the input are caller-supplied, and the impl
    // upserts their description and inputSchema into the shared `tools`
    // catalog and writes ACTIVE namespace tool mappings from them, so a
    // caller who can reach it for a namespace can rewrite what downstream
    // MCP clients are told a tool does and re-activate mappings that
    // `updateToolStatus` (adminProcedure) had switched off. On a PUBLIC
    // namespace the impl's ownership test is vacuous, so the role is what
    // has to decide it — threaded below, same shape as `reconnect` on the
    // mcpServers router.
    refreshTools: protectedProcedure
      .input(RefreshNamespaceToolsRequestSchema)
      .output(RefreshNamespaceToolsResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return await implementations.refreshTools(
          input,
          ctx.user.id,
          ctx.user.role === "admin",
        );
      }),
  });
};
