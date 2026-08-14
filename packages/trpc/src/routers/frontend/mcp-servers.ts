import {
  BulkImportMcpServersRequestSchema,
  BulkImportMcpServersResponseSchema,
  CreateMcpServerRequestSchema,
  CreateMcpServerResponseSchema,
  DeleteMcpServerResponseSchema,
  GetMcpServerResponseSchema,
  ListMcpServersResponseSchema,
  ReconnectMcpServerRequestSchema,
  ReconnectMcpServerResponseSchema,
  UpdateMcpServerRequestSchema,
  UpdateMcpServerResponseSchema,
} from "@repo/zod-types";
import { z } from "zod";

import {
  adminProcedure,
  type AuditActor,
  auditActor,
  protectedProcedure,
  router,
} from "../../trpc";

// Define the MCP servers router with procedure definitions
// The actual implementation will be provided by the backend
export const createMcpServersRouter = (
  // These are the implementation functions that the backend will provide
  implementations: {
    create: (
      input: z.infer<typeof CreateMcpServerRequestSchema>,
      userId: string,
      actor: AuditActor,
    ) => Promise<z.infer<typeof CreateMcpServerResponseSchema>>;
    // `isAdmin` decides whether the serialized servers keep their connection
    // URL and credential fields (env / bearerToken / headers / command /
    // args) or come back redacted. It is threaded from `ctx.user.role` at
    // the call site below rather than re-derived in the impl, so the RBAC
    // source of truth stays the session role that `adminProcedure` uses.
    list: (
      userId: string,
      isAdmin: boolean,
    ) => Promise<z.infer<typeof ListMcpServersResponseSchema>>;
    bulkImport: (
      input: z.infer<typeof BulkImportMcpServersRequestSchema>,
      userId: string,
      actor: AuditActor,
    ) => Promise<z.infer<typeof BulkImportMcpServersResponseSchema>>;
    get: (
      input: {
        uuid: string;
      },
      userId: string,
      isAdmin: boolean,
    ) => Promise<z.infer<typeof GetMcpServerResponseSchema>>;
    delete: (
      input: {
        uuid: string;
      },
      userId: string,
      actor: AuditActor,
    ) => Promise<z.infer<typeof DeleteMcpServerResponseSchema>>;
    update: (
      input: z.infer<typeof UpdateMcpServerRequestSchema>,
      userId: string,
      actor: AuditActor,
    ) => Promise<z.infer<typeof UpdateMcpServerResponseSchema>>;
    reconnect: (
      input: z.infer<typeof ReconnectMcpServerRequestSchema>,
      userId: string,
    ) => Promise<z.infer<typeof ReconnectMcpServerResponseSchema>>;
  },
) => {
  return router({
    // Protected (deliberate): members legitimately see the server inventory
    // in their dashboard, so this stays protectedProcedure. The disclosure
    // fix is redaction inside the serializer, driven by the flag below —
    // admin-gating the whole list would blank the member UI instead.
    list: protectedProcedure
      .output(ListMcpServersResponseSchema)
      .query(async ({ ctx }) => {
        return await implementations.list(
          ctx.user.id,
          ctx.user.role === "admin",
        );
      }),

    // Protected: Get single MCP server by UUID — same contract as `list`.
    get: protectedProcedure
      .input(z.object({ uuid: z.string() }))
      .output(GetMcpServerResponseSchema)
      .query(async ({ input, ctx }) => {
        return await implementations.get(
          input,
          ctx.user.id,
          ctx.user.role === "admin",
        );
      }),

    // Admin only: Create MCP server
    create: adminProcedure
      .input(CreateMcpServerRequestSchema)
      .output(CreateMcpServerResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return await implementations.create(
          input,
          ctx.user.id,
          auditActor(ctx),
        );
      }),

    // Admin only: Bulk import MCP servers. Gated even though the brief names
    // "create/update/delete" — bulkImport is a create path, so leaving it on
    // protectedProcedure would let a member mint servers and bypass the
    // create gate entirely, defeating the control.
    bulkImport: adminProcedure
      .input(BulkImportMcpServersRequestSchema)
      .output(BulkImportMcpServersResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return await implementations.bulkImport(
          input,
          ctx.user.id,
          auditActor(ctx),
        );
      }),

    // Admin only: Delete MCP server
    delete: adminProcedure
      .input(z.object({ uuid: z.string() }))
      .output(DeleteMcpServerResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return await implementations.delete(
          input,
          ctx.user.id,
          auditActor(ctx),
        );
      }),

    // Admin only: Update MCP server
    update: adminProcedure
      .input(UpdateMcpServerRequestSchema)
      .output(UpdateMcpServerResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return await implementations.update(
          input,
          ctx.user.id,
          auditActor(ctx),
        );
      }),

    // Protected (deliberate): Reconnect MCP server (drop pooled upstream
    // connection so tools re-list on next request — no gateway restart
    // required). Operational nudge, not a config mutation — do not fold into
    // the RBAC gate above.
    reconnect: protectedProcedure
      .input(ReconnectMcpServerRequestSchema)
      .output(ReconnectMcpServerResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return await implementations.reconnect(input, ctx.user.id);
      }),
  });
};
