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
  isAdminUser,
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
    ) => Promise<z.infer<typeof CreateMcpServerResponseSchema>>;
    list: (
      userId: string,
      includeSecrets: boolean,
    ) => Promise<z.infer<typeof ListMcpServersResponseSchema>>;
    bulkImport: (
      input: z.infer<typeof BulkImportMcpServersRequestSchema>,
      userId: string,
    ) => Promise<z.infer<typeof BulkImportMcpServersResponseSchema>>;
    get: (
      input: {
        uuid: string;
      },
      userId: string,
      includeSecrets: boolean,
    ) => Promise<z.infer<typeof GetMcpServerResponseSchema>>;
    delete: (
      input: {
        uuid: string;
      },
      userId: string,
    ) => Promise<z.infer<typeof DeleteMcpServerResponseSchema>>;
    update: (
      input: z.infer<typeof UpdateMcpServerRequestSchema>,
      userId: string,
    ) => Promise<z.infer<typeof UpdateMcpServerResponseSchema>>;
    reconnect: (
      input: z.infer<typeof ReconnectMcpServerRequestSchema>,
      userId: string,
    ) => Promise<z.infer<typeof ReconnectMcpServerResponseSchema>>;
  },
) => {
  return router({
    // Protected: List all MCP servers. Stays member-readable — the sidebar,
    // the namespace editor and the inspector all need the server catalogue —
    // but `includeSecrets` is false for anyone who is not an admin, so the
    // upstream credential columns (env / bearerToken / headers) never reach a
    // member. The role check lives here, in the RBAC layer, rather than in the
    // implementation: the impl takes a decided boolean and cannot get the
    // policy wrong.
    list: protectedProcedure
      .output(ListMcpServersResponseSchema)
      .query(async ({ ctx }) => {
        return await implementations.list(ctx.user.id, isAdminUser(ctx.user));
      }),

    // Protected: Get single MCP server by UUID. Same redaction as `list`.
    get: protectedProcedure
      .input(z.object({ uuid: z.string() }))
      .output(GetMcpServerResponseSchema)
      .query(async ({ input, ctx }) => {
        return await implementations.get(
          input,
          ctx.user.id,
          isAdminUser(ctx.user),
        );
      }),

    // Admin only: Create MCP server
    create: adminProcedure
      .input(CreateMcpServerRequestSchema)
      .output(CreateMcpServerResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return await implementations.create(input, ctx.user.id);
      }),

    // Admin only: Bulk import MCP servers. Gated even though the brief names
    // "create/update/delete" — bulkImport is a create path, so leaving it on
    // protectedProcedure would let a member mint servers and bypass the
    // create gate entirely, defeating the control.
    bulkImport: adminProcedure
      .input(BulkImportMcpServersRequestSchema)
      .output(BulkImportMcpServersResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return await implementations.bulkImport(input, ctx.user.id);
      }),

    // Admin only: Delete MCP server
    delete: adminProcedure
      .input(z.object({ uuid: z.string() }))
      .output(DeleteMcpServerResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return await implementations.delete(input, ctx.user.id);
      }),

    // Admin only: Update MCP server
    update: adminProcedure
      .input(UpdateMcpServerRequestSchema)
      .output(UpdateMcpServerResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return await implementations.update(input, ctx.user.id);
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
