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
  ResetMcpServerErrorsRequestSchema,
  ResetMcpServerErrorsResponseSchema,
  UpdateMcpServerAnyRequestSchema,
  UpdateMcpServerResponseSchema,
} from "@repo/zod-types";
import { z } from "zod";

import {
  adminProcedure,
  type AuditActor,
  auditActor,
  protectedProcedure,
  router,
  type ServerDetailLevel,
  serverDetailLevelOf,
} from "../../trpc";
import {
  type TopologyRemovalImplementations,
  topologyRemovalProcedures,
} from "./topology-removal";

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
    // `detail` decides how much of each server's stored connection the reply
    // carries (full for a person signed in as an administrator, names only for
    // an admin-plane key, nothing for a member). It is decided here, from the
    // verified request context (`serverDetailLevelOf`), and passed on as a
    // required argument: the implementation and the serializers have no
    // default, so a reply cannot carry a connection by omission. `create` and
    // `update` take the same decision from the actor they are given.
    list: (
      userId: string,
      detail: ServerDetailLevel,
    ) => Promise<z.infer<typeof ListMcpServersResponseSchema>>;
    // Every server regardless of owner; the caller id keeps another owner's
    // private rows redacted whatever the level, even in this admin inventory.
    listAll: (
      userId: string,
      detail: ServerDetailLevel,
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
      detail: ServerDetailLevel,
    ) => Promise<z.infer<typeof GetMcpServerResponseSchema>>;
    delete: (
      input: {
        uuid: string;
      },
      userId: string,
      actor: AuditActor,
    ) => Promise<z.infer<typeof DeleteMcpServerResponseSchema>>;
    update: (
      input: z.infer<typeof UpdateMcpServerAnyRequestSchema>,
      userId: string,
      actor: AuditActor,
    ) => Promise<z.infer<typeof UpdateMcpServerResponseSchema>>;
    // `isAdmin` decides whether a PUBLIC (unowned) server may be reconnected.
    // The impl's owner check can only compare `user_id` against the caller,
    // and a public server has none — so ownership alone cannot answer "may
    // this member drop every pooled connection to a shared server". Threaded
    // from `ctx.user.role` at the call site below, the same way `list`/`get`
    // thread theirs, rather than re-derived in the impl.
    reconnect: (
      input: z.infer<typeof ReconnectMcpServerRequestSchema>,
      userId: string,
      isAdmin: boolean,
    ) => Promise<z.infer<typeof ReconnectMcpServerResponseSchema>>;
    resetErrors: (
      input: z.infer<typeof ResetMcpServerErrorsRequestSchema>,
      actor: AuditActor,
    ) => Promise<z.infer<typeof ResetMcpServerErrorsResponseSchema>>;
  } & TopologyRemovalImplementations,
) => {
  return router({
    // Leaf-only removal by an admin or the operator key (see
    // ./topology-removal); the broad `delete` below stays human-only.
    ...topologyRemovalProcedures(implementations),

    // Protected (deliberate): members legitimately see the server inventory
    // in their dashboard, so this stays protectedProcedure. The disclosure
    // fix is redaction inside the serializer, driven by the level below —
    // admin-gating the whole list would blank the member UI instead.
    list: protectedProcedure
      .output(ListMcpServersResponseSchema)
      .query(async ({ ctx }) => {
        return await implementations.list(
          ctx.user.id,
          serverDetailLevelOf(ctx),
        );
      }),

    // Admin only: every server, whoever owns it, each row carrying its owner
    // in `user_id` (null = public). Deliberately NOT an admin branch inside
    // `list`: the platform's CI config sync matches servers by NAME over
    // `list`, and a private row owned by another user that shares a synced
    // server's name would become a match it could overwrite. `list` keeps its
    // public-plus-own result for every caller, admins included.
    listAll: adminProcedure
      .output(ListMcpServersResponseSchema)
      .query(async ({ ctx }) => {
        return await implementations.listAll(
          ctx.user.id,
          serverDetailLevelOf(ctx),
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
          serverDetailLevelOf(ctx),
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

    // Admin only: Update MCP server. Two request variants: the full one every
    // caller has always used (type plus a URL or command, and the rest), and a
    // strict metadata-only one (`metadata_only: true` with a name and/or a
    // description) that carries no connection field at all. An operator-scope
    // admin-plane key may send only the second; the implementation refuses the
    // first from it.
    update: adminProcedure
      .input(UpdateMcpServerAnyRequestSchema)
      .output(UpdateMcpServerResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return await implementations.update(
          input,
          ctx.user.id,
          auditActor(ctx),
        );
      }),

    // Admin only, and on the operator scope's set: clear the ERROR status of
    // one server (`serverUuid`) or of every server in ERROR. The tRPC twin of
    // the cookie-only REST route `POST /metamcp/:endpoint_name/admin/reset-errors`,
    // sharing its implementation (lib/metamcp/reset-server-errors): the status
    // change and its audit row commit together, an unknown server is
    // NOT_FOUND, and connection recovery starts only after the commit and is
    // reported apart from it. The REST route stays session-only, so an
    // admin-plane key reaches this action here and nowhere else.
    resetErrors: adminProcedure
      .input(ResetMcpServerErrorsRequestSchema)
      .output(ResetMcpServerErrorsResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return await implementations.resetErrors(input, auditActor(ctx));
      }),

    // Protected (deliberate): Reconnect MCP server (drop pooled upstream
    // connection so tools re-list on next request — no gateway restart
    // required). Operational nudge, not a config mutation — do not fold into
    // the RBAC gate above: adminProcedure here would also take away a
    // non-admin owner's ability to reconnect a server they own. The public
    // (unowned) case is what needs the role, and it is decided in the impl
    // from the flag threaded below.
    reconnect: protectedProcedure
      .input(ReconnectMcpServerRequestSchema)
      .output(ReconnectMcpServerResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return await implementations.reconnect(
          input,
          ctx.user.id,
          ctx.user.role === "admin",
        );
      }),
  });
};
