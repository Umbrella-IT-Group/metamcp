import {
  DeleteUserRequestSchema,
  DeleteUserResponseSchema,
  ListUsersResponseSchema,
  PreviewDeleteUserRequestSchema,
  PreviewDeleteUserResponseSchema,
  RevokeUserAccessRequestSchema,
  RevokeUserAccessResponseSchema,
  SetUserDisabledRequestSchema,
  SetUserDisabledResponseSchema,
} from "@repo/zod-types";
import { z } from "zod";

import {
  adminProcedure,
  type AuditActor,
  auditActor,
  router,
} from "../../trpc";

export const createUsersRouter = (implementations: {
  list: () => Promise<z.infer<typeof ListUsersResponseSchema>>;
  previewDelete: (
    input: z.infer<typeof PreviewDeleteUserRequestSchema>,
  ) => Promise<z.infer<typeof PreviewDeleteUserResponseSchema>>;
  setDisabled: (
    input: z.infer<typeof SetUserDisabledRequestSchema>,
    actorUserId: string,
    actor: AuditActor,
  ) => Promise<z.infer<typeof SetUserDisabledResponseSchema>>;
  revokeAccess: (
    input: z.infer<typeof RevokeUserAccessRequestSchema>,
    actorUserId: string,
    actor: AuditActor,
  ) => Promise<z.infer<typeof RevokeUserAccessResponseSchema>>;
  delete: (
    input: z.infer<typeof DeleteUserRequestSchema>,
    actorUserId: string,
    actor: AuditActor,
  ) => Promise<z.infer<typeof DeleteUserResponseSchema>>;
}) => {
  return router({
    // Every procedure here is adminProcedure — the same rule oauth-clients
    // follows, for the same reason. There is no per-user ownership to scope
    // an ACCOUNT listing by: the whole content of the response is other
    // people's identities, so a member-visible version would be an account
    // enumeration oracle rather than a narrower view. The mutations are
    // strictly more privileged still.
    //
    // The `.output()` schemas are the second redaction layer, after the
    // serializers: zod strips any field the contract does not name, so a
    // credential column added to `users` or `oauth_access_tokens` later
    // cannot reach the wire even if a serializer is edited carelessly.

    // Admin only: enumerate every account with its live access-path counts.
    // Before this procedure existed, accounts were invisible in the GUI, so a
    // self-registered attacker was too.
    list: adminProcedure.output(ListUsersResponseSchema).query(async () => {
      return implementations.list();
    }),

    // Admin only: what a delete would destroy, read BEFORE the irreversible
    // confirmation. A query, not a mutation — it writes nothing.
    //
    // This exists because the cascade is not confined to the target account:
    // it reaches endpoints owned by other users (living in this user's
    // namespaces) and API keys owned by other users (acting as this identity,
    // or scoped to a doomed endpoint). Both were verified against a real
    // postgres. The dialog shows these counts because a number is the only
    // thing that reliably stops the click.
    previewDelete: adminProcedure
      .input(PreviewDeleteUserRequestSchema)
      .output(PreviewDeleteUserResponseSchema)
      .query(async ({ input }) => {
        return implementations.previewDelete(input);
      }),

    // Admin only: lock or unlock an account (migration 0027). The
    // containment primitive — unlike revoke, a disabled account cannot
    // sign back in; unlike delete, everything is preserved as evidence.
    // Enforced in two places (auth.ts session hook + the tRPC context), so
    // both new logins and already-issued sessions are stopped.
    setDisabled: adminProcedure
      .input(SetUserDisabledRequestSchema)
      .output(SetUserDisabledResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return implementations.setDisabled(input, ctx.user.id, auditActor(ctx));
      }),

    // Admin only: sever an account's live access (sessions, OAuth tokens and
    // codes deleted; API keys that can act as this identity deactivated; M365
    // delegation reset) while KEEPING the account row. The caller's own id is
    // passed through so the impl can refuse self-revocation, which would sign
    // the responding administrator out mid-response.
    revokeAccess: adminProcedure
      .input(RevokeUserAccessRequestSchema)
      .output(RevokeUserAccessResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return implementations.revokeAccess(
          input,
          ctx.user.id,
          auditActor(ctx),
        );
      }),

    // Admin only: delete the account. Every FK into `users` is ON DELETE
    // CASCADE, so this also removes sessions, the stored password hash,
    // API keys, OAuth tokens/codes, m365 tokens, the MCP servers /
    // namespaces / endpoints that user owned — AND other users' endpoints and
    // keys that hang off those. Destructive and irreversible; `setDisabled`
    // is the reversible answer. Self-deletion is refused in the impl, which
    // is why the caller's id is passed.
    delete: adminProcedure
      .input(DeleteUserRequestSchema)
      .output(DeleteUserResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return implementations.delete(input, ctx.user.id, auditActor(ctx));
      }),
  });
};
