import {
  DeleteUserRequestSchema,
  DeleteUserResponseSchema,
  ListUsersResponseSchema,
  RevokeUserAccessRequestSchema,
  RevokeUserAccessResponseSchema,
} from "@repo/zod-types";
import { z } from "zod";

import { adminProcedure, router } from "../../trpc";

export const createUsersRouter = (implementations: {
  list: () => Promise<z.infer<typeof ListUsersResponseSchema>>;
  revokeAccess: (
    input: z.infer<typeof RevokeUserAccessRequestSchema>,
    actorUserId: string,
  ) => Promise<z.infer<typeof RevokeUserAccessResponseSchema>>;
  delete: (
    input: z.infer<typeof DeleteUserRequestSchema>,
    actorUserId: string,
  ) => Promise<z.infer<typeof DeleteUserResponseSchema>>;
}) => {
  return router({
    // Every procedure here is adminProcedure — the same rule oauth-clients
    // follows, for the same reason. There is no per-user ownership to scope
    // an ACCOUNT listing by: the whole content of the response is other
    // people's identities, so a member-visible version would be an account
    // enumeration oracle rather than a narrower view. The two mutations are
    // strictly more privileged still.
    //
    // The `.output()` schemas are the second redaction layer, after the
    // serializers: zod strips any field the contract does not name, so a
    // credential column added to `users` or `oauth_access_tokens` later
    // cannot reach the wire even if a serializer is edited carelessly.

    // Admin only: enumerate every account with its live access-path counts.
    // This procedure did not exist before the 2026-08-13 incident — accounts
    // were invisible in the GUI, so a self-registered attacker was too.
    list: adminProcedure.output(ListUsersResponseSchema).query(async () => {
      return implementations.list();
    }),

    // Admin only: sever an account's live access (sessions, OAuth tokens and
    // codes deleted; API keys deactivated) while KEEPING the account row as
    // incident evidence. The caller's own id is passed through so the impl
    // can refuse self-revocation, which would sign the responding
    // administrator out mid-incident.
    revokeAccess: adminProcedure
      .input(RevokeUserAccessRequestSchema)
      .output(RevokeUserAccessResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return implementations.revokeAccess(input, ctx.user.id);
      }),

    // Admin only: delete the account. Every FK into `users` is ON DELETE
    // CASCADE, so this also removes sessions, the stored password hash,
    // API keys, OAuth tokens/codes, m365 tokens, and the MCP servers /
    // namespaces / endpoints that user owned. Destructive and irreversible —
    // `revokeAccess` is the reversible option. Self-deletion is refused in
    // the impl, which is why the caller's id is passed.
    delete: adminProcedure
      .input(DeleteUserRequestSchema)
      .output(DeleteUserResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return implementations.delete(input, ctx.user.id);
      }),
  });
};
