import {
  CreateOAuthClientRequestSchema,
  CreateOAuthClientResponseSchema,
  DeleteOAuthClientRequestSchema,
  DeleteOAuthClientResponseSchema,
  ListOAuthClientsResponseSchema,
} from "@repo/zod-types";
import { z } from "zod";

import { adminProcedure, router } from "../../trpc";

export const createOAuthClientsRouter = (implementations: {
  create: (
    input: z.infer<typeof CreateOAuthClientRequestSchema>,
  ) => Promise<z.infer<typeof CreateOAuthClientResponseSchema>>;
  list: () => Promise<z.infer<typeof ListOAuthClientsResponseSchema>>;
  delete: (
    input: z.infer<typeof DeleteOAuthClientRequestSchema>,
  ) => Promise<z.infer<typeof DeleteOAuthClientResponseSchema>>;
}) => {
  return router({
    // Every procedure here is adminProcedure — unlike api-keys, which is
    // protectedProcedure because members legitimately own their own keys.
    // A registered OAuth client is gateway-level configuration: any user can
    // complete an authorization flow through it, and deleting one revokes
    // live tokens
    // fleet-wide. There is no per-user ownership to scope by, so there is no
    // reason to let a member reach any of these — matching how the sibling
    // `oauth.upsert` (upstream server credentials) is already gated.

    // Admin only: mint a new client. This is the UI-side twin of the public
    // RFC 7591 `POST /oauth/register` endpoint — both run the same
    // registration core; this one requires an admin session instead of being
    // anonymous + rate-limited.
    create: adminProcedure
      .input(CreateOAuthClientRequestSchema)
      .output(CreateOAuthClientResponseSchema)
      .mutation(async ({ input }) => {
        return implementations.create(input);
      }),

    // Admin only: list registered clients. The response carries no secrets,
    // only `has_client_secret`.
    list: adminProcedure
      .output(ListOAuthClientsResponseSchema)
      .query(async () => {
        return implementations.list();
      }),

    // Admin only: delete a client, cascading to its issued codes and tokens.
    delete: adminProcedure
      .input(DeleteOAuthClientRequestSchema)
      .output(DeleteOAuthClientResponseSchema)
      .mutation(async ({ input }) => {
        return implementations.delete(input);
      }),
  });
};
