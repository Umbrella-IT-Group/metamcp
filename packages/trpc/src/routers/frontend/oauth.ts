import {
  GetOAuthSessionRequestSchema,
  GetOAuthSessionResponseSchema,
  UpsertOAuthSessionRequestSchema,
  UpsertOAuthSessionResponseSchema,
} from "@repo/zod-types";
import { z } from "zod";

import { adminProcedure, router } from "../../trpc";

// Define the OAuth router with procedure definitions
// The actual implementation will be provided by the backend
export const createOAuthRouter = (
  // These are the implementation functions that the backend will provide
  implementations: {
    get: (
      input: z.infer<typeof GetOAuthSessionRequestSchema>,
    ) => Promise<z.infer<typeof GetOAuthSessionResponseSchema>>;
    upsert: (
      input: z.infer<typeof UpsertOAuthSessionRequestSchema>,
    ) => Promise<z.infer<typeof UpsertOAuthSessionResponseSchema>>;
  },
) => {
  return router({
    // Admin only: Get OAuth session by MCP server UUID. The response is the
    // raw upstream credential set for that MCP server — `tokens`
    // (access_token + refresh_token), `client_information` (client_id +
    // client_secret) and `code_verifier`, all unredacted (see
    // `apps/backend/src/db/serializers/oauth-sessions.serializer.ts`). It is
    // server config, not per-user data: there is no per-caller row here, so
    // `protectedProcedure` handed every member the gateway's credentials for
    // every upstream MCP server. Gated to match its sibling `upsert`, which
    // writes the same records.
    get: adminProcedure
      .input(GetOAuthSessionRequestSchema)
      .output(GetOAuthSessionResponseSchema)
      .query(async ({ input }) => {
        return await implementations.get(input);
      }),

    // Admin only: Upsert OAuth session — writes upstream MCP-server OAuth
    // client credentials/tokens, a server-config surface, not a per-user one.
    upsert: adminProcedure
      .input(UpsertOAuthSessionRequestSchema)
      .output(UpsertOAuthSessionResponseSchema)
      .mutation(async ({ input }) => {
        return await implementations.upsert(input);
      }),
  });
};
