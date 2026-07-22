import {
  GetOAuthSessionRequestSchema,
  GetOAuthSessionResponseSchema,
  UpsertOAuthSessionRequestSchema,
  UpsertOAuthSessionResponseSchema,
  ValidateOAuthStateRequestSchema,
  ValidateOAuthStateResponseSchema,
} from "@repo/zod-types";
import { z } from "zod";

import { adminProcedure, protectedProcedure, router } from "../../trpc";

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
    validateState: (
      input: z.infer<typeof ValidateOAuthStateRequestSchema>,
    ) => Promise<z.infer<typeof ValidateOAuthStateResponseSchema>>;
  },
) => {
  return router({
    // Protected: Get OAuth session by MCP server UUID
    get: protectedProcedure
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

    // Admin only: CSRF state validation at the OAuth callback. Gated the same
    // as upsert because it reads and clears the same server-config surface
    // (oauth_sessions.expected_state) that upsert seeds — the connecting user
    // who minted the nonce is the admin who validates it. Mutation because a
    // successful match clears the nonce (one-shot).
    validateState: adminProcedure
      .input(ValidateOAuthStateRequestSchema)
      .output(ValidateOAuthStateResponseSchema)
      .mutation(async ({ input }) => {
        return await implementations.validateState(input);
      }),
  });
};
