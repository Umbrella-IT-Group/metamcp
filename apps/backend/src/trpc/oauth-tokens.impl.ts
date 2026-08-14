import { ListActiveOAuthTokensResponseSchema } from "@repo/zod-types";
import { TRPCError } from "@trpc/server";
import { z } from "zod";

import logger from "@/utils/logger";

import { oauthRepository } from "../db/repositories";
import { OAuthTokensSerializer } from "../db/serializers";

/**
 * Admin read of LIVE OAuth access tokens — the "who is connected via OAuth"
 * section of the Access dashboard.
 *
 * Distinct from `oauth-clients.impl.ts`, which manages the registered clients
 * a token can be issued THROUGH, and from `oauth.impl.ts`, which manages this
 * gateway's own outbound credentials to upstream MCP servers. This one lists
 * the inbound grants that currently authenticate somebody.
 *
 * Read-only on purpose. Revoking OAuth access is already covered from both
 * ends — delete the client (revokes every token issued to it, cascade) or
 * revoke the user (deletes their tokens). A third per-token revoke button
 * would be a fourth way to do the same thing, so it is deliberately absent
 * rather than forgotten.
 */
export const oauthTokensImplementations = {
  list: async (): Promise<
    z.infer<typeof ListActiveOAuthTokensResponseSchema>
  > => {
    try {
      const tokens = await oauthRepository.listActiveAccessTokens();
      return {
        tokens: OAuthTokensSerializer.serializeActiveTokenList(tokens),
      };
    } catch (error) {
      logger.error("Error fetching active OAuth tokens:", error);
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to fetch active OAuth tokens",
      });
    }
  },
};
