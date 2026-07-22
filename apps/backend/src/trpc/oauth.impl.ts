import {
  GetOAuthSessionRequestSchema,
  GetOAuthSessionResponseSchema,
  UpsertOAuthSessionRequestSchema,
  UpsertOAuthSessionResponseSchema,
  ValidateOAuthStateRequestSchema,
  ValidateOAuthStateResponseSchema,
} from "@repo/zod-types";
import { z } from "zod";

import logger from "@/utils/logger";

import { oauthSessionsRepository } from "../db/repositories";
import { OAuthSessionsSerializer } from "../db/serializers";

export const oauthImplementations = {
  get: async (
    input: z.infer<typeof GetOAuthSessionRequestSchema>,
  ): Promise<z.infer<typeof GetOAuthSessionResponseSchema>> => {
    try {
      const session = await oauthSessionsRepository.findByMcpServerUuid(
        input.mcp_server_uuid,
      );

      if (!session) {
        return {
          success: false as const,
          message: "OAuth session not found",
        };
      }

      return {
        success: true as const,
        data: OAuthSessionsSerializer.serializeOAuthSession(session),
        message: "OAuth session retrieved successfully",
      };
    } catch (error) {
      logger.error("Error fetching OAuth session:", error);
      return {
        success: false as const,
        message: "Failed to fetch OAuth session",
      };
    }
  },

  upsert: async (
    input: z.infer<typeof UpsertOAuthSessionRequestSchema>,
  ): Promise<z.infer<typeof UpsertOAuthSessionResponseSchema>> => {
    try {
      const session = await oauthSessionsRepository.upsert({
        mcp_server_uuid: input.mcp_server_uuid,
        ...(input.client_information && {
          client_information: input.client_information,
        }),
        ...(input.tokens && { tokens: input.tokens }),
        ...(input.code_verifier && { code_verifier: input.code_verifier }),
        // CSRF-defence nonce. MUST be forwarded — omitting it here silently
        // disables state validation at validateState because the DB column
        // stays NULL and the validator takes the back-compat bypass. Pinned by
        // the "forwards expected_state to the repo" test.
        ...(input.expected_state && {
          expected_state: input.expected_state,
        }),
      });

      if (!session) {
        return {
          success: false as const,
          error: "Failed to upsert OAuth session",
        };
      }

      return {
        success: true as const,
        data: OAuthSessionsSerializer.serializeOAuthSession(session),
        message: "OAuth session upserted successfully",
      };
    } catch (error) {
      logger.error("Error upserting OAuth session:", error);
      return {
        success: false as const,
        error: error instanceof Error ? error.message : "Internal server error",
      };
    }
  },

  validateState: async (
    input: z.infer<typeof ValidateOAuthStateRequestSchema>,
  ): Promise<z.infer<typeof ValidateOAuthStateResponseSchema>> => {
    // RFC 6749 §10.12 CSRF defence. `expected_state` was persisted at the
    // authorize-redirect step by DbOAuthClientProvider.state(). Our upstream
    // token exchange runs client-side in the browser via the MCP SDK's auth(),
    // so this runs at the callback BEFORE that exchange: a mismatch aborts the
    // flow before the browser POSTs the authorization code upstream, so a code
    // obtained under a forged flow is never redeemed.
    //
    // Three cases:
    //   - no session, OR expected_state IS NULL → the flow started before this
    //     column existed, or a previous validation already cleared it. Accept
    //     for backward compat with in-flight pre-fix flows; the column is
    //     populated on the NEXT authorize attempt and validated then. This is
    //     fail-open on ABSENCE only, never on a present-but-wrong nonce.
    //   - expected_state non-null AND matches input.state → valid; clear the
    //     column so the row can't be replayed with the same code+state pair.
    //   - expected_state non-null AND input.state missing OR mismatched →
    //     fail-closed. The missing case is explicit: an attacker who omits
    //     state must not bypass the check via a truthy-undefined comparison.
    try {
      const session = await oauthSessionsRepository.findByMcpServerUuid(
        input.mcp_server_uuid,
      );

      if (!session || !session.expected_state) {
        return { valid: true as const };
      }

      if (!input.state || input.state !== session.expected_state) {
        logger.warn(
          `[oauth] state mismatch — server=${input.mcp_server_uuid} ` +
            `expected_present=true got_present=${Boolean(input.state)}`,
        );
        return {
          valid: false as const,
          error: "invalid_state",
          error_description:
            "OAuth state mismatch — possible CSRF. The authorize flow must be re-initiated.",
        };
      }

      // One-shot clear on a successful match. A replayed callback then falls
      // through the back-compat NULL branch above, but the authorization code
      // is already burned by the upstream at that point so a replayed exchange
      // fails with invalid_grant regardless. Belt-and-braces.
      await oauthSessionsRepository.clearExpectedState(input.mcp_server_uuid);

      return { valid: true as const };
    } catch (error) {
      // A validation-path failure (e.g. DB unavailable) must not silently
      // disable CSRF defence: fail closed so the callback aborts rather than
      // completing an unvalidated exchange.
      logger.error("Error validating OAuth state:", error);
      return {
        valid: false as const,
        error: "validation_error",
        error_description:
          "Failed to validate OAuth state. The authorize flow must be re-initiated.",
      };
    }
  },
};
