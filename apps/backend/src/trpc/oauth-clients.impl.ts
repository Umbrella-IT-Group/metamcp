import {
  CreateOAuthClientRequestSchema,
  CreateOAuthClientResponseSchema,
  DeleteOAuthClientRequestSchema,
  DeleteOAuthClientResponseSchema,
  ListOAuthClientsResponseSchema,
} from "@repo/zod-types";
import { TRPCError } from "@trpc/server";
import { z } from "zod";

import logger from "@/utils/logger";

import { oauthRepository } from "../db/repositories";
import { OAuthClientsSerializer } from "../db/serializers";
import { buildClientRegistration } from "../routers/oauth/client-registration";

/**
 * Admin CRUD over DCR-registered OAuth clients (the `oauth_clients` table).
 *
 * Before this existed, a client could only be minted by POSTing to the public
 * `/oauth/register` DCR endpoint by hand — so pairing a Claude connector meant
 * a hand-rolled curl. This is the same mint, reachable from the admin UI.
 *
 * `create` does NOT re-implement registration: it calls the same
 * `buildClientRegistration` core the DCR endpoint calls, then persists through
 * the same `oauthRepository.upsertClient`. The only thing that differs between
 * the two paths is the transport and who is allowed to use it.
 *
 * Distinct from `oauth.impl.ts`, which manages OAuth *sessions* — this
 * gateway's own outbound credentials when it connects to an upstream MCP
 * server. Different table, opposite direction of trust.
 */
export const oauthClientsImplementations = {
  create: async (
    input: z.infer<typeof CreateOAuthClientRequestSchema>,
  ): Promise<z.infer<typeof CreateOAuthClientResponseSchema>> => {
    // The zod contract has already constrained the enums and required a
    // non-empty redirect_uris, but the core is still the authority on
    // redirect-URI safety (scheme, and the production localhost/private-IP
    // ban) — rules the schema cannot express and which must not be skipped
    // just because the caller is an authenticated admin.
    const registration = buildClientRegistration(input);

    if (!registration.ok) {
      // A rejected registration is caller error, not a server fault: surface
      // the core's own RFC 7591 description so the dialog can show the
      // operator exactly which URI or value was refused.
      throw new TRPCError({
        code: "BAD_REQUEST",
        message: registration.error_description,
      });
    }

    const client = registration.client;

    try {
      await oauthRepository.upsertClient(client);
    } catch (error) {
      logger.error("Error creating OAuth client:", error);
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to create OAuth client",
      });
    }

    logger.info(
      `Created OAuth client ${client.client_id} (${client.client_name}) via admin UI`,
    );

    // The one and only time client_secret crosses the wire. It is returned
    // from the freshly-minted object rather than re-read from the database,
    // and no other route exposes it — see OAuthClientsSerializer.
    return {
      client_id: client.client_id,
      client_secret: client.client_secret,
      client_name: client.client_name,
      redirect_uris: client.redirect_uris,
      grant_types: client.grant_types,
      response_types: client.response_types,
      token_endpoint_auth_method: client.token_endpoint_auth_method,
      scope: client.scope,
      created_at: client.created_at,
    };
  },

  list: async (): Promise<z.infer<typeof ListOAuthClientsResponseSchema>> => {
    try {
      const clients = await oauthRepository.listClients();
      return {
        clients: OAuthClientsSerializer.serializeOAuthClientList(clients),
      };
    } catch (error) {
      logger.error("Error fetching OAuth clients:", error);
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to fetch OAuth clients",
      });
    }
  },

  delete: async (
    input: z.infer<typeof DeleteOAuthClientRequestSchema>,
  ): Promise<z.infer<typeof DeleteOAuthClientResponseSchema>> => {
    try {
      const deleted = await oauthRepository.deleteClient(input.client_id);

      if (!deleted) {
        // Report the miss instead of a cheerful success — an operator who
        // thinks they revoked a client that is still live is worse off than
        // one who sees the failure.
        return {
          success: false,
          message: "OAuth client not found",
        };
      }

      logger.info(`Deleted OAuth client ${input.client_id} via admin UI`);

      return {
        success: true,
        message: "OAuth client deleted successfully",
      };
    } catch (error) {
      logger.error("Error deleting OAuth client:", error);
      return {
        success: false,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },
};
