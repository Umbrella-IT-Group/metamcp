import type { AuditActor } from "@repo/trpc";
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
import { emitAdminEvent } from "../lib/audit/admin-event";
import { clampAuditText, clampAuditTextList } from "../lib/audit/audit-emitter";
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
    actor?: AuditActor,
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

    // A registered client is a standing permission to complete an
    // authorization flow against this gateway, so its birth is a security
    // event whichever door it came through — this is the attributed twin of
    // the anonymous `oauth.dcr.register` row that POST /oauth/register emits.
    // `client.client_secret` is deliberately absent from `detail`: it crosses
    // the wire once, in the response below, and nowhere else ever.
    emitAdminEvent(actor, {
      action: "oauthclient.create",
      target_type: "oauth_client",
      target_id: client.client_id,
      // Clamped for the same reason the DCR endpoint clamps: the zod contract
      // is `z.array(z.string().min(1))` with no `.max()` on either the array
      // or its elements, so an admin session can put an unbounded value into
      // a table that has no delete path. Lower stakes than the anonymous
      // endpoint, identical failure mode.
      detail: {
        client_name: clampAuditText(client.client_name, 100),
        redirect_uris: clampAuditTextList(client.redirect_uris, 10, 512),
        redirect_uri_count: Array.isArray(client.redirect_uris)
          ? client.redirect_uris.length
          : 0,
        token_endpoint_auth_method: clampAuditText(
          client.token_endpoint_auth_method,
          64,
        ),
        has_client_secret: Boolean(client.client_secret),
      },
    });

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
    actor?: AuditActor,
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

      // Emitted below the `!deleted` early return, so a delete that matched
      // nothing leaves no row claiming a client was revoked.
      emitAdminEvent(actor, {
        action: "oauthclient.delete",
        target_type: "oauth_client",
        target_id: input.client_id,
      });

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
