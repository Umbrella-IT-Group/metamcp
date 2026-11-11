import type { AuditActor } from "@repo/trpc";
import {
  CreateOAuthClientRequestSchema,
  CreateOAuthClientResponseSchema,
  DecideOAuthClientRequestSchema,
  DecideOAuthClientResponseSchema,
  DeleteOAuthClientRequestSchema,
  DeleteOAuthClientResponseSchema,
  ListOAuthClientsResponseSchema,
  type OAuthClient,
} from "@repo/zod-types";
import { TRPCError } from "@trpc/server";
import { z } from "zod";

import logger from "@/utils/logger";

import { oauthRepository } from "../db/repositories";
import { OAuthClientsSerializer } from "../db/serializers";
import { emitAdminEvent } from "../lib/audit/admin-event";
import { clampAuditText, clampAuditTextList } from "../lib/audit/audit-emitter";
import { buildClientRegistration } from "../routers/oauth/client-registration";
import { isDcrLoopbackRedirectUri } from "../routers/oauth/utils";

/**
 * The authenticated administrator a decision is attributed to.
 *
 * From the tRPC context only (auditActor), never from the request body. An
 * admin-plane (CI) key never reaches the decision procedures (they are not on
 * ADMIN_PLANE_ALLOWED_PROCEDURES); refusing one here as well keeps a future
 * allowlist edit from letting a CI credential approve clients unnoticed.
 */
function decidingAdministrator(actor: AuditActor | undefined): string {
  if (!actor?.actor_id || actor.admin_plane) {
    throw new TRPCError({
      code: "FORBIDDEN",
      message: "An administrator's own session is required for this decision.",
    });
  }
  return actor.actor_id;
}

/**
 * Refuse a decision on a row that is not a pending self-registration: gone,
 * not self-registered, or already decided. Returns quietly when the row IS
 * decidable. Never reported as success, and no success audit row is written.
 */
function assertDecidable(
  current: OAuthClient | null,
): asserts current is OAuthClient {
  if (!current) {
    throw new TRPCError({
      code: "NOT_FOUND",
      message: "OAuth client not found",
    });
  }
  if (current.registration_source !== "dcr") {
    throw new TRPCError({
      code: "CONFLICT",
      message:
        "Only self-registered clients are approved or rejected. Administrator-created and older clients are already approved.",
    });
  }
  if (current.approval_status !== "pending") {
    throw new TRPCError({
      code: "CONFLICT",
      message: `This client is no longer pending (it is ${String(current.approval_status).slice(0, 32)}). Refresh the list.`,
    });
  }
}

/**
 * A conditional decision UPDATE changed nothing although the row looked
 * decidable a moment earlier: another administrator (or the sweep, or a
 * delete) got there first. Re-read and report what happened instead.
 */
async function refuseLostDecision(clientId: string): Promise<never> {
  const current = await oauthRepository.getClient(clientId);
  assertDecidable(current);
  // Still pending yet the UPDATE matched nothing: its callbacks changed
  // between the check and the write. Refuse rather than retry blind.
  throw new TRPCError({
    code: "CONFLICT",
    message:
      "This client changed while it was being decided. Refresh the list.",
  });
}

function decisionResponse(
  row: OAuthClient,
): z.infer<typeof DecideOAuthClientResponseSchema> {
  return {
    client_id: row.client_id,
    approval_status: row.approval_status as z.infer<
      typeof DecideOAuthClientResponseSchema
    >["approval_status"],
    approved_by: row.approved_by ?? null,
    approved_at: row.approved_at ?? null,
    rejected_at: row.rejected_at ?? null,
  };
}

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

    // `registration_source: "admin"` is what exempts this row from the
    // retention sweep in ../routers/oauth/client-retention.ts. Pre-provisioning
    // a partner's client here and handing the credentials over days before they
    // pair is the normal way this dialog is used, so an admin-minted client
    // that has never produced a token is not junk — it is waiting. The
    // anonymous DCR endpoint stamps "dcr" at its own door for the same reason:
    // the shared mint core cannot tell them apart, since both draw their
    // client_id from generateSecureClientId.
    //
    // `approval_status: "approved"` for the same reason: an administrator
    // creating a client is the approval, so there is nothing to wait for. The
    // zod contract strips any status or approver field a caller adds, and the
    // shared core never reads one, so this line is the only source of it.
    const client = {
      ...registration.client,
      registration_source: "admin" as const,
      approval_status: "approved" as const,
    };

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
      approval_status: client.approval_status,
      created_at: client.created_at,
    };
  },

  /**
   * Approve a pending self-registered client so people can authorize it.
   *
   * Every stored callback is re-checked against the self-registration rule
   * (plain-http loopback) first, so a pending row that reached the table any
   * other way (written by hand, or before that rule existed) cannot be
   * approved with a hosted callback. The decision itself is one conditional
   * UPDATE (oauthRepository.approvePendingDcrClient): two administrators
   * deciding at once produce exactly one winner, and a stale, deleted or
   * already decided row is reported as such, never as success.
   *
   * Approval grants nothing by itself: each person still authorizes the
   * client on the consent screen.
   */
  approve: async (
    input: z.infer<typeof DecideOAuthClientRequestSchema>,
    actor?: AuditActor,
  ): Promise<z.infer<typeof DecideOAuthClientResponseSchema>> => {
    const approvedBy = decidingAdministrator(actor);

    const current = await oauthRepository.getClient(input.client_id);
    assertDecidable(current);
    const nonLoopback = current.redirect_uris.filter(
      (uri) => !isDcrLoopbackRedirectUri(uri),
    );
    if (nonLoopback.length > 0) {
      throw new TRPCError({
        code: "BAD_REQUEST",
        message:
          "This client has a callback that is not a local (loopback) address, so it cannot be approved. Delete it; hosted clients are created by an administrator.",
      });
    }

    const approved = await oauthRepository.approvePendingDcrClient(
      input.client_id,
      current.redirect_uris,
      approvedBy,
    );
    if (!approved) {
      return refuseLostDecision(input.client_id);
    }

    logger.info(
      `Approved OAuth client ${approved.client_id} via admin UI (approved_by=${approvedBy})`,
    );
    // After the UPDATE returned the changed row, so a row here means the
    // client really moved from pending to approved.
    emitAdminEvent(actor, {
      action: "oauthclient.approve",
      target_type: "oauth_client",
      target_id: approved.client_id,
      detail: {
        client_name: clampAuditText(approved.client_name, 100),
        previous_status: "pending",
        new_status: "approved",
      },
    });

    return decisionResponse(approved);
  },

  /**
   * Reject a pending self-registered client. It can no longer be authorized
   * and the retention sweep removes it a day later. Same single conditional
   * UPDATE, one-winner and stale-row rules as approve.
   */
  reject: async (
    input: z.infer<typeof DecideOAuthClientRequestSchema>,
    actor?: AuditActor,
  ): Promise<z.infer<typeof DecideOAuthClientResponseSchema>> => {
    const rejectedBy = decidingAdministrator(actor);

    const rejected = await oauthRepository.rejectPendingDcrClient(
      input.client_id,
    );
    if (!rejected) {
      return refuseLostDecision(input.client_id);
    }

    logger.info(
      `Rejected OAuth client ${rejected.client_id} via admin UI (rejected_by=${rejectedBy})`,
    );
    emitAdminEvent(actor, {
      action: "oauthclient.reject",
      target_type: "oauth_client",
      target_id: rejected.client_id,
      detail: {
        client_name: clampAuditText(rejected.client_name, 100),
        previous_status: "pending",
        new_status: "rejected",
      },
    });

    return decisionResponse(rejected);
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
