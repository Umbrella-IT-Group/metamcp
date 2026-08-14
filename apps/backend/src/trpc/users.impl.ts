import type { AuditActor } from "@repo/trpc";
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
import { TRPCError } from "@trpc/server";
import { z } from "zod";

import logger from "@/utils/logger";

import { usersRepository } from "../db/repositories";
import { UsersSerializer } from "../db/serializers";
import { emitAdminEvent } from "../lib/audit/admin-event";
import { clampAuditText } from "../lib/audit/audit-emitter";

/**
 * RFC 5321 §4.5.3.1.3: the longest legal email address.
 *
 * Emails are the only free-text values these audit rows carry, and
 * `audit_log` has no prune path — so they are clamped at the same bound the
 * failed-login row uses, rather than trusted to be sane because they came out
 * of the database.
 */
const MAX_EMAIL_LENGTH = 320;

// Every zero, for the responses that must report a shape even when nothing
// happened. Declared once so a new counter cannot be added to the contract
// and forgotten in one of the not-found branches.
const NO_REVOCATIONS = {
  sessions_deleted: 0,
  oauth_tokens_deleted: 0,
  authorization_codes_deleted: 0,
  api_keys_deactivated: 0,
  m365_tokens_revoked: 0,
};

const NO_IMPACT = {
  own_namespaces: 0,
  own_endpoints: 0,
  own_mcp_servers: 0,
  own_api_keys: 0,
  other_users_endpoints: 0,
  other_users_api_keys: 0,
  sessions: 0,
  oauth_tokens: 0,
  m365_tokens: 0,
};

/**
 * Admin surface over the account list — the Users section of the Access
 * dashboard.
 *
 * Incident 2026-08-13: an attacker's self-registered member accounts were
 * invisible, because MetaMCP has no users page and no list-users procedure.
 * Every access path (API keys, OAuth clients, endpoints) had an admin view;
 * the accounts those paths belong to did not.
 *
 * Three administrative tiers, deliberately distinct, weakest first:
 *   revokeAccess — sever live access; the account can sign straight back in
 *   setDisabled  — lock the account out; everything preserved as evidence
 *   delete       — destroy the account and everything the FK graph reaches
 * Disable is the incident-response primitive: it is the only one that both
 * stops the attacker and keeps the record of who they were.
 *
 * Every procedure in the matching router is `adminProcedure` — there is no
 * per-user ownership to scope an account listing by, and enumerating every
 * account in the deployment is exactly the disclosure a member must not have.
 *
 * ALL THREE TIERS EMIT (`user.disabled.set` / `user.enabled.set`,
 * `user.access.revoked`, `user.delete`), and that is not symmetry for its own
 * sake: these are the operations an administrator performs WHILE containing
 * an incident, so they are the ones an after-action review reads first. They
 * also tear their targets down with raw drizzle rather than through
 * better-auth, so no `databaseHooks` sink sees them — an emitter here is the
 * only way they are recorded at all.
 *
 * SECRETS. Between them these procedures delete sessions, OAuth access and
 * refresh tokens, authorization codes and API keys, and reset M365
 * delegations. `detail` therefore carries COUNTS and one clamped email,
 * never a credential value: `audit_log` is append-only with no prune path,
 * so a token copied into it would outlive the revocation meant to kill it.
 */
export const usersImplementations = {
  list: async (): Promise<z.infer<typeof ListUsersResponseSchema>> => {
    try {
      const { users, total } = await usersRepository.listAll();
      return {
        users: UsersSerializer.serializeUserList(users),
        total,
      };
    } catch (error) {
      logger.error("Error fetching users:", error);
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to fetch users",
      });
    }
  },

  previewDelete: async (
    input: z.infer<typeof PreviewDeleteUserRequestSchema>,
  ): Promise<z.infer<typeof PreviewDeleteUserResponseSchema>> => {
    try {
      const target = await usersRepository.findById(input.user_id);

      if (!target) {
        return { found: false, email: null, impact: NO_IMPACT };
      }

      const impact = await usersRepository.previewDeleteImpact(input.user_id);

      return { found: true, email: target.email, impact };
    } catch (error) {
      logger.error("Error previewing user delete impact:", error);
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to preview delete impact",
      });
    }
  },

  setDisabled: async (
    input: z.infer<typeof SetUserDisabledRequestSchema>,
    actorUserId: string,
    actor?: AuditActor,
  ): Promise<z.infer<typeof SetUserDisabledResponseSchema>> => {
    // Self-lockout is refused. Disabling yourself takes effect on your very
    // next request, so the administrator who does it loses the console they
    // would need to undo it — and if they are the only admin, the deployment
    // has no administrator at all and the only way back is psql.
    if (input.user_id === actorUserId) {
      throw new TRPCError({
        code: "BAD_REQUEST",
        message: "You cannot disable your own account.",
      });
    }

    try {
      const updated = await usersRepository.setDisabled(
        input.user_id,
        input.disabled,
        actorUserId,
      );

      if (!updated) {
        // Report the miss instead of a cheerful success — an operator who
        // believes they locked an attacker out who is still signing in is
        // worse off than one who sees the failure.
        return {
          success: false,
          message: "User not found",
          disabled: false,
        };
      }

      logger.info(
        `${input.disabled ? "Disabled" : "Enabled"} user ${input.user_id} ` +
          `via admin UI (actor ${actorUserId})`,
      );

      // Emitted here rather than above the `if (!updated)` return, so a
      // no-op against a user id that does not exist leaves no row claiming an
      // account was locked. Two distinct actions rather than one with a
      // boolean in `detail`: enabling an account someone else disabled is the
      // reversal of a containment decision, and it has to be greppable on its
      // own rather than hiding inside the same verb as the lock.
      emitAdminEvent(actor, {
        action: input.disabled ? "user.disabled.set" : "user.enabled.set",
        target_type: "user",
        target_id: input.user_id,
        detail: { disabled: updated.disabled },
      });

      return {
        success: true,
        message: input.disabled ? "Account disabled" : "Account enabled",
        disabled: updated.disabled,
      };
    } catch (error) {
      logger.error("Error setting user disabled state:", error);
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to update account state",
      });
    }
  },

  revokeAccess: async (
    input: z.infer<typeof RevokeUserAccessRequestSchema>,
    actorUserId: string,
    actor?: AuditActor,
  ): Promise<z.infer<typeof RevokeUserAccessResponseSchema>> => {
    // Self-revocation is refused rather than allowed-with-a-warning: it would
    // delete the caller's own session mid-request, signing the administrator
    // out in the middle of an incident response. There is a Sign out button
    // for the legitimate version of this.
    if (input.user_id === actorUserId) {
      throw new TRPCError({
        code: "BAD_REQUEST",
        message: "You cannot revoke your own access. Use sign out instead.",
      });
    }

    try {
      const target = await usersRepository.findById(input.user_id);

      if (!target) {
        return {
          success: false,
          message: "User not found",
          ...NO_REVOCATIONS,
        };
      }

      const revoked = await usersRepository.revokeAccess(input.user_id);

      logger.info(
        `Revoked access for user ${target.email} (${input.user_id}) via admin UI: ` +
          `${revoked.sessions_deleted} sessions, ${revoked.oauth_tokens_deleted} OAuth tokens, ` +
          `${revoked.authorization_codes_deleted} authorization codes, ` +
          `${revoked.api_keys_deactivated} API keys deactivated, ` +
          `${revoked.m365_tokens_revoked} M365 delegations reset`,
      );

      // Emitted AFTER the repository's single transaction committed — a throw
      // above means nothing was cut, and a row claiming an attacker was
      // severed when they were not is the worst thing this table could say.
      //
      // COUNTS ONLY. What this operation touches IS the credential set: it
      // deletes session rows, OAuth access and refresh tokens and
      // authorization codes, and resets M365 delegated tokens. None of those
      // values may be recorded — `audit_log` is append-only with no prune
      // path, so a token copied in here outlives the revocation that was
      // supposed to kill it. The counts answer "how much access was cut",
      // which is the question an incident review actually asks; the email is
      // clamped because it is the only free-text field in the row.
      emitAdminEvent(actor, {
        action: "user.access.revoked",
        target_type: "user",
        target_id: input.user_id,
        detail: {
          target_email: clampAuditText(target.email, MAX_EMAIL_LENGTH),
          sessions_revoked: revoked.sessions_deleted,
          oauth_tokens_revoked: revoked.oauth_tokens_deleted,
          auth_codes_revoked: revoked.authorization_codes_deleted,
          api_keys_revoked: revoked.api_keys_deactivated,
          // Part of the same teardown and a real credential plane of its own
          // — omitting it would under-report what was cut.
          m365_tokens_revoked: revoked.m365_tokens_revoked,
        },
      });

      return {
        success: true,
        message: "Access revoked",
        ...revoked,
      };
    } catch (error) {
      // The repository runs its five statements in ONE transaction, so a
      // throw here means nothing was committed. Reporting failure is
      // therefore honest — the half-cut state that would make this message a
      // lie cannot exist.
      logger.error("Error revoking user access:", error);
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to revoke user access",
      });
    }
  },

  delete: async (
    input: z.infer<typeof DeleteUserRequestSchema>,
    actorUserId: string,
    actor?: AuditActor,
  ): Promise<z.infer<typeof DeleteUserResponseSchema>> => {
    // An administrator deleting their own account cascades away their own
    // sessions, keys and owned namespaces/endpoints in one irreversible
    // statement, and can leave a deployment with no administrator at all.
    // Refused outright; removing an admin is another admin's job.
    if (input.user_id === actorUserId) {
      throw new TRPCError({
        code: "BAD_REQUEST",
        message: "You cannot delete your own account.",
      });
    }

    try {
      const target = await usersRepository.findById(input.user_id);

      if (!target) {
        return { success: false, message: "User not found" };
      }

      // Recorded BEFORE the delete: once the rows are gone there is no way to
      // reconstruct what the cascade took, and the cross-user reach (other
      // people's endpoints and production keys) is exactly what an incident
      // review will ask about.
      const impact = await usersRepository.previewDeleteImpact(input.user_id);

      const deleted = await usersRepository.deleteById(input.user_id);

      if (!deleted) {
        return { success: false, message: "User not found" };
      }

      logger.info(
        `Deleted user ${target.email} (${input.user_id}) via admin UI; cascade removed ` +
          `${impact.own_namespaces} namespaces, ${impact.own_endpoints} own endpoints, ` +
          `${impact.own_mcp_servers} MCP servers, ${impact.own_api_keys} own API keys, ` +
          `${impact.sessions} sessions, ${impact.oauth_tokens} OAuth tokens, ` +
          `${impact.m365_tokens} M365 tokens — AND ${impact.other_users_endpoints} ` +
          `endpoints + ${impact.other_users_api_keys} API keys belonging to OTHER users`,
      );

      // Emitted AFTER the delete committed, and below the `!deleted` guard, so
      // no row can claim an account was destroyed that still exists.
      //
      // This is the only row that will ever mention this account: every FK
      // into `users` is ON DELETE CASCADE, so by this line the user, its
      // sessions, its keys and its owned resources are gone from every other
      // table in the database. `target_email` is the sole remaining link
      // between the id in `target_id` and a human — captured before the
      // delete, clamped like every other free-text field here. The counts
      // come from the impact preview taken above for the same reason: after
      // the cascade there is nothing left to count, and the CROSS-USER reach
      // (other people's endpoints and production keys) is exactly what an
      // incident review asks about. Counts and one email, never a key value.
      emitAdminEvent(actor, {
        action: "user.delete",
        target_type: "user",
        target_id: input.user_id,
        detail: {
          target_email: clampAuditText(target.email, MAX_EMAIL_LENGTH),
          own_namespaces: impact.own_namespaces,
          own_endpoints: impact.own_endpoints,
          own_mcp_servers: impact.own_mcp_servers,
          own_api_keys: impact.own_api_keys,
          other_users_endpoints: impact.other_users_endpoints,
          other_users_api_keys: impact.other_users_api_keys,
          sessions: impact.sessions,
          oauth_tokens: impact.oauth_tokens,
          m365_tokens: impact.m365_tokens,
        },
      });

      return { success: true, message: "User deleted successfully" };
    } catch (error) {
      logger.error("Error deleting user:", error);
      // A fixed string, not `error.message`. A failed delete here is a driver
      // or constraint error, and the raw message carries table names and
      // internal hostnames — the same disclosure the tRPC errorFormatter
      // masks for INTERNAL_SERVER_ERROR. That mask does not apply to a
      // SUCCESSFUL response carrying a failure message, so it has to be
      // applied here. The detail is in the server log, where it belongs.
      return { success: false, message: "Failed to delete user" };
    }
  },
};
