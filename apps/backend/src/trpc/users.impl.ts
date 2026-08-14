import {
  DeleteUserRequestSchema,
  DeleteUserResponseSchema,
  ListUsersResponseSchema,
  RevokeUserAccessRequestSchema,
  RevokeUserAccessResponseSchema,
} from "@repo/zod-types";
import { TRPCError } from "@trpc/server";
import { z } from "zod";

import logger from "@/utils/logger";

import { usersRepository } from "../db/repositories";
import { UsersSerializer } from "../db/serializers";

/**
 * Admin surface over the account list — the Users section of the Access
 * dashboard.
 *
 * Incident 2026-08-13: an attacker's self-registered member accounts were
 * invisible, because MetaMCP has no users page and no list-users procedure.
 * Every access path (API keys, OAuth clients, endpoints) had an admin view;
 * the accounts those paths belong to did not. This closes that gap and adds
 * the two administrative actions the incident needed: revoke an account's
 * live access, and delete the account outright.
 *
 * Every procedure in the matching router is `adminProcedure` — there is no
 * per-user ownership to scope an account listing by, and enumerating every
 * account in the deployment is exactly the disclosure a member must not have.
 */
export const usersImplementations = {
  list: async (): Promise<z.infer<typeof ListUsersResponseSchema>> => {
    try {
      const users = await usersRepository.listAll();
      return {
        users: UsersSerializer.serializeUserList(users),
      };
    } catch (error) {
      logger.error("Error fetching users:", error);
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to fetch users",
      });
    }
  },

  revokeAccess: async (
    input: z.infer<typeof RevokeUserAccessRequestSchema>,
    actorUserId: string,
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
        // Report the miss instead of a cheerful success — an operator who
        // believes they cut off an attacker who is still connected is worse
        // off than one who sees the failure.
        return {
          success: false,
          message: "User not found",
          sessions_deleted: 0,
          oauth_tokens_deleted: 0,
          authorization_codes_deleted: 0,
          api_keys_deactivated: 0,
        };
      }

      const revoked = await usersRepository.revokeAccess(input.user_id);

      logger.info(
        `Revoked access for user ${target.email} (${input.user_id}) via admin UI: ` +
          `${revoked.sessions_deleted} sessions, ${revoked.oauth_tokens_deleted} OAuth tokens, ` +
          `${revoked.authorization_codes_deleted} authorization codes, ` +
          `${revoked.api_keys_deactivated} API keys deactivated`,
      );

      return {
        success: true,
        message: "Access revoked",
        ...revoked,
      };
    } catch (error) {
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

      const deleted = await usersRepository.deleteById(input.user_id);

      if (!deleted) {
        return { success: false, message: "User not found" };
      }

      // Logged at info with the email because this is a destructive
      // administrative action on an identity — the audit trail is the only
      // record left once the row is gone.
      logger.info(
        `Deleted user ${target.email} (${input.user_id}) via admin UI; ` +
          `sessions, accounts, API keys, OAuth tokens/codes, m365 tokens and owned ` +
          `MCP servers/namespaces/endpoints cascaded`,
      );

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
