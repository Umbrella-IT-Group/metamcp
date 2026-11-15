import {
  AuditListRequestSchema,
  AuditListResponseSchema,
} from "@repo/zod-types";
import { TRPCError } from "@trpc/server";
import { z } from "zod";

import { describeDbError } from "@/lib/db-error-summary";
import logger from "@/utils/logger";

import { readAuditLogPage } from "../db/repositories/audit-log-read.repo";
import { projectAuditDetail } from "../lib/audit/audit-read";

/**
 * `audit.list`: one page of the audit trail, newest first, with the fixed
 * columns and a whitelisted detail (lib/audit/audit-read). Reads one row more
 * than the page to know whether another page exists; the cursor is the last
 * returned row's (occurred_at, uuid).
 */
export const auditImplementations = {
  list: async (
    input: z.infer<typeof AuditListRequestSchema>,
  ): Promise<z.infer<typeof AuditListResponseSchema>> => {
    let rows;
    try {
      rows = await readAuditLogPage({ ...input, limit: input.limit + 1 });
    } catch (error) {
      logger.error("Error reading the audit trail:", describeDbError(error));
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: "The audit trail could not be read.",
      });
    }
    const page = rows.slice(0, input.limit);
    const last = page[page.length - 1];
    return {
      rows: page.map((row) => {
        const { detail, omitted } = projectAuditDetail(row.detail);
        return {
          uuid: row.uuid,
          occurred_at: row.occurred_at,
          actor_type: row.actor_type,
          actor_id: row.actor_id,
          actor_label: row.actor_label,
          actor_ip: row.actor_ip,
          action: row.action,
          target_type: row.target_type,
          target_id: row.target_id,
          outcome: row.outcome,
          request_id: row.request_id,
          http_status: row.http_status,
          detail,
          detail_omitted: omitted,
        };
      }),
      next_cursor:
        rows.length > input.limit && last
          ? { occurred_at: last.occurred_at, uuid: last.uuid }
          : null,
    };
  },
};
