import { z } from "zod";

/**
 * `audit.list`: a read of the control-plane audit trail (migration 0028) for
 * an administrator and an operator-scope admin-plane key, so a change can be
 * verified from its own audit row without database access.
 *
 * Bounded on every axis: a page is at most AUDIT_LIST_MAX_LIMIT rows, every
 * filter is an exact match on an indexed or short column, and the cursor is
 * the (occurred_at, uuid) pair of the last row of the previous page, so a page
 * is stable while new rows arrive. What a row returns is a fixed set of
 * columns plus a detail object reduced to a whitelist of keys (kept beside
 * the backend's read, lib/audit/audit-read), so no credential-bearing field
 * can be read back through this procedure even if one were ever written.
 */
export const AUDIT_LIST_MAX_LIMIT = 200;
export const AUDIT_LIST_DEFAULT_LIMIT = 50;

const shortFilter = z.string().min(1).max(200);

export const AuditListCursorSchema = z.object({
  occurred_at: z.string().datetime({ offset: true }),
  uuid: z.string().uuid(),
});

export const AuditListRequestSchema = z
  .object({
    limit: z
      .number()
      .int()
      .min(1)
      .max(AUDIT_LIST_MAX_LIMIT)
      .default(AUDIT_LIST_DEFAULT_LIMIT),
    cursor: AuditListCursorSchema.optional(),
    actor_id: shortFilter.optional(),
    actor_type: z
      .enum(["user", "api_key", "oauth_client", "anonymous", "system"])
      .optional(),
    action: z.string().min(1).max(100).optional(),
    target_type: z.string().min(1).max(100).optional(),
    target_id: shortFilter.optional(),
    outcome: z.enum(["success", "failure", "denied"]).optional(),
    since: z.string().datetime({ offset: true }).optional(),
    until: z.string().datetime({ offset: true }).optional(),
  })
  .default({ limit: AUDIT_LIST_DEFAULT_LIMIT });

export const AuditListRowSchema = z.object({
  uuid: z.string(),
  occurred_at: z.string(),
  actor_type: z.string(),
  actor_id: z.string().nullable(),
  actor_label: z.string().nullable(),
  actor_ip: z.string().nullable(),
  action: z.string(),
  target_type: z.string().nullable(),
  target_id: z.string().nullable(),
  outcome: z.string(),
  request_id: z.string().nullable(),
  http_status: z.number().nullable(),
  detail: z.record(z.string(), z.unknown()),
  /** How many detail keys were left out because they are not whitelisted. */
  detail_omitted: z.number().int().min(0),
});

export const AuditListResponseSchema = z.object({
  rows: z.array(AuditListRowSchema),
  next_cursor: AuditListCursorSchema.nullable(),
});

export type AuditListRequest = z.infer<typeof AuditListRequestSchema>;
export type AuditListRow = z.infer<typeof AuditListRowSchema>;
export type AuditListResponse = z.infer<typeof AuditListResponseSchema>;
