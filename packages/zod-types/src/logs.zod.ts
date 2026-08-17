import { z } from "zod";

export const MetaMcpLogCategorySchema = z.enum([
  "connection",
  "client",
  "tool_call",
  "server",
  "system",
]);

export const MetaMcpLogEntrySchema = z.object({
  id: z.string(),
  timestamp: z.date(),
  category: MetaMcpLogCategorySchema,
  serverName: z.string(),
  serverUuid: z.string().optional(),
  level: z.enum(["error", "info", "warn"]),
  message: z.string(),
  toolName: z.string().optional(),
  durationMs: z.number().optional(),
  clientName: z.string().optional(),
  sessionId: z.string().optional(),
  error: z.string().optional(),
});

export const GetLogsRequestSchema = z.object({
  limit: z.number().int().positive().max(2000).optional(),
});

export const GetLogsResponseSchema = z.object({
  success: z.literal(true),
  data: z.array(MetaMcpLogEntrySchema),
  totalCount: z.number(),
});

// There is deliberately no ClearLogsResponseSchema. The `logs.clear`
// procedure was removed with the audit_log work (migration 0028): a gateway
// whose promise is an immutable security record must not ship a
// "clear all logs" contract for anyone to re-wire a button to. Read-only is
// the whole surface.

// ---------------------------------------------------------------------------
// Durable gateway activity history (`gateway_events`, migration 0031)
// ---------------------------------------------------------------------------

/**
 * Categories the durable history can hold — the live-log categories MINUS
 * `tool_call`, which is persisted per call to `tool_call_audit` instead and is
 * filtered out by the writer. Declared as its own enum rather than derived
 * from `MetaMcpLogCategorySchema` so the omission is visible in the contract
 * and a future category added to the live view cannot silently start
 * validating against a table that never receives it.
 */
export const GatewayEventCategorySchema = z.enum([
  "connection",
  "client",
  "server",
  "system",
]);

export const GatewayEventLevelSchema = z.enum(["error", "info", "warn"]);

/**
 * ISO-8601 STRINGS ON THE WIRE, not `z.date()`, and this is not cosmetic.
 *
 * The tRPC client in `apps/frontend/lib/trpc.ts` is configured with a plain
 * `httpBatchLink` and NO data transformer, so JSON is the whole contract: a
 * Date sent from the browser arrives as a string and a `z.date()` INPUT
 * rejects it outright. The pre-existing `MetaMcpLogEntrySchema` declares
 * `timestamp: z.date()` and gets away with it only because output validation
 * runs server-side, before serialization — which is why `logs-store.ts` has to
 * re-wrap every value in `new Date()` on arrival. Declaring what actually
 * crosses the wire keeps the type honest in both directions.
 *
 * It also makes the pagination cursor exact. The client hands back the same
 * string it was given rather than a Date it re-parsed, so nothing in the round
 * trip can round or truncate the value the keyset compares against.
 */
export const GatewayEventSchema = z.object({
  uuid: z.string(),
  occurredAt: z.iso.datetime(),
  category: z.string(),
  level: z.string().nullable(),
  serverUuid: z.string().nullable(),
  serverName: z.string().nullable(),
  clientName: z.string().nullable(),
  sessionId: z.string().nullable(),
  message: z.string(),
  metadata: z.record(z.string(), z.unknown()).nullable(),
});

/** Largest page the history surface will return. Mirrors the backend bound. */
export const GATEWAY_EVENT_PAGE_MAX = 200;

/** Longest substring the history surface will match on. */
export const GATEWAY_EVENT_SEARCH_MAX = 200;

/**
 * Keyset cursor. The full `(occurredAt, uuid)` tuple, not just the timestamp:
 * a reconnect storm writes many rows inside the same millisecond, so a
 * timestamp-only cursor would repeat or skip rows at every page boundary.
 */
export const GatewayEventCursorSchema = z.object({
  occurredAt: z.iso.datetime(),
  uuid: z.string(),
});

export const GetGatewayEventsRequestSchema = z
  .object({
    from: z.iso.datetime().optional(),
    to: z.iso.datetime().optional(),
    category: GatewayEventCategorySchema.optional(),
    level: GatewayEventLevelSchema.optional(),
    serverName: z.string().max(256).optional(),
    clientName: z.string().max(256).optional(),
    // Clamped rather than rejected: this is a filter box an operator types into
    // during an investigation, and silently matching on the first 200 characters
    // is a better answer than a validation error on a paste. The backend escapes
    // LIKE metacharacters so the value stays a substring, not a pattern.
    search: z
      .string()
      .transform((value) => value.slice(0, GATEWAY_EVENT_SEARCH_MAX))
      .optional(),
    cursor: GatewayEventCursorSchema.optional(),
    limit: z.number().int().positive().max(GATEWAY_EVENT_PAGE_MAX).optional(),
  })
  .refine((input) => !input.cursor || input.from !== undefined, {
    // A caller that omits `from` gets a default window computed from the CURRENT
    // time, which slides forward between requests. Paging on that default means
    // page two is evaluated against a window whose older edge has moved past
    // where page one stopped, so the oldest rows of the run vanish — a silent
    // gap, which is the one outcome this surface must not produce. Rejecting the
    // combination turns it into an error the caller can see and fix by pinning
    // the window, which is what the history view already does.
    message: "from must be pinned when paging with a cursor",
    path: ["from"],
  });

export const GetGatewayEventsResponseSchema = z.object({
  success: z.literal(true),
  data: z.array(GatewayEventSchema),
  // Present when another page exists. Absent means the caller has reached the
  // end — deliberately not a `hasMore` boolean plus a separate cursor, so the
  // two cannot disagree.
  nextCursor: GatewayEventCursorSchema.nullable(),
  // Server names seen in the requested window, for the filter control. Scoped
  // to the window rather than the whole table so a name that stopped appearing
  // months ago does not clutter a filter over the last hour.
  serverNames: z.array(z.string()),
});

export type MetaMcpLogCategory = z.infer<typeof MetaMcpLogCategorySchema>;
export type MetaMcpLogEntry = z.infer<typeof MetaMcpLogEntrySchema>;
export type GetLogsRequest = z.infer<typeof GetLogsRequestSchema>;
export type GetLogsResponse = z.infer<typeof GetLogsResponseSchema>;
export type GatewayEventCategory = z.infer<typeof GatewayEventCategorySchema>;
export type GatewayEventLevel = z.infer<typeof GatewayEventLevelSchema>;
export type GatewayEvent = z.infer<typeof GatewayEventSchema>;
export type GatewayEventCursor = z.infer<typeof GatewayEventCursorSchema>;
export type GetGatewayEventsRequest = z.infer<
  typeof GetGatewayEventsRequestSchema
>;
export type GetGatewayEventsResponse = z.infer<
  typeof GetGatewayEventsResponseSchema
>;
