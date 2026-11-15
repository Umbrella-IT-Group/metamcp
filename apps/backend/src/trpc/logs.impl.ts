import {
  GATEWAY_EVENT_PAGE_MAX,
  GetGatewayEventsRequestSchema,
  GetGatewayEventsResponseSchema,
  GetLogsRequestSchema,
  GetLogsResponseSchema,
} from "@repo/zod-types";
import { TRPCError } from "@trpc/server";
import { z } from "zod";

import { describeDbError } from "@/lib/db-error-summary";
import logger from "@/utils/logger";

import { gatewayEventsRepository } from "../db/repositories/gateway-events.repo";
import { projectGatewayEventForAdminPlane } from "../lib/diagnostic-redaction";
import { metamcpLogStore } from "../lib/metamcp/log-store";

// Read-only by design. `clearLogs` was removed with migration 0028's
// audit_log — see the note in packages/trpc/src/routers/frontend/logs.ts.
// The in-memory `clearLogs()` method it called is gone from the log store
// too, so nothing in the process can empty the buffer any more. The history
// procedure below is read-only for the same reason, one layer deeper: its
// table refuses UPDATE and TRUNCATE at any age and DELETE inside the 30-day
// window (migration 0031).

/**
 * Default history window when the caller supplies no `from`.
 *
 * A history view that defaults to "everything ever" issues an unbounded scan
 * on every page load of a table that only grows, and answers a question nobody
 * asked — the first thing an operator wants is recent activity. 24 hours is
 * one shift plus change; the UI offers wider ranges explicitly.
 */
const DEFAULT_HISTORY_WINDOW_MS = 24 * 60 * 60 * 1000;

/**
 * What an admin-plane key is told when it asks the history to search. The
 * search runs against the message as stored, so which rows it returns would
 * show, a character at a time, text the redacted response hides. Fixed; names
 * no search term.
 */
export const HISTORY_SEARCH_REFUSAL =
  "An admin-plane API key cannot search the diagnostic history, because a search matches text that the response redacts. Filter by category, level, server or client instead.";

export const logsImplementations = {
  getLogs: async (
    input: z.infer<typeof GetLogsRequestSchema>,
  ): Promise<z.infer<typeof GetLogsResponseSchema>> => {
    try {
      const logs = metamcpLogStore.getLogs(input.limit);
      const totalCount = metamcpLogStore.getLogCount();

      return {
        success: true as const,
        data: logs,
        totalCount,
      };
    } catch (error) {
      logger.error("Error getting logs:", error);
      throw new Error("Failed to get logs");
    }
  },

  /**
   * One page of the durable history. `redactForAdminPlane` is set by the
   * router from the verified origin of the request: an admin-plane key reads
   * each row through lib/diagnostic-redaction (credential-shaped text
   * replaced, metadata reduced to the error text, no session id) and may not
   * search, since a search matches the text as stored; a person's session
   * reads the rows as stored and may search.
   */
  getHistory: async (
    input: z.infer<typeof GetGatewayEventsRequestSchema>,
    options: { redactForAdminPlane: boolean } = { redactForAdminPlane: false },
  ): Promise<z.infer<typeof GetGatewayEventsResponseSchema>> => {
    // Before the read, and outside the try whose catch-all would turn it into
    // a 500: a search term is refused for an admin-plane caller, because the
    // match is made on the unredacted text (see HISTORY_SEARCH_REFUSAL).
    if (options.redactForAdminPlane && input.search) {
      throw new TRPCError({
        code: "BAD_REQUEST",
        message: HISTORY_SEARCH_REFUSAL,
      });
    }
    try {
      // The contract carries ISO strings (no tRPC data transformer is
      // configured — see GatewayEventSchema); the driver wants Dates.
      const from = input.from
        ? new Date(input.from)
        : new Date(Date.now() - DEFAULT_HISTORY_WINDOW_MS);
      const to = input.to ? new Date(input.to) : null;
      const limit = Math.min(
        input.limit ?? GATEWAY_EVENT_PAGE_MAX,
        GATEWAY_EVENT_PAGE_MAX,
      );

      // Fetch one extra row rather than issuing a second COUNT query. The extra
      // row is the only evidence needed for "is there another page", it costs
      // one row instead of a full scan of the filtered range, and it cannot
      // disagree with the page it was fetched alongside the way a separate
      // count taken a moment later can.
      const rows = await gatewayEventsRepository.list({
        from,
        to,
        category: input.category ?? null,
        level: input.level ?? null,
        serverName: input.serverName ?? null,
        clientName: input.clientName ?? null,
        search: input.search ?? null,
        cursor: input.cursor
          ? {
              occurred_at: new Date(input.cursor.occurredAt),
              uuid: input.cursor.uuid,
            }
          : null,
        limit: limit + 1,
      });

      const page = rows.slice(0, limit);
      const last = page[page.length - 1];
      const nextCursor =
        rows.length > limit && last
          ? { occurredAt: last.occurred_at.toISOString(), uuid: last.uuid }
          : null;

      // FIRST PAGE ONLY, and the condition is the point rather than a
      // micro-optimisation.
      //
      // Scoped to the same window the rows came from — both ends of it — so the
      // filter offers the servers that actually appear in what the operator is
      // looking at. But that list is a `SELECT DISTINCT` over the window, which
      // no index can serve: it is a full scan of the range, on the MAIN pool,
      // and it costs more than the page it accompanies once the table is large.
      //
      // Paying it per page bought nothing at all. The window is pinned for the
      // whole paging run (a cursor without a pinned `from` is refused), so the
      // answer cannot change between page one and page four — and the client
      // keeps the first page's list and discards what later pages carry. So
      // every "load older" was re-running the most expensive query in the
      // request to produce a value nobody read.
      //
      // An empty array is a valid response, not a sentinel: the caller that
      // asked for a cursor page already has the list.
      const serverNames = input.cursor
        ? []
        : await gatewayEventsRepository.listServerNames(from, to);

      return {
        success: true as const,
        data: page.map((row) => {
          const event = {
            uuid: row.uuid,
            occurredAt: row.occurred_at.toISOString(),
            category: row.category,
            level: row.level,
            serverUuid: row.server_uuid,
            serverName: row.server_name,
            clientName: row.client_name,
            sessionId: row.session_id,
            message: row.message,
            metadata: row.metadata as Record<string, unknown> | null,
          };
          return options.redactForAdminPlane
            ? projectGatewayEventForAdminPlane(event)
            : event;
        }),
        nextCursor,
        serverNames,
      };
    } catch (error) {
      logger.error(
        "Error getting gateway event history:",
        describeDbError(error),
      );
      throw new Error("Failed to get gateway event history");
    }
  },
};
