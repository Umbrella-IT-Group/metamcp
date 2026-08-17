import { and, eq, gte, lte, SQL, sql } from "drizzle-orm";

import {
  clampGatewayMetadata,
  clampGatewayText,
  clampSearchText,
  escapeLikePattern,
  GATEWAY_EVENT_MESSAGE_MAX,
  GATEWAY_EVENT_PAGE_MAX,
} from "@/lib/gateway-events/bounds";

import { gatewayEventsDb } from "../gateway-events-db";
import { db } from "../index";
import { gatewayEventsTable } from "../schema";

export interface GatewayEventEntry {
  category: string;
  level?: string | null;
  server_uuid?: string | null;
  server_name?: string | null;
  client_name?: string | null;
  session_id?: string | null;
  message: string;
  metadata?: Record<string, unknown> | null;
}

export interface GatewayEventRow {
  uuid: string;
  occurred_at: Date;
  category: string;
  level: string | null;
  server_uuid: string | null;
  server_name: string | null;
  client_name: string | null;
  session_id: string | null;
  message: string;
  metadata: Record<string, unknown> | null;
}

export interface GatewayEventListFilters {
  from?: Date | null;
  to?: Date | null;
  category?: string | null;
  level?: string | null;
  serverName?: string | null;
  clientName?: string | null;
  search?: string | null;
  /** Keyset cursor — return rows strictly older than this (occurred_at, uuid). */
  cursor?: { occurred_at: Date; uuid: string } | null;
  limit?: number | null;
}

/**
 * Persistence for the gateway activity history (migration 0031).
 *
 * FOUR METHODS, ON TWO DIFFERENT POOLS, AND THE SPLIT IS THE DESIGN.
 *
 * `record()` writes through `gatewayEventsDb` — a deliberately tiny
 * two-connection pool with a 1s checkout timeout (`../gateway-events-db`).
 * Every non-tool-call entry that reaches the Live Logs ring buffer is also
 * written here, and the busiest of those are the connection retry loop and
 * backend stderr: a crash-looping backend is a write firehose. Sharing the
 * main pool would let that churn contend for the same ten connections the
 * request path uses. Sharing the AUDIT pool would be worse still — read
 * `../gateway-events-db` for why an operational firehose must not be able to
 * cost the gateway a security-audit row. Under saturation the write fails fast
 * and the caller drops it — see `lib/gateway-events/sink`, which is the only
 * thing that should ever call this method.
 *
 * `pruneOlderThan()`, `list()` and `listServerNames()` use the MAIN pool.
 * None of them belongs on a two-connection budget: the prune is a bounded
 * DELETE on a timer and the reads are admin-only queries, and putting any of
 * them there would let one stall the writer it is supposed to be isolated
 * from. The isolation that matters runs one way — the hot write path must not
 * be starved — not both.
 *
 * IMMUTABILITY. There is no `update()` and there never should be; migration
 * 0031 refuses UPDATE and TRUNCATE at every row age, and refuses DELETE for
 * rows younger than 30 days. `pruneOlderThan` is the one deletion path, and it
 * is written so it cannot ask for anything the database will refuse.
 */
export class GatewayEventsRepository {
  async record(entry: GatewayEventEntry): Promise<void> {
    await gatewayEventsDb.insert(gatewayEventsTable).values({
      category: entry.category,
      level: entry.level ?? null,
      server_uuid: entry.server_uuid ?? null,
      server_name: clampGatewayText(entry.server_name),
      client_name: clampGatewayText(entry.client_name),
      session_id: clampGatewayText(entry.session_id),
      message: entry.message.slice(0, GATEWAY_EVENT_MESSAGE_MAX),
      metadata: clampGatewayMetadata(entry.metadata),
    });
  }

  /**
   * Delete rows older than `days`. Best-effort; returns nothing.
   *
   * THE CUTOFF IS COMPUTED IN SQL, not in JavaScript, and that is the whole
   * subtlety of this method. Migration 0031's DELETE trigger refuses any row
   * whose `occurred_at >= now() - interval '30 days'`, evaluated against the
   * DATABASE clock at transaction-start time. If this method built its cutoff
   * from `Date.now()` instead, an application clock running even slightly
   * ahead of the database would select boundary rows the trigger then refuses
   * — turning a routine sweep into a recurring exception, on a timer, forever.
   * Deriving both sides from the same `now()` makes the two predicates
   * identical at the boundary by construction rather than by hoping the clocks
   * agree.
   *
   * The caller floor-clamps `days` to 30 (`lib/gateway-events/retention`), so
   * the range this deletes is always at or outside the immutability window.
   */
  async pruneOlderThan(days: number): Promise<void> {
    await db
      .delete(gatewayEventsTable)
      .where(
        sql`${gatewayEventsTable.occurred_at} < now() - make_interval(days => ${days})`,
      );
  }

  /**
   * One page of history, newest first.
   *
   * KEYSET, NOT OFFSET. `occurred_at` is only unique by luck — a reconnect
   * storm writes many rows inside the same millisecond — so paging on
   * `occurred_at` alone would repeat or skip rows at every page boundary. The
   * cursor is the full `(occurred_at, uuid)` tuple and the comparison is a row
   * comparison, which is both correct and index-friendly: the composite is
   * strictly decreasing, so the scan resumes where the previous page stopped
   * instead of re-reading and discarding everything before it the way OFFSET
   * does on a table that only grows.
   */
  async list(filters: GatewayEventListFilters): Promise<GatewayEventRow[]> {
    const conditions: SQL[] = [];

    if (filters.from) {
      conditions.push(gte(gatewayEventsTable.occurred_at, filters.from));
    }
    if (filters.to) {
      conditions.push(lte(gatewayEventsTable.occurred_at, filters.to));
    }
    if (filters.category) {
      conditions.push(eq(gatewayEventsTable.category, filters.category));
    }
    if (filters.level) {
      conditions.push(eq(gatewayEventsTable.level, filters.level));
    }
    if (filters.serverName) {
      conditions.push(eq(gatewayEventsTable.server_name, filters.serverName));
    }
    if (filters.clientName) {
      conditions.push(eq(gatewayEventsTable.client_name, filters.clientName));
    }
    if (filters.search) {
      // Escaped, clamped, and given an explicit ESCAPE clause: the operator
      // typed a substring, not a pattern, and `100%` must not silently become
      // a prefix match. See lib/gateway-events/bounds.
      const pattern = `%${escapeLikePattern(clampSearchText(filters.search))}%`;
      conditions.push(
        sql`${gatewayEventsTable.message} ILIKE ${pattern} ESCAPE '\\'`,
      );
    }
    if (filters.cursor) {
      conditions.push(
        sql`(${gatewayEventsTable.occurred_at}, ${gatewayEventsTable.uuid}) < (${filters.cursor.occurred_at}, ${filters.cursor.uuid}::uuid)`,
      );
    }

    // The ceiling is PAGE_MAX + 1, not PAGE_MAX, and the difference is a bug
    // that hid behind two clamps agreeing on the wrong number. The caller asks
    // for one row MORE than the page it intends to return, using the extra row
    // as evidence that a next page exists. Clamping here to PAGE_MAX made that
    // probe unrepresentable at the largest page size — which is also the
    // DEFAULT page size — so `rows.length > limit` was never true, the cursor
    // was always null, and every row past the first page became unreachable.
    // Silently skipping rows is precisely what the keyset design exists to
    // prevent, so the probe row gets its own headroom rather than competing
    // with the page for it.
    const limit = Math.min(
      Math.max(filters.limit ?? GATEWAY_EVENT_PAGE_MAX, 1),
      GATEWAY_EVENT_PAGE_MAX + 1,
    );

    const rows = await db
      .select()
      .from(gatewayEventsTable)
      .where(conditions.length > 0 ? and(...conditions) : undefined)
      .orderBy(
        sql`${gatewayEventsTable.occurred_at} DESC, ${gatewayEventsTable.uuid} DESC`,
      )
      .limit(limit);

    return rows as GatewayEventRow[];
  }

  /**
   * Distinct server names present in the window, for the history filter UI.
   *
   * Bounded by BOTH ends of the window the rows came from, so the filter offers
   * the servers that appear in what the operator is actually looking at rather
   * than every server seen since `from`.
   *
   * ORDER BY inside the query, not only in JavaScript afterwards. The LIMIT is
   * what makes it load-bearing: an unordered `SELECT DISTINCT ... LIMIT 200`
   * returns an ARBITRARY 200 of however many distinct names exist, so past that
   * count the filter would offer a different subset on each page load. Sorting
   * in the database makes the truncation deterministic — always the first 200
   * by name — and the JavaScript sort then only has to agree with it.
   */
  async listServerNames(since: Date, until?: Date | null): Promise<string[]> {
    const conditions: SQL[] = [
      gte(gatewayEventsTable.occurred_at, since),
      sql`${gatewayEventsTable.server_name} IS NOT NULL`,
    ];
    if (until) {
      conditions.push(lte(gatewayEventsTable.occurred_at, until));
    }

    const rows = await db
      .selectDistinct({ server_name: gatewayEventsTable.server_name })
      .from(gatewayEventsTable)
      .where(and(...conditions))
      .orderBy(gatewayEventsTable.server_name)
      .limit(GATEWAY_EVENT_PAGE_MAX);

    return rows
      .map((row) => row.server_name)
      .filter((name): name is string => Boolean(name));
  }
}

export const gatewayEventsRepository = new GatewayEventsRepository();
