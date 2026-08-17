/**
 * The history read surface: what the caller's filters become, and what the
 * caller gets back.
 *
 * The SQL these filters compile to is exercised against a real Postgres in
 * `db/repositories/gateway-events-immutability.integration.test.ts`. What is
 * pinned here is everything above the driver — the default window, the
 * fetch-one-extra pagination, the cursor translation, and the input contract's
 * clamps — because those are the parts that can be wrong while every query
 * still succeeds.
 */

import { GetGatewayEventsRequestSchema } from "@repo/zod-types";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { listMock, listServerNamesMock, loggerMock } = vi.hoisted(() => ({
  listMock: vi.fn(),
  listServerNamesMock: vi.fn(),
  loggerMock: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));
// Replaces the module before it evaluates, which also keeps `db/index` (and
// its DATABASE_URL requirement) out of this suite's graph entirely.
vi.mock("../db/repositories/gateway-events.repo", () => ({
  gatewayEventsRepository: {
    list: listMock,
    listServerNames: listServerNamesMock,
  },
}));

const { logsImplementations } = await import("./logs.impl");

const row = (n: number) => ({
  uuid: `0000000${n}-0000-4000-8000-000000000000`,
  occurred_at: new Date(Date.UTC(2026, 7, 17, 12, 0, n)),
  category: "connection",
  level: "warn",
  server_uuid: null,
  server_name: "example-backend",
  client_name: null,
  session_id: null,
  message: `event ${n}`,
  metadata: null,
});

beforeEach(() => {
  vi.clearAllMocks();
  listMock.mockResolvedValue([]);
  listServerNamesMock.mockResolvedValue([]);
});

describe("getHistory — the query it issues", () => {
  it("defaults to the last 24 hours rather than scanning the whole table", async () => {
    await logsImplementations.getHistory({});
    const after = Date.now();

    const { from } = listMock.mock.calls[0][0];
    const windowMs = after - from.getTime();
    // A history view that defaults to "everything ever" issues an unbounded
    // scan on every page load of a table that only grows. Bounded on both sides
    // with a tolerance rather than pinned exactly — the default is computed
    // from a live clock, so an exact equality would be a flake waiting for a
    // slow millisecond.
    expect(windowMs).toBeGreaterThanOrEqual(24 * 60 * 60 * 1000);
    expect(windowMs).toBeLessThan(24 * 60 * 60 * 1000 + 5000);
  });

  it("passes every filter through, parsing the wire strings into dates", async () => {
    const from = "2026-08-01T00:00:00.000Z";
    const to = "2026-08-02T00:00:00.000Z";
    const cursorAt = "2026-08-01T12:00:00.000Z";

    await logsImplementations.getHistory({
      from,
      to,
      category: "client",
      level: "error",
      serverName: "example-backend",
      clientName: "example-consumer",
      search: "hang up",
      cursor: { occurredAt: cursorAt, uuid: "abc" },
      limit: 50,
    });

    expect(listMock).toHaveBeenCalledWith({
      from: new Date(from),
      to: new Date(to),
      category: "client",
      level: "error",
      serverName: "example-backend",
      clientName: "example-consumer",
      search: "hang up",
      // Renamed to the column casing the repository speaks, and parsed: the
      // contract carries ISO strings because the tRPC client has no data
      // transformer, so a Date never survives the wire.
      cursor: { occurred_at: new Date(cursorAt), uuid: "abc" },
      // One more than the page size — see the pagination block below.
      limit: 51,
    });
  });

  it("scopes the server-name filter list to BOTH ends of the rows' window", async () => {
    const from = "2026-08-01T00:00:00.000Z";
    const to = "2026-08-02T00:00:00.000Z";
    await logsImplementations.getHistory({ from, to });

    // A name that stopped appearing months ago should not clutter a filter over
    // the last hour, and neither should one that only appears after the window
    // the operator asked for.
    expect(listServerNamesMock).toHaveBeenCalledWith(
      new Date(from),
      new Date(to),
    );
  });

  it("passes a null upper bound when the caller gave no `to`", async () => {
    const from = "2026-08-01T00:00:00.000Z";
    await logsImplementations.getHistory({ from });

    expect(listServerNamesMock).toHaveBeenCalledWith(new Date(from), null);
  });
});

describe("getHistory — pagination", () => {
  it("fetches one extra row and returns a cursor when it comes back", async () => {
    listMock.mockResolvedValue([row(1), row(2), row(3)]);

    const result = await logsImplementations.getHistory({ limit: 2 });

    expect(listMock.mock.calls[0][0].limit).toBe(3);
    // The extra row is evidence of a next page, not part of this one.
    expect(result.data).toHaveLength(2);
    expect(result.data.map((event) => event.message)).toEqual([
      "event 1",
      "event 2",
    ]);
    expect(result.nextCursor).toEqual({
      occurredAt: row(2).occurred_at.toISOString(),
      uuid: row(2).uuid,
    });
  });

  it("serializes timestamps as ISO strings, which is what crosses the wire", async () => {
    listMock.mockResolvedValue([row(1)]);

    const result = await logsImplementations.getHistory({});

    // A Date here would validate server-side and then arrive at the browser as
    // a string anyway — the pre-existing live-logs schema does exactly that,
    // which is why its store re-wraps every value in `new Date()`.
    expect(result.data[0].occurredAt).toBe("2026-08-17T12:00:01.000Z");
  });

  it("returns a null cursor on the last page", async () => {
    listMock.mockResolvedValue([row(1), row(2)]);

    const result = await logsImplementations.getHistory({ limit: 2 });

    expect(result.data).toHaveLength(2);
    // Absent rather than a `hasMore` boolean beside a cursor, so the two cannot
    // disagree.
    expect(result.nextCursor).toBeNull();
  });

  it("returns a null cursor on an empty result", async () => {
    const result = await logsImplementations.getHistory({});

    expect(result.data).toEqual([]);
    expect(result.nextCursor).toBeNull();
  });

  it("caps the page size even if a caller asks past the maximum", async () => {
    // The zod contract rejects >200 at the boundary; this is the same bound
    // applied again inside the implementation, so a future caller that bypasses
    // the schema cannot ask for an unbounded page.
    await logsImplementations.getHistory({ limit: 100000 });

    expect(listMock.mock.calls[0][0].limit).toBe(201);
  });

  it("still reports a next page AT the maximum page size", async () => {
    // The regression this exists for: the implementation asks for `limit + 1`
    // as a probe, and the repository used to clamp that request back down to
    // the page maximum. At the largest page size — which is also the DEFAULT —
    // the probe row was therefore unrepresentable, `rows.length > limit` was
    // never true, and every row past the first page became unreachable with no
    // error anywhere. Asserting the cursor at the boundary, not just at a
    // comfortable limit, is what makes that visible.
    listMock.mockResolvedValue(
      Array.from({ length: 201 }, (_, i) => row(i + 1)),
    );

    const result = await logsImplementations.getHistory({ limit: 200 });

    expect(result.data).toHaveLength(200);
    expect(result.nextCursor).not.toBeNull();
  });

  it("asks for exactly one row past the bound the repository enforces", async () => {
    // Pins the two clamps against each other rather than each against itself.
    // Both were individually correct while disagreeing about the same number,
    // which is how the probe row went missing. The repository's own half of
    // this contract is exercised against a real database in
    // db/repositories/gateway-events-immutability.integration.test.ts.
    const { GATEWAY_EVENT_PAGE_MAX: bound } = await import(
      "@/lib/gateway-events/bounds"
    );
    await logsImplementations.getHistory({});

    expect(listMock.mock.calls[0][0].limit).toBe(bound + 1);
  });
});

describe("getHistory — failures", () => {
  it("does not leak the driver message to the caller", async () => {
    listMock.mockRejectedValue(
      new Error('relation "gateway_events" does not exist at db.example:5432'),
    );

    // A raw driver message carries table names, SQL and the database host. The
    // procedure declares no try/catch of its own upstream, so replacing it here
    // is what keeps it out of the response.
    await expect(logsImplementations.getHistory({})).rejects.toThrow(
      "Failed to get gateway event history",
    );
    expect(loggerMock.error).toHaveBeenCalledTimes(1);
  });
});

describe("the input contract", () => {
  it("takes ISO strings for the time range, which is what JSON can carry", () => {
    expect(
      GetGatewayEventsRequestSchema.parse({ from: "2026-08-01T00:00:00.000Z" })
        .from,
    ).toBe("2026-08-01T00:00:00.000Z");
    expect(() =>
      GetGatewayEventsRequestSchema.parse({ from: "last tuesday" }),
    ).toThrow();
    // A Date is what a caller reaches for first, and it is exactly what does
    // NOT survive the wire: the tRPC client runs a plain httpBatchLink with no
    // transformer, so it would arrive here as a string and a `z.date()` field
    // would have refused it in production while passing every local test that
    // called the implementation directly.
    expect(() =>
      GetGatewayEventsRequestSchema.parse({ from: new Date() }),
    ).toThrow();
  });

  it("clamps a pasted search term instead of rejecting it", () => {
    const parsed = GetGatewayEventsRequestSchema.parse({
      search: "q".repeat(1000),
    });

    expect(parsed.search).toHaveLength(200);
  });

  it("refuses a cursor without a pinned from", () => {
    const cursor = { occurredAt: "2026-08-01T12:00:00.000Z", uuid: "abc" };
    // Without `from` the window is recomputed from the current clock on every
    // request, so its older edge slides forward between pages and the oldest
    // rows of a paging run disappear. A validation error is the honest answer;
    // a silent gap on an investigation surface is not.
    expect(() => GetGatewayEventsRequestSchema.parse({ cursor })).toThrow();
    expect(
      GetGatewayEventsRequestSchema.parse({
        cursor,
        from: "2026-08-01T00:00:00.000Z",
      }).cursor,
    ).toEqual(cursor);
  });

  it("refuses a page size past the maximum", () => {
    expect(() => GetGatewayEventsRequestSchema.parse({ limit: 201 })).toThrow();
    expect(GetGatewayEventsRequestSchema.parse({ limit: 200 }).limit).toBe(200);
  });

  it("refuses a category that is not one of the persisted four", () => {
    // `tool_call` is a live-log category but never a stored one — those rows
    // live in `tool_call_audit`. Accepting it here would return an always-empty
    // page that looks like "no tool calls happened".
    expect(() =>
      GetGatewayEventsRequestSchema.parse({ category: "tool_call" }),
    ).toThrow();
    expect(
      GetGatewayEventsRequestSchema.parse({ category: "system" }).category,
    ).toBe("system");
  });

  it("bounds the server and client name filters", () => {
    expect(() =>
      GetGatewayEventsRequestSchema.parse({ serverName: "s".repeat(257) }),
    ).toThrow();
    expect(() =>
      GetGatewayEventsRequestSchema.parse({ clientName: "c".repeat(257) }),
    ).toThrow();
  });
});
