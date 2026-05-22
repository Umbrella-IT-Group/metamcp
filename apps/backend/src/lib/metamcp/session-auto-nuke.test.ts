/**
 * Unit tests for `autoNukeStaleSessions`. Exercise the call-shape
 * decision tree end to end against a mocked Drizzle DB handle:
 *
 *   - Empty table → no-op (no DELETE issued).
 *   - Only current-hash rows → no-op.
 *   - One old-hash row → DELETE issued, one row reported deleted.
 *   - Mixed null + old + current → DELETE issued, null + old reported.
 *   - `MCP_AUTO_NUKE_ON_CAPABILITY_CHANGE=false` → fully skip.
 *   - DB throws → swallowed, no crash.
 *
 * Mocks the `@/db` handle so we don't touch postgres, and mocks
 * `@/db/schema` so the import graph stays satisfiable without a turbo
 * build (matches the pattern used by `mcp-sessions.repo.test.ts`).
 * `gateway-boot-id` is imported normally — the real
 * `GATEWAY_CAPABILITY_HASH` value flows through and the assertions
 * key off it.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Drizzle chain shapes — re-created per test so the call counters
// don't bleed across cases.
const selectDistinctChain = {
  from: vi.fn().mockReturnThis(),
  where: vi.fn().mockResolvedValue([] as Array<{ capability_hash: string }>),
};
const deleteChain = {
  where: vi.fn().mockReturnThis(),
  returning: vi.fn().mockResolvedValue([] as Array<{ session_id: string }>),
};

// The implementation issues TWO `db.select()` calls (null-count, then
// per-namespace group-by). Queue their resolved values per-test via
// these handles instead of a single mocked value, so cases with
// different shapes don't fight each other.
const nullCountResolver = { value: [{ count: 0 }] as Array<{ count: number }> };
const perNamespaceResolver = {
  value: [] as Array<{ namespace_uuid: string; count: number }>,
};

let selectCallCount = 0;

vi.mock("@/db", () => ({
  db: {
    selectDistinct: vi.fn(() => selectDistinctChain),
    select: vi.fn(() => {
      selectCallCount += 1;
      // First `select` after each test reset is the null-count
      // query; the second is the per-namespace group-by. The
      // implementation order is fixed so this queue is deterministic.
      if (selectCallCount === 1) {
        return {
          from: vi.fn().mockReturnThis(),
          where: vi.fn().mockResolvedValue(nullCountResolver.value),
        };
      }
      return {
        from: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
        groupBy: vi.fn().mockResolvedValue(perNamespaceResolver.value),
      };
    }),
    delete: vi.fn(() => deleteChain),
  },
}));

vi.mock("@/db/schema", () => ({
  mcpSessionsTable: {
    session_id: { name: "session_id" },
    namespace_uuid: { name: "namespace_uuid" },
    capability_hash: { name: "capability_hash" },
  },
}));

// Logger is real — its writes go to a stream we don't inspect. Tests
// assert on db-call shape, not log output, so leaving logger un-mocked
// matches the existing test conventions in this repo.

import { GATEWAY_CAPABILITY_HASH } from "./gateway-boot-id";
import { autoNukeStaleSessions } from "./session-auto-nuke";

const OTHER_HASH = "f".repeat(64);

describe("autoNukeStaleSessions", () => {
  const originalEnv = process.env.MCP_AUTO_NUKE_ON_CAPABILITY_CHANGE;

  beforeEach(() => {
    vi.clearAllMocks();
    selectCallCount = 0;
    selectDistinctChain.where.mockResolvedValue([]);
    nullCountResolver.value = [{ count: 0 }];
    perNamespaceResolver.value = [];
    deleteChain.returning.mockResolvedValue([]);
    delete process.env.MCP_AUTO_NUKE_ON_CAPABILITY_CHANGE;
  });

  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env.MCP_AUTO_NUKE_ON_CAPABILITY_CHANGE;
    } else {
      process.env.MCP_AUTO_NUKE_ON_CAPABILITY_CHANGE = originalEnv;
    }
  });

  it("is a no-op when the env knob is set to false", async () => {
    process.env.MCP_AUTO_NUKE_ON_CAPABILITY_CHANGE = "false";

    const { db } = await import("@/db");
    await autoNukeStaleSessions();

    // No DB activity at all — the env check short-circuits.
    expect(db.selectDistinct).not.toHaveBeenCalled();
    expect(db.select).not.toHaveBeenCalled();
    expect(db.delete).not.toHaveBeenCalled();
  });

  it("is a no-op on an empty table (no distinct hashes, no null rows)", async () => {
    selectDistinctChain.where.mockResolvedValueOnce([]);
    nullCountResolver.value = [{ count: 0 }];

    const { db } = await import("@/db");
    await autoNukeStaleSessions();

    expect(db.selectDistinct).toHaveBeenCalledTimes(1);
    expect(db.select).toHaveBeenCalledTimes(1); // null-count probe only
    expect(db.delete).not.toHaveBeenCalled();
  });

  it("is a no-op when the table contains only current-hash rows", async () => {
    selectDistinctChain.where.mockResolvedValueOnce([
      { capability_hash: GATEWAY_CAPABILITY_HASH },
    ]);
    nullCountResolver.value = [{ count: 0 }];

    const { db } = await import("@/db");
    await autoNukeStaleSessions();

    expect(db.selectDistinct).toHaveBeenCalledTimes(1);
    expect(db.delete).not.toHaveBeenCalled();
  });

  it("nukes when the table contains one old-hash row", async () => {
    selectDistinctChain.where.mockResolvedValueOnce([
      { capability_hash: OTHER_HASH },
    ]);
    nullCountResolver.value = [{ count: 0 }];
    perNamespaceResolver.value = [{ namespace_uuid: "ns-1", count: 1 }];
    deleteChain.returning.mockResolvedValueOnce([{ session_id: "sess-old" }]);

    const { db } = await import("@/db");
    await autoNukeStaleSessions();

    expect(db.delete).toHaveBeenCalledTimes(1);
    expect(deleteChain.returning).toHaveBeenCalledWith(
      expect.objectContaining({ session_id: expect.anything() }),
    );
  });

  it("nukes null + old rows when mixed with current-hash rows", async () => {
    selectDistinctChain.where.mockResolvedValueOnce([
      { capability_hash: GATEWAY_CAPABILITY_HASH },
      { capability_hash: OTHER_HASH },
    ]);
    nullCountResolver.value = [{ count: 3 }];
    perNamespaceResolver.value = [
      { namespace_uuid: "ns-1", count: 2 },
      { namespace_uuid: "ns-2", count: 2 },
    ];
    deleteChain.returning.mockResolvedValueOnce([
      { session_id: "sess-null-1" },
      { session_id: "sess-null-2" },
      { session_id: "sess-null-3" },
      { session_id: "sess-old" },
    ]);

    const { db } = await import("@/db");
    await autoNukeStaleSessions();

    expect(db.delete).toHaveBeenCalledTimes(1);
    expect(deleteChain.returning).toHaveBeenCalled();
  });

  it("nukes when only null-hash rows are present (pre-PR-23 baseline)", async () => {
    selectDistinctChain.where.mockResolvedValueOnce([]);
    nullCountResolver.value = [{ count: 5 }];
    perNamespaceResolver.value = [{ namespace_uuid: "ns-1", count: 5 }];
    deleteChain.returning.mockResolvedValueOnce([
      { session_id: "sess-1" },
      { session_id: "sess-2" },
      { session_id: "sess-3" },
      { session_id: "sess-4" },
      { session_id: "sess-5" },
    ]);

    const { db } = await import("@/db");
    await autoNukeStaleSessions();

    expect(db.delete).toHaveBeenCalledTimes(1);
  });

  it("swallows DB errors instead of throwing", async () => {
    selectDistinctChain.where.mockRejectedValueOnce(
      new Error("postgres: connection refused"),
    );

    // Must not throw — the gateway's start() routes through this
    // helper before app.listen(), so a thrown error would crash the
    // process. The helper is documented as workaround-not-correctness.
    await expect(autoNukeStaleSessions()).resolves.toBeUndefined();
  });

  it("treats env knob value '0' as disabled", async () => {
    process.env.MCP_AUTO_NUKE_ON_CAPABILITY_CHANGE = "0";

    const { db } = await import("@/db");
    await autoNukeStaleSessions();

    expect(db.selectDistinct).not.toHaveBeenCalled();
  });

  it("treats env knob value 'TRUE' (any non-falsy spelling) as enabled", async () => {
    process.env.MCP_AUTO_NUKE_ON_CAPABILITY_CHANGE = "TRUE";
    selectDistinctChain.where.mockResolvedValueOnce([]);
    nullCountResolver.value = [{ count: 0 }];

    const { db } = await import("@/db");
    await autoNukeStaleSessions();

    expect(db.selectDistinct).toHaveBeenCalled();
  });
});
