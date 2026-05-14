/**
 * Unit tests for the `mcp_sessions` repository contract.
 *
 * These tests run against a Drizzle mock — they exercise the call shape
 * the repository produces against the DB layer (INSERT … ON CONFLICT
 * DO NOTHING, SELECT … LIMIT 1, UPDATE … last_seen_at, DELETE … WHERE
 * last_seen_at < cutoff). They do NOT exercise the postgres engine
 * itself — that's covered by the manual validation in the task spec
 * §Validation (post-deploy restart test on mcp-host-prod).
 *
 * The router-side lazy-recovery behavior + cross-namespace defense +
 * auth-mismatch refusal live in the streamable-http integration tests
 * once we wire mocks for the router. For now this file pins the repo
 * surface so a future refactor that changes the SQL shape (e.g. moves
 * to a different ORM, splits the table, adds a soft-delete column)
 * surfaces in CI rather than at runtime.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock `../index` (the Drizzle DB handle) BEFORE importing the repo.
// The repo destructures `db` from there at module load.
const insertChain = {
  values: vi.fn().mockReturnThis(),
  onConflictDoNothing: vi.fn().mockResolvedValue(undefined),
};
const selectChain = {
  from: vi.fn().mockReturnThis(),
  where: vi.fn().mockReturnThis(),
  limit: vi.fn().mockResolvedValue([]),
};
const updateChain = {
  set: vi.fn().mockReturnThis(),
  where: vi.fn().mockResolvedValue(undefined),
};
const deleteChain = {
  where: vi.fn().mockReturnThis(),
  returning: vi.fn().mockResolvedValue([]),
};

vi.mock("../index", () => ({
  db: {
    insert: vi.fn(() => insertChain),
    select: vi.fn(() => selectChain),
    update: vi.fn(() => updateChain),
    delete: vi.fn(() => deleteChain),
  },
}));

// `schema.ts` imports `@repo/zod-types`, a workspace package vitest's
// vite resolver can't load in unit-test mode (no package entry exists
// at build-tree time without a turbo build). Stub the schema export
// the repo actually touches so the import graph stays satisfiable.
vi.mock("../schema", () => ({
  mcpSessionsTable: {
    session_id: { name: "session_id" },
    namespace_uuid: { name: "namespace_uuid" },
    endpoint_name: { name: "endpoint_name" },
    auth_principal: { name: "auth_principal" },
    auth_method: { name: "auth_method" },
    init_params: { name: "init_params" },
    created_at: { name: "created_at" },
    last_seen_at: { name: "last_seen_at" },
  },
}));

import { mcpSessionsRepository } from "./mcp-sessions.repo";

describe("McpSessionsRepository", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    selectChain.limit.mockResolvedValue([]);
    deleteChain.returning.mockResolvedValue([]);
  });

  it("persist() inserts with onConflictDoNothing on session_id", async () => {
    await mcpSessionsRepository.persist({
      session_id: "abc-123",
      namespace_uuid: "ns-uuid",
      endpoint_name: "autotask",
      auth_principal: "deadbeef".repeat(8),
      auth_method: "api_key",
    });

    expect(insertChain.values).toHaveBeenCalledWith(
      expect.objectContaining({
        session_id: "abc-123",
        namespace_uuid: "ns-uuid",
        endpoint_name: "autotask",
        auth_principal: "deadbeef".repeat(8),
        auth_method: "api_key",
        init_params: {},
      }),
    );
    expect(insertChain.onConflictDoNothing).toHaveBeenCalledWith(
      expect.objectContaining({ target: expect.anything() }),
    );
  });

  it("findById() returns null when no row matches", async () => {
    selectChain.limit.mockResolvedValueOnce([]);
    const result = await mcpSessionsRepository.findById("missing");
    expect(result).toBeNull();
  });

  it("findById() maps the row into PersistedMcpSession when present", async () => {
    const created = new Date("2026-05-14T17:00:00Z");
    const lastSeen = new Date("2026-05-14T17:30:00Z");
    selectChain.limit.mockResolvedValueOnce([
      {
        session_id: "abc",
        namespace_uuid: "ns",
        endpoint_name: "ep",
        auth_principal: "hash",
        auth_method: "api_key",
        init_params: { foo: "bar" },
        created_at: created,
        last_seen_at: lastSeen,
      },
    ]);
    const result = await mcpSessionsRepository.findById("abc");
    expect(result).toEqual({
      session_id: "abc",
      namespace_uuid: "ns",
      endpoint_name: "ep",
      auth_principal: "hash",
      auth_method: "api_key",
      init_params: { foo: "bar" },
      created_at: created,
      last_seen_at: lastSeen,
    });
  });

  it("touch() issues an UPDATE setting last_seen_at to NOW()", async () => {
    await mcpSessionsRepository.touch("session-id");
    expect(updateChain.set).toHaveBeenCalledWith(
      expect.objectContaining({ last_seen_at: expect.anything() }),
    );
    expect(updateChain.where).toHaveBeenCalled();
  });

  it("delete() issues a DELETE keyed by session_id", async () => {
    await mcpSessionsRepository.delete("session-id");
    expect(deleteChain.where).toHaveBeenCalled();
  });

  it("pruneOlderThan() returns the count of deleted rows", async () => {
    deleteChain.returning.mockResolvedValueOnce([
      { session_id: "old-1" },
      { session_id: "old-2" },
      { session_id: "old-3" },
    ]);
    const cutoff = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000);
    const count = await mcpSessionsRepository.pruneOlderThan(cutoff);
    expect(count).toBe(3);
  });

  it("pruneOlderThan() returns 0 when nothing is past the cutoff", async () => {
    deleteChain.returning.mockResolvedValueOnce([]);
    const count = await mcpSessionsRepository.pruneOlderThan(new Date(0));
    expect(count).toBe(0);
  });
});
