/**
 * Unit tests for the `mcpServers.reconnect` tRPC implementation.
 *
 * The unit-under-test is the wiring that turns an operator "Reconnect
 * server" click into the FULL pooled-connection cascade — the same
 * invalidateServerConnection path the transport-drop detector runs in
 * prod — rather than the update path's idle-only refresh (which leaves
 * live consumers on their stale connect-time tool list). These tests do
 * not exercise the pool internals (covered by
 * lib/metamcp/mcp-server-pool.test.ts); they assert the impl calls the
 * right cascade, honors the owner trust boundary, and treats the
 * namespace fan-out as best-effort without swallowing a primary failure.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

// The `../db/repositories` barrel reaches db/index, which needs a live
// DATABASE_URL — stub it so the unit test needs no postgres.
vi.mock("../db/repositories", () => ({
  mcpServersRepository: { findByUuid: vi.fn() },
  namespaceMappingsRepository: { findNamespacesByServerUuid: vi.fn() },
}));

vi.mock("../db/serializers", () => ({
  McpServersSerializer: { serializeMcpServer: vi.fn() },
}));

vi.mock("../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    invalidateServerConnection: vi.fn(),
  },
}));

vi.mock("../lib/metamcp/metamcp-middleware/tool-overrides.functional", () => ({
  clearOverrideCache: vi.fn(),
}));

vi.mock("../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {
    invalidateIdleServers: vi.fn(),
    invalidateOpenApiSessions: vi.fn(),
  },
}));

vi.mock("../lib/metamcp/server-error-tracker", () => ({
  serverErrorTracker: {
    resetServerErrorState: vi.fn(),
  },
}));

vi.mock("../lib/metamcp/utils", () => ({
  convertDbServerToParams: vi.fn(),
}));

import {
  mcpServersRepository,
  namespaceMappingsRepository,
} from "../db/repositories";
import { mcpServerPool } from "../lib/metamcp/mcp-server-pool";
import { clearOverrideCache } from "../lib/metamcp/metamcp-middleware/tool-overrides.functional";
import { metaMcpServerPool } from "../lib/metamcp/metamcp-server-pool";
import { serverErrorTracker } from "../lib/metamcp/server-error-tracker";
import { mcpServersImplementations } from "./mcp-servers.impl";

const fakeServer = (overrides: Record<string, unknown> = {}) =>
  ({
    uuid: "server-1",
    name: "autotask",
    user_id: null,
    ...overrides,
  }) as any;

describe("mcpServers.reconnect implementation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(mcpServerPool.invalidateServerConnection).mockResolvedValue(
      undefined,
    );
    vi.mocked(serverErrorTracker.resetServerErrorState).mockResolvedValue(
      undefined as never,
    );
    vi.mocked(metaMcpServerPool.invalidateIdleServers).mockResolvedValue(
      undefined,
    );
    vi.mocked(metaMcpServerPool.invalidateOpenApiSessions).mockResolvedValue(
      undefined,
    );
    vi.mocked(
      namespaceMappingsRepository.findNamespacesByServerUuid,
    ).mockResolvedValue([]);
  });

  it("runs the full cascade, resets error state, and fans out to every affected namespace", async () => {
    vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue(fakeServer());
    vi.mocked(
      namespaceMappingsRepository.findNamespacesByServerUuid,
    ).mockResolvedValue(["ns-1", "ns-2"]);

    const result = await mcpServersImplementations.reconnect(
      { uuid: "server-1" },
      "user-1",
    );

    expect(result.success).toBe(true);
    // The FULL cascade (active + idle slots), not invalidateIdleSession.
    expect(mcpServerPool.invalidateServerConnection).toHaveBeenCalledWith(
      expect.any(String),
      "server-1",
    );
    expect(serverErrorTracker.resetServerErrorState).toHaveBeenCalledWith(
      "server-1",
    );
    expect(metaMcpServerPool.invalidateIdleServers).toHaveBeenCalledWith([
      "ns-1",
      "ns-2",
    ]);
    expect(metaMcpServerPool.invalidateOpenApiSessions).toHaveBeenCalledWith([
      "ns-1",
      "ns-2",
    ]);
    expect(clearOverrideCache).toHaveBeenCalledTimes(2);
    expect(clearOverrideCache).toHaveBeenCalledWith("ns-1");
    expect(clearOverrideCache).toHaveBeenCalledWith("ns-2");
  });

  it("still reconnects a server that belongs to no namespace (no fan-out)", async () => {
    vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue(fakeServer());
    vi.mocked(
      namespaceMappingsRepository.findNamespacesByServerUuid,
    ).mockResolvedValue([]);

    const result = await mcpServersImplementations.reconnect(
      { uuid: "server-1" },
      "user-1",
    );

    expect(result.success).toBe(true);
    expect(mcpServerPool.invalidateServerConnection).toHaveBeenCalledWith(
      expect.any(String),
      "server-1",
    );
    expect(metaMcpServerPool.invalidateIdleServers).not.toHaveBeenCalled();
    expect(metaMcpServerPool.invalidateOpenApiSessions).not.toHaveBeenCalled();
    expect(clearOverrideCache).not.toHaveBeenCalled();
  });

  it("lets a user reconnect a public (unowned) server", async () => {
    vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue(
      fakeServer({ user_id: null }),
    );

    const result = await mcpServersImplementations.reconnect(
      { uuid: "server-1" },
      "anyone",
    );

    expect(result.success).toBe(true);
    expect(mcpServerPool.invalidateServerConnection).toHaveBeenCalledTimes(1);
  });

  it("denies reconnecting a server owned by another user and runs no cascade", async () => {
    vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue(
      fakeServer({ user_id: "owner-A" }),
    );

    const result = await mcpServersImplementations.reconnect(
      { uuid: "server-1" },
      "user-B",
    );

    expect(result.success).toBe(false);
    expect(result.message).toContain("Access denied");
    expect(mcpServerPool.invalidateServerConnection).not.toHaveBeenCalled();
    expect(serverErrorTracker.resetServerErrorState).not.toHaveBeenCalled();
  });

  it("returns not-found and runs no cascade when the server does not exist", async () => {
    vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue(
      undefined as never,
    );

    const result = await mcpServersImplementations.reconnect(
      { uuid: "missing" },
      "user-1",
    );

    expect(result.success).toBe(false);
    expect(result.message).toContain("not found");
    expect(mcpServerPool.invalidateServerConnection).not.toHaveBeenCalled();
  });

  it("surfaces a failure of the primary cascade instead of reporting success", async () => {
    vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue(fakeServer());
    vi.mocked(mcpServerPool.invalidateServerConnection).mockRejectedValueOnce(
      new Error("pool exploded"),
    );

    const result = await mcpServersImplementations.reconnect(
      { uuid: "server-1" },
      "user-1",
    );

    expect(result.success).toBe(false);
    expect(result.message).toBe("pool exploded");
  });

  it("treats a namespace fan-out failure as best-effort — the reconnect still succeeds", async () => {
    vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue(fakeServer());
    vi.mocked(
      namespaceMappingsRepository.findNamespacesByServerUuid,
    ).mockResolvedValue(["ns-1"]);
    vi.mocked(metaMcpServerPool.invalidateIdleServers).mockRejectedValueOnce(
      new Error("namespace pool down"),
    );

    const result = await mcpServersImplementations.reconnect(
      { uuid: "server-1" },
      "user-1",
    );

    // Primary cascade already dropped the connections + fired list_changed;
    // a fan-out failure is logged, not fatal. Override cache is still cleared.
    expect(result.success).toBe(true);
    expect(clearOverrideCache).toHaveBeenCalledWith("ns-1");
  });
});
