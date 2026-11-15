/**
 * The server error reset that `mcpServers.resetErrors` (tRPC) and the
 * cookie-only REST route share, with the database and the pools replaced:
 * the order of its steps (the status change and its audit row commit first,
 * then the in-memory counters, then connection recovery), that a database or
 * audit failure reaches the caller with nothing done after it, that an
 * unknown server is NOT_FOUND, and that recovery reports on its own without
 * ever turning a committed reset into a failure. The transaction itself, and
 * the audit row in it, are proven against a real Postgres in
 * trpc/admin-plane-key-powers.integration.test.ts.
 */
import type { AuditActor } from "@repo/trpc";
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  steps: [] as string[],
  clearErrorStatus: vi.fn(),
  findByUuid: vi.fn(),
  findNamespacesByServerUuid: vi.fn(),
  withAdminAuditTx: vi.fn(),
  resetServerAttempts: vi.fn(),
  ensureIdleSessionForNewServer: vi.fn(),
  getPoolStatus: vi.fn(),
  ensureIdleServers: vi.fn(),
  convertDbServerToParams: vi.fn(),
  stdioServersAllowed: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({
  default: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));
vi.mock("../../db/repositories", () => ({
  mcpServersRepository: {
    clearErrorStatus: h.clearErrorStatus,
    findByUuid: h.findByUuid,
  },
  namespaceMappingsRepository: {
    findNamespacesByServerUuid: h.findNamespacesByServerUuid,
  },
}));
vi.mock("../audit/admin-write", () => ({
  withAdminAuditTx: h.withAdminAuditTx,
}));
vi.mock("./server-error-tracker", () => ({
  serverErrorTracker: { resetServerAttempts: h.resetServerAttempts },
}));
vi.mock("./mcp-server-pool", () => ({
  mcpServerPool: {
    ensureIdleSessionForNewServer: h.ensureIdleSessionForNewServer,
    getPoolStatus: h.getPoolStatus,
  },
}));
vi.mock("./metamcp-server-pool", () => ({
  metaMcpServerPool: { ensureIdleServers: h.ensureIdleServers },
}));
vi.mock("./utils", () => ({
  convertDbServerToParams: h.convertDbServerToParams,
}));
vi.mock("./stdio-policy", () => ({
  isStdioServerType: (type: string) => type === "STDIO",
  stdioServersAllowed: h.stdioServersAllowed,
}));

const { resetServerErrors } = await import("./reset-server-errors");

const actor: AuditActor = {
  actor_id: "owner-1",
  actor_label: "o@example.test",
  actor_ip: null,
  actor_user_agent: null,
  request_id: null,
  admin_plane: {
    key_uuid: "6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b",
    owner_user_id: "owner-1",
    scope: "operator",
  },
  reason: "unit test",
};

const S1 = "11111111-1111-4111-8111-111111111111";
const S2 = "22222222-2222-4222-8222-222222222222";

/** The audited transaction: runs `write`, records the event, commits. */
function commitsLikeATransaction() {
  h.withAdminAuditTx.mockImplementation(
    async (
      _actor: unknown,
      write: (tx: unknown) => Promise<unknown>,
      eventFor: (written: unknown) => unknown,
    ) => {
      h.steps.push("tx:begin");
      const written = await write({ tx: true });
      const event = eventFor(written);
      if (event)
        h.steps.push(`tx:audit:${(event as { action: string }).action}`);
      h.steps.push("tx:commit");
      return written;
    },
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  h.steps = [];
  commitsLikeATransaction();
  h.clearErrorStatus.mockImplementation(async () => {
    h.steps.push("db:clear");
    return {
      status: "ok",
      reset: [{ uuid: S1, name: "alpha" }],
    };
  });
  h.findByUuid.mockImplementation(async (uuid: string) => ({
    uuid,
    name: "alpha",
    type: "STREAMABLE_HTTP",
  }));
  h.findNamespacesByServerUuid.mockResolvedValue(["ns-1"]);
  h.resetServerAttempts.mockImplementation((uuid: string) =>
    h.steps.push(`counter:${uuid}`),
  );
  h.convertDbServerToParams.mockImplementation(
    async (row: { uuid: string }) => ({
      uuid: row.uuid,
    }),
  );
  h.ensureIdleSessionForNewServer.mockImplementation(async (uuid: string) => {
    h.steps.push(`recover:${uuid}`);
  });
  h.getPoolStatus.mockReturnValue({
    idleServerUuids: [S1],
    perServerCounts: { [S1]: 1 },
  });
  h.ensureIdleServers.mockImplementation(async () => {
    h.steps.push("recover:namespaces");
  });
  h.stdioServersAllowed.mockReturnValue(false);
});

describe("resetServerErrors", () => {
  it("commits the status change with its audit row before touching counters or connections", async () => {
    const result = await resetServerErrors({ serverUuid: S1 }, actor);

    expect(h.steps).toEqual([
      "tx:begin",
      "db:clear",
      "tx:audit:mcpserver.errors.reset",
      "tx:commit",
      `counter:${S1}`,
      `recover:${S1}`,
      "recover:namespaces",
    ]);
    expect(h.clearErrorStatus).toHaveBeenCalledWith(
      { tx: true },
      { serverUuid: S1 },
    );
    expect(result).toEqual({
      reset: [{ uuid: S1, name: "alpha" }],
      recovery: {
        status: "succeeded",
        servers: [{ uuid: S1, name: "alpha", status: "connected" }],
      },
    });
  });

  it("describes the change in one audit event that names every reset server", async () => {
    h.clearErrorStatus.mockResolvedValue({
      status: "ok",
      reset: [
        { uuid: S1, name: "alpha" },
        { uuid: S2, name: "beta" },
      ],
    });
    await resetServerErrors({}, actor);
    const eventFor = h.withAdminAuditTx.mock.calls[0][2] as (
      written: unknown,
    ) => unknown;
    expect(
      eventFor({
        status: "ok",
        reset: [
          { uuid: S1, name: "alpha" },
          { uuid: S2, name: "beta" },
        ],
      }),
    ).toEqual({
      action: "mcpserver.errors.reset",
      target_type: "mcp_server",
      target_id: null,
      detail: {
        selection: "all_in_error",
        server_uuids: [S1, S2],
        server_names: ["alpha", "beta"],
        reset_count: 2,
      },
    });
    expect(eventFor({ status: "ok", reset: [] })).toBeNull();
    expect(eventFor({ status: "not_found" })).toBeNull();
  });

  it("propagates a database or audit failure and does nothing after it", async () => {
    const failure = new Error("audit insert refused");
    h.withAdminAuditTx.mockRejectedValue(failure);

    await expect(resetServerErrors({ serverUuid: S1 }, actor)).rejects.toBe(
      failure,
    );
    expect(h.resetServerAttempts).not.toHaveBeenCalled();
    expect(h.ensureIdleSessionForNewServer).not.toHaveBeenCalled();
    expect(h.ensureIdleServers).not.toHaveBeenCalled();
  });

  it("answers an unknown server, or a value that is not a uuid, with NOT_FOUND and does nothing else", async () => {
    h.clearErrorStatus.mockResolvedValue({ status: "not_found" });
    await expect(
      resetServerErrors({ serverUuid: S2 }, actor),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });

    await expect(
      resetServerErrors({ serverUuid: "not-a-uuid" }, actor),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(h.clearErrorStatus).toHaveBeenCalledTimes(1);
    expect(h.resetServerAttempts).not.toHaveBeenCalled();
    expect(h.ensureIdleSessionForNewServer).not.toHaveBeenCalled();
  });

  it("starts nothing when no server was in error", async () => {
    h.clearErrorStatus.mockResolvedValue({ status: "ok", reset: [] });
    const result = await resetServerErrors({}, actor);
    expect(result).toEqual({
      reset: [],
      recovery: { status: "not_needed", servers: [] },
    });
    expect(h.resetServerAttempts).not.toHaveBeenCalled();
    expect(h.ensureIdleSessionForNewServer).not.toHaveBeenCalled();
    expect(h.ensureIdleServers).not.toHaveBeenCalled();
  });

  it("reports a recovery that throws as failed, and still reports the committed reset", async () => {
    h.ensureIdleSessionForNewServer.mockRejectedValue(
      new Error("ECONNREFUSED"),
    );
    const result = await resetServerErrors({ serverUuid: S1 }, actor);
    expect(result).toEqual({
      reset: [{ uuid: S1, name: "alpha" }],
      recovery: {
        status: "failed",
        servers: [{ uuid: S1, name: "alpha", status: "failed" }],
      },
    });
    expect(h.withAdminAuditTx).toHaveBeenCalledTimes(1);
  });

  it("reports a server the pool could not connect as failed", async () => {
    h.getPoolStatus.mockReturnValue({
      idleServerUuids: [],
      perServerCounts: {},
    });
    const result = await resetServerErrors({ serverUuid: S1 }, actor);
    expect(result.recovery).toEqual({
      status: "failed",
      servers: [{ uuid: S1, name: "alpha", status: "failed" }],
    });
  });

  it("reports recovery still running when it outlasts the wait, without failing the call", async () => {
    let finish!: () => void;
    h.ensureIdleSessionForNewServer.mockReturnValue(
      new Promise<void>((resolve) => {
        finish = resolve;
      }),
    );
    const result = await resetServerErrors({ serverUuid: S1 }, actor, {
      recoveryWaitMs: 20,
    });
    expect(result).toEqual({
      reset: [{ uuid: S1, name: "alpha" }],
      recovery: {
        status: "pending",
        servers: [{ uuid: S1, name: "alpha", status: "pending" }],
      },
    });
    finish();
  });

  it("skips a stored stdio server while stdio servers are disabled, without calling it a failure or a success", async () => {
    h.findByUuid.mockResolvedValue({ uuid: S1, name: "alpha", type: "STDIO" });
    const result = await resetServerErrors({ serverUuid: S1 }, actor);
    // TEST-EDIT (SPEC): a recovery in which nothing was connected is reported
    // as `skipped`, not `succeeded`; the per-server entry is unchanged.
    expect(result.recovery).toEqual({
      status: "skipped",
      servers: [{ uuid: S1, name: "alpha", status: "skipped" }],
    });
    expect(h.ensureIdleSessionForNewServer).not.toHaveBeenCalled();
  });

  it("does not count a connection still being made as connected", async () => {
    // The pool's per-server count includes a connect in flight, so a count
    // without an idle connection says only that something is under way.
    h.getPoolStatus.mockReturnValue({
      idleServerUuids: [],
      perServerCounts: { [S1]: 1 },
    });
    const result = await resetServerErrors({ serverUuid: S1 }, actor);
    expect(result.recovery).toEqual({
      status: "pending",
      servers: [{ uuid: S1, name: "alpha", status: "pending" }],
    });
  });

  describe("with several servers reset", () => {
    beforeEach(() => {
      h.clearErrorStatus.mockResolvedValue({
        status: "ok",
        reset: [
          { uuid: S1, name: "alpha" },
          { uuid: S2, name: "beta" },
        ],
      });
      h.findByUuid.mockImplementation(async (uuid: string) => ({
        uuid,
        name: uuid === S1 ? "alpha" : "beta",
        type: uuid === S2 ? "STDIO" : "STREAMABLE_HTTP",
      }));
    });

    it("names the skipped server and still reports the connected one, so the call is succeeded only because one connected", async () => {
      const result = await resetServerErrors({}, actor);
      expect(result.recovery).toEqual({
        status: "succeeded",
        servers: [
          { uuid: S1, name: "alpha", status: "connected" },
          { uuid: S2, name: "beta", status: "skipped" },
        ],
      });
    });

    it("reports every server skipped as skipped, and a failure beside a skip as failed", async () => {
      h.findByUuid.mockResolvedValue(undefined);
      const allSkipped = await resetServerErrors({}, actor);
      expect(allSkipped.recovery.status).toBe("skipped");
      expect(allSkipped.recovery.servers.map((s) => s.status)).toEqual([
        "skipped",
        "skipped",
      ]);

      h.findByUuid.mockImplementation(async (uuid: string) =>
        uuid === S1
          ? { uuid, name: "alpha", type: "STREAMABLE_HTTP" }
          : undefined,
      );
      h.getPoolStatus.mockReturnValue({
        idleServerUuids: [],
        perServerCounts: {},
      });
      const failedBesideSkip = await resetServerErrors({}, actor);
      expect(failedBesideSkip.recovery.status).toBe("failed");
    });
  });
});
