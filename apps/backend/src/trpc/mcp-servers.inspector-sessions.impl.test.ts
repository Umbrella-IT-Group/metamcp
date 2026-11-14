/**
 * `mcpServers.update` and `.delete` close the Inspector sessions opened from
 * the row they change, through the real session registry:
 *   - an update closes them when it changed where the gateway connects or
 *     what it presents there, when the row is a stdio row (its command, args
 *     and env are not in that report), or when the locked write changed the
 *     row's owner; a re-save that changed none of this (the sync's routine
 *     one) leaves them open;
 *   - a delete closes the deleted row's sessions;
 *   - a refused, missing, denied, failed or rolled-back mutation closes
 *     nothing and leaves a connection that is still opening alone;
 *   - the close runs right after the write is confirmed, before the pooled
 *     invalidation, and a failing close does not change the result; a close
 *     that never settles holds neither the reply nor the invalidation past
 *     the registry's close limit.
 *
 * Repositories and pools are mocked so the unit needs no postgres (the
 * harness of mcp-servers.update-credentials.impl.test.ts).
 */
import type express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { order, audit } = vi.hoisted(() => ({
  order: [] as string[],
  audit: { fail: false },
}));

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

vi.mock("../db/repositories", () => ({
  mcpServersRepository: {
    findByUuid: vi.fn(),
    updateReportingChange: vi.fn(),
    deleteByUuid: vi.fn(),
  },
  namespaceMappingsRepository: {
    findNamespacesByServerUuid: vi.fn(async () => []),
  },
}));

// The transaction an admin-plane write and its audit row share, so a failed
// audit write can roll the change back as it does against a database.
vi.mock("../db/index", () => ({
  db: { transaction: vi.fn(async (run: (tx: object) => unknown) => run({})) },
}));
vi.mock("../db/repositories/audit-log-tx", () => ({
  recordAuditInTransaction: vi.fn(async () => {
    if (audit.fail) throw new Error("audit sink unavailable");
  }),
}));

vi.mock("../lib/audit/admin-event", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/audit/admin-event")>()),
  emitAdminEvent: vi.fn(),
}));

vi.mock("../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    invalidateServerConnection: vi.fn(async () => {
      order.push("pool");
    }),
    invalidateIdleSession: vi.fn(async () => undefined),
    cleanupIdleSession: vi.fn(async () => undefined),
  },
}));
vi.mock("../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {
    invalidateIdleServers: vi.fn(async () => undefined),
    invalidateOpenApiSessions: vi.fn(async () => undefined),
  },
}));
vi.mock("../lib/metamcp/metamcp-middleware/tool-overrides.functional", () => ({
  clearOverrideCache: vi.fn(),
}));
vi.mock("../lib/metamcp/server-error-tracker", () => ({
  serverErrorTracker: { resetServerErrorState: vi.fn(async () => undefined) },
}));
vi.mock("../lib/metamcp/utils", () => ({
  convertDbServerToParams: vi.fn(async () => undefined),
}));

import { mcpServersRepository } from "../db/repositories";
import { recordAuditInTransaction } from "../db/repositories/audit-log-tx";
import {
  ServerCredentialRetentionError,
  URL_CHANGE_NEEDS_BEARER_DECISION,
} from "../db/repositories/mcp-server-update-plan";
import {
  beginInspectorOpen,
  bindInspectorSession,
  finishInspectorOpen,
  forgetInspectorSession,
  INSPECTOR_SESSION_CLOSE_TIMEOUT_MS,
  inspectorSessionBelongsToCaller,
  isInspectorOpenUsable,
} from "../lib/metamcp/inspector-sessions";
import { mcpServerPool } from "../lib/metamcp/mcp-server-pool";
import { mcpServersImplementations } from "./mcp-servers.impl";

const UUID = "11111111-1111-4111-8111-111111111111";
const OTHER_UUID = "22222222-2222-4222-8222-222222222222";
const ADMIN = "admin-1";
const OPENER = { user: { id: "opener" } } as unknown as express.Request;

const ACTOR = {
  actor_id: ADMIN,
  actor_label: "admin@example.invalid",
  actor_ip: null,
  actor_user_agent: null,
  request_id: null,
};

const row = (overrides: Record<string, unknown> = {}) =>
  ({
    uuid: UUID,
    name: "vendor",
    description: null,
    type: "STREAMABLE_HTTP",
    command: null,
    args: [],
    env: {},
    url: "http://mcp-vendor:3000/mcp",
    bearerToken: "enc:v1:stored",
    headers: {},
    error_status: "NONE",
    created_at: new Date("2026-11-01T00:00:00Z"),
    user_id: null,
    ...overrides,
  }) as never;

/** The locked write's report, with nothing changed unless a case says so. */
const reported = (
  server: never,
  changes: {
    destinationOrCredentialChanged?: boolean;
    ownershipChanged?: boolean;
  } = {},
) =>
  ({
    server,
    destinationOrCredentialChanged: false,
    ownershipChanged: false,
    ...changes,
  }) as never;

const update = (input: Record<string, unknown> = {}, actor: object = ACTOR) =>
  mcpServersImplementations.update(
    {
      uuid: UUID,
      name: "vendor",
      type: "STREAMABLE_HTTP",
      url: "http://mcp-vendor:3000/mcp",
      ...input,
    } as never,
    ADMIN,
    actor as never,
  );

const remove = () =>
  mcpServersImplementations.delete({ uuid: UUID }, ADMIN, ACTOR as never);

let sessionCounter = 0;
const boundIds: string[] = [];
/** Bind a stand-in Inspector session on `serverUuid`; returns its close spy. */
function openSession(serverUuid: string, close?: () => unknown) {
  sessionCounter += 1;
  const sessionId = `inspector-${sessionCounter}`;
  const spy = vi.fn(
    close ??
      (() => {
        order.push(`inspector:${serverUuid}`);
      }),
  );
  boundIds.push(sessionId);
  expect(bindInspectorSession(sessionId, OPENER, spy, serverUuid)).toBe(true);
  return { sessionId, close: spy };
}

const stillOpen = (sessionId: string) =>
  inspectorSessionBelongsToCaller(sessionId, OPENER);

beforeEach(() => {
  vi.clearAllMocks();
  vi.unstubAllEnvs();
  order.length = 0;
  audit.fail = false;
  vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue(row());
});

afterEach(() => {
  for (const sessionId of boundIds.splice(0)) forgetInspectorSession(sessionId);
  vi.unstubAllEnvs();
});

describe("mcpServers.update closes the row's Inspector sessions", () => {
  it("when the destination or a credential changed, and not another row's", async () => {
    const mine = openSession(UUID);
    const other = openSession(OTHER_UUID);
    vi.mocked(mcpServersRepository.updateReportingChange).mockResolvedValue(
      reported(row({ url: "http://mcp-other:3000/mcp", bearerToken: null }), {
        destinationOrCredentialChanged: true,
      }),
    );

    const result = await update({
      url: "http://mcp-other:3000/mcp",
      clearBearerToken: true,
    });
    order.push("returned");

    expect(result.success).toBe(true);
    expect(mine.close).toHaveBeenCalledTimes(1);
    expect(stillOpen(mine.sessionId)).toBe(false);
    expect(other.close).not.toHaveBeenCalled();
    expect(stillOpen(other.sessionId)).toBe(true);
    expect(order).toEqual([`inspector:${UUID}`, "pool", "returned"]);
  });

  it("not when an HTTP re-save changed nothing it reports", async () => {
    const mine = openSession(UUID);
    vi.mocked(mcpServersRepository.updateReportingChange).mockResolvedValue(
      reported(row({ description: "Vendor tools" })),
    );

    const result = await update({ description: "Vendor tools" });

    expect(result.success).toBe(true);
    expect(mine.close).not.toHaveBeenCalled();
    expect(stillOpen(mine.sessionId)).toBe(true);
  });

  it("when a stdio row is updated, whatever the report says", async () => {
    vi.stubEnv("ALLOW_STDIO_SERVERS", "true");
    const stdioRow = row({
      type: "STDIO",
      url: null,
      bearerToken: null,
      command: "npx",
      args: ["vendor-mcp"],
    });
    vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue(stdioRow);
    const mine = openSession(UUID);
    vi.mocked(mcpServersRepository.updateReportingChange).mockResolvedValue(
      reported(stdioRow),
    );

    const result = await update({
      type: "STDIO",
      url: undefined,
      command: "npx",
      args: ["vendor-mcp", "--verbose"],
    });

    expect(result.success).toBe(true);
    expect(mine.close).toHaveBeenCalledTimes(1);
  });

  it("when the locked write changed the owner, even though the earlier read shows the final owner", async () => {
    // The unlocked read and the written row agree; only the lock saw the
    // owner that was there immediately before this write.
    vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue(
      row({ user_id: ADMIN }),
    );
    const mine = openSession(UUID);
    vi.mocked(mcpServersRepository.updateReportingChange).mockResolvedValue(
      reported(row({ user_id: ADMIN }), { ownershipChanged: true }),
    );

    const result = await update({ description: "edited" });

    expect(result.success).toBe(true);
    expect(mine.close).toHaveBeenCalledTimes(1);
  });

  it("not when the earlier read differs from the written owner but the locked write changed none", async () => {
    vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue(
      row({ user_id: null }),
    );
    const mine = openSession(UUID);
    vi.mocked(mcpServersRepository.updateReportingChange).mockResolvedValue(
      reported(row({ user_id: ADMIN })),
    );

    const result = await update({ user_id: ADMIN });

    expect(result.success).toBe(true);
    expect(mine.close).not.toHaveBeenCalled();
  });

  it("before the pooled invalidation, and even when that invalidation fails", async () => {
    const mine = openSession(UUID);
    vi.mocked(mcpServersRepository.updateReportingChange).mockResolvedValue(
      reported(row({ bearerToken: "enc:v1:rotated" }), {
        destinationOrCredentialChanged: true,
      }),
    );
    vi.mocked(mcpServerPool.invalidateServerConnection).mockImplementationOnce(
      async () => {
        order.push("pool");
        throw new Error("pool unavailable");
      },
    );

    await update({ bearerToken: "rotated" });

    expect(mine.close).toHaveBeenCalledTimes(1);
    expect(order).toEqual([`inspector:${UUID}`, "pool"]);
  });

  it("and a close that throws or rejects does not change the result", async () => {
    const throwing = openSession(UUID, () => {
      throw new Error("close failed");
    });
    const rejecting = openSession(UUID, async () => {
      throw new Error("close rejected");
    });
    vi.mocked(mcpServersRepository.updateReportingChange).mockResolvedValue(
      reported(row({ bearerToken: "enc:v1:rotated" }), {
        destinationOrCredentialChanged: true,
      }),
    );

    const result = await update({ bearerToken: "rotated" });

    expect(result.success).toBe(true);
    expect(throwing.close).toHaveBeenCalledTimes(1);
    expect(rejecting.close).toHaveBeenCalledTimes(1);
    expect(mcpServerPool.invalidateServerConnection).toHaveBeenCalledTimes(1);
  });

  it("and a close that never settles holds the reply and the pooled invalidation no longer than the close limit", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    try {
      const hanging = openSession(UUID, () => {
        order.push(`inspector:${UUID}`);
        return new Promise<never>(() => {});
      });
      vi.mocked(mcpServersRepository.updateReportingChange).mockResolvedValue(
        reported(row({ bearerToken: "enc:v1:rotated" }), {
          destinationOrCredentialChanged: true,
        }),
      );

      let result: { success: boolean } | undefined;
      const updating = update({ bearerToken: "rotated" }).then((value) => {
        result = value;
      });
      await vi.advanceTimersByTimeAsync(INSPECTOR_SESSION_CLOSE_TIMEOUT_MS - 1);
      expect(hanging.close).toHaveBeenCalledTimes(1);
      expect(result).toBeUndefined();
      expect(mcpServerPool.invalidateServerConnection).not.toHaveBeenCalled();

      await vi.advanceTimersByTimeAsync(1);
      await vi.waitFor(() => expect(result?.success).toBe(true));
      await updating;
      expect(mcpServerPool.invalidateServerConnection).toHaveBeenCalledTimes(1);
      expect(order).toEqual([`inspector:${UUID}`, "pool"]);
      expect(stillOpen(hanging.sessionId)).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it("a connection still opening on the row is refused after a change and allowed after a re-save", async () => {
    vi.mocked(mcpServersRepository.updateReportingChange).mockResolvedValueOnce(
      reported(row({ description: "Vendor tools" })),
    );
    const resaved = beginInspectorOpen();
    try {
      await update({ description: "Vendor tools" });
      expect(isInspectorOpenUsable(resaved, UUID)).toBe(true);
    } finally {
      finishInspectorOpen(resaved);
    }

    vi.mocked(mcpServersRepository.updateReportingChange).mockResolvedValueOnce(
      reported(row({ url: "http://mcp-other:3000/mcp" }), {
        destinationOrCredentialChanged: true,
      }),
    );
    const changed = beginInspectorOpen();
    try {
      await update({ url: "http://mcp-other:3000/mcp", bearerToken: "new" });
      expect(isInspectorOpenUsable(changed, UUID)).toBe(false);
      expect(isInspectorOpenUsable(changed, OTHER_UUID)).toBe(true);
    } finally {
      finishInspectorOpen(changed);
    }
  });
});

describe("a mutation that did not happen closes nothing", () => {
  const cases: Array<
    [string, () => void, () => Promise<{ success: boolean }>]
  > = [
    [
      "a refused update",
      () =>
        vi
          .mocked(mcpServersRepository.updateReportingChange)
          .mockRejectedValue(
            new ServerCredentialRetentionError(
              URL_CHANGE_NEEDS_BEARER_DECISION,
            ),
          ),
      () => update({ url: "http://mcp-other:3000/mcp" }),
    ],
    [
      "an update of a missing row",
      () =>
        vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue(undefined),
      () => update({ url: "http://mcp-other:3000/mcp" }),
    ],
    [
      "an update of a row gone by the time it is locked",
      () =>
        vi
          .mocked(mcpServersRepository.updateReportingChange)
          .mockResolvedValue(undefined),
      () => update({ url: "http://mcp-other:3000/mcp" }),
    ],
    [
      "an update of another user's row",
      () =>
        vi
          .mocked(mcpServersRepository.findByUuid)
          .mockResolvedValue(row({ user_id: "someone-else" })),
      () => update({ url: "http://mcp-other:3000/mcp" }),
    ],
    [
      "an update the database fails",
      () =>
        vi
          .mocked(mcpServersRepository.updateReportingChange)
          .mockRejectedValue(
            new Error(
              "Failed to update MCP server. Please check your input and try again.",
            ),
          ),
      () => update({ url: "http://mcp-other:3000/mcp" }),
    ],
    [
      "an update rolled back with its audit record",
      () => {
        audit.fail = true;
        vi.mocked(mcpServersRepository.updateReportingChange).mockResolvedValue(
          reported(row({ url: "http://mcp-other:3000/mcp" }), {
            destinationOrCredentialChanged: true,
            ownershipChanged: true,
          }),
        );
      },
      async () => {
        const result = await update(
          { url: "http://mcp-other:3000/mcp", bearerToken: "new" },
          { ...ACTOR, admin_plane: true },
        );
        // The write ran inside the transaction; its audit record failed.
        expect(
          mcpServersRepository.updateReportingChange,
        ).toHaveBeenCalledTimes(1);
        expect(recordAuditInTransaction).toHaveBeenCalledTimes(1);
        return result;
      },
    ],
    [
      "a delete of a missing row",
      () =>
        vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue(undefined),
      remove,
    ],
    [
      "a delete of a row gone by the time it is deleted",
      () =>
        vi
          .mocked(mcpServersRepository.deleteByUuid)
          .mockResolvedValue(undefined),
      remove,
    ],
    [
      "a delete of another user's row",
      () =>
        vi
          .mocked(mcpServersRepository.findByUuid)
          .mockResolvedValue(row({ user_id: "someone-else" })),
      remove,
    ],
    [
      "a delete the database fails",
      () =>
        vi
          .mocked(mcpServersRepository.deleteByUuid)
          .mockRejectedValue(new Error("delete failed")),
      remove,
    ],
  ];

  it.each(cases)("%s", async (_label, arrange, act) => {
    const mine = openSession(UUID);
    arrange();
    const opening = beginInspectorOpen();
    try {
      const result = await act();

      expect(result.success).toBe(false);
      expect(mine.close).not.toHaveBeenCalled();
      expect(stillOpen(mine.sessionId)).toBe(true);
      expect(isInspectorOpenUsable(opening, UUID)).toBe(true);
    } finally {
      finishInspectorOpen(opening);
    }
  });
});

describe("mcpServers.delete closes the row's Inspector sessions", () => {
  it("closes only the deleted row's sessions", async () => {
    const mine = openSession(UUID);
    const other = openSession(OTHER_UUID);
    vi.mocked(mcpServersRepository.deleteByUuid).mockResolvedValue(row());
    const opening = beginInspectorOpen();
    try {
      const result = await remove();

      expect(result.success).toBe(true);
      expect(mine.close).toHaveBeenCalledTimes(1);
      expect(stillOpen(mine.sessionId)).toBe(false);
      expect(other.close).not.toHaveBeenCalled();
      expect(stillOpen(other.sessionId)).toBe(true);
      expect(isInspectorOpenUsable(opening, UUID)).toBe(false);
    } finally {
      finishInspectorOpen(opening);
    }
  });

  it("a close that throws or rejects does not change the result", async () => {
    const throwing = openSession(UUID, () => {
      throw new Error("close failed");
    });
    const rejecting = openSession(UUID, async () => {
      throw new Error("close rejected");
    });
    vi.mocked(mcpServersRepository.deleteByUuid).mockResolvedValue(row());

    const result = await remove();

    expect(result).toEqual({
      success: true,
      message: "MCP server deleted successfully",
    });
    expect(throwing.close).toHaveBeenCalledTimes(1);
    expect(rejecting.close).toHaveBeenCalledTimes(1);
  });
});
