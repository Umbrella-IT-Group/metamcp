/**
 * withAdminAudit / runAuditedTransaction: who gets the audit row inside the
 * change's own transaction, and what a failing row does.
 *
 * The contract (plan, foreman decision 1): a request authenticated by an
 * admin-plane key has no person watching, so its change and its audit row are
 * one transaction and an audit failure fails the change. Every other actor
 * keeps the best-effort record, written after the change by `emit`. The
 * Postgres behaviour (rollback of the real rows) is pinned in
 * admin-write.integration.test.ts; this pins the dispatch and the
 * no-leakage properties without a database.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const { loggerMock, txAudit, emitMock, dbState } = vi.hoisted(() => ({
  loggerMock: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  txAudit: {
    record: vi.fn(async (_tx: unknown, _event: unknown) => undefined),
  },
  emitMock: vi.fn(),
  dbState: { transactions: 0, rolledBack: 0 },
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));
vi.mock("./admin-event", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./admin-event")>()),
  emitAdminEvent: emitMock,
}));
vi.mock("../../db/index", () => ({
  db: {
    // A transaction that records whether its callback threw (a rollback).
    transaction: async (callback: (tx: object) => Promise<unknown>) => {
      dbState.transactions += 1;
      try {
        return await callback({ id: `tx-${dbState.transactions}` });
      } catch (error) {
        dbState.rolledBack += 1;
        throw error;
      }
    },
  },
}));
vi.mock("../../db/repositories/audit-log-tx", () => ({
  recordAuditInTransaction: txAudit.record,
}));

const {
  ADMIN_AUDIT_WRITE_FAILED_MESSAGE,
  AdminAuditWriteError,
  requiresTransactionalAudit,
  runAuditedTransaction,
  withAdminAudit,
} = await import("./admin-write");

const adminPlaneActor = {
  actor_id: "owner-1",
  actor_label: "owner@example.test",
  actor_ip: "203.0.113.5",
  actor_user_agent: "ua",
  request_id: "r1",
  admin_plane: {
    key_uuid: "6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b",
    owner_user_id: "owner-1",
    scope: "sync" as const,
  },
};
const humanActor = {
  actor_id: "admin-1",
  actor_label: "admin@example.test",
  actor_ip: null,
  actor_user_agent: null,
  request_id: null,
};
const EVENT = {
  action: "thing.create",
  target_type: "thing",
  target_id: "t-1",
  detail: { name: "x" },
};

beforeEach(() => {
  vi.clearAllMocks();
  dbState.transactions = 0;
  dbState.rolledBack = 0;
  txAudit.record.mockImplementation(async () => undefined);
});

describe("requiresTransactionalAudit", () => {
  it("is true only for an actor carrying admin-plane provenance", () => {
    expect(requiresTransactionalAudit(adminPlaneActor)).toBe(true);
    expect(requiresTransactionalAudit(humanActor)).toBe(false);
    expect(requiresTransactionalAudit(undefined)).toBe(false);
    expect(requiresTransactionalAudit(null)).toBe(false);
  });
});

describe("withAdminAudit for an admin-plane actor", () => {
  it("runs the write and records the row on the same transaction handle", async () => {
    const write = vi.fn(async (..._tx: unknown[]) => ({ uuid: "t-1" }));

    const result = await withAdminAudit(adminPlaneActor, write, () => EVENT);

    expect(result).toEqual({ uuid: "t-1" });
    expect(dbState.transactions).toBe(1);
    expect(write).toHaveBeenCalledTimes(1);
    const handle = write.mock.calls[0][0];
    expect(handle).toEqual({ id: "tx-1" });
    expect(txAudit.record).toHaveBeenCalledTimes(1);
    expect(txAudit.record.mock.calls[0][0]).toBe(handle);
    // The row names the KEY as the actor, with the owner and scope beside it.
    expect(txAudit.record.mock.calls[0][1]).toMatchObject({
      actor_type: "api_key",
      actor_id: adminPlaneActor.admin_plane.key_uuid,
      action: "thing.create",
      detail: {
        name: "x",
        admin_plane: {
          key_uuid: adminPlaneActor.admin_plane.key_uuid,
          owner_user_id: "owner-1",
          scope: "sync",
        },
      },
    });
    // Not the best-effort emitter.
    expect(emitMock).not.toHaveBeenCalled();
  });

  it("records nothing, and still commits, when the write reports nothing was written", async () => {
    const write = vi.fn(async () => undefined);

    const result = await withAdminAudit(adminPlaneActor, write, () => null);

    expect(result).toBeUndefined();
    expect(txAudit.record).not.toHaveBeenCalled();
    expect(dbState.rolledBack).toBe(0);
  });

  it("rolls the write back and throws a fixed error when the audit insert fails", async () => {
    txAudit.record.mockRejectedValueOnce(
      new Error("insert into audit_log params: sensitive-looking text"),
    );

    const failure = await withAdminAudit(
      adminPlaneActor,
      async () => ({ uuid: "t-1" }),
      () => EVENT,
    ).catch((e) => e);

    expect(failure).toBeInstanceOf(AdminAuditWriteError);
    expect(failure.message).toBe(ADMIN_AUDIT_WRITE_FAILED_MESSAGE);
    expect(failure.message).not.toContain("sensitive");
    expect(failure.cause).toBeUndefined();
    expect(dbState.rolledBack).toBe(1);
    // The failure is logged by code only, never by message.
    expect(JSON.stringify(loggerMock.error.mock.calls)).not.toContain(
      "sensitive",
    );
  });

  it("rolls back when building the event throws", async () => {
    const failure = await withAdminAudit(
      adminPlaneActor,
      async () => ({ uuid: "t-1" }),
      () => {
        throw new Error("builder failed");
      },
    ).catch((e) => e);

    expect(failure).toBeInstanceOf(AdminAuditWriteError);
    expect(dbState.rolledBack).toBe(1);
    expect(txAudit.record).not.toHaveBeenCalled();
  });

  it("lets a failure of the write propagate unchanged, with no audit row", async () => {
    const original = new Error("the write failed");

    const failure = await withAdminAudit(
      adminPlaneActor,
      async () => {
        throw original;
      },
      () => EVENT,
    ).catch((e) => e);

    expect(failure).toBe(original);
    expect(txAudit.record).not.toHaveBeenCalled();
    expect(dbState.rolledBack).toBe(1);
  });
});

describe("withAdminAudit for every other actor", () => {
  it.each([
    ["a human session", humanActor],
    ["no actor", undefined],
  ])(
    "keeps %s on the best-effort record, with no transaction",
    async (_l, actor) => {
      const write = vi.fn(async (..._tx: unknown[]) => ({ uuid: "t-1" }));

      const result = await withAdminAudit(actor, write, () => EVENT);

      expect(result).toEqual({ uuid: "t-1" });
      expect(dbState.transactions).toBe(0);
      // The write is called with no handle at all, so a repository method keeps
      // exactly the arguments it always had.
      expect(write.mock.calls[0]).toHaveLength(0);
      expect(txAudit.record).not.toHaveBeenCalled();
      expect(emitMock).toHaveBeenCalledTimes(1);
      expect(emitMock).toHaveBeenCalledWith(actor, EVENT);
    },
  );

  it("emits nothing when nothing was written", async () => {
    await withAdminAudit(
      humanActor,
      async () => undefined,
      () => null,
    );

    expect(emitMock).not.toHaveBeenCalled();
  });

  it("does not turn a completed change into a failure when the event builder throws", async () => {
    const result = await withAdminAudit(
      humanActor,
      async () => ({ uuid: "t-1" }),
      () => {
        throw new Error("builder failed");
      },
    );

    expect(result).toEqual({ uuid: "t-1" });
  });

  it("does not swallow a failure of the write", async () => {
    await expect(
      withAdminAudit(
        humanActor,
        async () => {
          throw new Error("the write failed");
        },
        () => EVENT,
      ),
    ).rejects.toThrow("the write failed");
    expect(emitMock).not.toHaveBeenCalled();
  });
});

describe("runAuditedTransaction (always transactional, whoever calls)", () => {
  it("records a human administrator's row in the transaction too", async () => {
    await runAuditedTransaction(
      humanActor,
      async () => ({ uuid: "t-1" }),
      () => EVENT,
    );

    expect(dbState.transactions).toBe(1);
    expect(txAudit.record).toHaveBeenCalledTimes(1);
    expect(emitMock).not.toHaveBeenCalled();
  });
});
