/**
 * How the audited-write helpers (lib/audit/admin-write) carry the change
 * budget and coded refusals, without a database: the budget is opened before
 * the write and its class judged before the audit row; the row carries the
 * class; a refusal rolls the transaction back, leaves a denied row written
 * AFTER the rollback (never inside it), and reaches the caller as a coded
 * TRPCError; a person's change gets a real transaction too. The same claims
 * are pinned against Postgres in trpc/admin-plane-rails.integration.test.ts.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const { order, budget, deniedRows, txAudit } = vi.hoisted(() => ({
  order: [] as string[],
  budget: { opened: null as unknown, throwOnOpen: false, throwOnClass: false },
  deniedRows: [] as Array<Record<string, unknown>>,
  txAudit: vi.fn(async (_tx: unknown, _event: unknown) => {
    order.push("audit insert");
  }),
}));

vi.mock("@/utils/logger", () => ({
  default: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));
vi.mock("../../db/index", () => ({
  db: {
    transaction: async (callback: (tx: object) => Promise<unknown>) => {
      order.push("begin");
      try {
        const out = await callback({ id: "tx" });
        order.push("commit");
        return out;
      } catch (error) {
        order.push("rollback");
        throw error;
      }
    },
  },
}));
vi.mock("../../db/repositories/audit-log-tx", () => ({
  recordAuditInTransaction: txAudit,
}));
vi.mock("../../db/repositories/audit-log.repo", () => ({
  auditLogRepository: {
    record: vi.fn(async (row: Record<string, unknown>) => {
      order.push("denied row");
      deniedRows.push(row);
    }),
  },
}));
vi.mock("../admin-plane-budget", async (importOriginal) => {
  const real = await importOriginal<typeof import("../admin-plane-budget")>();
  return {
    ...real,
    openBudget: vi.fn(async () => {
      order.push("budget open");
      if (budget.throwOnOpen) {
        throw new real.AdminPlaneBudgetExceeded("total", 3, 3600);
      }
      return budget.opened;
    }),
    judgeBudgetClass: vi.fn(() => {
      order.push("budget class");
      if (budget.throwOnClass) {
        throw new real.AdminPlaneBudgetExceeded("loosen", 1, 3600);
      }
    }),
  };
});

const { AdminRuleRefusal, runAuditedTransaction, withAdminAuditTx } =
  await import("./admin-write");
const { ADMIN_PLANE_BUDGET_REFUSAL } = await import("../admin-plane-budget");

const keyActor = {
  actor_id: "owner-1",
  actor_label: "owner@example.test",
  actor_ip: "203.0.113.5",
  actor_user_agent: "ua",
  request_id: "r1",
  reason: "rollout",
  admin_plane: {
    key_uuid: "6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b",
    owner_user_id: "owner-1",
    scope: "operator" as const,
  },
};
const person = {
  actor_id: "admin-1",
  actor_label: null,
  actor_ip: null,
  actor_user_agent: null,
  request_id: null,
};

beforeEach(() => {
  order.length = 0;
  deniedRows.length = 0;
  txAudit.mockClear();
  budget.opened = { counts: { total: 0, loosen: 0, destroy: 0 }, config: {} };
  budget.throwOnOpen = false;
  budget.throwOnClass = false;
});

describe("an admin-plane change", () => {
  it("opens the budget first, judges the class before the audit row, and records the class", async () => {
    await runAuditedTransaction(
      keyActor,
      async () => {
        order.push("write");
        return { uuid: "g" };
      },
      () => ({ action: "group.member.add", target_type: "access_group" }),
    );
    expect(order).toEqual([
      "begin",
      "budget open",
      "write",
      "budget class",
      "audit insert",
      "commit",
    ]);
    expect(txAudit.mock.calls[0][1]).toMatchObject({
      detail: { budget_class: "loosen", reason: "rollout" },
    });
  });

  it("refuses over the total before the write, rolls back, then records the denial and answers 429", async () => {
    budget.throwOnOpen = true;
    const write = vi.fn();
    const failure = await runAuditedTransaction(keyActor, write, () => null)
      .then(() => null)
      .catch((e) => e);
    expect(write).not.toHaveBeenCalled();
    expect(failure).toMatchObject({
      code: "TOO_MANY_REQUESTS",
      message: ADMIN_PLANE_BUDGET_REFUSAL,
    });
    expect(order).toEqual(["begin", "budget open", "rollback", "denied row"]);
    expect(deniedRows[0]).toMatchObject({
      action: "admin_plane.budget.exceeded",
      outcome: "denied",
      actor_type: "api_key",
      detail: expect.objectContaining({
        rule: "change_budget",
        budget_class: "total",
        reason: "rollout",
      }),
    });
  });

  it("refuses over a class after the write but before its audit row, and keeps nothing", async () => {
    budget.throwOnClass = true;
    const failure = await runAuditedTransaction(
      keyActor,
      async () => {
        order.push("write");
        return {};
      },
      () => ({ action: "apikey.create", target_type: "api_key" }),
    ).catch((e) => e);
    expect(failure.code).toBe("TOO_MANY_REQUESTS");
    expect(order).toEqual([
      "begin",
      "budget open",
      "write",
      "budget class",
      "rollback",
      "denied row",
    ]);
    expect(txAudit).not.toHaveBeenCalled();
  });

  it("turns a rule refusal into its coded error, with its denied row after the rollback", async () => {
    const failure = await runAuditedTransaction(
      keyActor,
      async () => {
        throw new AdminRuleRefusal("CONFLICT", "fixed sentence", {
          action: "group.delete",
          target_type: "access_group",
          target_id: "g",
          detail: { rule: "group_not_empty" },
        });
      },
      () => null,
    ).catch((e) => e);
    expect(failure).toMatchObject({
      code: "CONFLICT",
      message: "fixed sentence",
    });
    expect(order.slice(-2)).toEqual(["rollback", "denied row"]);
    expect(deniedRows[0]).toMatchObject({
      action: "group.delete",
      outcome: "denied",
      detail: expect.objectContaining({ rule: "group_not_empty" }),
    });
  });
});

describe("a person's change through withAdminAuditTx", () => {
  it("runs in a real transaction with no budget, and refuses the same way", async () => {
    await withAdminAuditTx(
      person,
      async () => {
        order.push("write");
        return {};
      },
      () => null,
    );
    expect(order).toEqual(["begin", "write", "commit"]);

    order.length = 0;
    const failure = await withAdminAuditTx(
      person,
      async () => {
        throw new AdminRuleRefusal("CONFLICT", "no", {
          action: "endpoint.create",
          target_type: "endpoint",
        });
      },
      () => null,
    ).catch((e) => e);
    expect(failure.code).toBe("CONFLICT");
    expect(order).toEqual(["begin", "rollback", "denied row"]);
    expect(deniedRows[0]).toMatchObject({ actor_type: "user" });
  });
});
