/**
 * The per-key change budget (lib/admin-plane-budget) without a database: the
 * deploy-environment numbers and their bounds, the class every budgeted
 * action is counted in, and the order of the two halves of a charge (the lock
 * and the total before the change, the class after it says what it is). The
 * real count, the lock across connections and the rollback are pinned against
 * Postgres in trpc/admin-plane-rails.integration.test.ts.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

const {
  __resetAdminPlaneBudgetWarningsForTesting,
  ADMIN_PLANE_BUDGET_ENV,
  ADMIN_PLANE_BUDGET_REFUSAL,
  AdminPlaneBudgetExceeded,
  adminPlaneBudgetConfig,
  BUDGETED_ACTIONS,
  budgetClassOf,
  DEFAULT_ADMIN_PLANE_BUDGET,
  judgeBudgetClass,
  openBudget,
} = await import("./admin-plane-budget");

const ENV_NAMES = Object.values(ADMIN_PLANE_BUDGET_ENV);
let saved: Record<string, string | undefined> = {};

beforeEach(() => {
  saved = Object.fromEntries(ENV_NAMES.map((n) => [n, process.env[n]]));
  for (const name of ENV_NAMES) delete process.env[name];
  __resetAdminPlaneBudgetWarningsForTesting();
});
afterEach(() => {
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
});

const operatorActor = {
  actor_id: "owner-1",
  actor_label: null,
  actor_ip: null,
  actor_user_agent: null,
  request_id: null,
  admin_plane: {
    key_uuid: "6F1D2C3B-4A5E-4F60-8A7B-9C0D1E2F3A4B",
    owner_user_id: "owner-1",
    scope: "operator" as const,
  },
};
const syncActor = {
  ...operatorActor,
  admin_plane: { ...operatorActor.admin_plane, scope: "sync" as const },
};

describe("the numbers", () => {
  it("ships the reviewed default numbers per key and class, so changing one is a deliberate budget change", () => {
    expect(adminPlaneBudgetConfig()).toEqual({
      windowSeconds: 3600,
      operator: { total: 318, loosen: 33, destroy: 3 },
      sync: { total: 1056, loosen: 0, destroy: 0 },
    });
    expect(DEFAULT_ADMIN_PLANE_BUDGET).toEqual(adminPlaneBudgetConfig());
  });

  it("reads each number from the deploy environment", () => {
    process.env.ADMIN_PLANE_BUDGET_WINDOW_SECONDS = "600";
    process.env.ADMIN_PLANE_BUDGET_OPERATOR_TOTAL = "50";
    process.env.ADMIN_PLANE_BUDGET_OPERATOR_LOOSEN = "5";
    process.env.ADMIN_PLANE_BUDGET_OPERATOR_DESTROY = "2";
    process.env.ADMIN_PLANE_BUDGET_SYNC_TOTAL = "400";
    expect(adminPlaneBudgetConfig()).toEqual({
      windowSeconds: 600,
      operator: { total: 50, loosen: 5, destroy: 2 },
      sync: { total: 400, loosen: 0, destroy: 0 },
    });
  });

  it.each([
    ["ADMIN_PLANE_BUDGET_WINDOW_SECONDS", "59"],
    ["ADMIN_PLANE_BUDGET_WINDOW_SECONDS", "86401"],
    ["ADMIN_PLANE_BUDGET_OPERATOR_TOTAL", "0"],
    ["ADMIN_PLANE_BUDGET_OPERATOR_TOTAL", "-1"],
    ["ADMIN_PLANE_BUDGET_OPERATOR_TOTAL", "1e3"],
    ["ADMIN_PLANE_BUDGET_OPERATOR_TOTAL", "12.5"],
    ["ADMIN_PLANE_BUDGET_OPERATOR_TOTAL", "lots"],
    ["ADMIN_PLANE_BUDGET_OPERATOR_TOTAL", "100001"],
  ])(
    "keeps the reviewed default when %s=%s is outside its bounds",
    (name, value) => {
      process.env[name] = value;
      expect(adminPlaneBudgetConfig()).toEqual(DEFAULT_ADMIN_PLANE_BUDGET);
    },
  );

  it("holds a class limit to the total, so it can always bind", () => {
    process.env.ADMIN_PLANE_BUDGET_OPERATOR_TOTAL = "10";
    process.env.ADMIN_PLANE_BUDGET_OPERATOR_LOOSEN = "500";
    expect(adminPlaneBudgetConfig().operator).toEqual({
      total: 10,
      loosen: 10,
      destroy: 3,
    });
  });
});

describe("the class of a change", () => {
  it.each([
    ["apikey.create", undefined, "loosen"],
    ["group.member.add", undefined, "loosen"],
    ["group.endpoint.add", undefined, "loosen"],
    ["endpoint.restricted.set", { restricted: false }, "loosen"],
    ["endpoint.restricted.set", { restricted: true }, "tighten"],
    ["namespace.tool_policy", { tool_policy: "allow_all" }, "loosen"],
    ["namespace.tool_policy", { tool_policy: "allowlist" }, "tighten"],
    ["group.delete", undefined, "destroy"],
    ["apikey.revoke", undefined, "tighten"],
    ["group.member.remove", undefined, "tighten"],
    ["mcpserver.update", undefined, "change"],
    ["namespace.update", undefined, "change"],
    ["apikey.ip_policy.set", { policy_widened: false }, "change"],
    ["apikey.ip_policy.set", { policy_widened: true }, "loosen"],
    ["apikey.ip_policy.set", undefined, "loosen"],
  ] as const)("counts %s %j as %s", (action, detail, expected) => {
    expect(budgetClassOf(action, detail as never)).toBe(expected);
  });

  it("counts an action nobody classified in the strictest class", () => {
    expect(budgetClassOf("something.new", {})).toBe("destroy");
  });

  it("classifies every action the admin-plane mutations write", () => {
    // The full list per procedure is pinned in the classification test; this
    // is the table's own shape.
    expect(BUDGETED_ACTIONS.length).toBeGreaterThanOrEqual(21);
    for (const action of BUDGETED_ACTIONS) {
      expect(["tighten", "change", "loosen", "destroy"]).toContain(
        budgetClassOf(action, {}),
      );
    }
  });
});

/** A stand-in transaction that records its statements and answers a count. */
function fakeTx(counts: { total: number; loosen: number; destroy: number }) {
  const statements: string[] = [];
  const tx = {
    execute: vi.fn(async (query: { queryChunks?: unknown[] }) => {
      const text = JSON.stringify(query);
      statements.push(
        text.includes("pg_advisory_xact_lock") ? "lock" : "count",
      );
      return { rows: [counts] };
    }),
  };
  return { tx, statements };
}

describe("openBudget and judgeBudgetClass", () => {
  it("does nothing for an actor without admin-plane provenance", async () => {
    const { tx } = fakeTx({ total: 0, loosen: 0, destroy: 0 });
    expect(
      await openBudget(tx as never, {
        actor_id: "a",
        actor_label: null,
        actor_ip: null,
        actor_user_agent: null,
        request_id: null,
      }),
    ).toBeNull();
    expect(tx.execute).not.toHaveBeenCalled();
  });

  it("takes the key's lock first, then counts, and lets a change through under the total", async () => {
    const { tx, statements } = fakeTx({ total: 317, loosen: 0, destroy: 0 });
    const opened = await openBudget(tx as never, operatorActor);
    expect(statements).toEqual(["lock", "count"]);
    expect(opened?.counts.total).toBe(317);
  });

  it("refuses before the change once the total is spent", async () => {
    const { tx } = fakeTx({ total: 318, loosen: 0, destroy: 0 });
    const failure = await openBudget(tx as never, operatorActor).catch(
      (e) => e,
    );
    expect(failure).toBeInstanceOf(AdminPlaneBudgetExceeded);
    expect(failure.message).toBe(ADMIN_PLANE_BUDGET_REFUSAL);
    expect(failure.budgetClass).toBe("total");
  });

  it("holds a sync key to the sync scope's numbers", async () => {
    const { tx } = fakeTx({ total: 1055, loosen: 0, destroy: 0 });
    const opened = await openBudget(tx as never, syncActor);
    expect(opened).not.toBeNull();
    const spent = fakeTx({ total: 1056, loosen: 0, destroy: 0 });
    await expect(
      openBudget(spent.tx as never, syncActor),
    ).rejects.toBeInstanceOf(AdminPlaneBudgetExceeded);
  });

  it("judges a class against its own limit, and only that class", async () => {
    const opened = {
      counts: { total: 10, loosen: 33, destroy: 3 },
      config: adminPlaneBudgetConfig(),
    };
    expect(() => judgeBudgetClass(operatorActor, opened, "loosen")).toThrow(
      AdminPlaneBudgetExceeded,
    );
    expect(() => judgeBudgetClass(operatorActor, opened, "destroy")).toThrow(
      AdminPlaneBudgetExceeded,
    );
    expect(() =>
      judgeBudgetClass(operatorActor, opened, "tighten"),
    ).not.toThrow();
    expect(() =>
      judgeBudgetClass(operatorActor, opened, "change"),
    ).not.toThrow();
  });

  it("refuses every loosening change to a sync key", () => {
    const opened = {
      counts: { total: 0, loosen: 0, destroy: 0 },
      config: adminPlaneBudgetConfig(),
    };
    expect(() => judgeBudgetClass(syncActor, opened, "loosen")).toThrow(
      AdminPlaneBudgetExceeded,
    );
  });
});
