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
  ADMIN_PLANE_GRANT_REFUSAL,
  AdminPlaneBudgetExceeded,
  adminPlaneBudgetConfig,
  BUDGETED_ACTIONS,
  budgetClassOf,
  DEFAULT_ADMIN_PLANE_BUDGET,
  GRANT_ACTIONS,
  isGrantChange,
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
  // TEST-EDIT (SPEC): the defaults cover the loosen classes the reply-shape
  // change adds (operator loosen 33 to 102, sync total 1056 to 1089 and sync
  // loosen 0 to 48), and each scope gains a grant sub-limit inside loosen
  // (operator 33, the loosen limit before the topology classes joined it; sync
  // 0); the numbers are explained in DEFAULT_ADMIN_PLANE_BUDGET and the
  // README.
  it("ships the reviewed default numbers per key and class, so changing one is a deliberate budget change", () => {
    expect(adminPlaneBudgetConfig()).toEqual({
      windowSeconds: 3600,
      operator: { total: 318, loosen: 102, grant: 33, destroy: 3 },
      sync: { total: 1089, loosen: 48, grant: 0, destroy: 0 },
    });
    expect(DEFAULT_ADMIN_PLANE_BUDGET).toEqual(adminPlaneBudgetConfig());
  });

  it("reads each number from the deploy environment", () => {
    process.env.ADMIN_PLANE_BUDGET_WINDOW_SECONDS = "600";
    process.env.ADMIN_PLANE_BUDGET_OPERATOR_TOTAL = "50";
    process.env.ADMIN_PLANE_BUDGET_OPERATOR_LOOSEN = "20";
    process.env.ADMIN_PLANE_BUDGET_OPERATOR_GRANT = "5";
    process.env.ADMIN_PLANE_BUDGET_OPERATOR_DESTROY = "2";
    process.env.ADMIN_PLANE_BUDGET_SYNC_TOTAL = "400";
    process.env.ADMIN_PLANE_BUDGET_SYNC_GRANT = "4";
    expect(adminPlaneBudgetConfig()).toEqual({
      windowSeconds: 600,
      operator: { total: 50, loosen: 20, grant: 5, destroy: 2 },
      sync: { total: 400, loosen: 48, grant: 4, destroy: 0 },
    });
  });

  it.each([
    ["ADMIN_PLANE_BUDGET_OPERATOR_GRANT", "-1"],
    ["ADMIN_PLANE_BUDGET_OPERATOR_GRANT", "12.5"],
    ["ADMIN_PLANE_BUDGET_OPERATOR_GRANT", "lots"],
    ["ADMIN_PLANE_BUDGET_OPERATOR_GRANT", "100001"],
    ["ADMIN_PLANE_BUDGET_SYNC_GRANT", "-1"],
    ["ADMIN_PLANE_BUDGET_SYNC_GRANT", "1e3"],
    ["ADMIN_PLANE_BUDGET_SYNC_GRANT", "100001"],
  ])(
    "keeps the reviewed default when %s=%s is outside its bounds",
    (name, value) => {
      process.env[name] = value;
      expect(adminPlaneBudgetConfig()).toEqual(DEFAULT_ADMIN_PLANE_BUDGET);
    },
  );

  it("accepts a grant limit of zero, which refuses every grant", () => {
    process.env.ADMIN_PLANE_BUDGET_OPERATOR_GRANT = "0";
    expect(adminPlaneBudgetConfig().operator.grant).toBe(0);
  });

  it("holds the grant limit to the loosen limit, since every grant is also a loosening change", () => {
    process.env.ADMIN_PLANE_BUDGET_OPERATOR_LOOSEN = "7";
    process.env.ADMIN_PLANE_BUDGET_OPERATOR_GRANT = "500";
    process.env.ADMIN_PLANE_BUDGET_SYNC_LOOSEN = "2";
    process.env.ADMIN_PLANE_BUDGET_SYNC_GRANT = "9";
    const config = adminPlaneBudgetConfig();
    expect(config.operator.grant).toBe(7);
    expect(config.sync.grant).toBe(2);
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
      grant: 10,
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
    // TEST-EDIT (SPEC): a namespace update with no evidence of what it did is
    // loosen now (missing evidence never reads as the lesser class); one that
    // added no mount is a change.
    ["namespace.update", undefined, "loosen"],
    ["namespace.update", { mounts_added: 0 }, "change"],
    ["apikey.ip_policy.set", { policy_widened: false }, "change"],
    ["apikey.ip_policy.set", { policy_widened: true }, "loosen"],
    ["apikey.ip_policy.set", undefined, "loosen"],
    // The classes a topology write earns from what it can put in front of
    // callers (a tool row is born ACTIVE under allow_all): each loosen unless
    // its own audit event proves it widened nothing, and missing or malformed
    // evidence is never the lesser class.
    ["mcpserver.create", undefined, "loosen"],
    ["namespace.create", undefined, "loosen"],
    ["namespace.update", { mounts_added: 1 }, "loosen"],
    ["namespace.update", { mounts_added: "0" }, "loosen"],
    ["namespace.update", { mounts_added: Number.NaN }, "loosen"],
    ["namespace.refresh_tools", { active_rows_written: 3 }, "loosen"],
    ["namespace.refresh_tools", { active_rows_written: 0 }, "change"],
    ["namespace.refresh_tools", undefined, "loosen"],
    ["namespace.tool_status", { status: "ACTIVE" }, "loosen"],
    ["namespace.tool_status", { status: "INACTIVE" }, "tighten"],
    ["namespace.tool_status", undefined, "loosen"],
    ["endpoint.create", { restricted: false }, "loosen"],
    ["endpoint.create", { restricted: true }, "change"],
    ["endpoint.create", undefined, "loosen"],
    // Only a boolean true says the endpoint is restricted: a truthy value of
    // another type is no evidence of it and reads as the stricter class.
    ["endpoint.create", { restricted: "true" }, "loosen"],
    ["endpoint.create", { restricted: 1 }, "loosen"],
    ["endpoint.create", { restricted: {} }, "loosen"],
    ["endpoint.update", undefined, "change"],
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
function fakeTx(counts: {
  total: number;
  loosen: number;
  destroy: number;
  grant?: number;
}) {
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

describe("what the sync scope can do within its budget", () => {
  it("can register many declared servers in one run within its loosen allowance, and a first extra one past it is refused", () => {
    // The allowance is sized so a declaration that grows by many servers still
    // registers in one run, and a runaway still stops.
    const config = adminPlaneBudgetConfig();
    expect(config.sync.loosen).toBe(48);
    const open = (loosen: number) => ({
      counts: { total: 0, loosen, grant: 0, destroy: 0 },
      config,
    });
    for (let created = 0; created < 16; created++) {
      expect(() =>
        judgeBudgetClass(syncActor, open(created), "loosen", false),
      ).not.toThrow();
    }
    expect(() =>
      judgeBudgetClass(syncActor, open(config.sync.loosen), "loosen", false),
    ).toThrow(AdminPlaneBudgetExceeded);
  });

  it("still holds a sync that re-saves every declared server on repeated runs in one window within the total", () => {
    expect(adminPlaneBudgetConfig().sync.total).toBeGreaterThanOrEqual(1000);
  });
});

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

  // TEST-EDIT (SPEC): the sync total is 1089 now, 1056 before.
  it("holds a sync key to the sync scope's numbers", async () => {
    const { tx } = fakeTx({ total: 1088, loosen: 0, destroy: 0 });
    const opened = await openBudget(tx as never, syncActor);
    expect(opened).not.toBeNull();
    const spent = fakeTx({ total: 1089, loosen: 0, destroy: 0 });
    await expect(
      openBudget(spent.tx as never, syncActor),
    ).rejects.toBeInstanceOf(AdminPlaneBudgetExceeded);
  });

  it("judges a class against its own limit, and only that class", async () => {
    // TEST-EDIT (SPEC): the operator loosen limit is 102 now, 33 before.
    const opened = {
      counts: { total: 10, loosen: 102, grant: 0, destroy: 3 },
      config: adminPlaneBudgetConfig(),
    };
    expect(() =>
      judgeBudgetClass(operatorActor, opened, "loosen", false),
    ).toThrow(AdminPlaneBudgetExceeded);
    expect(() =>
      judgeBudgetClass(operatorActor, opened, "destroy", false),
    ).toThrow(AdminPlaneBudgetExceeded);
    expect(() =>
      judgeBudgetClass(operatorActor, opened, "tighten", false),
    ).not.toThrow();
    expect(() =>
      judgeBudgetClass(operatorActor, opened, "change", false),
    ).not.toThrow();
  });

  // TEST-EDIT (SPEC): the sync scope now has a loosen allowance of its own
  // (it creates the servers its declaration lists, and that spends loosen); it
  // is judged against it like the operator's, and still has no destroy.
  it("judges a sync key's loosening changes against the sync allowance, and allows it no destroy", () => {
    const config = adminPlaneBudgetConfig();
    const open = (loosen: number) => ({
      counts: { total: 0, loosen, grant: 0, destroy: 0 },
      config,
    });
    expect(() =>
      judgeBudgetClass(
        syncActor,
        open(config.sync.loosen - 1),
        "loosen",
        false,
      ),
    ).not.toThrow();
    expect(() =>
      judgeBudgetClass(syncActor, open(config.sync.loosen), "loosen", false),
    ).toThrow(AdminPlaneBudgetExceeded);
    expect(() =>
      judgeBudgetClass(syncActor, open(0), "destroy", false),
    ).toThrow(AdminPlaneBudgetExceeded);
  });
});

// The grant sub-limit sits inside loosen: the topology writes that joined the
// loosening class raised its limit, and a grant (a change that gives access to
// a key, a person or an endpoint) counts against both, so a key's grants stay
// bounded by the smaller number. The real count, and the last slot across two
// connections, are pinned against Postgres in
// trpc/admin-plane-reply-shape.integration.test.ts.
describe("the grant sub-limit", () => {
  // TEST-EDIT (SPEC, R-3): the list gains "namespace.tool_policy", so one write
  // that widens a whole namespace keeps the cap a loosening change had before
  // the topology classes joined the loosen limit.
  it("names the seven grant actions, and no other", () => {
    expect([...GRANT_ACTIONS].sort()).toEqual([
      "apikey.create",
      "apikey.ip_policy.set",
      "apikey.reactivate",
      "endpoint.restricted.set",
      "group.endpoint.add",
      "group.member.add",
      "namespace.tool_policy",
    ]);
  });

  it.each([
    // Grants: loosening changes that give access.
    ["apikey.create", undefined, "loosen", true],
    ["apikey.reactivate", undefined, "loosen", true],
    ["apikey.ip_policy.set", { policy_widened: true }, "loosen", true],
    ["apikey.ip_policy.set", undefined, "loosen", true],
    ["group.member.add", undefined, "loosen", true],
    ["group.endpoint.add", undefined, "loosen", true],
    ["endpoint.restricted.set", { restricted: false }, "loosen", true],
    ["namespace.tool_policy", { tool_policy: "allow_all" }, "loosen", true],
    // The same actions narrowed are not grants.
    ["apikey.ip_policy.set", { policy_widened: false }, "change", false],
    ["endpoint.restricted.set", { restricted: true }, "tighten", false],
    ["namespace.tool_policy", { tool_policy: "allowlist" }, "tighten", false],
    // Loosening changes that are not grants spend loosen only.
    ["namespace.create", undefined, "loosen", false],
    ["mcpserver.create", undefined, "loosen", false],
    ["namespace.update", { mounts_added: 1 }, "loosen", false],
    ["namespace.refresh_tools", { active_rows_written: 2 }, "loosen", false],
    ["namespace.tool_status", { status: "ACTIVE" }, "loosen", false],
    ["endpoint.create", { restricted: false }, "loosen", false],
    // Other classes.
    ["group.member.remove", undefined, "tighten", false],
    ["apikey.revoke", undefined, "tighten", false],
    ["apikey.update", undefined, "change", false],
    ["group.create", undefined, "change", false],
    ["group.delete", undefined, "destroy", false],
  ] as const)(
    "counts %s %j as %s, and as a grant: %s",
    (action, detail, expectedClass, expectedGrant) => {
      const budgetClass = budgetClassOf(action, detail as never);
      expect(budgetClass).toBe(expectedClass);
      expect(isGrantChange(action, budgetClass)).toBe(expectedGrant);
    },
  );

  const config = adminPlaneBudgetConfig();
  const open = (
    scope: "operator" | "sync",
    spent: { loosen?: number; grant?: number },
  ) => ({
    counts: { total: 0, loosen: 0, grant: 0, destroy: 0, ...spent },
    config,
    actor: scope === "operator" ? operatorActor : syncActor,
  });

  it("refuses a grant once the grant limit is spent while loosen has room, naming the grant limit", () => {
    const { counts, actor } = open("operator", {
      loosen: config.operator.grant,
      grant: config.operator.grant,
    });
    expect(config.operator.loosen).toBeGreaterThan(config.operator.grant);

    const failure = (() => {
      try {
        judgeBudgetClass(actor, { counts, config }, "loosen", true);
      } catch (error) {
        return error as InstanceType<typeof AdminPlaneBudgetExceeded>;
      }
    })();

    expect(failure).toBeInstanceOf(AdminPlaneBudgetExceeded);
    expect(failure?.budgetClass).toBe("grant");
    expect(failure?.limit).toBe(config.operator.grant);
    expect(failure?.message).toBe(ADMIN_PLANE_GRANT_REFUSAL);
    expect(ADMIN_PLANE_GRANT_REFUSAL).toContain("grant limit");
    expect(ADMIN_PLANE_GRANT_REFUSAL).not.toBe(ADMIN_PLANE_BUDGET_REFUSAL);
  });

  it("still allows a loosening change that is not a grant when the grant limit is spent", () => {
    const { counts, actor } = open("operator", {
      loosen: config.operator.grant,
      grant: config.operator.grant,
    });
    expect(() =>
      judgeBudgetClass(actor, { counts, config }, "loosen", false),
    ).not.toThrow();
  });

  it("allows the last grant and refuses the next one", () => {
    const last = open("operator", {
      loosen: config.operator.grant - 1,
      grant: config.operator.grant - 1,
    });
    expect(() =>
      judgeBudgetClass(last.actor, last, "loosen", true),
    ).not.toThrow();

    const next = open("operator", {
      loosen: config.operator.grant,
      grant: config.operator.grant,
    });
    expect(() => judgeBudgetClass(next.actor, next, "loosen", true)).toThrow(
      AdminPlaneBudgetExceeded,
    );
  });

  it("names the loosen limit when it refused, even if the grant limit is spent too", () => {
    const both = open("operator", {
      loosen: config.operator.loosen,
      grant: config.operator.grant,
    });

    const failure = (() => {
      try {
        judgeBudgetClass(both.actor, both, "loosen", true);
      } catch (error) {
        return error as InstanceType<typeof AdminPlaneBudgetExceeded>;
      }
    })();

    expect(failure?.budgetClass).toBe("loosen");
    expect(failure?.message).toBe(ADMIN_PLANE_BUDGET_REFUSAL);
  });

  it("refuses every grant to the sync scope, whose grant limit is zero, and not its other loosening changes", () => {
    const fresh = open("sync", {});
    expect(config.sync.grant).toBe(0);
    expect(() => judgeBudgetClass(fresh.actor, fresh, "loosen", true)).toThrow(
      AdminPlaneBudgetExceeded,
    );
    expect(() =>
      judgeBudgetClass(fresh.actor, fresh, "loosen", false),
    ).not.toThrow();
  });
});
