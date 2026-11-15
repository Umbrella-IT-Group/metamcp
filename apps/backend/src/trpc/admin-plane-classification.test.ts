/**
 * Every procedure in the app router is classified exactly once: the sync set,
 * the operator-only set (the operator set minus the sync set) or the
 * human-only set. A procedure added to the router without a decision fails
 * here. Also pinned: the operator mutation list matches the router's own
 * procedure types, every operator mutation refuses a non-object input before
 * its implementation (the reason requirement relies on it), the change
 * context rule, the whitelisted audit read, and that every audit action an
 * admin-plane mutation writes has a budget class.
 */
import { readFileSync } from "node:fs";
import path from "node:path";

import {
  ADMIN_PLANE_HUMAN_ONLY_PROCEDURES,
  ADMIN_PLANE_OPERATOR_MUTATIONS,
  ADMIN_PLANE_OPERATOR_PROCEDURES,
  ADMIN_PLANE_SYNC_PROCEDURES,
  auditActor,
  CHANGE_CONTEXT_REFUSALS,
  changeContextOf,
  createAppRouter,
} from "@repo/trpc";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

const { BUDGETED_ACTIONS } = await import("../lib/admin-plane-budget");
const { buildAdminAuditEvent } = await import("../lib/audit/admin-event");
const { projectAuditDetail } = await import("../lib/audit/audit-read");

let reached: Array<{ path: string; args: unknown[] }> = [];
const stub = (router: string) =>
  new Proxy(
    {},
    {
      get: (_t, prop) =>
        typeof prop === "string"
          ? async (...args: unknown[]) => {
              reached.push({ path: `${router}.${prop}`, args });
              return {};
            }
          : undefined,
    },
  );
const ROUTERS = [
  "mcpServers",
  "namespaces",
  "endpoints",
  "oauth",
  "oauthClients",
  "oauthTokens",
  "users",
  "tools",
  "apiKeys",
  "config",
  "logs",
  "accessGroups",
  "endpointPresentation",
  "audit",
];
const appRouter = createAppRouter({
  frontend: Object.fromEntries(ROUTERS.map((r) => [r, stub(r)])) as never,
});
const PROCEDURES = (
  appRouter as unknown as {
    _def: { procedures: Record<string, { _def: { type: string } }> };
  }
)._def.procedures;
const ALL = Object.keys(PROCEDURES).sort();

const operatorCtx = (scope: "sync" | "operator") => ({
  user: { id: "owner-1", role: "admin", email: "o@example.test" },
  session: { id: "s" },
  authOrigin: {
    kind: "admin_plane" as const,
    key_uuid: "6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b",
    owner_user_id: "owner-1",
    scope,
  },
});
async function call(ctx: object, path: string, input: unknown) {
  const caller = appRouter.createCaller(ctx as never) as unknown;
  const fn = path
    .split(".")
    .reduce<unknown>(
      (node, key) => (node as Record<string, unknown>)[key],
      caller,
    ) as (input: unknown) => Promise<unknown>;
  const before = reached.length;
  // The create procedure's refusal mapper (apiKeys.mintInputRefusal) only
  // words a refusal; reaching it is not reaching the change.
  const changed = () =>
    reached
      .slice(before)
      .some((entry) => entry.path !== "apiKeys.mintInputRefusal");
  try {
    await fn(input);
    return { reached: changed(), code: null as string | null };
  } catch (error) {
    return {
      reached: changed(),
      code: (error as { code?: string }).code ?? null,
      message: (error as { message?: string }).message,
    };
  }
}

describe("classification", () => {
  const operatorOnly = [...ADMIN_PLANE_OPERATOR_PROCEDURES].filter(
    (p) => !ADMIN_PLANE_SYNC_PROCEDURES.has(p),
  );

  it("places every procedure in the router in exactly one of sync, operator-only and human-only", () => {
    for (const path of ALL) {
      const homes = [
        ADMIN_PLANE_SYNC_PROCEDURES.has(path),
        operatorOnly.includes(path),
        ADMIN_PLANE_HUMAN_ONLY_PROCEDURES.has(path),
      ].filter(Boolean).length;
      expect({ path, homes }).toEqual({ path, homes: 1 });
    }
  });

  it("names no procedure the router does not have, and the operator set is sync plus operator-only", () => {
    for (const path of [
      ...ADMIN_PLANE_OPERATOR_PROCEDURES,
      ...ADMIN_PLANE_HUMAN_ONLY_PROCEDURES,
    ]) {
      expect(ALL).toContain(path);
    }
    for (const path of ADMIN_PLANE_SYNC_PROCEDURES) {
      expect(ADMIN_PLANE_OPERATOR_PROCEDURES.has(path)).toBe(true);
    }
    expect(ALL).toHaveLength(
      ADMIN_PLANE_OPERATOR_PROCEDURES.size +
        ADMIN_PLANE_HUMAN_ONLY_PROCEDURES.size,
    );
    expect(ALL).toHaveLength(89);
  });

  it("lists as operator mutations exactly the operator procedures that are mutations", () => {
    const fromRouter = [...ADMIN_PLANE_OPERATOR_PROCEDURES]
      .filter((p) => PROCEDURES[p]._def.type === "mutation")
      .sort();
    expect([...ADMIN_PLANE_OPERATOR_MUTATIONS].sort()).toEqual(fromRouter);
    expect(fromRouter).toHaveLength(21);
  });

  it.each([...ADMIN_PLANE_OPERATOR_MUTATIONS])(
    "%s refuses a non-object input before its implementation runs",
    async (path) => {
      for (const input of [undefined, "a string", ["an", "array"], 7]) {
        const result = await call(operatorCtx("operator"), path, input);
        expect({ path, input, reached: result.reached }).toEqual({
          path,
          input,
          reached: false,
        });
      }
    },
  );
});

describe("the change context of a call", () => {
  it("refuses an operator-scope key's change without a reason, before it runs", async () => {
    const result = await call(
      operatorCtx("operator"),
      "frontend.accessGroups.create",
      { name: "g" },
    );
    expect(result).toMatchObject({
      reached: false,
      code: "BAD_REQUEST",
      message: CHANGE_CONTEXT_REFUSALS.reasonRequired,
    });
  });

  it("hands an operator-scope key's reason and run id to the implementation's actor", async () => {
    reached = [];
    const result = await call(
      operatorCtx("operator"),
      "frontend.accessGroups.create",
      { name: "g", reason: "  rollout step 3  ", run_id: "run-0001.a" },
    );
    expect(result.reached).toBe(true);
    const actor = reached[0].args[1] as { reason?: string; run_id?: string };
    expect(actor.reason).toBe("rollout step 3");
    expect(actor.run_id).toBe("run-0001.a");
  });

  it("lets a sync-scope key and a person change without a reason", async () => {
    expect(
      (
        await call(operatorCtx("sync"), "frontend.mcpServers.update", {
          uuid: "33333333-3333-4333-8333-333333333333",
          name: "s",
          type: "STREAMABLE_HTTP",
          url: "http://backend.internal:8000/mcp",
        })
      ).reached,
    ).toBe(true);
    expect(
      (
        await call(
          { user: { id: "a", role: "admin" }, session: { id: "b" } },
          "frontend.accessGroups.create",
          { name: "g" },
        )
      ).reached,
    ).toBe(true);
  });

  it("does not ask a read for a reason", async () => {
    expect(
      (
        await call(
          operatorCtx("operator"),
          "frontend.accessGroups.list",
          undefined,
        )
      ).reached,
    ).toBe(true);
  });

  it.each([
    [
      "an empty reason",
      { reason: "   " },
      CHANGE_CONTEXT_REFUSALS.reasonInvalid,
    ],
    [
      "a reason over 500 characters",
      { reason: "x".repeat(501) },
      CHANGE_CONTEXT_REFUSALS.reasonInvalid,
    ],
    [
      "a control character",
      { reason: "ok\u0007" },
      CHANGE_CONTEXT_REFUSALS.reasonInvalid,
    ],
    [
      "a direction override",
      { reason: "ok\u202e" },
      CHANGE_CONTEXT_REFUSALS.reasonInvalid,
    ],
    [
      "a reason that is not text",
      { reason: 7 },
      CHANGE_CONTEXT_REFUSALS.reasonInvalid,
    ],
    [
      "a run id with a space",
      { reason: "ok", run_id: "a b" },
      CHANGE_CONTEXT_REFUSALS.runIdInvalid,
    ],
  ])(
    "refuses %s, from any caller, without echoing it",
    (_l, extra, message) => {
      expect(() => changeContextOf({ name: "g", ...extra })).toThrow(message);
    },
  );

  it("records the reason and run id in the change's audit row, beside the verified actor", () => {
    const actor = auditActor({
      ...operatorCtx("operator"),
      change: { reason: "rotate the poller key", run_id: "r-1" },
    } as never);
    const event = buildAdminAuditEvent(actor, {
      action: "apikey.revoke",
      target_type: "api_key",
      target_id: "k",
      detail: { reason: "a call site cannot shadow it" },
    });
    expect(event.actor_type).toBe("api_key");
    expect(event.detail).toMatchObject({
      reason: "rotate the poller key",
      run_id: "r-1",
    });
  });
});

describe("budget classes", () => {
  // The audit actions each admin-plane mutation can write, as a reviewed pin
  // of what the scan below must find in the implementations. A mutation that
  // starts writing a new action must add it here and to the budget's class
  // table.
  const ACTIONS_BY_MUTATION: Record<string, string[]> = {
    "frontend.accessGroups.addEndpoint": ["group.endpoint.add"],
    "frontend.accessGroups.addMember": ["group.member.add"],
    "frontend.accessGroups.create": ["group.create"],
    "frontend.accessGroups.delete": ["group.delete"],
    "frontend.accessGroups.removeEndpoint": ["group.endpoint.remove"],
    "frontend.accessGroups.removeMember": ["group.member.remove"],
    "frontend.accessGroups.setEndpointRestricted": ["endpoint.restricted.set"],
    "frontend.accessGroups.update": ["group.update"],
    "frontend.apiKeys.create": ["apikey.create"],
    "frontend.apiKeys.deactivate": ["apikey.revoke"],
    "frontend.apiKeys.setGlobalIpPolicy": ["config.api_key_ip_policy.set"],
    "frontend.apiKeys.setIpPolicy": ["apikey.ip_policy.set"],
    "frontend.endpoints.create": ["endpoint.create"],
    "frontend.endpoints.update": ["endpoint.update"],
    "frontend.mcpServers.create": ["mcpserver.create"],
    "frontend.mcpServers.update": ["mcpserver.update"],
    "frontend.namespaces.create": ["namespace.create"],
    "frontend.namespaces.refreshTools": ["namespace.refresh_tools"],
    "frontend.namespaces.setToolPolicy": ["namespace.tool_policy"],
    "frontend.namespaces.update": ["namespace.update"],
    "frontend.namespaces.updateToolStatus": ["namespace.tool_status"],
  };

  // The audit actions written by procedures that are NOT operator mutations
  // but live in an implementation file that also hosts operator mutations, so
  // the scan sees them. They are a person's acts, outside the budget. An
  // action found by the scan that is in neither the budget's class table nor
  // this list fails the test, so a new action must be decided one way or the
  // other when it is added.
  const WRITTEN_BY_HUMAN_ONLY_PROCEDURES: readonly string[] = [
    "apikey.delete",
    "endpoint.delete",
    "mcpserver.bulk_import",
    "mcpserver.delete",
    "namespace.delete",
    "namespace.server_status",
    "namespace.tool_overrides",
  ];

  /**
   * Every audit action named in the implementation files that host the
   * operator mutations, read from the source: the files are derived from the
   * mutation list (router `x` is implemented in `x.impl.ts`, kebab-cased), and
   * an action is any `action: "name"` literal outside comments.
   */
  const scanImplementationActions = () => {
    const routers = [
      ...new Set(
        [...ADMIN_PLANE_OPERATOR_MUTATIONS].map((p) => p.split(".")[1]),
      ),
    ].sort();
    const found = new Map<string, string[]>();
    for (const router of routers) {
      const file = `${router.replace(/([A-Z])/g, "-$1").toLowerCase()}.impl.ts`;
      const source = readFileSync(
        path.resolve(import.meta.dirname, file),
        "utf8",
      )
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
      for (const match of source.matchAll(
        /\baction:\s*"([a-z][a-z0-9_.]*)"/g,
      )) {
        found.set(match[1], [...(found.get(match[1]) ?? []), file]);
      }
    }
    return { routers, found };
  };

  it("covers every operator mutation and gives each of its actions a class", () => {
    expect(Object.keys(ACTIONS_BY_MUTATION).sort()).toEqual(
      [...ADMIN_PLANE_OPERATOR_MUTATIONS].sort(),
    );
    for (const actions of Object.values(ACTIONS_BY_MUTATION)) {
      for (const action of actions) expect(BUDGETED_ACTIONS).toContain(action);
    }
  });

  it("finds every audit action the operator mutations' implementations write in the budget's table or the human-only list", () => {
    const { routers, found } = scanImplementationActions();
    // The scan reads what it is meant to read: each router's file yields
    // actions, so a moved or renamed file cannot make it pass by finding none.
    expect(routers).toEqual([
      "accessGroups",
      "apiKeys",
      "endpoints",
      "mcpServers",
      "namespaces",
    ]);
    expect(found.size).toBeGreaterThan(20);

    const unclassified = [...found.keys()].filter(
      (action) =>
        !BUDGETED_ACTIONS.includes(action) &&
        !WRITTEN_BY_HUMAN_ONLY_PROCEDURES.includes(action),
    );
    expect(unclassified).toEqual([]);
  });

  it("keeps the budget's table, the pin and the human-only list true to what the implementations write", () => {
    const { found } = scanImplementationActions();
    // Nothing is listed that no implementation writes (a stale entry would
    // hide a removed action), and nothing is both budgeted and exempt.
    for (const action of BUDGETED_ACTIONS) expect(found.has(action)).toBe(true);
    for (const action of WRITTEN_BY_HUMAN_ONLY_PROCEDURES) {
      expect(found.has(action)).toBe(true);
      expect(BUDGETED_ACTIONS).not.toContain(action);
    }
    for (const actions of Object.values(ACTIONS_BY_MUTATION)) {
      for (const action of actions) expect(found.has(action)).toBe(true);
    }
  });
});

describe("the audit read", () => {
  it("returns whitelisted detail keys only, reduced, and counts what it dropped", () => {
    const { detail, omitted } = projectAuditDetail({
      reason: "why",
      rule: "group_not_empty",
      bearer_token: "never",
      credential: { sha256: "x" },
      admin_plane: { key_uuid: "k", scope: "operator", nested: { deep: 1 } },
      old_value: { allowed_cidrs: ["203.0.113.0/24"], mode: "enforce" },
      name: "y".repeat(400),
    });
    expect(detail).toEqual({
      reason: "why",
      rule: "group_not_empty",
      admin_plane: { key_uuid: "k", scope: "operator" },
      old_value: { allowed_cidrs: ["203.0.113.0/24"], mode: "enforce" },
      name: "y".repeat(300),
    });
    expect(omitted).toBe(3);
  });
});
