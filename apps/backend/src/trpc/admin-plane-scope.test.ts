/**
 * An admin-plane API key may call only the procedures of its scope; a human
 * administrator's browser session keeps its whole surface.
 *
 * Two scopes (migration 0043). `sync` is what a CI credential holds: exactly
 * the 10 procedures the configuration-sync tooling calls. `operator` is those
 * 10 plus 16 more for the operator's tooling, 26 in all, and `apiKeys.create`
 * (which reaches the implementation's narrow agent-mint branch) is among the
 * operator's and never the sync set's.
 *
 * Driven through the REAL app router from @repo/trpc (createAppRouter) and its
 * real procedure builders and middleware, with stub implementations: what is
 * under test is which procedures a context may reach, not what they do. A
 * procedure "reached" its implementation when the stub ran; a refused one
 * throws FORBIDDEN before the stub can run. The Postgres-backed version, with
 * the real bearer resolver, createContext and implementations, is
 * ./admin-plane-scope.integration.test.ts.
 */

import type { AddressInfo } from "node:net";

import {
  ADMIN_PLANE_FORBIDDEN_MESSAGE,
  ADMIN_PLANE_OPERATOR_PROCEDURES,
  ADMIN_PLANE_SYNC_PROCEDURES,
  auditActor,
  createAppRouter,
  setTrpcAuditSink,
  type TrpcDenialEvent,
} from "@repo/trpc";
import * as trpcExpress from "@trpc/server/adapters/express";
import express from "express";
import { afterAll, afterEach, beforeEach, describe, expect, it } from "vitest";

const KEY_UUID = "6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b";
const OWNER_ID = "owner-admin-1";
const UUID_A = "11111111-1111-4111-8111-111111111111";
const UUID_B = "22222222-2222-4222-8222-222222222222";
const UUID_C = "33333333-3333-4333-8333-333333333333";

// The two lists, written out here rather than read from the constants, so this
// test fails if either constant changes. Oracle: the plan's decision 2 and the
// sync tooling's pinned copy (Umbrella-MCP-Server
// metamcp/sync/tests/test_admin_plane_procedures.py).
const EXPECTED_SYNC = [
  "frontend.config.getMcpMaxTotalTimeout",
  "frontend.config.getMcpTimeout",
  "frontend.endpoints.list",
  "frontend.mcpServers.create",
  "frontend.mcpServers.list",
  "frontend.mcpServers.update",
  "frontend.namespaces.get",
  "frontend.namespaces.getTools",
  "frontend.namespaces.list",
  "frontend.tools.getByMcpServerUuid",
];

const EXPECTED_OPERATOR_EXTRA = [
  "frontend.accessGroups.get",
  "frontend.accessGroups.list",
  "frontend.apiKeys.create",
  "frontend.apiKeys.deactivate",
  "frontend.apiKeys.getGlobalIpPolicy",
  "frontend.apiKeys.listAll",
  "frontend.apiKeys.setGlobalIpPolicy",
  "frontend.apiKeys.setIpPolicy",
  "frontend.endpoints.create",
  "frontend.endpoints.update",
  "frontend.namespaces.create",
  "frontend.namespaces.refreshTools",
  "frontend.namespaces.update",
  "frontend.namespaces.updateToolStatus",
  "frontend.oauthClients.list",
  "frontend.users.list",
];

const EXPECTED_OPERATOR = [...EXPECTED_SYNC, ...EXPECTED_OPERATOR_EXTRA];

// A valid input for each procedure either scope may call, shaped like what the
// tooling sends, so input validation passes and the scope check is what
// decides.
const VALID_INPUTS: Record<string, unknown> = {
  "frontend.accessGroups.get": { uuid: UUID_A },
  "frontend.accessGroups.list": undefined,
  "frontend.apiKeys.create": {
    name: "agent minted",
    user_id: "member-user-1",
    endpoint_uuid: UUID_A,
    ip_policy: { mode: "enforce", allowed_cidrs: ["203.0.113.0/24"] },
  },
  "frontend.apiKeys.deactivate": { uuid: UUID_B },
  "frontend.apiKeys.getGlobalIpPolicy": undefined,
  "frontend.apiKeys.listAll": undefined,
  "frontend.apiKeys.setGlobalIpPolicy": {
    mode: "enforce",
    allowed_cidrs: ["203.0.113.0/24"],
  },
  "frontend.apiKeys.setIpPolicy": {
    uuid: UUID_A,
    allowed_cidrs: ["198.51.100.7/32"],
    ip_policy_mode: "enforce",
  },
  "frontend.config.getMcpMaxTotalTimeout": undefined,
  "frontend.config.getMcpTimeout": undefined,
  "frontend.endpoints.create": {
    name: "sync-endpoint",
    namespaceUuid: UUID_A,
    enableClientMaxRate: false,
    enableMaxRate: false,
  },
  "frontend.endpoints.list": undefined,
  "frontend.endpoints.update": {
    uuid: UUID_B,
    name: "sync-endpoint",
    namespaceUuid: UUID_A,
    enableClientMaxRate: false,
    enableMaxRate: false,
  },
  "frontend.mcpServers.create": {
    name: "sync-server",
    type: "STREAMABLE_HTTP",
    url: "http://backend.internal:8000/mcp",
  },
  "frontend.mcpServers.list": undefined,
  "frontend.mcpServers.update": {
    uuid: UUID_C,
    name: "sync-server",
    type: "STREAMABLE_HTTP",
    url: "http://backend.internal:8000/mcp",
  },
  "frontend.namespaces.create": { name: "sync-namespace" },
  "frontend.namespaces.get": { uuid: UUID_A },
  "frontend.namespaces.getTools": { namespaceUuid: UUID_A },
  "frontend.namespaces.list": undefined,
  "frontend.namespaces.refreshTools": {
    namespaceUuid: UUID_A,
    tools: [{ name: "sync-server__ping", inputSchema: { type: "object" } }],
  },
  "frontend.namespaces.update": { uuid: UUID_A, name: "sync-namespace" },
  "frontend.namespaces.updateToolStatus": {
    namespaceUuid: UUID_A,
    toolUuid: UUID_B,
    serverUuid: UUID_C,
    status: "ACTIVE",
  },
  "frontend.oauthClients.list": undefined,
  "frontend.tools.getByMcpServerUuid": { mcpServerUuid: UUID_C },
  "frontend.users.list": undefined,
};

const owner = { id: OWNER_ID, role: "admin", email: "owner@example.test" };

/**
 * An admin-plane request as createContext builds it, for a given scope. The
 * scope is `unknown` on purpose: the point of several cases is that a value
 * outside the type (null, a number, an object) still fails closed to `sync`.
 */
const adminPlaneCtxFor = (scope?: unknown) => ({
  user: owner,
  session: { id: "synthetic-session" },
  authOrigin: {
    kind: "admin_plane" as const,
    key_uuid: KEY_UUID,
    owner_user_id: OWNER_ID,
    ...(scope === undefined ? {} : { scope: scope as "sync" | "operator" }),
  },
  audit: { actor_ip: "203.0.113.5", actor_user_agent: "ci", request_id: "r1" },
});
const syncCtx = adminPlaneCtxFor("sync");
const operatorCtx = adminPlaneCtxFor("operator");
const humanAdminCtx = {
  user: owner,
  session: { id: "browser-session" },
};

// Every implementation method on every router is a stub that records that it
// ran. Implementations are reached lazily inside each procedure, so a Proxy
// covers methods this file never names. `apiKeys.create` also keeps its
// arguments, to show which actor bundle the router hands the implementation.
let reached = 0;
let createCalls: unknown[][] = [];
function stubRouter(name?: string) {
  return new Proxy(
    {},
    {
      get: (_target, prop) =>
        typeof prop === "string"
          ? async (...args: unknown[]) => {
              reached += 1;
              if (name === "apiKeys" && prop === "create") {
                createCalls.push(args);
              }
              return {};
            }
          : undefined,
    },
  );
}

const appRouter = createAppRouter({
  frontend: {
    mcpServers: stubRouter(),
    namespaces: stubRouter(),
    endpoints: stubRouter(),
    oauth: stubRouter(),
    oauthClients: stubRouter(),
    oauthTokens: stubRouter(),
    users: stubRouter(),
    tools: stubRouter(),
    apiKeys: stubRouter("apiKeys"),
    config: stubRouter(),
    logs: stubRouter(),
    accessGroups: stubRouter(),
  } as unknown as Parameters<typeof createAppRouter>[0]["frontend"],
});

/** Every procedure path in the app router, from tRPC's own registry. */
const ALL_PROCEDURES = Object.keys(
  (appRouter as unknown as { _def: { procedures: Record<string, unknown> } })
    ._def.procedures,
).sort();

type CallResult = {
  reached: boolean;
  error: { code?: string; message?: string } | null;
};

async function call(
  ctx: object,
  path: string,
  input: unknown,
): Promise<CallResult> {
  const caller = appRouter.createCaller(ctx as never) as unknown as Record<
    string,
    unknown
  >;
  const fn = path
    .split(".")
    .reduce<unknown>(
      (node, key) => (node as Record<string, unknown>)[key],
      caller,
    ) as (input: unknown) => Promise<unknown>;
  const before = reached;
  try {
    await fn(input);
    return { reached: reached > before, error: null };
  } catch (error) {
    return {
      reached: reached > before,
      error: error as { code?: string; message?: string },
    };
  }
}

let denials: TrpcDenialEvent[] = [];
beforeEach(() => {
  denials = [];
  createCalls = [];
  setTrpcAuditSink((event) => {
    denials.push(event);
  });
});
afterEach(() => {
  setTrpcAuditSink(null);
});

describe("the two procedure sets", () => {
  it("pins the sync set to exactly the 10 procedures the sync tooling calls", () => {
    expect([...ADMIN_PLANE_SYNC_PROCEDURES].sort()).toEqual(
      [...EXPECTED_SYNC].sort(),
    );
    expect(ADMIN_PLANE_SYNC_PROCEDURES.size).toBe(10);
  });

  it("pins the operator set to exactly those 10 plus 16 more, 26 in all", () => {
    expect([...ADMIN_PLANE_OPERATOR_PROCEDURES].sort()).toEqual(
      [...EXPECTED_OPERATOR].sort(),
    );
    expect(ADMIN_PLANE_OPERATOR_PROCEDURES.size).toBe(26);
  });

  it("holds every sync procedure inside the operator set", () => {
    for (const name of ADMIN_PLANE_SYNC_PROCEDURES) {
      expect(ADMIN_PLANE_OPERATOR_PROCEDURES.has(name)).toBe(true);
    }
  });

  it("puts apiKeys.create in the operator set and never in the sync set", () => {
    expect(ADMIN_PLANE_OPERATOR_PROCEDURES.has("frontend.apiKeys.create")).toBe(
      true,
    );
    expect(ADMIN_PLANE_SYNC_PROCEDURES.has("frontend.apiKeys.create")).toBe(
      false,
    );
  });

  it("names only procedures that exist in the app router, with the frontend. prefix", () => {
    expect(ALL_PROCEDURES.length).toBeGreaterThan(EXPECTED_OPERATOR.length);
    for (const name of ADMIN_PLANE_OPERATOR_PROCEDURES) {
      expect(ALL_PROCEDURES).toContain(name);
    }
  });
});

// Never reachable by either scope. Named so a change that lets one in has to
// change this list: key lifecycle writes other than create and deactivate,
// every user change, every access-group write, every OAuth client decision, and
// every config setter.
const NEVER_REACHABLE = [
  "frontend.apiKeys.update",
  "frontend.apiKeys.delete",
  "frontend.apiKeys.list",
  "frontend.apiKeys.validate",
  "frontend.users.setDisabled",
  "frontend.users.revokeAccess",
  "frontend.users.delete",
  "frontend.users.previewDelete",
  "frontend.accessGroups.create",
  "frontend.accessGroups.update",
  "frontend.accessGroups.delete",
  "frontend.accessGroups.addMember",
  "frontend.accessGroups.removeMember",
  "frontend.accessGroups.addEndpoint",
  "frontend.accessGroups.removeEndpoint",
  "frontend.accessGroups.setEndpointRestricted",
  "frontend.oauthClients.approve",
  "frontend.oauthClients.reject",
  "frontend.oauthClients.create",
  "frontend.oauthClients.delete",
  "frontend.config.setSignupDisabled",
  "frontend.config.getSignupDisabled",
  "frontend.mcpServers.delete",
  "frontend.namespaces.delete",
  "frontend.endpoints.delete",
];

describe("a sync-scope admin-plane key", () => {
  it.each(EXPECTED_SYNC)("reaches %s with a valid input", async (path) => {
    const result = await call(syncCtx, path, VALID_INPUTS[path]);

    expect(result.reached).toBe(true);
    // A stub's empty result may fail an output schema; that is not a refusal.
    expect(result.error?.code).not.toBe("FORBIDDEN");
    expect(result.error?.code).not.toBe("UNAUTHORIZED");
    expect(denials).toEqual([]);
  });

  it("is refused every other procedure in the router, before its implementation runs", async () => {
    const denied = ALL_PROCEDURES.filter(
      (path) => !ADMIN_PLANE_SYNC_PROCEDURES.has(path),
    );
    expect(denied).toEqual(expect.arrayContaining(NEVER_REACHABLE));
    // The operator-only procedures too: this is what a CI key loses.
    expect(denied).toEqual(expect.arrayContaining(EXPECTED_OPERATOR_EXTRA));
    for (const path of denied) {
      const result = await call(syncCtx, path, undefined);
      expect({ path, reached: result.reached }).toEqual({
        path,
        reached: false,
      });
      expect({ path, code: result.error?.code }).toEqual({
        path,
        code: "FORBIDDEN",
      });
      expect(result.error?.message).toBe(ADMIN_PLANE_FORBIDDEN_MESSAGE);
    }
  });

  it("cannot create a key of any kind, and the refusal is the standing sentence", async () => {
    for (const input of [
      VALID_INPUTS["frontend.apiKeys.create"],
      { name: "second key", admin_plane: true },
      {
        name: "acts as someone",
        user_id: "another-user",
        acts_as_user_id: "another-user",
        endpoint_uuid: UUID_A,
      },
    ]) {
      const result = await call(syncCtx, "frontend.apiKeys.create", input);

      expect(result.reached).toBe(false);
      expect(result.error?.code).toBe("FORBIDDEN");
      expect(result.error?.message).toBe(ADMIN_PLANE_FORBIDDEN_MESSAGE);
    }
  });

  it("records the refusal with the key as the actor, the owner and the sync scope beside it", async () => {
    await call(syncCtx, "frontend.apiKeys.listAll", undefined);

    expect(denials).toEqual([
      {
        action: "rbac.denied",
        actor_type: "api_key",
        actor_id: KEY_UUID,
        actor_label: "owner@example.test",
        path: "frontend.apiKeys.listAll",
        type: "query",
        http_status: 403,
        audit: syncCtx.audit,
        admin_plane: {
          key_uuid: KEY_UUID,
          owner_user_id: OWNER_ID,
          scope: "sync",
        },
      },
    ]);
  });
});

describe("an operator-scope admin-plane key", () => {
  it.each(EXPECTED_OPERATOR)("reaches %s with a valid input", async (path) => {
    const result = await call(operatorCtx, path, VALID_INPUTS[path]);

    expect(result.reached).toBe(true);
    expect(result.error?.code).not.toBe("FORBIDDEN");
    expect(result.error?.code).not.toBe("UNAUTHORIZED");
    expect(denials).toEqual([]);
  });

  it("is refused every other procedure in the router, before its implementation runs", async () => {
    const denied = ALL_PROCEDURES.filter(
      (path) => !ADMIN_PLANE_OPERATOR_PROCEDURES.has(path),
    );
    // Includes the public procedures and every admin mutation.
    expect(denied).toEqual(expect.arrayContaining(NEVER_REACHABLE));
    for (const path of denied) {
      const result = await call(operatorCtx, path, undefined);
      expect({ path, reached: result.reached }).toEqual({
        path,
        reached: false,
      });
      expect({ path, code: result.error?.code }).toEqual({
        path,
        code: "FORBIDDEN",
      });
      expect(result.error?.message).toBe(ADMIN_PLANE_FORBIDDEN_MESSAGE);
    }
  });

  it("records a refusal with the operator scope", async () => {
    await call(operatorCtx, "frontend.users.setDisabled", undefined);

    expect(denials).toEqual([
      expect.objectContaining({
        path: "frontend.users.setDisabled",
        admin_plane: {
          key_uuid: KEY_UUID,
          owner_user_id: OWNER_ID,
          scope: "operator",
        },
      }),
    ]);
  });

  it("hands apiKeys.create the actor bundle with the verified key, owner and scope", async () => {
    await call(
      operatorCtx,
      "frontend.apiKeys.create",
      VALID_INPUTS["frontend.apiKeys.create"],
    );

    expect(createCalls).toHaveLength(1);
    const [input, userId, isAdmin, actor] = createCalls[0] as [
      Record<string, unknown>,
      string,
      boolean,
      ReturnType<typeof auditActor>,
    ];
    expect(input).toMatchObject({
      name: "agent minted",
      user_id: "member-user-1",
    });
    expect(userId).toBe(OWNER_ID);
    expect(isAdmin).toBe(true);
    expect(actor.admin_plane).toEqual({
      key_uuid: KEY_UUID,
      owner_user_id: OWNER_ID,
      scope: "operator",
    });
  });

  it("keeps the admin-plane provenance on the actor when attribution degrades, so create never reads it as a human session", async () => {
    // A session user whose `email` getter throws makes auditActor take its
    // never-throws fallback (the router itself only reads `id` and `role`). The
    // actor must still say the request came from an admin-plane key: an actor
    // without that is what the human branch of apiKeys.create (which can
    // create ANY key) treats as an administrator at a browser.
    const hostile = {
      ...operatorCtx,
      user: {
        id: OWNER_ID,
        role: "admin",
        get email(): never {
          throw new Error("hostile getter");
        },
      },
    };

    const actor = auditActor(hostile as never);

    expect(actor.admin_plane).toEqual({
      key_uuid: KEY_UUID,
      owner_user_id: OWNER_ID,
      scope: "operator",
    });
    expect(actor.actor_id).toBeNull();

    const result = await call(
      hostile,
      "frontend.apiKeys.create",
      VALID_INPUTS["frontend.apiKeys.create"],
    );
    expect(result.reached).toBe(true);
    expect(createCalls).toHaveLength(1);
    expect(
      (createCalls[0][3] as ReturnType<typeof auditActor>).admin_plane?.scope,
    ).toBe("operator");
  });

  it("carries the key and its scope into the audit actor of an allowed mutation", () => {
    expect(auditActor(operatorCtx)).toEqual({
      actor_id: OWNER_ID,
      actor_label: "owner@example.test",
      actor_ip: "203.0.113.5",
      actor_user_agent: "ci",
      request_id: "r1",
      admin_plane: {
        key_uuid: KEY_UUID,
        owner_user_id: OWNER_ID,
        scope: "operator",
      },
    });
  });

  it("attributes a role refusal on an allowed procedure to the key after its owner is demoted", async () => {
    const result = await call(
      { ...operatorCtx, user: { ...owner, role: "member" } },
      "frontend.apiKeys.deactivate",
      VALID_INPUTS["frontend.apiKeys.deactivate"],
    );

    expect(result.reached).toBe(false);
    expect(result.error?.code).toBe("FORBIDDEN");
    expect(denials).toEqual([
      expect.objectContaining({
        action: "rbac.denied",
        actor_type: "api_key",
        actor_id: KEY_UUID,
        admin_plane: {
          key_uuid: KEY_UUID,
          owner_user_id: OWNER_ID,
          scope: "operator",
        },
      }),
    ]);
  });
});

describe("a missing or unknown scope is the sync scope", () => {
  it.each([
    ["missing", undefined],
    ["null", null],
    ["empty", ""],
    ["capitalised", "Operator"],
    ["padded", " operator"],
    ["a superset word", "admin"],
    ["an object", { toString: () => "operator" }],
    ["a number", 1],
  ])("a scope that is %s reaches only the sync set", async (_label, scope) => {
    const ctx = adminPlaneCtxFor(scope);

    for (const path of EXPECTED_OPERATOR_EXTRA) {
      const result = await call(ctx, path, VALID_INPUTS[path]);
      expect({ path, reached: result.reached }).toEqual({
        path,
        reached: false,
      });
      expect({ path, code: result.error?.code }).toEqual({
        path,
        code: "FORBIDDEN",
      });
    }
    for (const path of EXPECTED_SYNC) {
      const result = await call(ctx, path, VALID_INPUTS[path]);
      expect({ path, reached: result.reached }).toEqual({
        path,
        reached: true,
      });
    }
    // The refusal names the scope it applied.
    expect(denials[0]?.admin_plane?.scope).toBe("sync");
  });

  it("carries the sync scope into the audit actor", () => {
    expect(auditActor(adminPlaneCtxFor("Operator")).admin_plane?.scope).toBe(
      "sync",
    );
    expect(auditActor(adminPlaneCtxFor(undefined)).admin_plane?.scope).toBe(
      "sync",
    );
  });
});

describe("a human administrator's session is unchanged", () => {
  it.each([
    [
      "frontend.apiKeys.create",
      { name: "human minted key", endpoint_uuid: UUID_A },
    ],
    ["frontend.apiKeys.deactivate", { uuid: UUID_B }],
    ["frontend.users.list", undefined],
    ["frontend.accessGroups.list", undefined],
    ["frontend.config.setSignupDisabled", { disabled: true }],
    ["frontend.oauthClients.list", undefined],
    ["frontend.mcpServers.list", undefined],
  ])("reaches %s", async (path, input) => {
    const result = await call(humanAdminCtx, path, input);

    expect(result.reached).toBe(true);
    expect(result.error?.code).not.toBe("FORBIDDEN");
    expect(denials).toEqual([]);
  });

  it("keeps the actor shape it had, with no admin-plane field", () => {
    expect(auditActor(humanAdminCtx)).toEqual({
      actor_id: OWNER_ID,
      actor_label: "owner@example.test",
      actor_ip: null,
      actor_user_agent: null,
      request_id: null,
    });
  });
});

describe("an anonymous caller is unchanged", () => {
  it("still reads the public login-page settings", async () => {
    for (const path of [
      "frontend.config.getSignupDisabled",
      "frontend.config.getAuthProviders",
    ]) {
      const result = await call({}, path, undefined);
      expect({ path, reached: result.reached }).toEqual({
        path,
        reached: true,
      });
      expect(result.error?.code).not.toBe("FORBIDDEN");
    }
  });

  it("still gets UNAUTHORIZED, not the admin-plane refusal, on a protected procedure", async () => {
    const result = await call({}, "frontend.users.list", undefined);
    expect(result.error?.code).toBe("UNAUTHORIZED");
  });
});

describe("a tRPC batch shares one context but is checked per procedure", () => {
  let server: import("node:http").Server;
  let base: string;

  async function start(ctx: object) {
    const app = express();
    app.use(
      "/trpc",
      trpcExpress.createExpressMiddleware({
        router: appRouter,
        createContext: () => ctx as never,
      }),
    );
    await new Promise<void>((resolve) => {
      server = app.listen(0, "127.0.0.1", resolve);
    });
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }

  afterAll(async () => {
    await new Promise((resolve) => server?.close(resolve));
  });

  it("answers the allowed call and refuses the denied one in the same request, for a sync key", async () => {
    await start(syncCtx);
    const paths = ["frontend.mcpServers.list", "frontend.users.list"];
    const input = encodeURIComponent(JSON.stringify({}));
    const res = await fetch(
      `${base}/trpc/${paths.join(",")}?batch=1&input=${input}`,
    );
    const body = (await res.json()) as Array<{
      result?: unknown;
      error?: { json?: { data?: { code?: string } }; data?: { code?: string } };
    }>;

    expect(body).toHaveLength(2);
    const codeOf = (entry: (typeof body)[number] | undefined) =>
      entry?.error?.data?.code ?? entry?.error?.json?.data?.code;
    const [allowed, refused] = body;
    expect(allowed).toBeDefined();
    expect(codeOf(allowed)).not.toBe("FORBIDDEN");
    expect(codeOf(refused)).toBe("FORBIDDEN");
    expect(denials.map((d) => d.path)).toEqual(["frontend.users.list"]);
  });

  it("applies each scope per procedure within one batch: an operator reads users, a sync key does not", async () => {
    const paths = [
      "frontend.users.list",
      "frontend.mcpServers.list",
      "frontend.apiKeys.listAll",
    ];
    const input = encodeURIComponent(JSON.stringify({}));
    const codeOf = (entry: {
      error?: { json?: { data?: { code?: string } }; data?: { code?: string } };
    }) => entry?.error?.data?.code ?? entry?.error?.json?.data?.code;
    type Entry = Parameters<typeof codeOf>[0] & { result?: unknown };
    // The stubs return {}, which an output schema may reject as a 500; only
    // FORBIDDEN is a refusal by the scope check.
    const verdict = (entry: Entry) =>
      codeOf(entry) === "FORBIDDEN" ? "FORBIDDEN" : "reached";

    await new Promise((resolve) => server?.close(resolve));
    await start(operatorCtx);
    const operatorBody = (await (
      await fetch(`${base}/trpc/${paths.join(",")}?batch=1&input=${input}`)
    ).json()) as Entry[];
    expect(operatorBody.map(verdict)).toEqual([
      "reached",
      "reached",
      "reached",
    ]);

    await new Promise((resolve) => server?.close(resolve));
    denials = [];
    await start(syncCtx);
    const syncBody = (await (
      await fetch(`${base}/trpc/${paths.join(",")}?batch=1&input=${input}`)
    ).json()) as Entry[];
    expect(syncBody.map(verdict)).toEqual([
      "FORBIDDEN",
      "reached",
      "FORBIDDEN",
    ]);
    expect(denials.map((d) => d.path)).toEqual([
      "frontend.users.list",
      "frontend.apiKeys.listAll",
    ]);
  });
});
