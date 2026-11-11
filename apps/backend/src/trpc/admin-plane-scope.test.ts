/**
 * An admin-plane (CI) API key may call only the configuration-sync
 * procedures; a human administrator's browser session keeps its whole
 * surface.
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
  ADMIN_PLANE_ALLOWED_PROCEDURES,
  ADMIN_PLANE_FORBIDDEN_MESSAGE,
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

// The configuration-sync tooling's calls, written out here rather than read
// from the constant, so this test fails if the constant changes.
const EXPECTED_ALLOWLIST = [
  "frontend.apiKeys.getGlobalIpPolicy",
  "frontend.apiKeys.listAll",
  "frontend.apiKeys.setGlobalIpPolicy",
  "frontend.apiKeys.setIpPolicy",
  "frontend.config.getMcpMaxTotalTimeout",
  "frontend.config.getMcpTimeout",
  "frontend.endpoints.create",
  "frontend.endpoints.list",
  "frontend.endpoints.update",
  "frontend.mcpServers.create",
  "frontend.mcpServers.list",
  "frontend.mcpServers.update",
  "frontend.namespaces.create",
  "frontend.namespaces.get",
  "frontend.namespaces.getTools",
  "frontend.namespaces.list",
  "frontend.namespaces.refreshTools",
  "frontend.namespaces.update",
  "frontend.namespaces.updateToolStatus",
  "frontend.tools.getByMcpServerUuid",
];

// A valid input for each allowlisted procedure, shaped like what the sync
// tooling sends, so input validation passes and the scope check is what
// decides.
const VALID_INPUTS: Record<string, unknown> = {
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
  "frontend.tools.getByMcpServerUuid": { mcpServerUuid: UUID_C },
};

const owner = { id: OWNER_ID, role: "admin", email: "owner@example.test" };

const adminPlaneCtx = {
  user: owner,
  session: { id: "synthetic-session" },
  authOrigin: {
    kind: "admin_plane" as const,
    key_uuid: KEY_UUID,
    owner_user_id: OWNER_ID,
  },
  audit: { actor_ip: "203.0.113.5", actor_user_agent: "ci", request_id: "r1" },
};
const humanAdminCtx = {
  user: owner,
  session: { id: "browser-session" },
};

// Every implementation method on every router is a stub that records that it
// ran. Implementations are reached lazily inside each procedure, so a Proxy
// covers methods this file never names.
let reached = 0;
function stubRouter() {
  return new Proxy(
    {},
    {
      get: (_target, prop) =>
        typeof prop === "string"
          ? async () => {
              reached += 1;
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
    apiKeys: stubRouter(),
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
  setTrpcAuditSink((event) => {
    denials.push(event);
  });
});
afterEach(() => {
  setTrpcAuditSink(null);
});

describe("the admin-plane allowlist", () => {
  it("is exactly the configuration-sync tooling's procedures", () => {
    expect([...ADMIN_PLANE_ALLOWED_PROCEDURES].sort()).toEqual(
      [...EXPECTED_ALLOWLIST].sort(),
    );
  });

  it("names only procedures that exist in the app router, with the frontend. prefix", () => {
    expect(ALL_PROCEDURES.length).toBeGreaterThan(EXPECTED_ALLOWLIST.length);
    for (const name of ADMIN_PLANE_ALLOWED_PROCEDURES) {
      expect(ALL_PROCEDURES).toContain(name);
    }
  });
});

describe("an admin-plane key", () => {
  it.each(EXPECTED_ALLOWLIST)("reaches %s with a valid input", async (path) => {
    const result = await call(adminPlaneCtx, path, VALID_INPUTS[path]);

    expect(result.reached).toBe(true);
    // A stub's empty result may fail an output schema; that is not a refusal.
    expect(result.error?.code).not.toBe("FORBIDDEN");
    expect(result.error?.code).not.toBe("UNAUTHORIZED");
    expect(denials).toEqual([]);
  });

  it("is refused every other procedure in the router, before its implementation runs", async () => {
    const denied = ALL_PROCEDURES.filter(
      (path) => !ADMIN_PLANE_ALLOWED_PROCEDURES.has(path),
    );
    // Includes the public procedures and every admin mutation.
    expect(denied).toEqual(
      expect.arrayContaining([
        "frontend.apiKeys.create",
        "frontend.apiKeys.update",
        "frontend.apiKeys.delete",
        "frontend.users.list",
        "frontend.users.setDisabled",
        "frontend.config.setSignupDisabled",
        "frontend.config.getSignupDisabled",
        "frontend.oauthClients.list",
        // Deciding which self-registered clients people may authorize, and
        // minting an already approved client, stay with administrators'
        // own sessions (migration 0042).
        "frontend.oauthClients.approve",
        "frontend.oauthClients.reject",
        "frontend.oauthClients.create",
      ]),
    );
    for (const path of denied) {
      const result = await call(adminPlaneCtx, path, undefined);
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

  it.each([
    [
      "an acts-as key for another user",
      {
        name: "acts as someone",
        user_id: "another-user",
        acts_as_user_id: "another-user",
        endpoint_uuid: UUID_A,
      },
    ],
    ["another admin-plane key", { name: "second key", admin_plane: true }],
  ])("cannot mint %s", async (_label, input) => {
    const result = await call(adminPlaneCtx, "frontend.apiKeys.create", input);

    expect(result.reached).toBe(false);
    expect(result.error?.code).toBe("FORBIDDEN");
  });

  it("records each refusal with the key as the actor and the owner beside it", async () => {
    await call(adminPlaneCtx, "frontend.users.list", undefined);

    expect(denials).toEqual([
      {
        action: "rbac.denied",
        actor_type: "api_key",
        actor_id: KEY_UUID,
        actor_label: "owner@example.test",
        path: "frontend.users.list",
        type: "query",
        http_status: 403,
        audit: adminPlaneCtx.audit,
        admin_plane: { key_uuid: KEY_UUID, owner_user_id: OWNER_ID },
      },
    ]);
  });

  it("carries the key into the audit actor of an allowed mutation", () => {
    expect(auditActor(adminPlaneCtx)).toEqual({
      actor_id: OWNER_ID,
      actor_label: "owner@example.test",
      actor_ip: "203.0.113.5",
      actor_user_agent: "ci",
      request_id: "r1",
      admin_plane: { key_uuid: KEY_UUID, owner_user_id: OWNER_ID },
    });
  });

  it("attributes a role refusal on an allowed procedure to the key after its owner is demoted", async () => {
    const result = await call(
      { ...adminPlaneCtx, user: { ...owner, role: "member" } },
      "frontend.mcpServers.create",
      VALID_INPUTS["frontend.mcpServers.create"],
    );

    expect(result.reached).toBe(false);
    expect(result.error?.code).toBe("FORBIDDEN");
    expect(denials).toEqual([
      expect.objectContaining({
        action: "rbac.denied",
        actor_type: "api_key",
        actor_id: KEY_UUID,
        admin_plane: { key_uuid: KEY_UUID, owner_user_id: OWNER_ID },
      }),
    ]);
  });
});

describe("a human administrator's session is unchanged", () => {
  it.each([
    [
      "frontend.apiKeys.create",
      { name: "human minted key", endpoint_uuid: UUID_A },
    ],
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

  it("answers the allowed call and refuses the denied one in the same request", async () => {
    await start(adminPlaneCtx);
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
});
