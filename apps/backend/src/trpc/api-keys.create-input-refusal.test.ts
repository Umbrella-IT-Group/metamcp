/**
 * What an admin-plane key sees when its `apiKeys.create` request is refused by
 * the input schema, through the REAL app router, procedure builders, schema and
 * router middleware, with the repository doubled.
 *
 * Before this the schema's own message reached the caller: a multi-line JSON
 * dump of zod issues, where every other refusal of the procedure is one fixed
 * sentence a client can match. Now an admin-plane request the schema refuses is
 * answered with the sentence and code the implementation gives the same
 * request, and one denied row; a browser session keeps the schema's messages
 * (the admin UI reads them), and a refusal the implementation itself throws
 * keeps its own sentence rather than being replaced.
 */

import { createAppRouter } from "@repo/trpc";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { repoMock, loggerMock, emitMock } = vi.hoisted(() => ({
  repoMock: {
    create: vi.fn(),
    mintDataPlaneKey: vi.fn(),
    deactivate: vi.fn(),
  },
  loggerMock: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  emitMock: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));
vi.mock("../db/repositories", () => ({
  ApiKeysRepository: class {
    create = repoMock.create;
    mintDataPlaneKey = repoMock.mintDataPlaneKey;
    deactivate = repoMock.deactivate;
  },
  endpointsRepository: { findByUuid: vi.fn() },
  usersRepository: {
    findById: vi.fn(),
    findRoleById: vi.fn(),
    isDisabled: vi.fn(),
  },
}));
vi.mock("../lib/config.service", () => ({
  configService: { getApiKeyIpPolicy: vi.fn(), setApiKeyIpPolicy: vi.fn() },
}));
vi.mock("../lib/audit/admin-event", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/audit/admin-event")>()),
  emitAdminEvent: emitMock,
}));
vi.mock("../db/index", () => ({
  db: {
    transaction: async (callback: (tx: object) => Promise<unknown>) =>
      callback({}),
  },
}));
vi.mock("../db/repositories/audit-log-tx", () => ({
  recordAuditInTransaction: vi.fn(async () => undefined),
}));

const { apiKeysImplementations } = await import("./api-keys.impl");
const { ApiKeyMintRefusal, MINT_REFUSALS } = await import(
  "../lib/api-key-mint-rules"
);
const { ADMIN_PLANE_FORBIDDEN_MESSAGE } = await import("@repo/trpc");

const KEY_UUID = "6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b";
const ENDPOINT_UUID = "11111111-1111-4111-8111-111111111111";
const OWNER = { id: "owner-admin-1", role: "admin", email: "o@example.test" };

const stubRouter = () =>
  new Proxy(
    {},
    { get: (_t, prop) => (typeof prop === "string" ? vi.fn() : undefined) },
  );

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
    apiKeys: apiKeysImplementations,
    config: stubRouter(),
    logs: stubRouter(),
    accessGroups: stubRouter(),
  } as unknown as Parameters<typeof createAppRouter>[0]["frontend"],
});

const adminPlaneCtx = (scope: "sync" | "operator") => ({
  user: OWNER,
  session: { id: "synthetic-session" },
  authOrigin: {
    kind: "admin_plane" as const,
    key_uuid: KEY_UUID,
    owner_user_id: OWNER.id,
    scope,
  },
  audit: { actor_ip: "203.0.113.5", actor_user_agent: "t", request_id: "r1" },
});
const browserCtx = { user: OWNER, session: { id: "browser-session" } };

const create = (ctx: object, input: unknown) =>
  (
    appRouter.createCaller(ctx as never) as unknown as {
      frontend: {
        apiKeys: { create: (input: unknown) => Promise<unknown> };
      };
    }
  ).frontend.apiKeys
    .create(input)
    .then(
      () => null,
      (error: { code?: string; message?: string }) => error,
    );

const mintInput = (over: Record<string, unknown> = {}) => ({
  name: "metrics poller",
  user_id: "owner-user-1",
  endpoint_uuid: ENDPOINT_UUID,
  ip_policy: { mode: "enforce", allowed_cidrs: ["203.0.113.0/24"] },
  ...over,
});

beforeEach(() => {
  vi.clearAllMocks();
});

describe("a request the schema refuses, from an operator-scope admin-plane key", () => {
  // The schema refuses each of these before the implementation runs. What the
  // caller must get is the rule's own sentence and code, as for a request that
  // got past the schema.
  const cases: Array<[string, Record<string, unknown>, string]> = [
    [
      "admin_plane with an endpoint",
      { admin_plane: true },
      "admin_plane_field",
    ],
    [
      "a scope without admin_plane",
      { admin_plane_scope: "sync" },
      "admin_plane_field",
    ],
    [
      "admin_plane of the wrong type",
      { admin_plane: "yes" },
      "admin_plane_field",
    ],
    ["acts-as null", { acts_as_user_id: null }, "acts_as_field"],
    ["acts-as empty", { acts_as_user_id: "" }, "acts_as_field"],
    ["no endpoint choice", { endpoint_uuid: undefined }, "scope_choice"],
    ["both endpoint choices", { all_endpoints: true }, "scope_choice"],
    [
      "an endpoint that is not a uuid",
      { endpoint_uuid: "not-a-uuid" },
      "scope_choice",
    ],
    ["a bad name", { name: "bad/name" }, "name_invalid"],
    ["an empty name", { name: "" }, "name_invalid"],
    ["a null owner", { user_id: null }, "owner_required"],
    [
      "mode off",
      { ip_policy: { mode: "off", allowed_cidrs: ["203.0.113.0/24"] } },
      "ip_policy_shape",
    ],
    [
      "mode audit",
      { ip_policy: { mode: "audit", allowed_cidrs: ["203.0.113.0/24"] } },
      "ip_policy_shape",
    ],
    [
      "a mode in the wrong case",
      { ip_policy: { mode: "ENFORCE", allowed_cidrs: ["203.0.113.0/24"] } },
      "ip_policy_shape",
    ],
    [
      "an empty list",
      { ip_policy: { mode: "enforce", allowed_cidrs: [] } },
      "ip_policy_shape",
    ],
    [
      "nine entries",
      {
        ip_policy: {
          mode: "enforce",
          allowed_cidrs: Array.from({ length: 9 }, (_v, i) => `203.0.113.${i}`),
        },
      },
      "ip_policy_shape",
    ],
  ];

  it.each(cases)(
    "answers %s with the rule's fixed sentence, never the schema's issue list",
    async (_label, over, rule) => {
      const failure = await create(adminPlaneCtx("operator"), mintInput(over));

      const expected = MINT_REFUSALS[rule as keyof typeof MINT_REFUSALS];
      expect(failure).toMatchObject({
        code: expected.code,
        message: expected.message,
      });
      expect(() => JSON.parse(failure?.message ?? "")).toThrow();
      expect(repoMock.mintDataPlaneKey).not.toHaveBeenCalled();
      expect(emitMock).toHaveBeenCalledTimes(1);
      expect(emitMock.mock.calls[0][1]).toEqual({
        action: "apikey.create",
        target_type: "api_key",
        outcome: "denied",
        detail: { rule },
      });
    },
  );

  it("echoes nothing of the request in the refusal or its denial row", async () => {
    const failure = await create(
      adminPlaneCtx("operator"),
      mintInput({
        name: "probe/name-alpha",
        user_id: "probe-owner-beta",
        acts_as_user_id: "",
      }),
    );

    const seen = JSON.stringify([failure, emitMock.mock.calls]);
    for (const probe of ["alpha", "beta"]) expect(seen).not.toContain(probe);
  });

  it("answers a request no rule names with the generic sentence", async () => {
    const failure = await create(adminPlaneCtx("operator"), "not an object");

    expect(failure).toMatchObject({
      code: "BAD_REQUEST",
      message: MINT_REFUSALS.request_invalid.message,
    });
  });
});

describe("the replacement is for a schema refusal from an admin-plane key and nothing else", () => {
  it("leaves a browser session's schema messages as they were", async () => {
    const failure = await create(browserCtx, mintInput({ name: "bad/name" }));

    expect(failure?.code).toBe("BAD_REQUEST");
    // The schema's own message: the issue list as JSON, with its path.
    expect(JSON.parse(failure?.message ?? "[]")).toEqual(
      expect.arrayContaining([expect.objectContaining({ path: ["name"] })]),
    );
    expect(emitMock).not.toHaveBeenCalled();
  });

  it("keeps a sync-scope key's standing refusal, whatever the request", async () => {
    const failure = await create(
      adminPlaneCtx("sync"),
      mintInput({ name: "bad/name" }),
    );

    expect(failure).toMatchObject({
      code: "FORBIDDEN",
      message: ADMIN_PLANE_FORBIDDEN_MESSAGE,
    });
  });

  it("does not replace a refusal the implementation throws for a valid request", async () => {
    repoMock.mintDataPlaneKey.mockRejectedValueOnce(
      new ApiKeyMintRefusal("name_taken"),
    );

    const failure = await create(adminPlaneCtx("operator"), mintInput());

    expect(failure).toMatchObject({
      code: MINT_REFUSALS.name_taken.code,
      message: MINT_REFUSALS.name_taken.message,
    });
  });
});
