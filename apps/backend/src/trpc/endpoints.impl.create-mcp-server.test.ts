/**
 * The companion-MCP-server half of `endpoints.create`, and what happens when
 * it cannot be built.
 *
 * The auto-generated MCP server needs a bearer token, and since migration
 * 0034 the ONLY way to get one is to mint a fresh key — no stored key's value
 * can be read back any more, so the branch that reused an existing key is
 * gone. That makes the mint a single point of failure for this convenience,
 * and the old code swallowed a mint failure and created the server anyway
 * with `bearerToken: ""`. On an endpoint that gates on API keys that server
 * is a connection which 401s on its first call: a broken artifact the caller
 * never asked for, created under a success response, with the cause only in
 * a server-side log.
 *
 * These cases pin the two halves of the fix — the broken row is not created,
 * and the caller is told in the response (`warning`, distinct from `message`
 * so it does not have to be string-matched out of the happy path).
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const {
  apiKeyCreateMock,
  endpointsRepositoryMock,
  mcpServersRepositoryMock,
  namespacesRepositoryMock,
} = vi.hoisted(() => ({
  apiKeyCreateMock: vi.fn(),
  endpointsRepositoryMock: { findByName: vi.fn(), create: vi.fn() },
  mcpServersRepositoryMock: { create: vi.fn() },
  namespacesRepositoryMock: { findByUuid: vi.fn() },
}));

vi.mock("../db/repositories", () => ({
  ApiKeysRepository: class {
    create = apiKeyCreateMock;
  },
  endpointsRepository: endpointsRepositoryMock,
  mcpServersRepository: mcpServersRepositoryMock,
  namespacesRepository: namespacesRepositoryMock,
}));

vi.mock("../db/serializers", () => ({
  EndpointsSerializer: { serializeEndpoint: (row: unknown) => row },
}));

const { emitAdminEventMock } = vi.hoisted(() => ({
  emitAdminEventMock: vi.fn(),
}));
vi.mock("../lib/audit/admin-event", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/audit/admin-event")>()),
  emitAdminEvent: emitAdminEventMock,
}));

// An admin-plane key's endpoint row and its audit row share one transaction
// (lib/audit/admin-write.ts); a stand-in transaction keeps that path loadable
// here. The real one is pinned against Postgres in the integration tests.
vi.mock("../db/index", () => ({
  db: {
    transaction: async (callback: (tx: object) => Promise<unknown>) =>
      callback({}),
  },
}));
vi.mock("../db/repositories/audit-log-tx", () => ({
  recordAuditInTransaction: vi.fn(async () => undefined),
}));

import { endpointsImplementations } from "./endpoints.impl";

const NAMESPACE_UUID = "11111111-1111-4111-8111-111111111111";
const ENDPOINT_UUID = "22222222-2222-4222-8222-222222222222";
const USER_ID = "user-1";

function createInput(overrides: Record<string, unknown> = {}) {
  return {
    name: "reporting",
    namespaceUuid: NAMESPACE_UUID,
    enableApiKeyAuth: true,
    requireScopedApiKey: false,
    enableClientMaxRate: false,
    enableMaxRate: false,
    enableOauth: true,
    useQueryParamAuth: false,
    createMcpServer: true,
    user_id: USER_ID,
    ...overrides,
  } as Parameters<typeof endpointsImplementations.create>[0];
}

beforeEach(() => {
  vi.clearAllMocks();
  endpointsRepositoryMock.findByName.mockResolvedValue(undefined);
  endpointsRepositoryMock.create.mockResolvedValue({
    uuid: ENDPOINT_UUID,
    name: "reporting",
  });
  namespacesRepositoryMock.findByUuid.mockResolvedValue({
    uuid: NAMESPACE_UUID,
    name: "ns",
    user_id: USER_ID,
  });
  mcpServersRepositoryMock.create.mockResolvedValue({});
  apiKeyCreateMock.mockResolvedValue({ key: "sk_mt_fresh_scoped_value" });
});

describe("endpoints.create — companion MCP server", () => {
  it("embeds the freshly minted key when the mint succeeds", async () => {
    const result = await endpointsImplementations.create(
      createInput(),
      USER_ID,
    );

    expect(result.success).toBe(true);
    expect(result.warning).toBeUndefined();
    expect(mcpServersRepositoryMock.create).toHaveBeenCalledTimes(1);
    expect(mcpServersRepositoryMock.create.mock.calls[0][0]).toMatchObject({
      bearerToken: "sk_mt_fresh_scoped_value",
    });
    // The mint is endpoint-scoped, not gateway-wide.
    expect(apiKeyCreateMock.mock.calls[0][0]).toMatchObject({
      endpoint_uuid: ENDPOINT_UUID,
    });
  });

  it("creates NO MCP server when the bearer-token mint fails, and says so in the response", async () => {
    apiKeyCreateMock.mockRejectedValue(new Error("unique constraint"));

    const result = await endpointsImplementations.create(
      createInput(),
      USER_ID,
    );

    // The row that would 401 on first use is simply not created.
    expect(mcpServersRepositoryMock.create).not.toHaveBeenCalled();

    // The endpoint itself DID get created, so reporting failure would send
    // the caller into a retry that hits "Endpoint name already exists".
    expect(result.success).toBe(true);
    expect(result.data).toMatchObject({ uuid: ENDPOINT_UUID });

    // ... and the partial failure is carried where a caller can act on it,
    // naming the underlying cause rather than a generic apology.
    expect(result.warning).toBeDefined();
    expect(result.warning).toContain("companion MCP server");
    expect(result.warning).toContain("unique constraint");
  });

  it("reports a warning when the MCP server insert itself fails", async () => {
    mcpServersRepositoryMock.create.mockRejectedValue(new Error("db down"));

    const result = await endpointsImplementations.create(
      createInput(),
      USER_ID,
    );

    // Same rule: the endpoint stands, the caller is told. A silently absent
    // MCP server is indistinguishable from one the user cannot find.
    expect(result.success).toBe(true);
    expect(result.warning).toContain("db down");
  });

  it("still creates the server with an empty bearer token when the endpoint has no API-key gate", async () => {
    // Deliberate, not an oversight: with `enableApiKeyAuth` false the
    // endpoint accepts unauthenticated MCP calls, so an empty bearer token
    // is a working configuration rather than a broken one.
    const result = await endpointsImplementations.create(
      createInput({ enableApiKeyAuth: false }),
      USER_ID,
    );

    expect(apiKeyCreateMock).not.toHaveBeenCalled();
    expect(mcpServersRepositoryMock.create).toHaveBeenCalledTimes(1);
    expect(mcpServersRepositoryMock.create.mock.calls[0][0]).toMatchObject({
      bearerToken: "",
    });
    expect(result.warning).toBeUndefined();
  });

  it("mints nothing and creates nothing when createMcpServer is off", async () => {
    const result = await endpointsImplementations.create(
      createInput({ createMcpServer: false }),
      USER_ID,
    );

    expect(apiKeyCreateMock).not.toHaveBeenCalled();
    expect(mcpServersRepositoryMock.create).not.toHaveBeenCalled();
    expect(result.success).toBe(true);
    expect(result.warning).toBeUndefined();
  });
});

describe("endpoints.create: an admin-plane key cannot mint a key through the companion server", () => {
  // The companion-server path mints an endpoint-scoped key straight in the
  // repository, bypassing apiKeys.create and every rule that procedure holds an
  // admin-plane key to. So a request authenticated by an admin-plane key of
  // either scope may not ask for it, and is refused before any side effect.
  const adminPlaneActor = (scope: "sync" | "operator") => ({
    actor_id: USER_ID,
    actor_label: "owner@example.test",
    actor_ip: "203.0.113.5",
    actor_user_agent: "test",
    request_id: "r1",
    admin_plane: {
      key_uuid: "6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b",
      owner_user_id: USER_ID,
      scope,
    },
  });

  it.each(["sync", "operator"] as const)(
    "refuses createMcpServer from a %s-scope key before any write",
    async (scope) => {
      const failure = await endpointsImplementations
        .create(createInput(), USER_ID, adminPlaneActor(scope))
        .catch((error) => error);

      // A thrown tRPC error (HTTP 403), not `success: false` inside a 200.
      expect(failure).toMatchObject({ code: "FORBIDDEN" });
      expect(endpointsRepositoryMock.findByName).not.toHaveBeenCalled();
      expect(endpointsRepositoryMock.create).not.toHaveBeenCalled();
      expect(apiKeyCreateMock).not.toHaveBeenCalled();
      expect(mcpServersRepositoryMock.create).not.toHaveBeenCalled();
    },
  );

  it.each([
    ["true", true],
    ["a truthy non-boolean", "yes"],
    ["a number", 1],
  ])("refuses createMcpServer that is %s", async (_label, value) => {
    await expect(
      endpointsImplementations.create(
        createInput({ createMcpServer: value }),
        USER_ID,
        adminPlaneActor("operator"),
      ),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(apiKeyCreateMock).not.toHaveBeenCalled();
  });

  it.each([
    ["false", false],
    ["omitted", undefined],
  ])(
    "still creates the endpoint when createMcpServer is %s (the operator CLI's call)",
    async (_label, value) => {
      const result = await endpointsImplementations.create(
        createInput({ createMcpServer: value }),
        USER_ID,
        adminPlaneActor("operator"),
      );

      expect(result.success).toBe(true);
      expect(endpointsRepositoryMock.create).toHaveBeenCalledTimes(1);
      // Handed the transaction handle, so its audit row shares it.
      expect(endpointsRepositoryMock.create.mock.calls[0]).toHaveLength(2);
      expect(apiKeyCreateMock).not.toHaveBeenCalled();
      expect(mcpServersRepositoryMock.create).not.toHaveBeenCalled();
    },
  );

  it("leaves a human administrator's companion-server creation working", async () => {
    const result = await endpointsImplementations.create(
      createInput(),
      USER_ID,
      {
        actor_id: USER_ID,
        actor_label: "admin@example.test",
        actor_ip: null,
        actor_user_agent: null,
        request_id: null,
      },
    );

    expect(result.success).toBe(true);
    expect(apiKeyCreateMock).toHaveBeenCalledTimes(1);
    expect(mcpServersRepositoryMock.create).toHaveBeenCalledTimes(1);
  });
});
