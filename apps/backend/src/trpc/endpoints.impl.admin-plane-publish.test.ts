/**
 * An admin-plane key may create an API key only for a public, unrestricted
 * endpoint. These cases pin the other half of that rule, at the implementation
 * with the repositories doubled: the same key may not create, or re-point, a
 * public unrestricted endpoint over a namespace that a restricted or private
 * endpoint already serves, because a key created for the new endpoint would
 * reach through it what the old one keeps from that key's owner.
 *
 * What is judged is the kind of endpoint a key may be created for. A private or
 * restricted endpoint is not one, an endpoint left on its namespace keeps the
 * reach it had, and a human administrator's session is not held to the rule.
 * The refusal is a `success: false` answer with one fixed sentence that names
 * no endpoint and no namespace, like the rules beside it, and nothing is
 * written. Against Postgres the whole sequence is pinned in
 * api-key-mint.integration.test.ts.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const { endpointsRepositoryMock, namespacesRepositoryMock } = vi.hoisted(
  () => ({
    endpointsRepositoryMock: {
      findByName: vi.fn(),
      create: vi.fn(),
      findByUuidWithNamespace: vi.fn(),
      update: vi.fn(),
      hasGatedEndpointOnNamespace: vi.fn(),
    },
    namespacesRepositoryMock: { findByUuid: vi.fn() },
  }),
);

vi.mock("../db/repositories", () => ({
  ApiKeysRepository: class {
    create = vi.fn();
  },
  endpointsRepository: endpointsRepositoryMock,
  mcpServersRepository: { create: vi.fn() },
  namespacesRepository: namespacesRepositoryMock,
}));
vi.mock("../db/serializers", () => ({
  EndpointsSerializer: { serializeEndpoint: (row: unknown) => row },
}));
vi.mock("../lib/audit/admin-event", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/audit/admin-event")>()),
  emitAdminEvent: vi.fn(),
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

import { endpointsImplementations } from "./endpoints.impl";

const NEW_NAMESPACE = "11111111-1111-4111-8111-111111111111";
const OLD_NAMESPACE = "33333333-3333-4333-8333-333333333333";
const ENDPOINT_UUID = "22222222-2222-4222-8222-222222222222";
const OWNER_ID = "owner-admin-1";

const adminPlaneActor = (scope: "sync" | "operator") => ({
  actor_id: OWNER_ID,
  actor_label: "owner@example.test",
  actor_ip: "203.0.113.5",
  actor_user_agent: "test",
  request_id: "req-1",
  admin_plane: {
    key_uuid: "6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b",
    owner_user_id: OWNER_ID,
    scope,
  },
});
const humanActor = {
  actor_id: OWNER_ID,
  actor_label: "owner@example.test",
  actor_ip: "198.51.100.9",
  actor_user_agent: "test",
  request_id: "req-2",
};

const createInput = (over: Record<string, unknown> = {}) =>
  ({
    name: "reporting",
    namespaceUuid: NEW_NAMESPACE,
    enableApiKeyAuth: true,
    requireScopedApiKey: false,
    enableClientMaxRate: false,
    enableMaxRate: false,
    enableOauth: false,
    useQueryParamAuth: false,
    createMcpServer: false,
    user_id: null,
    ...over,
  }) as Parameters<typeof endpointsImplementations.create>[0];

const updateInput = (over: Record<string, unknown> = {}) =>
  ({
    uuid: ENDPOINT_UUID,
    name: "reporting",
    namespaceUuid: NEW_NAMESPACE,
    enableApiKeyAuth: true,
    requireScopedApiKey: false,
    enableClientMaxRate: false,
    enableMaxRate: false,
    enableOauth: false,
    useQueryParamAuth: false,
    ...over,
  }) as Parameters<typeof endpointsImplementations.update>[0];

const REFUSAL =
  "An admin-plane API key cannot make a namespace public that a restricted or private endpoint already serves. Do this in the admin UI.";

beforeEach(() => {
  vi.clearAllMocks();
  endpointsRepositoryMock.findByName.mockResolvedValue(undefined);
  endpointsRepositoryMock.create.mockResolvedValue({
    uuid: ENDPOINT_UUID,
    name: "reporting",
  });
  endpointsRepositoryMock.update.mockResolvedValue({
    uuid: ENDPOINT_UUID,
    name: "reporting",
  });
  endpointsRepositoryMock.hasGatedEndpointOnNamespace.mockResolvedValue(false);
  endpointsRepositoryMock.findByUuidWithNamespace.mockResolvedValue({
    uuid: ENDPOINT_UUID,
    name: "reporting",
    namespace_uuid: OLD_NAMESPACE,
    user_id: null,
    restricted: false,
  });
  namespacesRepositoryMock.findByUuid.mockResolvedValue({
    uuid: NEW_NAMESPACE,
    name: "a namespace name that must not be echoed",
    user_id: null,
  });
});

describe("endpoints.create by an admin-plane key", () => {
  it.each(["sync", "operator"] as const)(
    "refuses a public unrestricted endpoint over a namespace a restricted or private endpoint serves (%s scope), writing nothing",
    async (scope) => {
      endpointsRepositoryMock.hasGatedEndpointOnNamespace.mockResolvedValue(
        true,
      );

      const result = await endpointsImplementations.create(
        createInput(),
        OWNER_ID,
        adminPlaneActor(scope),
      );

      expect(result).toEqual({ success: false, message: REFUSAL });
      expect(
        endpointsRepositoryMock.hasGatedEndpointOnNamespace,
      ).toHaveBeenCalledWith(NEW_NAMESPACE);
      expect(endpointsRepositoryMock.create).not.toHaveBeenCalled();
      expect(result.message).not.toContain("namespace name");
      expect(result.message).not.toContain(NEW_NAMESPACE);
    },
  );

  it("creates a public unrestricted endpoint over a namespace nothing gates", async () => {
    const result = await endpointsImplementations.create(
      createInput(),
      OWNER_ID,
      adminPlaneActor("operator"),
    );

    expect(result.success).toBe(true);
    expect(endpointsRepositoryMock.create).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["a private endpoint", { user_id: OWNER_ID }],
    ["a restricted endpoint", { restricted: true }],
  ])(
    "does not judge %s, which is not a kind a key may be created for",
    async (_label, over) => {
      endpointsRepositoryMock.hasGatedEndpointOnNamespace.mockResolvedValue(
        true,
      );
      namespacesRepositoryMock.findByUuid.mockResolvedValue({
        uuid: NEW_NAMESPACE,
        name: "ns",
        user_id: null,
      });

      const result = await endpointsImplementations.create(
        createInput(over),
        OWNER_ID,
        adminPlaneActor("operator"),
      );

      expect(result.success).toBe(true);
      expect(
        endpointsRepositoryMock.hasGatedEndpointOnNamespace,
      ).not.toHaveBeenCalled();
    },
  );

  it("leaves a human administrator's session unjudged", async () => {
    endpointsRepositoryMock.hasGatedEndpointOnNamespace.mockResolvedValue(true);

    const result = await endpointsImplementations.create(
      createInput(),
      OWNER_ID,
      humanActor,
    );

    expect(result.success).toBe(true);
    expect(
      endpointsRepositoryMock.hasGatedEndpointOnNamespace,
    ).not.toHaveBeenCalled();
  });
});

describe("endpoints.update by an admin-plane key", () => {
  it("refuses re-pointing a public unrestricted endpoint at a namespace a restricted or private endpoint serves, writing nothing", async () => {
    endpointsRepositoryMock.hasGatedEndpointOnNamespace.mockResolvedValue(true);

    const result = await endpointsImplementations.update(
      updateInput(),
      OWNER_ID,
      adminPlaneActor("operator"),
    );

    expect(result).toEqual({ success: false, message: REFUSAL });
    // The endpoint being changed does not count as one that gates the target.
    expect(
      endpointsRepositoryMock.hasGatedEndpointOnNamespace,
    ).toHaveBeenCalledWith(NEW_NAMESPACE, ENDPOINT_UUID);
    expect(endpointsRepositoryMock.update).not.toHaveBeenCalled();
  });

  it("re-points it at a namespace nothing gates", async () => {
    const result = await endpointsImplementations.update(
      updateInput(),
      OWNER_ID,
      adminPlaneActor("operator"),
    );

    expect(result.success).toBe(true);
    expect(endpointsRepositoryMock.update).toHaveBeenCalledTimes(1);
  });

  it("does not judge an endpoint left on its namespace", async () => {
    endpointsRepositoryMock.hasGatedEndpointOnNamespace.mockResolvedValue(true);

    const result = await endpointsImplementations.update(
      updateInput({ namespaceUuid: OLD_NAMESPACE }),
      OWNER_ID,
      adminPlaneActor("operator"),
    );

    expect(result.success).toBe(true);
    expect(
      endpointsRepositoryMock.hasGatedEndpointOnNamespace,
    ).not.toHaveBeenCalled();
  });

  it.each([
    ["a restricted endpoint", { user_id: null, restricted: true }],
    ["a private endpoint", { user_id: OWNER_ID, restricted: false }],
  ])(
    "does not judge %s, which is not a kind a key may be created for",
    async (_label, row) => {
      endpointsRepositoryMock.hasGatedEndpointOnNamespace.mockResolvedValue(
        true,
      );
      endpointsRepositoryMock.findByUuidWithNamespace.mockResolvedValue({
        uuid: ENDPOINT_UUID,
        name: "reporting",
        namespace_uuid: OLD_NAMESPACE,
        ...row,
      });

      const result = await endpointsImplementations.update(
        updateInput(),
        OWNER_ID,
        adminPlaneActor("operator"),
      );

      expect(result.success).toBe(true);
      expect(
        endpointsRepositoryMock.hasGatedEndpointOnNamespace,
      ).not.toHaveBeenCalled();
    },
  );

  it("leaves a human administrator's session unjudged", async () => {
    endpointsRepositoryMock.hasGatedEndpointOnNamespace.mockResolvedValue(true);

    const result = await endpointsImplementations.update(
      updateInput(),
      OWNER_ID,
      humanActor,
    );

    expect(result.success).toBe(true);
    expect(
      endpointsRepositoryMock.hasGatedEndpointOnNamespace,
    ).not.toHaveBeenCalled();
  });
});
