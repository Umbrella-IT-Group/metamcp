/**
 * Endpoint create/update defaults and the restricted => require_scoped_api_key
 * pairing.
 *
 * Two behaviours pinned here:
 *
 *  - A new endpoint defaults CLOSED. Ownership is the creating admin unless the
 *    caller explicitly opts in to public (user_id: null), and a new endpoint
 *    gets a per-credential tool-call ceiling (enable_max_rate on with a
 *    conservative default budget) rather than shipping unbounded.
 *
 *  - The pairing is enforced server-side: restricting an endpoint (on create,
 *    or by editing one that is already restricted) forces the scoped-key
 *    requirement on, so a restricted endpoint can never keep admitting unscoped
 *    gateway-wide API keys, the two controls only confine an endpoint together.
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
  endpointsRepositoryMock: {
    findByName: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
    findByUuidWithNamespace: vi.fn(),
  },
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

vi.mock("../lib/audit/admin-event", () => ({
  emitAdminEvent: vi.fn(),
}));

import { endpointsImplementations } from "./endpoints.impl";

const NAMESPACE_UUID = "11111111-1111-4111-8111-111111111111";
const ENDPOINT_UUID = "22222222-2222-4222-8222-222222222222";
const ADMIN_ID = "admin-1";

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
    // Off by default in these cases so the companion-server path stays out of
    // the way; it has its own dedicated test file.
    createMcpServer: false,
    ...overrides,
  } as Parameters<typeof endpointsImplementations.create>[0];
}

function updateInput(overrides: Record<string, unknown> = {}) {
  return {
    uuid: ENDPOINT_UUID,
    name: "reporting",
    namespaceUuid: NAMESPACE_UUID,
    enableApiKeyAuth: true,
    requireScopedApiKey: false,
    enableClientMaxRate: false,
    enableMaxRate: false,
    enableOauth: true,
    useQueryParamAuth: false,
    ...overrides,
  } as Parameters<typeof endpointsImplementations.update>[0];
}

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
  // Public namespace so both public and private endpoints are permitted.
  namespacesRepositoryMock.findByUuid.mockResolvedValue({
    uuid: NAMESPACE_UUID,
    name: "ns",
    user_id: null,
  });
});

describe("endpoints.create: default-closed ownership", () => {
  it("defaults ownership to the creating admin when user_id is omitted", async () => {
    await endpointsImplementations.create(createInput(), ADMIN_ID);

    expect(endpointsRepositoryMock.create.mock.calls[0][0]).toMatchObject({
      user_id: ADMIN_ID,
    });
  });

  it("makes a public endpoint only on an explicit null user_id", async () => {
    await endpointsImplementations.create(
      createInput({ user_id: null }),
      ADMIN_ID,
    );

    expect(endpointsRepositoryMock.create.mock.calls[0][0]).toMatchObject({
      user_id: null,
    });
  });
});

describe("endpoints.create: restricted => require_scoped_api_key pairing", () => {
  it("forces require_scoped_api_key on when restricted is set, even if false was passed", async () => {
    await endpointsImplementations.create(
      createInput({ restricted: true, requireScopedApiKey: false }),
      ADMIN_ID,
    );

    expect(endpointsRepositoryMock.create.mock.calls[0][0]).toMatchObject({
      restricted: true,
      require_scoped_api_key: true,
    });
  });

  it("leaves require_scoped_api_key as-passed on an unrestricted endpoint", async () => {
    await endpointsImplementations.create(
      createInput({ restricted: false, requireScopedApiKey: false }),
      ADMIN_ID,
    );

    expect(endpointsRepositoryMock.create.mock.calls[0][0]).toMatchObject({
      restricted: false,
      require_scoped_api_key: false,
    });
  });
});

describe("endpoints.create: default tool-call ceiling", () => {
  it("supplies a conservative default budget when rate limiting is on without numbers", async () => {
    await endpointsImplementations.create(
      createInput({ enableMaxRate: true }),
      ADMIN_ID,
    );

    const persisted = endpointsRepositoryMock.create.mock.calls[0][0];
    expect(persisted.enable_max_rate).toBe(true);
    expect(persisted.max_rate).toBeGreaterThan(0);
    expect(persisted.max_rate_seconds).toBeGreaterThan(0);
  });

  it("respects an explicit budget instead of the default", async () => {
    await endpointsImplementations.create(
      createInput({ enableMaxRate: true, maxRate: 5, maxRateSeconds: 1 }),
      ADMIN_ID,
    );

    expect(endpointsRepositoryMock.create.mock.calls[0][0]).toMatchObject({
      enable_max_rate: true,
      max_rate: 5,
      max_rate_seconds: 1,
    });
  });
});

describe("endpoints.update: pairing on a restricted endpoint", () => {
  it("forces require_scoped_api_key back on when the endpoint is already restricted", async () => {
    endpointsRepositoryMock.findByUuidWithNamespace.mockResolvedValue({
      uuid: ENDPOINT_UUID,
      name: "reporting",
      namespace_uuid: NAMESPACE_UUID,
      restricted: true,
      user_id: ADMIN_ID,
      namespace: { uuid: NAMESPACE_UUID, name: "ns", user_id: null },
    });

    await endpointsImplementations.update(
      updateInput({ requireScopedApiKey: false }),
      ADMIN_ID,
    );

    expect(endpointsRepositoryMock.update.mock.calls[0][0]).toMatchObject({
      require_scoped_api_key: true,
    });
  });

  it("honors require_scoped_api_key false on an unrestricted endpoint", async () => {
    endpointsRepositoryMock.findByUuidWithNamespace.mockResolvedValue({
      uuid: ENDPOINT_UUID,
      name: "reporting",
      namespace_uuid: NAMESPACE_UUID,
      restricted: false,
      user_id: ADMIN_ID,
      namespace: { uuid: NAMESPACE_UUID, name: "ns", user_id: null },
    });

    await endpointsImplementations.update(
      updateInput({ requireScopedApiKey: false }),
      ADMIN_ID,
    );

    expect(endpointsRepositoryMock.update.mock.calls[0][0]).toMatchObject({
      require_scoped_api_key: false,
    });
  });
});
