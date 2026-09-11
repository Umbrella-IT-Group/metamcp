import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock("../db/repositories", () => ({
  mcpServersRepository: { findByUuid: vi.fn() },
  namespaceMappingsRepository: {},
  namespacesRepository: { create: vi.fn() },
  toolsRepository: {},
}));

vi.mock("../db/serializers", () => ({
  NamespacesSerializer: { serializeNamespace: vi.fn() },
}));

vi.mock("../lib/audit/admin-event", () => ({
  emitAdminEvent: vi.fn(),
}));

vi.mock("../lib/metamcp/metamcp-middleware/tool-overrides.functional", () => ({
  clearOverrideCache: vi.fn(),
  mapOverrideNameToOriginal: vi.fn(),
}));

vi.mock("../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {
    ensureIdleServerForNewNamespace: vi.fn().mockResolvedValue(undefined),
  },
}));

import { mcpServersRepository, namespacesRepository } from "../db/repositories";
import { NamespacesSerializer } from "../db/serializers";
import { namespacesImplementations } from "./namespaces.impl";

const USER_ID = "user-1";
const SERVER_UUID = "11111111-1111-4111-8111-111111111111";

describe("namespaces.create implementation — ownership defaults", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(namespacesRepository.create).mockResolvedValue({
      uuid: "namespace-1",
      name: "private-namespace",
    } as never);
    vi.mocked(NamespacesSerializer.serializeNamespace).mockReturnValue({
      uuid: "namespace-1",
      name: "private-namespace",
      description: null,
      created_at: "2026-09-08T00:00:00.000Z",
      updated_at: "2026-09-08T00:00:00.000Z",
      user_id: USER_ID,
    });
  });

  it("uses the current user when user_id is omitted", async () => {
    const result = await namespacesImplementations.create(
      { name: "private-namespace" },
      USER_ID,
    );

    expect(result.success).toBe(true);
    expect(namespacesRepository.create).toHaveBeenCalledWith(
      expect.objectContaining({ user_id: USER_ID }),
    );
  });

  it("allows an omitted user_id namespace to contain the user's private server", async () => {
    vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue({
      uuid: SERVER_UUID,
      name: "private-server",
      user_id: USER_ID,
    } as never);

    const result = await namespacesImplementations.create(
      { name: "private-namespace", mcpServerUuids: [SERVER_UUID] },
      USER_ID,
    );

    expect(result.success).toBe(true);
    expect(namespacesRepository.create).toHaveBeenCalledWith(
      expect.objectContaining({ user_id: USER_ID }),
    );
  });

  it("keeps an explicit null user_id public", async () => {
    const result = await namespacesImplementations.create(
      { name: "public-namespace", user_id: null },
      USER_ID,
    );

    expect(result.success).toBe(true);
    expect(namespacesRepository.create).toHaveBeenCalledWith(
      expect.objectContaining({ user_id: null }),
    );
  });
});
