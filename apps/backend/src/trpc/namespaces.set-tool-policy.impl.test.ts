/**
 * Unit tests for the `namespaces.setToolPolicy` implementation (migration
 * 0040).
 *
 * The router gate (adminProcedure) is pinned in
 * namespaces-curation-admin.test.ts and the repository write against real
 * Postgres in namespace-tool-policy.integration.test.ts. This file pins what
 * sits between them:
 *   - a PRIVATE namespace is changed only by its owner, as for the other
 *     curation mutations;
 *   - a successful set writes the admin audit event, carrying the value it
 *     replaced, and clears the filter cache for that namespace so the flip
 *     applies to the next tools/list or tools/call;
 *   - a refused or failed set writes nothing, audits nothing and leaves the
 *     cache alone.
 *
 * The repositories are mocked so the unit needs no postgres.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

// The `../db/repositories` barrel reaches db/index, which needs a live
// DATABASE_URL, so stub it and the unit test needs no postgres.
vi.mock("../db/repositories", () => ({
  mcpServersRepository: {},
  namespaceMappingsRepository: {},
  namespacesRepository: { findByUuid: vi.fn(), setToolPolicy: vi.fn() },
  toolsRepository: {},
}));

vi.mock("../lib/audit/admin-event", () => ({
  emitAdminEvent: vi.fn(),
}));

vi.mock("../lib/metamcp/metamcp-middleware/filter-tools.functional", () => ({
  clearFilterCache: vi.fn(),
}));

vi.mock("../lib/metamcp/metamcp-middleware/tool-overrides.functional", () => ({
  clearOverrideCache: vi.fn(),
  mapOverrideNameToOriginal: vi.fn(),
}));

vi.mock("../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {},
}));

import { namespacesRepository } from "../db/repositories";
import { emitAdminEvent } from "../lib/audit/admin-event";
import { clearFilterCache } from "../lib/metamcp/metamcp-middleware/filter-tools.functional";
import { namespacesImplementations } from "./namespaces.impl";

const NAMESPACE_UUID = "11111111-1111-4111-8111-111111111111";
const ACTOR = {
  actor_id: "admin-1",
  actor_label: "admin@example.invalid",
  actor_ip: null,
  actor_user_agent: null,
  request_id: null,
};

const dbNamespace = (overrides: Record<string, unknown> = {}) =>
  ({
    uuid: NAMESPACE_UUID,
    name: "universal",
    description: null,
    created_at: new Date("2026-10-01T00:00:00Z"),
    updated_at: new Date("2026-10-14T00:00:00Z"),
    user_id: null,
    tool_policy: "allow_all",
    ...overrides,
  }) as never;

const setPolicy = (
  toolPolicy: "allow_all" | "allowlist",
  userId: string = "admin-1",
) =>
  namespacesImplementations.setToolPolicy(
    { namespaceUuid: NAMESPACE_UUID, toolPolicy },
    userId,
    ACTOR,
  );

beforeEach(() => {
  vi.clearAllMocks();
});

describe("namespaces.setToolPolicy implementation", () => {
  it("sets the policy, audits the change with the value it replaced, and clears the filter cache", async () => {
    vi.mocked(namespacesRepository.findByUuid).mockResolvedValue(dbNamespace());
    vi.mocked(namespacesRepository.setToolPolicy).mockResolvedValue({
      previous: "allow_all",
      namespace: dbNamespace({ tool_policy: "allowlist" }),
    });

    const result = await setPolicy("allowlist");

    expect(result.success).toBe(true);
    expect(result.data?.tool_policy).toBe("allowlist");
    expect(namespacesRepository.setToolPolicy).toHaveBeenCalledWith(
      NAMESPACE_UUID,
      "allowlist",
    );
    expect(clearFilterCache).toHaveBeenCalledWith(NAMESPACE_UUID);
    expect(emitAdminEvent).toHaveBeenCalledTimes(1);
    expect(emitAdminEvent).toHaveBeenCalledWith(ACTOR, {
      action: "namespace.tool_policy",
      target_type: "namespace",
      target_id: NAMESPACE_UUID,
      detail: {
        name: "universal",
        previous: "allow_all",
        tool_policy: "allowlist",
      },
    });
  });

  it("rolls back to allow_all the same way (the rollback is one call)", async () => {
    vi.mocked(namespacesRepository.findByUuid).mockResolvedValue(
      dbNamespace({ tool_policy: "allowlist" }),
    );
    vi.mocked(namespacesRepository.setToolPolicy).mockResolvedValue({
      previous: "allowlist",
      namespace: dbNamespace({ tool_policy: "allow_all" }),
    });

    const result = await setPolicy("allow_all");

    expect(result.success).toBe(true);
    expect(result.data?.tool_policy).toBe("allow_all");
    expect(vi.mocked(emitAdminEvent).mock.calls[0][1].detail).toEqual({
      name: "universal",
      previous: "allowlist",
      tool_policy: "allow_all",
    });
  });

  it("lets the OWNER of a private namespace set it", async () => {
    vi.mocked(namespacesRepository.findByUuid).mockResolvedValue(
      dbNamespace({ user_id: "admin-1" }),
    );
    vi.mocked(namespacesRepository.setToolPolicy).mockResolvedValue({
      previous: "allow_all",
      namespace: dbNamespace({ user_id: "admin-1", tool_policy: "allowlist" }),
    });

    expect((await setPolicy("allowlist")).success).toBe(true);
  });

  it("refuses someone else's PRIVATE namespace and writes, audits and clears nothing", async () => {
    vi.mocked(namespacesRepository.findByUuid).mockResolvedValue(
      dbNamespace({ user_id: "owner-A" }),
    );

    const result = await setPolicy("allowlist", "admin-1");

    expect(result.success).toBe(false);
    expect(result.message).toContain("Access denied");
    expect(namespacesRepository.setToolPolicy).not.toHaveBeenCalled();
    expect(emitAdminEvent).not.toHaveBeenCalled();
    expect(clearFilterCache).not.toHaveBeenCalled();
  });

  it("returns not-found for an unknown namespace and writes nothing", async () => {
    vi.mocked(namespacesRepository.findByUuid).mockResolvedValue(
      undefined as never,
    );

    const result = await setPolicy("allowlist");

    expect(result.success).toBe(false);
    expect(result.message).toBe("Namespace not found");
    expect(namespacesRepository.setToolPolicy).not.toHaveBeenCalled();
    expect(emitAdminEvent).not.toHaveBeenCalled();
  });

  it("returns not-found when the row disappears before the write", async () => {
    vi.mocked(namespacesRepository.findByUuid).mockResolvedValue(dbNamespace());
    vi.mocked(namespacesRepository.setToolPolicy).mockResolvedValue(undefined);

    const result = await setPolicy("allowlist");

    expect(result.success).toBe(false);
    expect(emitAdminEvent).not.toHaveBeenCalled();
    expect(clearFilterCache).not.toHaveBeenCalled();
  });

  it("reports a failed write instead of success, with no audit row", async () => {
    vi.mocked(namespacesRepository.findByUuid).mockResolvedValue(dbNamespace());
    vi.mocked(namespacesRepository.setToolPolicy).mockRejectedValue(
      new Error("connection terminated"),
    );

    const result = await setPolicy("allowlist");

    expect(result.success).toBe(false);
    expect(result.message).toBe("connection terminated");
    expect(emitAdminEvent).not.toHaveBeenCalled();
    expect(clearFilterCache).not.toHaveBeenCalled();
  });
});
