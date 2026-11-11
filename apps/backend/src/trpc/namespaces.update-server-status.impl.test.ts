/**
 * Unit tests for the `namespaces.updateServerStatus` implementation: a mount
 * status change tells the namespace's live sessions to drop their routes and
 * re-list (namespace-mount-events.ts) BEFORE it returns success, and a refused
 * or failed change tells nobody.
 *
 * Enforcement does not depend on that signal (the tool filter reads the mount
 * status on every call; metamcp-proxy.mount-status.test.ts pins it). This file
 * pins the ordering the admin relies on: once the write is confirmed, no live
 * session still holds a route to the mount it switched.
 *
 * The repositories are mocked so the unit needs no postgres.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const { order } = vi.hoisted(() => ({ order: [] as string[] }));

vi.mock("@/utils/logger", () => ({
  default: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock("../db/repositories", () => ({
  mcpServersRepository: {},
  namespaceMappingsRepository: { updateServerStatus: vi.fn() },
  namespacesRepository: { findByUuid: vi.fn() },
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
  metaMcpServerPool: {
    invalidateIdleServer: vi.fn(async () => undefined),
    invalidateOpenApiSessions: vi.fn(async () => undefined),
  },
}));

vi.mock("../lib/metamcp/namespace-mount-events", () => ({
  notifyNamespaceMountChange: vi.fn(() => {
    order.push("notify");
    return 1;
  }),
}));

import {
  namespaceMappingsRepository,
  namespacesRepository,
} from "../db/repositories";
import { notifyNamespaceMountChange } from "../lib/metamcp/namespace-mount-events";
import { namespacesImplementations } from "./namespaces.impl";

const NAMESPACE_UUID = "11111111-1111-4111-8111-111111111111";
const SERVER_UUID = "22222222-2222-4222-8222-222222222222";
const OWNER = "owner-1";

const input = (status: "ACTIVE" | "INACTIVE") => ({
  namespaceUuid: NAMESPACE_UUID,
  serverUuid: SERVER_UUID,
  status,
});

beforeEach(() => {
  vi.clearAllMocks();
  order.length = 0;
  vi.mocked(namespacesRepository.findByUuid).mockResolvedValue({
    uuid: NAMESPACE_UUID,
    user_id: OWNER,
  } as never);
  vi.mocked(namespaceMappingsRepository.updateServerStatus).mockImplementation(
    async (row) => {
      order.push("write");
      return { ...row } as never;
    },
  );
});

describe("namespaces.updateServerStatus signals live sessions", () => {
  it.each(["INACTIVE", "ACTIVE"] as const)(
    "a %s change signals the namespace after the write and before it returns",
    async (status) => {
      const result = await namespacesImplementations.updateServerStatus(
        input(status),
        OWNER,
      );
      order.push("returned");

      expect(result.success).toBe(true);
      expect(notifyNamespaceMountChange).toHaveBeenCalledTimes(1);
      expect(notifyNamespaceMountChange).toHaveBeenCalledWith(
        NAMESPACE_UUID,
        SERVER_UUID,
      );
      expect(order).toEqual(["write", "notify", "returned"]);
    },
  );

  it("a server not mounted in the namespace signals nobody", async () => {
    vi.mocked(
      namespaceMappingsRepository.updateServerStatus,
    ).mockResolvedValueOnce(undefined as never);
    const result = await namespacesImplementations.updateServerStatus(
      input("INACTIVE"),
      OWNER,
    );
    expect(result.success).toBe(false);
    expect(notifyNamespaceMountChange).not.toHaveBeenCalled();
  });

  it("a caller who does not own the namespace signals nobody", async () => {
    const result = await namespacesImplementations.updateServerStatus(
      input("INACTIVE"),
      "someone-else",
    );
    expect(result.success).toBe(false);
    expect(
      namespaceMappingsRepository.updateServerStatus,
    ).not.toHaveBeenCalled();
    expect(notifyNamespaceMountChange).not.toHaveBeenCalled();
  });

  it("a failed write signals nobody", async () => {
    vi.mocked(
      namespaceMappingsRepository.updateServerStatus,
    ).mockRejectedValueOnce(new Error("write failed"));
    const result = await namespacesImplementations.updateServerStatus(
      input("INACTIVE"),
      OWNER,
    );
    expect(result.success).toBe(false);
    expect(notifyNamespaceMountChange).not.toHaveBeenCalled();
  });
});
