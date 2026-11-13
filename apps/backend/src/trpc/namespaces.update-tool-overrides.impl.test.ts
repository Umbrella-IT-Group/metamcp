/**
 * Unit tests for what `namespaces.updateToolOverrides` tells the rest of the
 * process after it writes an override (a name, an alias, a title, a
 * description or an annotation override).
 *
 * It is the only writer of those fields. After a committed write it clears the
 * override cache for the namespace, and THAT call is the signal every live lean
 * session hears (`onOverrideCacheCleared`) to drop its search snapshot, so a
 * search or describe after the change shows it. The real override module is
 * used here, not a mock, because the signal is the thing under test. A refused
 * or failed write changes nothing and must tell nobody.
 *
 * The repositories are mocked so the unit needs no postgres. The proxy side of
 * the signal (a session's snapshot actually dropping) is pinned in
 * metamcp-proxy.lean.test.ts.
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

// The `../db/repositories` barrel and the override module both reach db/index,
// which needs a live DATABASE_URL; the cache clear under test reads no table.
vi.mock("../db/index", () => ({ db: {} }));
vi.mock("../db/repositories", () => ({
  mcpServersRepository: {},
  namespaceMappingsRepository: { updateToolOverrides: vi.fn() },
  namespacesRepository: { findByUuid: vi.fn() },
  toolsRepository: {},
}));

vi.mock("../lib/audit/admin-event", () => ({
  emitAdminEvent: vi.fn(),
}));

vi.mock("../lib/metamcp/metamcp-middleware/filter-tools.functional", () => ({
  clearFilterCache: vi.fn(),
}));

vi.mock("../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {},
}));

import {
  namespaceMappingsRepository,
  namespacesRepository,
} from "../db/repositories";
import { emitAdminEvent } from "../lib/audit/admin-event";
import { onOverrideCacheCleared } from "../lib/metamcp/metamcp-middleware/tool-overrides.functional";
import { namespacesImplementations } from "./namespaces.impl";

const NAMESPACE_UUID = "11111111-1111-4111-8111-111111111111";
const OTHER_NAMESPACE_UUID = "22222222-2222-4222-8222-222222222222";
const ACTOR = {
  actor_id: "admin-1",
  actor_label: "admin@example.invalid",
  actor_ip: null,
  actor_user_agent: null,
  request_id: null,
};

const INPUT = {
  namespaceUuid: NAMESPACE_UUID,
  toolUuid: "33333333-3333-4333-8333-333333333333",
  serverUuid: "44444444-4444-4444-8444-444444444444",
  overrideName: "modern",
  overrideTitle: null,
  overrideDescription: null,
  overrideAnnotations: { readOnlyHint: false },
};

const dbNamespace = (overrides: Record<string, unknown> = {}) =>
  ({
    uuid: NAMESPACE_UUID,
    name: "universal",
    user_id: null,
    ...overrides,
  }) as never;

const update = (userId: string = "admin-1") =>
  namespacesImplementations.updateToolOverrides(INPUT, userId, ACTOR);

beforeEach(() => {
  vi.clearAllMocks();
});

describe("namespaces.updateToolOverrides tells the namespace's listeners", () => {
  it("tells every listener of that namespace once the write has committed, and no other namespace's", async () => {
    const heard: string[] = [];
    const stopHere = onOverrideCacheCleared(NAMESPACE_UUID, () =>
      heard.push("this namespace"),
    );
    const stopThere = onOverrideCacheCleared(OTHER_NAMESPACE_UUID, () =>
      heard.push("another namespace"),
    );
    vi.mocked(namespacesRepository.findByUuid).mockResolvedValue(dbNamespace());
    vi.mocked(
      namespaceMappingsRepository.updateToolOverrides,
    ).mockImplementation(async () => {
      // Not before the row is written.
      expect(heard).toEqual([]);
      return {} as never;
    });

    const result = await update();

    expect(result.success).toBe(true);
    expect(heard).toEqual(["this namespace"]);
    expect(emitAdminEvent).toHaveBeenCalledTimes(1);
    stopHere();
    stopThere();
  });

  it("tells nobody when the namespace is missing, belongs to someone else, or holds no such tool", async () => {
    const heard = vi.fn();
    const stop = onOverrideCacheCleared(NAMESPACE_UUID, heard);

    vi.mocked(namespacesRepository.findByUuid).mockResolvedValue(undefined);
    expect((await update()).success).toBe(false);

    vi.mocked(namespacesRepository.findByUuid).mockResolvedValue(
      dbNamespace({ user_id: "someone-else" }),
    );
    expect((await update("admin-1")).success).toBe(false);
    expect(
      namespaceMappingsRepository.updateToolOverrides,
    ).not.toHaveBeenCalled();

    vi.mocked(namespacesRepository.findByUuid).mockResolvedValue(dbNamespace());
    vi.mocked(
      namespaceMappingsRepository.updateToolOverrides,
    ).mockResolvedValue(undefined as never);
    expect((await update()).success).toBe(false);

    vi.mocked(
      namespaceMappingsRepository.updateToolOverrides,
    ).mockRejectedValue(new Error("write failed"));
    expect((await update()).success).toBe(false);

    expect(heard).not.toHaveBeenCalled();
    expect(emitAdminEvent).not.toHaveBeenCalled();
    stop();
  });
});
