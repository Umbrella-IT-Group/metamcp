/**
 * What `namespaces.update`, `namespaces.refreshTools` and `namespaces.get`
 * hand to their repositories and serializer, by caller, without a database:
 *
 *  - an admin-plane actor's update and refresh reach the repository as
 *    `admin_plane` (the write that keeps the rows a person curated), a
 *    person's as `person`; the repository's own behaviour is pinned against
 *    Postgres (namespace-tool-policy.integration.test.ts and
 *    admin-plane-reply-shape.integration.test.ts);
 *  - the audit event of each carries the evidence the change budget classes
 *    it by: the mounts an update added and the ACTIVE rows a refresh wrote;
 *  - the embedded servers of `namespaces.get` are serialized at the level the
 *    router decided.
 *
 * The audit transaction and the denied-row writer are the real ones, over a
 * stand-in database transport.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const { auditRows } = vi.hoisted(() => ({
  auditRows: [] as Array<Record<string, unknown>>,
}));

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));
vi.mock("../db/index", () => ({
  db: {
    transaction: async (callback: (tx: object) => Promise<unknown>) =>
      callback({ id: "tx" }),
  },
}));
vi.mock("../db/repositories/audit-log-tx", () => ({
  recordAuditInTransaction: vi.fn(async (_tx: unknown, row: unknown) => {
    auditRows.push(row as Record<string, unknown>);
  }),
}));
vi.mock("../lib/admin-plane-budget", async (importOriginal) => {
  const real =
    await importOriginal<typeof import("../lib/admin-plane-budget")>();
  return {
    ...real,
    openBudget: vi.fn(async () => ({
      counts: { total: 0, loosen: 0, destroy: 0 },
      config: real.adminPlaneBudgetConfig(),
    })),
  };
});
vi.mock("../db/repositories", () => ({
  mcpServersRepository: { findByUuid: vi.fn(), findByName: vi.fn() },
  namespaceMappingsRepository: {
    bulkUpsertNamespaceToolMappings: vi.fn(),
    updateToolStatusReportingPrevious: vi.fn(),
  },
  namespacesRepository: {
    create: vi.fn(),
    findByUuid: vi.fn(),
    findByUuidWithServers: vi.fn(),
    updateReportingPrevious: vi.fn(),
  },
  toolsRepository: { bulkUpsert: vi.fn() },
}));
vi.mock("../lib/audit/admin-event", async (importOriginal) => {
  const real =
    await importOriginal<typeof import("../lib/audit/admin-event")>();
  return { ...real, emitAdminEvent: vi.fn() };
});
vi.mock("../lib/metamcp/metamcp-middleware/tool-overrides.functional", () => ({
  clearOverrideCache: vi.fn(),
  mapOverrideNameToOriginal: vi.fn(async (name: string) => name),
}));
vi.mock("../lib/metamcp/metamcp-middleware/filter-tools.functional", () => ({
  clearFilterCache: vi.fn(),
}));
vi.mock("../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {
    invalidateIdleServer: vi.fn(async () => undefined),
    invalidateOpenApiSessions: vi.fn(async () => undefined),
  },
}));

import {
  mcpServersRepository,
  namespaceMappingsRepository,
  namespacesRepository,
  toolsRepository,
} from "../db/repositories";
import { adminPlaneBudgetConfig, openBudget } from "../lib/admin-plane-budget";
import { namespacesImplementations } from "./namespaces.impl";

const NAMESPACE = "11111111-1111-4111-8111-111111111111";
const KEEP = "22222222-2222-4222-8222-222222222222";
const DROP = "33333333-3333-4333-8333-333333333333";
const ADD = "44444444-4444-4444-8444-444444444444";
const KEY_UUID = "6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b";

const actorOf = (scope: "sync" | "operator" | null) => ({
  actor_id: "owner-1",
  actor_label: "owner@example.test",
  actor_ip: null,
  actor_user_agent: null,
  request_id: null,
  ...(scope
    ? { admin_plane: { key_uuid: KEY_UUID, owner_user_id: "owner-1", scope } }
    : {}),
});

const namespaceRow = {
  uuid: NAMESPACE,
  name: "ns",
  description: null,
  created_at: new Date("2026-11-01T00:00:00Z"),
  updated_at: new Date("2026-11-01T00:00:00Z"),
  user_id: null,
  tool_policy: "allow_all",
};

beforeEach(() => {
  vi.clearAllMocks();
  auditRows.length = 0;
  vi.mocked(namespacesRepository.findByUuid).mockResolvedValue(
    namespaceRow as never,
  );
  vi.mocked(mcpServersRepository.findByUuid).mockImplementation(
    async (uuid: string) => ({ uuid, name: "srv", user_id: null }) as never,
  );
  vi.mocked(mcpServersRepository.findByName).mockResolvedValue({
    uuid: KEEP,
    name: "srv",
  } as never);
  vi.mocked(toolsRepository.bulkUpsert).mockResolvedValue([
    { uuid: "tool-1" },
    { uuid: "tool-2" },
  ] as never);
});

describe("namespaces.update", () => {
  const update = (actor: ReturnType<typeof actorOf>, servers: string[]) =>
    namespacesImplementations.update(
      { uuid: NAMESPACE, name: "ns", mcpServerUuids: servers } as never,
      "owner-1",
      actor,
    );
  const reported = (previousServerUuids: string[]) =>
    vi.mocked(namespacesRepository.updateReportingPrevious).mockResolvedValue({
      namespace: namespaceRow,
      previous: namespaceRow,
      previousServerUuids,
    } as never);

  it.each([
    ["sync", "admin_plane"],
    ["operator", "admin_plane"],
    [null, "person"],
  ] as const)(
    "hands the repository the caller kind of a %s actor: %s",
    async (scope, kind) => {
      reported([KEEP, DROP]);

      await update(actorOf(scope), [KEEP]);

      expect(namespacesRepository.updateReportingPrevious).toHaveBeenCalledWith(
        expect.objectContaining({ uuid: NAMESPACE, mcpServerUuids: [KEEP] }),
        kind,
        ...(scope ? [expect.anything()] : []),
      );
    },
  );

  it("records how many mounts the write added, against the list it locked", async () => {
    reported([KEEP, DROP]);
    await update(actorOf("operator"), [KEEP, ADD]);
    reported([KEEP, DROP]);
    await update(actorOf("operator"), [KEEP]);
    reported([KEEP]);
    await update(actorOf("operator"), [KEEP, ADD, ADD.toUpperCase()]);

    expect(
      auditRows.map(
        (row) => (row.detail as Record<string, unknown>).mounts_added,
      ),
    ).toEqual([1, 0, 1]);
  });

  it("records no mount added for a request that carries no server list", async () => {
    reported([KEEP]);

    await namespacesImplementations.update(
      { uuid: NAMESPACE, name: "renamed" } as never,
      "owner-1",
      actorOf("operator"),
    );

    expect((auditRows[0].detail as Record<string, unknown>).mounts_added).toBe(
      0,
    );
  });
});

describe("namespaces.refreshTools", () => {
  const refresh = (actor: ReturnType<typeof actorOf>) =>
    namespacesImplementations.refreshTools(
      {
        namespaceUuid: NAMESPACE,
        tools: [
          {
            name: "srv__one",
            description: "one",
            inputSchema: { type: "object" },
          },
          {
            name: "srv__two",
            description: "two",
            inputSchema: { type: "object" },
          },
        ],
      } as never,
      "owner-1",
      true,
      actor,
    );

  it.each([
    ["sync", "admin_plane"],
    ["operator", "admin_plane"],
    [null, "person"],
  ] as const)(
    "hands the repository the caller kind of a %s actor: %s",
    async (scope, kind) => {
      vi.mocked(
        namespaceMappingsRepository.bulkUpsertNamespaceToolMappings,
      ).mockResolvedValue({ mappings: [], toolPolicy: "allow_all" } as never);

      await refresh(actorOf(scope));

      expect(
        namespaceMappingsRepository.bulkUpsertNamespaceToolMappings,
      ).toHaveBeenCalledWith(
        expect.objectContaining({ namespaceUuid: NAMESPACE }),
        kind,
        ...(scope ? [expect.anything()] : []),
      );
    },
  );

  it("records the ACTIVE rows the refresh wrote, and none for rows that were INACTIVE or already there", async () => {
    const written = (statuses: string[]) =>
      vi
        .mocked(namespaceMappingsRepository.bulkUpsertNamespaceToolMappings)
        .mockResolvedValue({
          mappings: statuses.map((status, index) => ({
            tool_uuid: `t${index}`,
            status,
          })),
          toolPolicy: "allow_all",
        } as never);

    written(["ACTIVE", "INACTIVE", "ACTIVE"]);
    await refresh(actorOf("operator"));
    written([]);
    await refresh(actorOf("operator"));
    written(["INACTIVE"]);
    await refresh(actorOf("operator"));

    expect(
      auditRows.map(
        (row) => (row.detail as Record<string, unknown>).active_rows_written,
      ),
    ).toEqual([2, 0, 0]);
  });
});

describe("namespaces.get", () => {
  it("serializes the embedded servers at the level the router decided", async () => {
    vi.mocked(namespacesRepository.findByUuidWithServers).mockResolvedValue({
      ...namespaceRow,
      servers: [
        {
          uuid: KEEP,
          name: "srv",
          description: null,
          type: "STREAMABLE_HTTP",
          command: "canary-command-3f2a91",
          args: ["canary-arg-71be04"],
          url: "https://canary-user:canary-pass@vendor.internal/canary-path-d1f60b",
          env: { TOKEN: "canary-env-value-c05d17" },
          bearerToken: "enc:v1:canary",
          headers: { Authorization: "canary-header-value-9a44e2" },
          error_status: "NONE",
          created_at: new Date("2026-11-01T00:00:00Z"),
          user_id: null,
          status: "ACTIVE",
        },
      ],
    } as never);

    const names = await namespacesImplementations.get(
      { uuid: NAMESPACE },
      "owner-1",
      "names_only",
    );
    const full = await namespacesImplementations.get(
      { uuid: NAMESPACE },
      "owner-1",
      "full",
    );

    expect(JSON.stringify(names)).not.toContain("canary-");
    expect(names.data?.servers[0]).toMatchObject({
      env: { TOKEN: "" },
      headers: { Authorization: "" },
      url: null,
      command: null,
      args: [],
    });
    expect(full.data?.servers[0]).toMatchObject({
      env: { TOKEN: "canary-env-value-c05d17" },
      command: "canary-command-3f2a91",
    });
  });
});

// Each procedure below answers a caller's request inside a catch-all that turns
// an unexpected failure into `success: false`. A coded refusal (here the change
// budget's) is not an unexpected failure: it has to leave the procedure as the
// TOO_MANY_REQUESTS it is, so a caller reads "refused before it ran" and never
// an HTTP 200 whose body says the write failed. Each case spends the whole
// loosen allowance first and then makes a write of the loosening class.
describe("a coded refusal leaves every namespace write that spends the loosen allowance", () => {
  const spentLoosen = () =>
    vi.mocked(openBudget).mockResolvedValueOnce({
      counts: {
        total: 0,
        loosen: adminPlaneBudgetConfig().operator.loosen,
        grant: 0,
        destroy: 0,
      },
      config: adminPlaneBudgetConfig(),
    });

  const refresh = () =>
    namespacesImplementations.refreshTools(
      {
        namespaceUuid: NAMESPACE,
        tools: [
          {
            name: "srv__one",
            description: "one",
            inputSchema: { type: "object" },
          },
        ],
      } as never,
      "owner-1",
      true,
      actorOf("operator"),
    );

  it.each([
    [
      "create",
      () => {
        vi.mocked(namespacesRepository.create).mockResolvedValue(
          namespaceRow as never,
        );
        return namespacesImplementations.create(
          { name: "ns", mcpServerUuids: [] } as never,
          "owner-1",
          actorOf("operator"),
        );
      },
    ],
    [
      "update",
      () => {
        vi.mocked(
          namespacesRepository.updateReportingPrevious,
        ).mockResolvedValue({
          namespace: namespaceRow,
          previous: namespaceRow,
          previousServerUuids: [KEEP],
        } as never);
        return namespacesImplementations.update(
          { uuid: NAMESPACE, name: "ns", mcpServerUuids: [KEEP, ADD] } as never,
          "owner-1",
          actorOf("operator"),
        );
      },
    ],
    [
      "updateToolStatus",
      () => {
        vi.mocked(
          namespaceMappingsRepository.updateToolStatusReportingPrevious,
        ).mockResolvedValue({
          mapping: { status: "ACTIVE" },
          previousStatus: "INACTIVE",
        } as never);
        return namespacesImplementations.updateToolStatus(
          {
            namespaceUuid: NAMESPACE,
            toolUuid: "55555555-5555-4555-8555-555555555555",
            serverUuid: KEEP,
            status: "ACTIVE",
          } as never,
          "owner-1",
          actorOf("operator"),
        );
      },
    ],
    [
      "refreshTools",
      () => {
        vi.mocked(
          namespaceMappingsRepository.bulkUpsertNamespaceToolMappings,
        ).mockResolvedValue({
          mappings: [{ tool_uuid: "t0", status: "ACTIVE" }],
          toolPolicy: "allow_all",
        } as never);
        return refresh();
      },
    ],
  ] as const)(
    "namespaces.%s answers a spent loosen allowance as TOO_MANY_REQUESTS, with no audit row",
    async (_procedure, call) => {
      spentLoosen();

      const failure = await call().then(
        (reply) => ({ replied: reply }),
        (error: unknown) => error,
      );

      expect(failure).toMatchObject({ code: "TOO_MANY_REQUESTS" });
      expect(auditRows).toEqual([]);
    },
  );
});
