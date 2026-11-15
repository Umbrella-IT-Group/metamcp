/**
 * What an admin-plane key may do to a server, and what its replies carry,
 * without a database (the same claims run against Postgres in
 * admin-plane-reply-shape.integration.test.ts):
 *
 *  - an operator-scope key cannot create a server, and cannot send the full
 *    update (the variant that carries a connection): each is refused with its
 *    coded rule, a `denied` audit row is written, and nothing is read or
 *    written first;
 *  - the sync scope keeps both, and a person keeps both;
 *  - the metadata-only update (a rename and/or a description) reaches only the
 *    metadata write, never the full one, for either scope;
 *  - the reply of create and update carries the stored connection for a person
 *    only: names only for an admin-plane actor, and for an actor missing
 *    altogether.
 *
 * The audit transaction and the denied-row writer are the real ones, over a
 * stand-in database transport (a transaction that records begin, commit and
 * rollback, and an audit table that records the rows it is given).
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const { order, deniedRows, auditRows } = vi.hoisted(() => ({
  order: [] as string[],
  deniedRows: [] as Array<Record<string, unknown>>,
  auditRows: [] as Array<Record<string, unknown>>,
}));

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));
vi.mock("../db/index", () => ({
  db: {
    transaction: async (callback: (tx: object) => Promise<unknown>) => {
      order.push("begin");
      try {
        const out = await callback({ id: "tx" });
        order.push("commit");
        return out;
      } catch (error) {
        order.push("rollback");
        throw error;
      }
    },
  },
}));
vi.mock("../db/repositories/audit-log-tx", () => ({
  recordAuditInTransaction: vi.fn(async (_tx: unknown, row: unknown) => {
    auditRows.push(row as Record<string, unknown>);
  }),
}));
vi.mock("../db/repositories/audit-log.repo", () => ({
  auditLogRepository: {
    record: vi.fn(async (row: Record<string, unknown>) => {
      order.push("denied row");
      deniedRows.push(row);
    }),
  },
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
  mcpServersRepository: {
    create: vi.fn(),
    findByUuid: vi.fn(),
    updateReportingChange: vi.fn(),
    updateMetadataReportingChange: vi.fn(),
    findAllAccessibleToUser: vi.fn(),
    findAll: vi.fn(),
  },
  namespaceMappingsRepository: {
    findNamespacesByServerUuid: vi.fn(async () => []),
  },
}));
vi.mock("../lib/audit/admin-event", async (importOriginal) => {
  const real =
    await importOriginal<typeof import("../lib/audit/admin-event")>();
  return { ...real, emitAdminEvent: vi.fn() };
});
vi.mock("../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    invalidateServerConnection: vi.fn(async () => undefined),
    invalidateIdleSession: vi.fn(async () => undefined),
    ensureIdleSessionForNewServer: vi.fn(async () => undefined),
  },
}));
vi.mock("../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {
    invalidateIdleServers: vi.fn(async () => undefined),
    invalidateOpenApiSessions: vi.fn(async () => undefined),
  },
}));
vi.mock("../lib/metamcp/metamcp-middleware/tool-overrides.functional", () => ({
  clearOverrideCache: vi.fn(),
}));
vi.mock("../lib/metamcp/server-error-tracker", () => ({
  serverErrorTracker: { resetServerErrorState: vi.fn(async () => undefined) },
}));
vi.mock("../lib/metamcp/utils", () => ({
  convertDbServerToParams: vi.fn(async () => undefined),
}));

import { mcpServersRepository } from "../db/repositories";
import {
  SERVER_NAME_TAKEN_MESSAGE,
  ServerNameTakenError,
} from "../db/repositories/mcp-server-name-rule";
import { mcpServersImplementations } from "./mcp-servers.impl";
import { OPERATOR_SERVER_REFUSALS } from "./mcp-servers.impl";

const UUID = "11111111-1111-4111-8111-111111111111";
const KEY_UUID = "6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b";

const actorOf = (scope: "sync" | "operator" | null) => ({
  actor_id: "owner-1",
  actor_label: "owner@example.test",
  actor_ip: null,
  actor_user_agent: null,
  request_id: null,
  ...(scope
    ? {
        admin_plane: {
          key_uuid: KEY_UUID,
          owner_user_id: "owner-1",
          scope,
        },
      }
    : {}),
});

const CANARY = {
  command: "canary-command-3f2a91",
  envValue: "canary-env-value-c05d17",
  headerValue: "canary-header-value-9a44e2",
  url: "https://canary-user:canary-pass@vendor.internal/canary-path-d1f60b?q=canary-query-47c3aa#canary-fragment-e82b59",
};
const row = (overrides: Record<string, unknown> = {}) =>
  ({
    uuid: UUID,
    name: "vendor",
    description: null,
    type: "STREAMABLE_HTTP",
    command: CANARY.command,
    args: ["canary-arg-71be04"],
    env: { TOKEN: CANARY.envValue },
    url: CANARY.url,
    bearerToken: "enc:v1:canary",
    headers: { Authorization: CANARY.headerValue },
    error_status: "NONE",
    created_at: new Date("2026-11-01T00:00:00Z"),
    user_id: null,
    ...overrides,
  }) as never;

const createInput = {
  name: "vendor",
  type: "STREAMABLE_HTTP",
  url: CANARY.url,
  env: { TOKEN: CANARY.envValue },
} as never;
const fullUpdate = {
  uuid: UUID,
  name: "vendor",
  type: "STREAMABLE_HTTP",
  url: CANARY.url,
} as never;
const metadataUpdate = {
  uuid: UUID,
  metadata_only: true,
  name: "vendor-renamed",
} as never;

beforeEach(() => {
  vi.clearAllMocks();
  order.length = 0;
  deniedRows.length = 0;
  auditRows.length = 0;
  vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue(row());
  vi.mocked(mcpServersRepository.create).mockResolvedValue(row());
  vi.mocked(mcpServersRepository.updateReportingChange).mockResolvedValue({
    server: row(),
    previous: row(),
    destinationOrCredentialChanged: false,
    ownershipChanged: false,
  });
  vi.mocked(
    mcpServersRepository.updateMetadataReportingChange,
  ).mockResolvedValue({
    kind: "updated",
    server: row({ name: "vendor-renamed" }),
    previous: row(),
  });
});

describe("an operator-scope key and server create", () => {
  it("is refused with its rule, a denied row, and no write", async () => {
    await expect(
      mcpServersImplementations.create(
        createInput,
        "owner-1",
        actorOf("operator"),
      ),
    ).rejects.toMatchObject({
      code: "FORBIDDEN",
      message: OPERATOR_SERVER_REFUSALS.operator_server_create.message,
    });

    expect(mcpServersRepository.create).not.toHaveBeenCalled();
    expect(deniedRows).toHaveLength(1);
    expect(deniedRows[0]).toMatchObject({
      action: "mcpserver.create",
      outcome: "denied",
      actor_type: "api_key",
      actor_id: KEY_UUID,
      detail: expect.objectContaining({ rule: "operator_server_create" }),
    });
  });

  it("is refused before the stdio and identity-header gates, so the rule is the answer whatever else is wrong", async () => {
    await expect(
      mcpServersImplementations.create(
        {
          name: "x",
          type: "STDIO",
          command: "/bin/true",
          headers: { "X-Umbrella-User-Id": "x" },
        } as never,
        "owner-1",
        actorOf("operator"),
      ),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(deniedRows).toHaveLength(1);
  });

  it("is not a refusal for the sync scope, whose reply carries names only", async () => {
    const result = await mcpServersImplementations.create(
      createInput,
      "owner-1",
      actorOf("sync"),
    );

    expect(result.success).toBe(true);
    expect(mcpServersRepository.create).toHaveBeenCalledTimes(1);
    expect(deniedRows).toHaveLength(0);
    expect(auditRows).toHaveLength(1);
    expect(result.data).toMatchObject({
      env: { TOKEN: "" },
      headers: { Authorization: "" },
      command: null,
      url: null,
      args: [],
    });
    expect(JSON.stringify(result)).not.toContain("canary-");
  });

  it("is not a refusal for a person, whose reply carries what they submitted", async () => {
    const result = await mcpServersImplementations.create(
      createInput,
      "owner-1",
      actorOf(null),
    );

    expect(result.success).toBe(true);
    expect(result.data).toMatchObject({
      env: { TOKEN: CANARY.envValue },
      url: CANARY.url,
    });
    expect(deniedRows).toHaveLength(0);
  });
});

describe("an operator-scope key and the full update", () => {
  it("is refused with its rule, a denied row naming the server, and neither a read nor a write", async () => {
    await expect(
      mcpServersImplementations.update(
        fullUpdate,
        "owner-1",
        actorOf("operator"),
      ),
    ).rejects.toMatchObject({
      code: "FORBIDDEN",
      message:
        OPERATOR_SERVER_REFUSALS.operator_server_connection_change.message,
    });

    expect(mcpServersRepository.findByUuid).not.toHaveBeenCalled();
    expect(mcpServersRepository.updateReportingChange).not.toHaveBeenCalled();
    expect(
      mcpServersRepository.updateMetadataReportingChange,
    ).not.toHaveBeenCalled();
    expect(deniedRows).toHaveLength(1);
    expect(deniedRows[0]).toMatchObject({
      action: "mcpserver.update",
      target_id: UUID,
      outcome: "denied",
      detail: expect.objectContaining({
        rule: "operator_server_connection_change",
      }),
    });
  });

  it("is refused even when the full update would change nothing", async () => {
    await expect(
      mcpServersImplementations.update(
        {
          uuid: UUID,
          name: "vendor",
          type: "STREAMABLE_HTTP",
          url: CANARY.url,
        } as never,
        "owner-1",
        actorOf("operator"),
      ),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("is not a refusal for the sync scope, and the reply carries names only", async () => {
    const result = await mcpServersImplementations.update(
      fullUpdate,
      "owner-1",
      actorOf("sync"),
    );

    expect(result.success).toBe(true);
    expect(mcpServersRepository.updateReportingChange).toHaveBeenCalledTimes(1);
    expect(deniedRows).toHaveLength(0);
    expect(result.data).toMatchObject({ env: { TOKEN: "" }, url: null });
    expect(JSON.stringify(result)).not.toContain("canary-");
  });

  it("is not a refusal for a person, whose reply keeps the stored connection", async () => {
    const result = await mcpServersImplementations.update(
      fullUpdate,
      "owner-1",
      actorOf(null),
    );

    expect(result.success).toBe(true);
    expect(result.data).toMatchObject({
      env: { TOKEN: CANARY.envValue },
      url: CANARY.url,
    });
  });
});

describe("the metadata-only update", () => {
  it.each(["operator", "sync"] as const)(
    "reaches only the metadata write for a %s-scope key, and the reply carries names only",
    async (scope) => {
      const result = await mcpServersImplementations.update(
        metadataUpdate,
        "owner-1",
        actorOf(scope),
      );

      expect(result.success).toBe(true);
      expect(mcpServersRepository.updateReportingChange).not.toHaveBeenCalled();
      expect(
        mcpServersRepository.updateMetadataReportingChange,
      ).toHaveBeenCalledWith(
        { uuid: UUID, name: "vendor-renamed", description: undefined },
        "owner-1",
        expect.anything(),
      );
      expect(deniedRows).toHaveLength(0);
      expect(auditRows).toHaveLength(1);
      expect(auditRows[0]).toMatchObject({
        action: "mcpserver.update",
        target_id: UUID,
      });
      expect(result.data).toMatchObject({
        name: "vendor-renamed",
        env: { TOKEN: "" },
        headers: { Authorization: "" },
        url: null,
        command: null,
      });
      expect(JSON.stringify(result)).not.toContain("canary-");
    },
  );

  it("answers a server that is gone, or that someone else owns, without writing a row", async () => {
    vi.mocked(
      mcpServersRepository.updateMetadataReportingChange,
    ).mockResolvedValueOnce({ kind: "not_found" });
    expect(
      await mcpServersImplementations.update(
        metadataUpdate,
        "owner-1",
        actorOf("operator"),
      ),
    ).toEqual({ success: false, message: "MCP server not found" });

    vi.mocked(
      mcpServersRepository.updateMetadataReportingChange,
    ).mockResolvedValueOnce({ kind: "not_owner" });
    expect(
      await mcpServersImplementations.update(
        metadataUpdate,
        "owner-1",
        actorOf("operator"),
      ),
    ).toEqual({
      success: false,
      message: "Access denied: You can only update servers you own",
    });
    expect(auditRows).toHaveLength(0);
  });
});

describe("a reply with no actor", () => {
  it("carries names only, never the stored connection by omission", async () => {
    const created = await mcpServersImplementations.create(
      createInput,
      "owner-1",
    );
    const updated = await mcpServersImplementations.update(
      fullUpdate,
      "owner-1",
    );

    for (const result of [created, updated]) {
      expect(result.success).toBe(true);
      expect(JSON.stringify(result)).not.toContain("canary-");
      expect(result.data).toMatchObject({ env: { TOKEN: "" }, url: null });
    }
  });
});

describe("the listings", () => {
  it("hand each caller the level the router decided, and keep another owner's private row redacted at every level", async () => {
    vi.mocked(mcpServersRepository.findAllAccessibleToUser).mockResolvedValue([
      row(),
    ]);
    vi.mocked(mcpServersRepository.findAll).mockResolvedValue([
      row(),
      row({
        uuid: "22222222-2222-4222-8222-222222222222",
        user_id: "someone-else",
      }),
    ]);

    const names = await mcpServersImplementations.list("owner-1", "names_only");
    expect(names.data[0]).toMatchObject({ env: { TOKEN: "" }, url: null });

    const full = await mcpServersImplementations.list("owner-1", "full");
    expect(full.data[0]).toMatchObject({ env: { TOKEN: CANARY.envValue } });

    for (const level of ["full", "names_only"] as const) {
      const all = await mcpServersImplementations.listAll("owner-1", level);
      const foreign = all.data.find(
        (server) => server.user_id === "someone-else",
      );
      expect(foreign).toMatchObject({ env: {}, headers: {}, url: null });
    }
  });
});

// The repository refuses a write that would give a second server a name in an
// owner scope (ServerNameTakenError, after the name's lock, with nothing
// written). Every caller gets it as the same coded CONFLICT; a key's write
// also leaves one `denied` row naming the rule, and nothing is recorded as
// done. The check itself is pinned against Postgres in
// admin-plane-reply-shape.integration.test.ts.
describe("a server name another server already holds", () => {
  const taken = () => new ServerNameTakenError();
  const cases = {
    "a sync-scope create": [
      "mcpserver.create",
      undefined,
      () => {
        vi.mocked(mcpServersRepository.create).mockRejectedValue(taken());
        return mcpServersImplementations.create(
          createInput,
          "owner-1",
          actorOf("sync"),
        );
      },
    ],
    "a sync-scope full update": [
      "mcpserver.update",
      UUID,
      () => {
        vi.mocked(mcpServersRepository.updateReportingChange).mockRejectedValue(
          taken(),
        );
        return mcpServersImplementations.update(
          fullUpdate,
          "owner-1",
          actorOf("sync"),
        );
      },
    ],
    "an operator-scope rename": [
      "mcpserver.update",
      UUID,
      () => {
        vi.mocked(
          mcpServersRepository.updateMetadataReportingChange,
        ).mockRejectedValue(taken());
        return mcpServersImplementations.update(
          metadataUpdate,
          "owner-1",
          actorOf("operator"),
        );
      },
    ],
  } as const;

  it.each(Object.entries(cases))(
    "refuses %s with the coded conflict, one denied row naming the rule, and no recorded change",
    async (_label, [action, targetId, call]) => {
      await expect(call()).rejects.toMatchObject({
        code: "CONFLICT",
        message: SERVER_NAME_TAKEN_MESSAGE,
      });

      expect(deniedRows).toHaveLength(1);
      expect(deniedRows[0]).toMatchObject({
        action,
        outcome: "denied",
        actor_type: "api_key",
        actor_id: KEY_UUID,
        detail: expect.objectContaining({ rule: "server_name_taken" }),
        ...(targetId ? { target_id: targetId } : {}),
      });
      expect(auditRows).toEqual([]);
      expect(order.at(-2)).toBe("rollback");
    },
  );

  it.each([
    [
      "create",
      () => {
        vi.mocked(mcpServersRepository.create).mockRejectedValue(taken());
        return mcpServersImplementations.create(
          createInput,
          "owner-1",
          actorOf(null),
        );
      },
    ],
    [
      "full update",
      () => {
        vi.mocked(mcpServersRepository.updateReportingChange).mockRejectedValue(
          taken(),
        );
        return mcpServersImplementations.update(
          fullUpdate,
          "owner-1",
          actorOf(null),
        );
      },
    ],
    [
      "rename",
      () => {
        vi.mocked(
          mcpServersRepository.updateMetadataReportingChange,
        ).mockRejectedValue(taken());
        return mcpServersImplementations.update(
          metadataUpdate,
          "owner-1",
          actorOf(null),
        );
      },
    ],
  ] as const)(
    "refuses a person's %s with the same coded conflict, as an error and not as success false",
    async (_label, call) => {
      await expect(call()).rejects.toMatchObject({
        code: "CONFLICT",
        message: SERVER_NAME_TAKEN_MESSAGE,
      });
      expect(deniedRows).toEqual([]);
    },
  );

  it("words the refusal with the two phrases the admin UI reads to flag the name field", () => {
    expect(SERVER_NAME_TAKEN_MESSAGE).toContain("already exists");
    expect(SERVER_NAME_TAKEN_MESSAGE).toContain("Server names must be unique");
  });
});
