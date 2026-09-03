/**
 * Ownership scoping for the `tools.getByMcpServerUuid` implementation.
 *
 * The tool catalog (names, descriptions, input schemas) is a per-user
 * disclosure surface, the same class as the server row itself. `mcpServers.get`
 * already gates that row to own-plus-public; this reader used to return any
 * server's catalog to any authenticated caller who knew the UUID, with no
 * ownership check at all. The suite pins the three outcomes that matter: a
 * member is refused another user's PRIVATE server, allowed on a PUBLIC
 * (unowned) server, and allowed on their OWN server. The refusal path must
 * also never reach the catalog query.
 *
 * Same isolation approach as `mcp-servers.reconnect.impl.test.ts`: the
 * `../db/repositories` barrel reaches `db/index`, which needs a live
 * DATABASE_URL, so it is stubbed and the unit needs no postgres.
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

vi.mock("../db/repositories", () => ({
  mcpServersRepository: { findByUuid: vi.fn() },
  toolsRepository: { findByMcpServerUuid: vi.fn() },
}));

// Passthrough serializer: the ownership decision is the unit under test, not
// the shape mapping, and mocking the barrel keeps db out of the import graph.
vi.mock("../db/serializers", () => ({
  ToolsSerializer: { serializeToolList: vi.fn((tools) => tools) },
}));

import { mcpServersRepository, toolsRepository } from "../db/repositories";
import { toolsImplementations } from "./tools.impl";

const SERVER_UUID = "11111111-1111-4111-8111-111111111111";
const OWNER_ID = "owner-1";
const OTHER_ID = "member-2";

const fakeServer = (overrides: Record<string, unknown> = {}) =>
  ({
    uuid: SERVER_UUID,
    name: "autotask",
    user_id: null,
    ...overrides,
  }) as any;

const CATALOG = [
  { uuid: "tool-1", name: "create_ticket", description: "", toolSchema: {} },
];

describe("tools.getByMcpServerUuid — ownership scoping", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(toolsRepository.findByMcpServerUuid).mockResolvedValue(
      CATALOG as never,
    );
  });

  it("refuses a member reading another user's PRIVATE server catalog", async () => {
    vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue(
      fakeServer({ user_id: OWNER_ID }),
    );

    const result = await toolsImplementations.getByMcpServerUuid(
      { mcpServerUuid: SERVER_UUID },
      OTHER_ID,
    );

    expect(result.success).toBe(false);
    expect(result.data).toEqual([]);
    // The catalog query must never run once ownership is refused.
    expect(toolsRepository.findByMcpServerUuid).not.toHaveBeenCalled();
  });

  it("allows any member on a PUBLIC (unowned) server", async () => {
    vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue(
      fakeServer({ user_id: null }),
    );

    const result = await toolsImplementations.getByMcpServerUuid(
      { mcpServerUuid: SERVER_UUID },
      OTHER_ID,
    );

    expect(result.success).toBe(true);
    expect(result.data).toEqual(CATALOG);
    expect(toolsRepository.findByMcpServerUuid).toHaveBeenCalledWith(
      SERVER_UUID,
    );
  });

  it("allows the OWNER on their own private server", async () => {
    vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue(
      fakeServer({ user_id: OWNER_ID }),
    );

    const result = await toolsImplementations.getByMcpServerUuid(
      { mcpServerUuid: SERVER_UUID },
      OWNER_ID,
    );

    expect(result.success).toBe(true);
    expect(result.data).toEqual(CATALOG);
    expect(toolsRepository.findByMcpServerUuid).toHaveBeenCalledWith(
      SERVER_UUID,
    );
  });
});
