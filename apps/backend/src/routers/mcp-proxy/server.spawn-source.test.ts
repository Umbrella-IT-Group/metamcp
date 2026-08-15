/**
 * Where the MCP proxy's STDIO spawn parameters come from.
 *
 * `createTransport` used to read `command`, `args` and `env` off the query
 * string and hand them to `ProcessManagedStdioTransport`, i.e. the request
 * described the process and the backend ran it with its own environment. The
 * request now only IDENTIFIES a registered `mcp_servers` row; the row supplies
 * everything that reaches `spawn()`.
 *
 * The load-bearing assertion in this file is the negative one: NO request
 * shape may produce spawn parameters that are not in a server record. The
 * positive cases are here so the closure can never be "fixed" by refusing
 * everything — the Inspector has to keep working.
 *
 * `resolveStdioSpawnParams` is exported for this suite (the same pattern
 * `checkApiKeyAccess` and `resolveActsAsUserId` follow), which keeps the MCP
 * SDK's server transports and the server pool out of the import graph.
 *
 * THIS SUITE IS HALF THE PROOF AND KNOWS IT. A resolver can be correct while
 * the call site ignores it — reintroducing the request-controlled spawn inside
 * `createTransport` leaves every assertion here passing, because nothing below
 * reaches the transport constructor. `server.spawn-call-site.test.ts` drives
 * the real route and asserts on what the constructor received; the two are
 * required together and neither is sufficient alone.
 */

import express from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const { findAccessibleMock, findAllMock, findByUuidMock } = vi.hoisted(() => ({
  findAccessibleMock: vi.fn(),
  findAllMock: vi.fn(),
  findByUuidMock: vi.fn(),
}));

// `findAll` and `findByUuid` are wired as TRIPWIRES, not as fallbacks. Both
// ignore ownership, and resolving a spawn through either is the bug the
// ownership scope below exists to prevent — so a regression that reaches for
// them fails loudly here instead of silently widening what an admin can start.
vi.mock("../../db/repositories", () => ({
  mcpServersRepository: {
    findAllAccessibleToUser: findAccessibleMock,
    findAll: findAllMock,
    findByUuid: findByUuidMock,
  },
}));

// The server pool reaches the database and the metamcp client stack; neither
// is involved in resolving spawn parameters.
vi.mock("../../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: { handleServerCrashWithoutNamespace: vi.fn() },
}));

vi.mock("../../lib/metamcp/client", () => ({
  transformDockerUrl: (url: string) => url,
}));

// Stubbed at the leaf rather than by mocking `lib/metamcp/utils`, so the REAL
// `resolveEnvVariables` runs against the row's env — the env assertions below
// would be worthless against a reimplementation. `db/index.ts` throws without
// DATABASE_URL and is reached transitively through that module.
vi.mock("../../db/index", () => ({ db: {}, pool: {} }));

const { resolveStdioSpawnParams } = await import("./server");

const SERVER_UUID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";

/** A registered STDIO row, in the shape `mcp_servers` rows arrive in. */
const registeredServer = (overrides: Record<string, unknown> = {}) => ({
  uuid: SERVER_UUID,
  name: "filesystem",
  type: "STDIO",
  command: "npx",
  args: ["@modelcontextprotocol/server-filesystem", "/workspace"],
  env: { FILESYSTEM_TOKEN: "s3cret" },
  url: null,
  error_status: null,
  ...overrides,
});

const OWNER_ID = "user-owner";

const makeReq = (
  query: Record<string, string>,
  user: { id?: string } | undefined = { id: OWNER_ID },
): express.Request => ({ query, user }) as unknown as express.Request;

beforeEach(() => {
  vi.clearAllMocks();
  findAccessibleMock.mockResolvedValue([]);
  findByUuidMock.mockRejectedValue(
    new Error("findByUuid ignores ownership and must not resolve a spawn"),
  );
  findAllMock.mockRejectedValue(
    new Error("findAll ignores ownership and must not resolve a spawn"),
  );
});

describe("resolveStdioSpawnParams — the request cannot describe the process", () => {
  it("spawns the ROW's command even when the query asks for another one", async () => {
    // The exact primitive: a caller who can reach this route sends its own
    // command alongside a legitimate uuid. The uuid is honoured; the command
    // is not read at all.
    findAccessibleMock.mockResolvedValue([registeredServer()]);

    const params = await resolveStdioSpawnParams(
      makeReq({
        transportType: "STDIO",
        mcpServerUuid: SERVER_UUID,
        command: "/bin/sh",
        args: "-c id",
        env: JSON.stringify({ INJECTED: "1" }),
      }),
    );

    expect(params.cmd).not.toContain("/bin/sh");
    expect(params.args).toEqual([
      "@modelcontextprotocol/server-filesystem",
      "/workspace",
    ]);
    expect(params.args).not.toContain("-c");
    expect(params.args).not.toContain("id");
    expect(params.env.INJECTED).toBeUndefined();
    expect(params.env.FILESYSTEM_TOKEN).toBe("s3cret");
    expect(params.serverUuid).toBe(SERVER_UUID);
  });

  it("refuses a command that matches no registered server", async () => {
    findAccessibleMock.mockResolvedValue([registeredServer()]);

    await expect(
      resolveStdioSpawnParams(
        makeReq({
          transportType: "STDIO",
          command: "/bin/sh",
          args: "-c id",
        }),
      ),
    ).rejects.toThrow(/No registered STDIO MCP server/);
  });

  it("refuses an unknown uuid rather than falling back to the query command", async () => {
    // Fail closed: an unresolvable identifier must not hand the decision back
    // to the caller-supplied command line.
    findAccessibleMock.mockResolvedValue([registeredServer()]);

    await expect(
      resolveStdioSpawnParams(
        makeReq({
          transportType: "STDIO",
          mcpServerUuid: "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb",
          command: "npx",
          args: "@modelcontextprotocol/server-filesystem /workspace",
        }),
      ),
    ).rejects.toThrow(/No registered STDIO MCP server/);
  });

  it("refuses a uuid that resolves to a non-STDIO server", async () => {
    findAccessibleMock.mockResolvedValue([
      registeredServer({ type: "SSE", command: null, url: "https://example" }),
    ]);

    await expect(
      resolveStdioSpawnParams(
        makeReq({ transportType: "STDIO", mcpServerUuid: SERVER_UUID }),
      ),
    ).rejects.toThrow(/No registered STDIO MCP server/);
  });

  it("does NOT accept a command-only match — `npx <anything>` is not a match", async () => {
    // A registered server running `npx` must not make every `npx ...` line
    // legitimate. The whole command line has to match, or nothing does.
    findAccessibleMock.mockResolvedValue([registeredServer()]);

    await expect(
      resolveStdioSpawnParams(
        makeReq({
          transportType: "STDIO",
          command: "npx",
          args: "--yes attacker-package",
        }),
      ),
    ).rejects.toThrow(/No registered STDIO MCP server/);
  });

  it("ignores a query env even on the command-matched path", async () => {
    findAccessibleMock.mockResolvedValue([registeredServer()]);

    const params = await resolveStdioSpawnParams(
      makeReq({
        transportType: "STDIO",
        command: "npx",
        args: "@modelcontextprotocol/server-filesystem /workspace",
        env: JSON.stringify({ LD_PRELOAD: "/tmp/evil.so" }),
      }),
    );

    expect(params.env.LD_PRELOAD).toBeUndefined();
    expect(params.serverUuid).toBe(SERVER_UUID);
  });
});

describe("resolveStdioSpawnParams — scoped to what the caller may see", () => {
  it("resolves against the caller's ACCESSIBLE set, not every row", async () => {
    // The admin gate on this router answers "may this person use the proxy",
    // not "whose servers may they start". `findAll` / `findByUuid` are armed to
    // reject in beforeEach, so reaching for either fails here.
    findAccessibleMock.mockResolvedValue([registeredServer()]);

    await resolveStdioSpawnParams(
      makeReq({ transportType: "STDIO", mcpServerUuid: SERVER_UUID }),
    );

    expect(findAccessibleMock).toHaveBeenCalledWith(OWNER_ID);
    expect(findAllMock).not.toHaveBeenCalled();
    expect(findByUuidMock).not.toHaveBeenCalled();
  });

  it("refuses another user's PRIVATE server by uuid", async () => {
    // The row exists and the caller is an admin; it is simply not theirs, so
    // it never appears in their own server list. Starting it would drive that
    // user's tools with that user's stored env secrets.
    findAccessibleMock.mockResolvedValue([]);

    await expect(
      resolveStdioSpawnParams(
        makeReq({ transportType: "STDIO", mcpServerUuid: SERVER_UUID }),
      ),
    ).rejects.toThrow(/No registered STDIO MCP server/);
  });

  it("refuses another user's PRIVATE server by command line too", async () => {
    // Scoping only the uuid path would leave the fallback as the way around it.
    findAccessibleMock.mockResolvedValue([]);

    await expect(
      resolveStdioSpawnParams(
        makeReq({
          transportType: "STDIO",
          command: "npx",
          args: "@modelcontextprotocol/server-filesystem /workspace",
        }),
      ),
    ).rejects.toThrow(/No registered STDIO MCP server/);
  });

  it("refuses when the request carries no session user at all", async () => {
    // Fail closed rather than resolving against an undefined scope.
    await expect(
      resolveStdioSpawnParams(
        makeReq({ transportType: "STDIO", mcpServerUuid: SERVER_UUID }, {}),
      ),
    ).rejects.toThrow(/No registered STDIO MCP server/);
    expect(findAccessibleMock).not.toHaveBeenCalled();
  });

  it('refuses a MALFORMED identifier, including the literal "undefined"', async () => {
    // Pins the BEHAVIOUR, and is honest about what proves it: the ownership
    // scope resolves in memory, so no caller-supplied uuid reaches Postgres and
    // the 22P02 these values would otherwise raise is already unreachable.
    // Deleting the explicit uuid check therefore does NOT fail this test — it
    // is a guard rail for a future by-uuid lookup, not the thing keeping these
    // refusals correct today. See the note on `uuidSchema`.
    findAccessibleMock.mockResolvedValue([registeredServer()]);

    for (const malformed of ["undefined", "null", "' OR 1=1--", "not-a-uuid"]) {
      await expect(
        resolveStdioSpawnParams(
          makeReq({ transportType: "STDIO", mcpServerUuid: malformed }),
        ),
      ).rejects.toThrow(/No registered STDIO MCP server/);
    }
  });

  it("never passes a caller-supplied value to a repository lookup", async () => {
    // The structural reason the malformed case above is safe: the only argument
    // any repository call receives is the SESSION's user id.
    findAccessibleMock.mockResolvedValue([registeredServer()]);

    await resolveStdioSpawnParams(
      makeReq({
        transportType: "STDIO",
        mcpServerUuid: "undefined",
        command: "/bin/sh",
      }),
    ).catch(() => undefined);

    expect(findAccessibleMock.mock.calls.flat()).toEqual([OWNER_ID]);
    expect(findAllMock).not.toHaveBeenCalled();
    expect(findByUuidMock).not.toHaveBeenCalled();
  });

  it("answers every refusal with the SAME message", async () => {
    // No enumeration oracle: "wrong uuid", "malformed uuid", "not yours" and
    // "no such command" must be indistinguishable to the caller.
    findAccessibleMock.mockResolvedValue([]);

    const messages: string[] = [];
    const queries: Record<string, string>[] = [
      { transportType: "STDIO", mcpServerUuid: SERVER_UUID },
      { transportType: "STDIO", mcpServerUuid: "undefined" },
      { transportType: "STDIO", command: "/bin/sh", args: "-c id" },
    ];
    for (const query of queries) {
      await resolveStdioSpawnParams(makeReq(query)).catch((error: Error) =>
        messages.push(error.message),
      );
    }

    expect(messages).toHaveLength(3);
    expect(new Set(messages).size).toBe(1);
  });
});

describe("resolveStdioSpawnParams — the Inspector still connects", () => {
  it("resolves a registered server by uuid", async () => {
    findAccessibleMock.mockResolvedValue([registeredServer()]);

    const params = await resolveStdioSpawnParams(
      makeReq({ transportType: "STDIO", mcpServerUuid: SERVER_UUID }),
    );

    expect(findAccessibleMock).toHaveBeenCalledWith(OWNER_ID);
    expect(params.serverName).toBe("filesystem");
    expect(params.args).toEqual([
      "@modelcontextprotocol/server-filesystem",
      "/workspace",
    ]);
  });

  it("resolves an older client that sends only the command line", async () => {
    // Back-compat path: a tab still holding the previous bundle sends no
    // uuid. It keeps working because its command line matches a real row —
    // and the row is still what gets spawned.
    findAccessibleMock.mockResolvedValue([registeredServer()]);

    const params = await resolveStdioSpawnParams(
      makeReq({
        transportType: "STDIO",
        command: "npx",
        args: "@modelcontextprotocol/server-filesystem /workspace",
      }),
    );

    expect(params.serverUuid).toBe(SERVER_UUID);
  });

  it("matches a server that has no args at all", async () => {
    findAccessibleMock.mockResolvedValue([
      registeredServer({ command: "my-server", args: [] }),
    ]);

    const params = await resolveStdioSpawnParams(
      makeReq({ transportType: "STDIO", command: "my-server", args: "" }),
    );

    expect(params.serverUuid).toBe(SERVER_UUID);
    expect(params.args).toEqual([]);
  });

  it("keeps an argument that contains a space in one piece", async () => {
    // The old path flattened args to a string and shell-parsed them back,
    // which split `/my documents` into two arguments. Reading the stored array
    // is what fixes that.
    findAccessibleMock.mockResolvedValue([
      registeredServer({ args: ["--root", "/my documents"] }),
    ]);

    const params = await resolveStdioSpawnParams(
      makeReq({ transportType: "STDIO", mcpServerUuid: SERVER_UUID }),
    );

    expect(params.args).toEqual(["--root", "/my documents"]);
  });

  it("reports the row's error status instead of swallowing it", async () => {
    findAccessibleMock.mockResolvedValue([
      registeredServer({ error_status: "ERROR" }),
    ]);

    const params = await resolveStdioSpawnParams(
      makeReq({ transportType: "STDIO", mcpServerUuid: SERVER_UUID }),
    );

    expect(params.errorStatus).toBe("ERROR");
  });

  it("passes the backend environment through, so a server keeps its own", async () => {
    // Read generically rather than by name: the spawned process inherits the
    // whole backend environment, and naming one variable here would both pin
    // an assumption about the host and add it to turbo's declared env set.
    findAccessibleMock.mockResolvedValue([registeredServer()]);

    const params = await resolveStdioSpawnParams(
      makeReq({ transportType: "STDIO", mcpServerUuid: SERVER_UUID }),
    );

    const [inheritedKey, inheritedValue] = Object.entries(process.env)[0];
    expect(params.env[inheritedKey]).toBe(inheritedValue);
  });
});
