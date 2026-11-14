/**
 * What the STDIO proxy actually HANDS TO `spawn()`.
 *
 * `server.spawn-source.test.ts` next door pins the resolver — given a request,
 * which row do we pick and what parameters does it yield. That is necessary and
 * NOT sufficient, and the gap is the whole reason this file exists: a resolver
 * can be perfectly correct while the call site ignores it. Reintroducing the
 * old request-controlled spawn inside `createTransport` leaves every resolver
 * assertion passing, because nothing in that suite ever reaches the constructor.
 *
 * So these tests drive the REAL route — `GET /mcp-proxy/server/stdio`, the
 * handler that used to be the command-execution primitive — and assert on the
 * arguments `ProcessManagedStdioTransport` was CONSTRUCTED with. The transport
 * is the last thing before `spawn()`, so it is the honest place to ask "what
 * would have run".
 *
 * Everything between the route and that constructor is mocked away (the SSE
 * server transport, the proxy pump, the server pool), because none of it
 * participates in the decision under test. The repository is mocked; the
 * spawn-parameter build path — `resolveEnvVariables`, `findActualExecutable` —
 * is REAL, so the env and argv asserted below are the ones production computes.
 */

import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const { spawnCalls, findAllAccessibleToUserMock, findByUuidMock, stdio } =
  vi.hoisted(() => ({
    /** Every ProcessManagedStdioTransport construction, in order. */
    spawnCalls: [] as Array<{
      command: string;
      args: string[];
      env: Record<string, string>;
    }>,
    findAllAccessibleToUserMock: vi.fn(),
    findByUuidMock: vi.fn(),
    /** Closes of those transports, and a gate each start waits on when set. */
    stdio: { closed: 0, startGate: undefined as Promise<void> | undefined },
  }));

// THE ASSERTION SURFACE. Captures what would have been spawned and starts
// nothing: a real one forks a process, which on a test that deliberately sends
// `/bin/sh -c id` is the outcome being guarded against.
vi.mock("../../lib/stdio-transport/process-managed-transport", () => ({
  ProcessManagedStdioTransport: class {
    stderr: undefined = undefined;
    onclose?: () => void;
    onprocesscrash?: (exitCode: number | null, signal: string | null) => void;
    constructor(params: {
      command: string;
      args: string[];
      env: Record<string, string>;
    }) {
      spawnCalls.push(params);
    }
    async start() {
      if (stdio.startGate) await stdio.startGate;
    }
    async close() {
      stdio.closed += 1;
    }
    async send() {}
  },
}));

vi.mock("@modelcontextprotocol/sdk/server/sse.js", () => ({
  SSEServerTransport: class {
    sessionId = "test-session";
    constructor(
      public endpoint: string,
      public res: unknown,
    ) {}
    async start() {}
    async close() {}
    async send() {}
    async handlePostMessage() {}
  },
}));

vi.mock("../../lib/mcp-proxy", () => ({ default: vi.fn() }));

vi.mock("../../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: { handleServerCrashWithoutNamespace: vi.fn() },
}));

vi.mock("../../lib/metamcp/client", () => ({
  transformDockerUrl: (url: string) => url,
}));

vi.mock("../../db/repositories", () => ({
  mcpServersRepository: {
    findAllAccessibleToUser: findAllAccessibleToUserMock,
    findByUuid: findByUuidMock,
    findAll: vi.fn(async () => {
      throw new Error(
        "findAll must not be used to resolve a spawn: it ignores ownership",
      );
    }),
  },
}));

// Stubbed at the leaf so the REAL `resolveEnvVariables` stays in the graph —
// see the sibling suite. `db/index.ts` throws without DATABASE_URL.
vi.mock("../../db/index", () => ({ db: {}, pool: {} }));

const { default: serverRouter } = await import("./server");
const { default: mcpProxy } = await import("../../lib/mcp-proxy");
const {
  closeInspectorSessionsForServer,
  forgetInspectorSession,
  inspectorOpensPending,
  inspectorSessionBelongsToCaller,
} = await import("../../lib/metamcp/inspector-sessions");

const SERVER_UUID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
const OWNER_ID = "user-owner";

const registeredServer = (overrides: Record<string, unknown> = {}) => ({
  uuid: SERVER_UUID,
  name: "filesystem",
  type: "STDIO",
  command: "npx",
  args: ["@modelcontextprotocol/server-filesystem", "/workspace"],
  env: { FILESYSTEM_TOKEN: "s3cret" },
  url: null,
  user_id: null,
  error_status: null,
  ...overrides,
});

/**
 * The attack shape, carried on every request below: a caller-supplied command,
 * args and env riding alongside a perfectly legitimate identifier.
 */
const HOSTILE_QUERY = {
  command: "/bin/sh",
  args: "-c id",
  env: JSON.stringify({ LD_PRELOAD: "/tmp/evil.so" }),
};

/** Drive GET /stdio through the real router and settle. */
async function getStdio(query: Record<string, string>): Promise<number> {
  const search = new URLSearchParams(query).toString();
  const req = {
    method: "GET",
    url: `/stdio?${search}`,
    originalUrl: `/mcp-proxy/server/stdio?${search}`,
    baseUrl: "",
    query: Object.fromEntries(new URLSearchParams(search)),
    headers: {},
    user: { id: OWNER_ID, role: "admin" },
  } as unknown as express.Request;

  let statusCode = 200;
  const res = {
    statusCode: 200,
    status(code: number) {
      statusCode = code;
      return res;
    },
    json() {
      return res;
    },
    end() {
      return res;
    },
    on() {
      return res;
    },
    setHeader() {
      return res;
    },
    writeHead() {
      return res;
    },
    write() {
      return true;
    },
    flushHeaders() {},
  };

  await new Promise<void>((resolve, reject) => {
    (serverRouter as unknown as express.RequestHandler)(
      req,
      res as unknown as express.Response,
      (err?: unknown) => (err ? reject(err) : resolve()),
    );
    // The handler is async and never calls next() on success; settle on the
    // next macrotask, by which point the awaits above have run.
    setTimeout(resolve, 50);
  });

  return statusCode;
}

beforeEach(() => {
  vi.clearAllMocks();
  spawnCalls.length = 0;
  findAllAccessibleToUserMock.mockResolvedValue([registeredServer()]);
  findByUuidMock.mockResolvedValue(undefined);
  // Every case here is about WHICH command reaches the transport, which only
  // exists once stdio servers are allowed; the default refusal comes before
  // all of it and has its own suite (server.stdio-policy.test.ts). Without
  // the opt-in the "spawns NOTHING" cases below would pass for the wrong
  // reason. Scoped to this file and restored after each case.
  vi.stubEnv("ALLOW_STDIO_SERVERS", "true");
  // The SSE transport stand-in names every session "test-session".
  forgetInspectorSession("test-session");
  stdio.startGate = undefined;
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("GET /mcp-proxy/server/stdio — what reaches the transport", () => {
  it("constructs the transport with the ROW's command, not the query's", async () => {
    // THE TEST THE OTHER SUITE CANNOT WRITE. If the query-controlled spawn is
    // reintroduced anywhere between the resolver and the constructor, this is
    // what catches it.
    await getStdio({
      transportType: "STDIO",
      mcpServerUuid: SERVER_UUID,
      ...HOSTILE_QUERY,
    });

    expect(spawnCalls).toHaveLength(1);
    const spawned = spawnCalls[0];
    expect(spawned.command).not.toBe("/bin/sh");
    expect(spawned.command).not.toContain("sh");
    expect(spawned.args).toEqual([
      "@modelcontextprotocol/server-filesystem",
      "/workspace",
    ]);
    expect(spawned.args).not.toContain("-c");
    expect(spawned.args).not.toContain("id");
  });

  it("constructs the transport with the ROW's env, not the query's", async () => {
    await getStdio({
      transportType: "STDIO",
      mcpServerUuid: SERVER_UUID,
      ...HOSTILE_QUERY,
    });

    expect(spawnCalls).toHaveLength(1);
    // LD_PRELOAD is the point: an injected env alone is arbitrary code in the
    // spawned process even when the command is honest.
    expect(spawnCalls[0].env.LD_PRELOAD).toBeUndefined();
    expect(spawnCalls[0].env.FILESYSTEM_TOKEN).toBe("s3cret");
  });

  it("spawns NOTHING when the query names a command nobody registered", async () => {
    await getStdio({ transportType: "STDIO", ...HOSTILE_QUERY });

    expect(spawnCalls).toEqual([]);
  });

  it("spawns NOTHING for a server belonging to another user", async () => {
    // The row exists and the caller is an admin; it is simply not theirs. The
    // repository answers with the accessible set, so an inaccessible uuid finds
    // no row — asserted at the constructor because that is where the private
    // server's stored secrets would have been handed to a process.
    findAllAccessibleToUserMock.mockResolvedValue([]);
    findByUuidMock.mockResolvedValue(
      registeredServer({ user_id: "someone-else" }),
    );

    await getStdio({
      transportType: "STDIO",
      mcpServerUuid: SERVER_UUID,
      ...HOSTILE_QUERY,
    });

    expect(spawnCalls).toEqual([]);
    expect(findAllAccessibleToUserMock).toHaveBeenCalledWith(OWNER_ID);
  });

  it("spawns NOTHING on a malformed identifier, and asks the DB nothing about it", async () => {
    // "undefined" is the literal string a stale bundle sends, and a non-uuid
    // reaching a Postgres `uuid` column raises 22P02 in the driver. It cannot
    // get there: the only value any repository call receives is the session's
    // user id, so the refusal happens entirely in memory.
    await getStdio({
      transportType: "STDIO",
      mcpServerUuid: "undefined",
      ...HOSTILE_QUERY,
    });

    expect(spawnCalls).toEqual([]);
    expect(findByUuidMock).not.toHaveBeenCalled();
    expect(findAllAccessibleToUserMock.mock.calls.flat()).toEqual([OWNER_ID]);
  });

  it("still spawns a legitimate server the caller may reach", async () => {
    // The closure must not be "refuse everything": the Inspector has to work.
    await getStdio({ transportType: "STDIO", mcpServerUuid: SERVER_UUID });

    expect(spawnCalls).toHaveLength(1);
    expect(spawnCalls[0].args).toEqual([
      "@modelcontextprotocol/server-filesystem",
      "/workspace",
    ]);
  });

  it("still spawns for an older client that sends only the command line", async () => {
    await getStdio({
      transportType: "STDIO",
      command: "npx",
      args: "@modelcontextprotocol/server-filesystem /workspace",
    });

    expect(spawnCalls).toHaveLength(1);
    expect(spawnCalls[0].args).toEqual([
      "@modelcontextprotocol/server-filesystem",
      "/workspace",
    ]);
  });

  it("refuses to spawn a server the row marks as in ERROR", async () => {
    findAllAccessibleToUserMock.mockResolvedValue([
      registeredServer({ error_status: "ERROR" }),
    ]);

    await getStdio({ transportType: "STDIO", mcpServerUuid: SERVER_UUID });

    expect(spawnCalls).toEqual([]);
  });

  it("does NOT leak the gateway's own process.env secrets into the child env", async () => {
    // The Inspector used to spread the whole gateway process.env into the
    // spawned child, so an npx MCP an admin registers inherited DATABASE_URL,
    // BETTER_AUTH_SECRET and every vendor secret. The child env is now the
    // curated getDefaultEnvironment (which allowlists operational vars, NOT
    // arbitrary secrets) plus the row's own env. A gateway secret no server env
    // references must not reach the child; the row's FILESYSTEM_TOKEN still
    // must, proving the curated path is not simply empty. Real declared gateway
    // vars are used (saved/restored) so this asserts against the actual secrets.
    const priorAuth = process.env.BETTER_AUTH_SECRET;
    const priorDb = process.env.DATABASE_URL;
    process.env.BETTER_AUTH_SECRET = "auth-secret-must-not-leak";
    process.env.DATABASE_URL = "postgres://must-not-leak";
    try {
      await getStdio({ transportType: "STDIO", mcpServerUuid: SERVER_UUID });
    } finally {
      if (priorAuth === undefined) delete process.env.BETTER_AUTH_SECRET;
      else process.env.BETTER_AUTH_SECRET = priorAuth;
      if (priorDb === undefined) delete process.env.DATABASE_URL;
      else process.env.DATABASE_URL = priorDb;
    }

    expect(spawnCalls).toHaveLength(1);
    expect(spawnCalls[0].env.BETTER_AUTH_SECRET).toBeUndefined();
    expect(spawnCalls[0].env.DATABASE_URL).toBeUndefined();
    expect(spawnCalls[0].env.FILESYSTEM_TOKEN).toBe("s3cret");
  });
});

/**
 * GET /stdio driven like `getStdio`, as `user` (the session user the gates
 * leave on the request; null for none), keeping the answer and the response
 * listeners the route registered.
 */
async function driveStdio(
  query: Record<string, string>,
  user: { id: unknown; role: string } | null = {
    id: OWNER_ID,
    role: "admin",
  },
) {
  const search = new URLSearchParams(query).toString();
  const req = {
    method: "GET",
    url: `/stdio?${search}`,
    originalUrl: `/mcp-proxy/server/stdio?${search}`,
    baseUrl: "",
    query: Object.fromEntries(new URLSearchParams(search)),
    headers: {},
    user: user ?? undefined,
  } as unknown as express.Request;

  const answer = { status: 200, body: undefined as unknown };
  const listeners: Record<string, Array<() => void>> = {};
  const res = {
    statusCode: 200,
    headersSent: false,
    status(code: number) {
      answer.status = code;
      return res;
    },
    json(body: unknown) {
      answer.body = body;
      return res;
    },
    end() {
      return res;
    },
    on(event: string, listener: () => void) {
      (listeners[event] ??= []).push(listener);
      return res;
    },
    setHeader() {
      return res;
    },
    writeHead() {
      return res;
    },
    write() {
      return true;
    },
    flushHeaders() {},
  };

  const done = new Promise<void>((resolve, reject) => {
    (serverRouter as unknown as express.RequestHandler)(
      req,
      res as unknown as express.Response,
      (err?: unknown) => (err ? reject(err) : resolve()),
    );
    setTimeout(resolve, 50);
  });

  return { answer, listeners, done };
}

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

const OTHER_SERVER_UUID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";

describe("GET /mcp-proxy/server/stdio: the session it opens", () => {
  it("belongs to the user who opened it and closes with its row", async () => {
    const pendingBefore = inspectorOpensPending();
    const { done } = await driveStdio({
      transportType: "STDIO",
      mcpServerUuid: SERVER_UUID,
    });
    await done;

    expect(spawnCalls).toHaveLength(1);
    // The stream stays open (this response double never closes), but the
    // open itself is over.
    expect(inspectorOpensPending()).toBe(pendingBefore);
    expect(
      inspectorSessionBelongsToCaller("test-session", {
        user: { id: OWNER_ID },
      } as never),
    ).toBe(true);
    expect(
      inspectorSessionBelongsToCaller("test-session", {
        user: { id: "someone-else" },
      } as never),
    ).toBe(false);

    const closedBefore = stdio.closed;
    expect(await closeInspectorSessionsForServer(OTHER_SERVER_UUID)).toBe(0);
    expect(await closeInspectorSessionsForServer(SERVER_UUID)).toBe(1);
    expect(stdio.closed).toBeGreaterThan(closedBefore);
    expect(
      inspectorSessionBelongsToCaller("test-session", {
        user: { id: OWNER_ID },
      } as never),
    ).toBe(false);
  });

  it("is not opened when its row changes while the process starts, and the process is closed", async () => {
    const gate = deferred();
    stdio.startGate = gate.promise;
    const pendingBefore = inspectorOpensPending();

    const { answer, done } = await driveStdio({
      transportType: "STDIO",
      mcpServerUuid: SERVER_UUID,
    });
    await vi.waitFor(() => expect(spawnCalls).toHaveLength(1));
    await closeInspectorSessionsForServer(SERVER_UUID);
    const closedBefore = stdio.closed;
    gate.resolve();
    await done;

    await vi.waitFor(() => expect(stdio.closed).toBeGreaterThan(closedBefore));
    await vi.waitFor(() => expect(answer.status).toBe(409));
    expect(
      inspectorSessionBelongsToCaller("test-session", {
        user: { id: OWNER_ID },
      } as never),
    ).toBe(false);
    expect(inspectorOpensPending()).toBe(pendingBefore);
  });

  it("opens when another row changes while the process starts (control)", async () => {
    const gate = deferred();
    stdio.startGate = gate.promise;

    const { answer, done } = await driveStdio({
      transportType: "STDIO",
      mcpServerUuid: SERVER_UUID,
    });
    await vi.waitFor(() => expect(spawnCalls).toHaveLength(1));
    await closeInspectorSessionsForServer(OTHER_SERVER_UUID);
    gate.resolve();
    await done;

    await vi.waitFor(() =>
      expect(
        inspectorSessionBelongsToCaller("test-session", {
          user: { id: OWNER_ID },
        } as never),
      ).toBe(true),
    );
    expect(answer.status).toBe(200);
  });

  it("is not opened when the request ends while the process starts, and the process is closed", async () => {
    const gate = deferred();
    stdio.startGate = gate.promise;
    const pendingBefore = inspectorOpensPending();

    const { listeners, done } = await driveStdio({
      transportType: "STDIO",
      mcpServerUuid: SERVER_UUID,
    });
    await vi.waitFor(() => expect(spawnCalls).toHaveLength(1));
    expect(inspectorOpensPending()).toBe(pendingBefore + 1);
    for (const listener of listeners.close ?? []) listener();
    expect(inspectorOpensPending()).toBe(pendingBefore);
    const closedBefore = stdio.closed;
    gate.resolve();
    await done;

    await vi.waitFor(() => expect(stdio.closed).toBeGreaterThan(closedBefore));
    expect(
      inspectorSessionBelongsToCaller("test-session", {
        user: { id: OWNER_ID },
      } as never),
    ).toBe(false);
    expect(await closeInspectorSessionsForServer(SERVER_UUID)).toBe(0);
  });
});

describe("GET /mcp-proxy/server/stdio: an open with no usable user id", () => {
  it.each([
    ["no signed-in user", null, 0, 500],
    ["a user whose id is a number", { id: 42, role: "admin" }, 1, 409],
  ])(
    "with %s issues no session id and leaves no process open",
    async (_label, user, spawned, status) => {
      const pendingBefore = inspectorOpensPending();
      const closedBefore = stdio.closed;

      const { answer, done } = await driveStdio(
        { transportType: "STDIO", mcpServerUuid: SERVER_UUID },
        user,
      );
      await done;

      await vi.waitFor(() => expect(answer.status).toBe(status));
      expect(spawnCalls).toHaveLength(spawned);
      expect(stdio.closed - closedBefore).toBe(spawned);
      // The refused open is never wired to the client.
      expect(mcpProxy).not.toHaveBeenCalled();
      expect(inspectorOpensPending()).toBe(pendingBefore);
      expect(
        inspectorSessionBelongsToCaller("test-session", {
          user: { id: OWNER_ID },
        } as never),
      ).toBe(false);
      expect(await closeInspectorSessionsForServer(SERVER_UUID)).toBe(0);
    },
  );
});
