/**
 * How the namespace-level pool hands out a proxy for a session that has a
 * presentation (title, instructions, output-schema trim).
 *
 * An idle shell is built per namespace before any client or endpoint exists, so
 * it cannot carry endpoint-level settings, and the SDK reads `instructions` and
 * `serverInfo` only at construction. A session WITH a presentation therefore
 * never converts the idle shell: it gets a fresh one built with the
 * presentation, and the idle shell stays for the next default session. A
 * session WITHOUT one converts the idle shell and calls `createServer` with
 * the same arguments it always did.
 *
 * Oracle: the pool's own contract as the existing suite
 * (metamcp-server-pool.test.ts) pins it, and the design's rule that a default
 * session's path is unchanged. The `createServer` mock records the argument
 * list it receives, so a stray extra argument on a default session is visible.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const { createServerMock } = vi.hoisted(() => ({
  createServerMock: vi.fn(),
}));

vi.mock("./metamcp-proxy", () => ({
  createServer: createServerMock,
}));

vi.mock("./mcp-server-pool", () => ({
  mcpServerPool: {
    cleanupSession: vi.fn().mockResolvedValue(undefined),
    cleanupAll: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../config.service", () => ({
  configService: {
    getSessionLifetime: vi.fn().mockResolvedValue(null),
  },
}));

vi.mock("@/utils/logger", () => ({
  default: {
    error: vi.fn(),
    warn: vi.fn(),
    info: vi.fn(),
    debug: vi.fn(),
  },
}));

import type { SessionPresentation } from "./endpoint-presentation";
import { MetaMcpServerPool } from "./metamcp-server-pool";

// The constructor is private (singleton); a fresh instance per test.
const PoolConstructor = MetaMcpServerPool as unknown as new (
  defaultIdleCount?: number,
) => MetaMcpServerPool;

type Instance = { server: unknown; cleanup: () => Promise<void> };
type PoolInternals = {
  idleServers: Record<string, Instance>;
  activeServers: Record<string, Instance>;
};

const NS = "ns-1";
const PRESENTATION: SessionPresentation = {
  title: "Desk",
  instructions: "Be brief.",
  toolListing: "full",
  omitOutputSchemas: true,
};

function makeInstance(label: string) {
  return { server: { label }, cleanup: () => Promise.resolve() };
}

/** Let the pool's fire-and-forget idle replacement run to completion. */
const settleIdleReplacement = () =>
  new Promise<void>((resolve) => setImmediate(resolve));

describe("MetaMcpServerPool.getServer with a presentation", () => {
  let pool: MetaMcpServerPool;
  let internals: PoolInternals;

  beforeEach(() => {
    vi.clearAllMocks();
    pool = new PoolConstructor();
    internals = pool as unknown as PoolInternals;
    createServerMock.mockImplementation(async (_ns: string, id: string) =>
      makeInstance(`built-for-${id}`),
    );
  });

  it("pin: a session without a presentation converts the idle shell, and builds only the replacement, with the three-argument call", async () => {
    const idle = makeInstance("idle-shell");
    internals.idleServers[NS] = idle;

    const served = await pool.getServer("session-default", NS);
    await settleIdleReplacement();

    expect(served?.server).toBe(idle.server);
    expect(internals.activeServers["session-default"]).toBe(served);
    // Only the replacement idle shell was built, exactly as before.
    expect(createServerMock).toHaveBeenCalledTimes(1);
    expect(createServerMock).toHaveBeenCalledWith(
      NS,
      expect.stringMatching(/^idle_/),
      false,
    );
  });

  it("pin: with no idle shell, a session without a presentation is built with the three-argument call", async () => {
    await pool.getServer("session-default", NS);
    await settleIdleReplacement();

    expect(createServerMock).toHaveBeenCalledWith(NS, "session-default", false);
  });

  it("builds a fresh shell with the presentation and leaves the idle shell for the next default session", async () => {
    const idle = makeInstance("idle-shell");
    internals.idleServers[NS] = idle;

    const served = await pool.getServer(
      "session-presented",
      NS,
      false,
      PRESENTATION,
    );
    await settleIdleReplacement();

    expect(served?.server).not.toBe(idle.server);
    expect(served?.server).toEqual({ label: "built-for-session-presented" });
    expect(createServerMock).toHaveBeenCalledWith(
      NS,
      "session-presented",
      false,
      PRESENTATION,
    );
    // The idle shell was not used or replaced.
    expect(internals.idleServers[NS]).toBe(idle);
    expect(internals.activeServers["session-presented"]).toBe(served);
  });

  it("a second request for the same session id returns the same instance and builds nothing", async () => {
    const first = await pool.getServer(
      "session-presented",
      NS,
      false,
      PRESENTATION,
    );
    await settleIdleReplacement();
    createServerMock.mockClear();

    const second = await pool.getServer(
      "session-presented",
      NS,
      false,
      PRESENTATION,
    );

    expect(second).toBe(first);
    expect(createServerMock).not.toHaveBeenCalled();
  });

  it("the next default session still converts the idle shell the presentation session left", async () => {
    const idle = makeInstance("idle-shell");
    internals.idleServers[NS] = idle;
    await pool.getServer("session-presented", NS, false, PRESENTATION);
    await settleIdleReplacement();

    const served = await pool.getServer("session-default", NS);

    expect(served?.server).toBe(idle.server);
  });
});
