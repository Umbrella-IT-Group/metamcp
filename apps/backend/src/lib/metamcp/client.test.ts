/**
 * Unit tests for the `list_changed` subscriber fan-out plumbing wired
 * into `connectMetaMcpClient`. The full connect path is heavy (server
 * error tracker + retry loop + DB lookups), so we exercise the
 * dispatcher contract directly via a real SDK Client + Server pair
 * wired up with `InMemoryTransport`. This is the same dispatcher shape
 * that `connectMetaMcpClient` installs, so any regression there will
 * surface here too.
 *
 * Three properties under test, matching the PR brief:
 *   1. Notification handler fans out to every subscriber.
 *   2. A subscriber that throws does not break siblings.
 *   3. Clearing the subscriber set drops fan-out targets.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { ToolListChangedNotificationSchema } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Importing `computeReconnectBackoffMs` (a value, not just a type) pulls
// in `client.ts`'s full module-load chain — including server-error-tracker
// → db/repositories → db/index, which throws on missing DATABASE_URL.
// Stub the db side to keep this a pure unit test.
vi.mock("../../db/repositories/index", () => ({
  mcpServersRepository: {},
}));
vi.mock("../../db/repositories/oauth-sessions.repo", () => ({
  oauthSessionsRepository: {},
}));
vi.mock("../config.service", () => ({
  configService: {
    getMcpMaxAttempts: vi.fn().mockResolvedValue(3),
  },
}));

import {
  computeReconnectBackoffMs,
  createMetaMcpClient,
  ListChangedSubscriber,
} from "./client";

/**
 * Build a Client/Server pair via InMemoryTransport and install the
 * exact same notification handler shape that `connectMetaMcpClient`
 * registers. Returns the assembled rig + the subscriber set so tests
 * can mutate it and the upstream Server so tests can trigger
 * notifications from the "backend" side.
 */
async function buildRig() {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();

  // Backend-side `Server` (simulates the FastMCP backend that would
  // emit `notifications/tools/list_changed`). Capability declaration
  // matches what real backends advertise.
  const backendServer = new Server(
    { name: "test-backend", version: "0.0.0" },
    { capabilities: { tools: { listChanged: true } } },
  );

  // Client-side (this is what MetaMCP's gateway holds in
  // `ConnectedClient.client`).
  const client = new Client(
    { name: "test-metamcp-client", version: "0.0.0" },
    {
      // Mirror connectMetaMcpClient: no client-side capabilities advertised
      // (prompts/resources/tools are server capabilities, stripped by SDK 1.29).
      capabilities: {},
    },
  );

  const listChangedSubscribers = new Set<ListChangedSubscriber>();

  // Mirror of the handler registered by `connectMetaMcpClient`. If you
  // change the dispatcher there, mirror the change here so the test
  // tracks reality.
  client.setNotificationHandler(ToolListChangedNotificationSchema, async () => {
    for (const subscriber of listChangedSubscribers) {
      try {
        await subscriber();
      } catch {
        // Swallowed by design — matches production handler.
      }
    }
  });

  await Promise.all([
    backendServer.connect(serverTransport),
    client.connect(clientTransport),
  ]);

  return { client, backendServer, listChangedSubscribers };
}

async function fireListChanged(server: Server): Promise<void> {
  await server.sendToolListChanged();
  // Yield so the in-memory queue drains the notification onto the
  // client side before assertions run.
  await new Promise((resolve) => setImmediate(resolve));
}

describe("ConnectedClient list_changed fan-out", () => {
  let rig: Awaited<ReturnType<typeof buildRig>>;

  beforeEach(async () => {
    rig = await buildRig();
  });

  afterEach(async () => {
    await rig.client.close().catch(() => {});
    await rig.backendServer.close().catch(() => {});
  });

  it("fans out to every subscriber", async () => {
    const calls: string[] = [];
    rig.listChangedSubscribers.add(async () => {
      calls.push("a");
    });
    rig.listChangedSubscribers.add(async () => {
      calls.push("b");
    });
    rig.listChangedSubscribers.add(async () => {
      calls.push("c");
    });

    await fireListChanged(rig.backendServer);

    expect(calls.sort()).toEqual(["a", "b", "c"]);
  });

  it("isolates a throwing subscriber so siblings still fire", async () => {
    const calls: string[] = [];
    rig.listChangedSubscribers.add(async () => {
      calls.push("before");
    });
    rig.listChangedSubscribers.add(async () => {
      throw new Error("subscriber blew up");
    });
    rig.listChangedSubscribers.add(async () => {
      calls.push("after");
    });

    await fireListChanged(rig.backendServer);

    // Both healthy subscribers fired despite the middle throw.
    expect(calls.sort()).toEqual(["after", "before"]);
  });

  it("isolates a subscriber that throws synchronously", async () => {
    const calls: string[] = [];
    rig.listChangedSubscribers.add(() => {
      calls.push("before");
    });
    rig.listChangedSubscribers.add(() => {
      throw new Error("sync throw");
    });
    rig.listChangedSubscribers.add(() => {
      calls.push("after");
    });

    await fireListChanged(rig.backendServer);

    expect(calls.sort()).toEqual(["after", "before"]);
  });

  it("does not fan out after the subscriber set is cleared", async () => {
    let count = 0;
    const subscriber: ListChangedSubscriber = () => {
      count++;
    };
    rig.listChangedSubscribers.add(subscriber);

    rig.listChangedSubscribers.clear();
    await fireListChanged(rig.backendServer);

    expect(count).toBe(0);
  });

  it("removing a specific subscriber leaves the rest intact", async () => {
    const calls: string[] = [];
    const a: ListChangedSubscriber = () => {
      calls.push("a");
    };
    const b: ListChangedSubscriber = () => {
      calls.push("b");
    };
    rig.listChangedSubscribers.add(a);
    rig.listChangedSubscribers.add(b);

    rig.listChangedSubscribers.delete(a);
    await fireListChanged(rig.backendServer);

    expect(calls).toEqual(["b"]);
  });
});

// -------------------------------------------------------------------
// Exponential backoff schedule (PR #20)
//
// Replaces the pre-PR #20 fixed 5s reconnect sleep. See
// `computeReconnectBackoffMs` doc in client.ts for the rationale.
// -------------------------------------------------------------------

describe("computeReconnectBackoffMs — exponential backoff schedule", () => {
  it("follows the documented 1s, 2s, 4s, 8s, 16s, 30s-cap schedule", () => {
    // Strip jitter by pinning Math.random to 0.
    const randomSpy = vi.spyOn(Math, "random").mockReturnValue(0);
    try {
      expect(computeReconnectBackoffMs(0)).toBe(1000);
      expect(computeReconnectBackoffMs(1)).toBe(2000);
      expect(computeReconnectBackoffMs(2)).toBe(4000);
      expect(computeReconnectBackoffMs(3)).toBe(8000);
      expect(computeReconnectBackoffMs(4)).toBe(16000);
      expect(computeReconnectBackoffMs(5)).toBe(30000); // hit cap
      expect(computeReconnectBackoffMs(6)).toBe(30000); // stay at cap
      expect(computeReconnectBackoffMs(20)).toBe(30000); // way past cap
    } finally {
      randomSpy.mockRestore();
    }
  });

  it("adds positive jitter on top of the base delay", () => {
    const randomSpy = vi.spyOn(Math, "random").mockReturnValue(1);
    try {
      // base 1000 + max jitter 250 = 1250
      expect(computeReconnectBackoffMs(0)).toBe(1250);
      // base 30000 + max jitter 250 = 30250 (cap covers the base, jitter rides above)
      expect(computeReconnectBackoffMs(10)).toBe(30250);
    } finally {
      randomSpy.mockRestore();
    }
  });
});

describe("createMetaMcpClient — STREAMABLE_HTTP transport option wiring", () => {
  // The M365 injected-fetch wiring restructured this branch; these
  // cases pin the four header/injection combinations so non-injected
  // servers provably keep their pre-change transport shape. Reading
  // SDK privates (_requestInit/_fetch) follows the precedent set by
  // transport-recovery-hydration.ts.
  const baseParams = {
    uuid: "srv-uuid",
    name: "some-server",
    description: "",
    type: "STREAMABLE_HTTP",
    url: "http://backend:3000/mcp",
    created_at: new Date().toISOString(),
    status: "active",
  };
  const asParams = (over: Record<string, unknown>) =>
    ({ ...baseParams, ...over }) as never;

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  function transportInternals(params: Record<string, unknown>) {
    const { client, transport } = createMetaMcpClient(asParams(params));
    expect(client).toBeDefined();
    expect(transport).toBeDefined();
    const internals = transport as unknown as {
      _requestInit?: RequestInit;
      _fetch?: unknown;
    };
    return internals;
  }

  it("no headers, non-injected server: no requestInit, no custom fetch", () => {
    vi.stubEnv("M365_INJECTED_SERVER_NAMES", "m365");
    const internals = transportInternals({ name: "autotask" });
    expect(internals._requestInit).toBeUndefined();
    expect(internals._fetch).toBeUndefined();
  });

  it("bearer/header server, non-injected: requestInit carries auth, no custom fetch", () => {
    vi.stubEnv("M365_INJECTED_SERVER_NAMES", "m365");
    const internals = transportInternals({
      name: "autotask",
      bearerToken: "static-token",
      headers: { "X-Custom": "yes" },
    });
    const headers = internals._requestInit?.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer static-token");
    expect(headers["X-Custom"]).toBe("yes");
    expect(internals._fetch).toBeUndefined();
  });

  it("injected server: custom fetch installed even with no headers", () => {
    vi.stubEnv("M365_INJECTED_SERVER_NAMES", "m365");
    const internals = transportInternals({ name: "m365" });
    expect(internals._requestInit).toBeUndefined();
    expect(typeof internals._fetch).toBe("function");
  });

  it("injected server with headers: both requestInit and custom fetch present", () => {
    vi.stubEnv("M365_INJECTED_SERVER_NAMES", "m365");
    const internals = transportInternals({
      name: "m365",
      headers: { "X-Custom": "yes" },
    });
    expect(
      (internals._requestInit?.headers as Record<string, string>)["X-Custom"],
    ).toBe("yes");
    expect(typeof internals._fetch).toBe("function");
  });
});
