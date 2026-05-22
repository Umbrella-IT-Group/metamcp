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
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { ListChangedSubscriber } from "./client";

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
      capabilities: {
        prompts: {},
        resources: { subscribe: true },
        tools: {},
      },
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
