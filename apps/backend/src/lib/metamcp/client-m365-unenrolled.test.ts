/**
 * A user with no usable Microsoft 365 grant must be able to connect, list
 * the m365 tools and tear the connection down; only a tool call needs their
 * token. Driven at SDK level: a real `Client`, a real
 * `StreamableHTTPClientTransport`, the real injected fetch with a mint stub
 * that throws exactly what the broker throws for a user who has not enrolled,
 * and a fake Streamable-HTTP backend behind it, all wired through
 * `connectMetaMcpClient`.
 *
 * The defect this pins: the injected fetch minted a token for EVERY request,
 * so for such a user the `initialize`, `tools/list` and the teardown DELETE
 * threw the broker error. The connect failed (or the listing did), the SDK's
 * `onerror` ran the backend-drop cascade (invalidating every session's pooled
 * connection for the server), and the DELETE failed with the same error, so
 * the backend session was never terminated: one leaked backend session per
 * attempt. A listing that fails is also re-notified to the session, which
 * re-lists and fails again, which is how one unenrolled user looped.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import logger from "@/utils/logger";

vi.mock("../../db/index", () => ({ db: {} }));
vi.mock("../../db/repositories/index", () => ({
  mcpServersRepository: {},
}));
vi.mock("../../db/repositories/oauth-sessions.repo", () => ({
  oauthSessionsRepository: {},
}));
vi.mock("./server-error-tracker", () => ({
  serverErrorTracker: {
    getServerMaxAttempts: vi.fn().mockResolvedValue(3),
    isServerInErrorState: vi.fn().mockResolvedValue(false),
  },
}));

import { M365BrokerError } from "../m365/errors";
import {
  m365ServerParams as params,
  makeCreateClient,
  makeFakeBackend,
  makeMint,
} from "../m365/fake-streamable-backend.test-util";
import { runWithM365UserContext } from "../m365/request-context";
import { connectMetaMcpClient } from "./client";
import { metamcpLogStore } from "./log-store";

describe("an m365 user with no grant: connect, list and teardown never need their token", () => {
  let warnSpy: ReturnType<typeof vi.spyOn>;
  let recordSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    warnSpy = vi.spyOn(logger, "warn").mockImplementation(() => {});
    vi.spyOn(logger, "info").mockImplementation(() => {});
    vi.spyOn(logger, "debug").mockImplementation(() => {});
    vi.spyOn(logger, "error").mockImplementation(() => {});
    recordSpy = vi
      .spyOn(metamcpLogStore, "record")
      .mockImplementation(() => {});
    vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const warnings = (): string[] =>
    warnSpy.mock.calls.map((call: unknown[]) => String(call[0]));
  const records = (): string[] =>
    recordSpy.mock.calls.map(
      (call: unknown[]) => (call[0] as { message: string }).message,
    );

  it("connects, lists the tools, refuses only the tool call, never drops, and ends with one token-free DELETE", async () => {
    const { fetchImpl, seen } = makeFakeBackend();
    const mint = makeMint();
    const onTransportDrop = vi.fn();

    await runWithM365UserContext({ userId: "user-unenrolled" }, async () => {
      const connected = await connectMetaMcpClient(
        params,
        undefined,
        onTransportDrop,
        { createClient: makeCreateClient(mint, fetchImpl as never) },
      );
      // The connect succeeds: the handshake needs no token.
      expect(connected).toBeDefined();
      if (!connected) return;

      // The listing returns the tools.
      const listed = await connected.client.listTools();
      expect(listed.tools.map((t) => t.name)).toEqual(["mail_search"]);

      // The call is refused with the typed error, before any byte leaves.
      const callsBefore = fetchImpl.mock.calls.length;
      const refusal = await connected.client
        .callTool({ name: "mail_search", arguments: {} })
        .then(
          () => undefined,
          (error: unknown) => error,
        );
      expect(refusal).toBeInstanceOf(M365BrokerError);
      expect((refusal as M365BrokerError).code).toBe("credential_missing");
      expect(fetchImpl.mock.calls.length).toBe(callsBefore);

      // The refusal did not drop the connection: it still lists.
      expect((await connected.client.listTools()).tools).toHaveLength(1);

      // Teardown sends exactly one DELETE and does not warn.
      const deletesBefore = seen.filter((r) => r.httpMethod === "DELETE");
      expect(deletesBefore).toHaveLength(0);
      await connected.cleanup();
    });

    // Not one of the user's requests carried a credential or a user id.
    expect(seen.length).toBeGreaterThan(0);
    for (const request of seen) {
      expect(request.authorization).toBeNull();
      expect(request.userId).toBeNull();
    }
    const rpcMethods = seen
      .filter((r) => r.httpMethod === "POST")
      .map((r) => r.rpcMethod);
    expect(rpcMethods).toEqual([
      "initialize",
      "notifications/initialized",
      "tools/list",
      "tools/list",
    ]);
    expect(seen.some((r) => r.httpMethod === "GET")).toBe(true);
    expect(seen.filter((r) => r.httpMethod === "DELETE")).toHaveLength(1);

    // The mint was asked once: for the tool call, and nothing else.
    expect(mint.getAccessToken).toHaveBeenCalledTimes(1);
    expect(mint.getAccessToken).toHaveBeenCalledWith("user-unenrolled");

    // No backend-drop path ran, and the teardown did not fail.
    expect(onTransportDrop).not.toHaveBeenCalled();
    expect(warnings().some((m) => m.includes("Transport error"))).toBe(false);
    expect(warnings().some((m) => m.includes("Failed to terminate"))).toBe(
      false,
    );
    expect(records().some((m) => m.includes("backend drop"))).toBe(false);
    expect(records().some((m) => m.includes("Connect attempt"))).toBe(false);
  });

  it("an enrolled user's call carries only their own token; everything else is still token-free", async () => {
    const { fetchImpl, seen } = makeFakeBackend();
    const mint = makeMint({ "user-enrolled": "graph-token-enrolled" });

    await runWithM365UserContext({ userId: "user-enrolled" }, async () => {
      const connected = await connectMetaMcpClient(params, undefined, vi.fn(), {
        createClient: makeCreateClient(mint, fetchImpl as never),
      });
      if (!connected) throw new Error("connect failed");
      await connected.client.listTools();
      const result = await connected.client.callTool({
        name: "mail_search",
        arguments: {},
      });
      expect(result.isError).toBeFalsy();
      await connected.cleanup();
    });

    const withToken = seen.filter((r) => r.authorization !== null);
    expect(withToken).toHaveLength(1);
    expect(withToken[0].rpcMethod).toBe("tools/call");
    expect(withToken[0].authorization).toBe("Bearer graph-token-enrolled");
    expect(withToken[0].userId).toBe("user-enrolled");
    expect(mint.getAccessToken).toHaveBeenCalledTimes(1);
  });

  it("one pooled connection serves two users: each call carries its own user's token, and the refused user's call drops nothing", async () => {
    const { fetchImpl, seen } = makeFakeBackend();
    const mint = makeMint({ "user-enrolled": "graph-token-enrolled" });
    const onTransportDrop = vi.fn();

    // The connection is made by whichever session asks first (here the
    // unenrolled one) and then shared, as the pool's idle handoff does.
    const connected = await runWithM365UserContext(
      { userId: "user-unenrolled" },
      () =>
        connectMetaMcpClient(params, undefined, onTransportDrop, {
          createClient: makeCreateClient(mint, fetchImpl as never),
        }),
    );
    if (!connected) throw new Error("connect failed");

    const call = (userId: string) =>
      runWithM365UserContext({ userId }, () =>
        connected.client.callTool({ name: "mail_search", arguments: {} }),
      );

    const [enrolledCall, other] = await Promise.allSettled([
      call("user-enrolled"),
      call("user-unenrolled"),
    ]);
    expect(enrolledCall.status).toBe("fulfilled");
    expect(other.status).toBe("rejected");
    // The healthy user can call again straight away.
    expect((await call("user-enrolled")).isError).toBeFalsy();

    expect(onTransportDrop).not.toHaveBeenCalled();
    const calls = seen.filter((r) => r.rpcMethod === "tools/call");
    expect(calls).toHaveLength(2);
    for (const request of calls) {
      expect(request.authorization).toBe("Bearer graph-token-enrolled");
      expect(request.userId).toBe("user-enrolled");
    }
    // Nothing that carried the refused user's id reached the backend.
    expect(seen.some((r) => r.userId === "user-unenrolled")).toBe(false);

    await connected.cleanup();
  });
});
