import * as React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/trpc", () => {
  const setting = { useQuery: () => ({ data: undefined }) };
  return {
    trpc: {
      frontend: {
        config: {
          getMcpTimeout: setting,
          getMcpMaxTotalTimeout: setting,
          getMcpResetTimeoutOnProgress: setting,
        },
      },
    },
  };
});

vi.mock("@/lib/oauth-provider", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/oauth-provider")>()),
  createAuthProvider: () => ({ tokens: async () => undefined }),
}));

vi.mock("@/lib/env", () => ({
  getAppUrl: () => "https://gateway.example.test",
}));

import { useConnection } from "@/hooks/useConnection";

import { RpcTrafficStore } from "./rpc-traffic/store";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// Render with real React hooks. The connect callback can run after the render;
// this test observes the live store, without requiring a browser or a server.
function connection(captureTraffic: boolean) {
  let current: ReturnType<typeof useConnection> | undefined;
  function Consumer() {
    current = useConnection({
      mcpServerUuid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      transportType: "SSE",
      command: "",
      args: "",
      url: "/mcp-proxy/metamcp/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/sse",
      isMetaMCP: true,
      captureTraffic,
    });
    return null;
  }
  renderToStaticMarkup(React.createElement(Consumer));
  return current!;
}

describe("the connection's traffic log", () => {
  it("records a failed proxy health check with the original diagnosis", async () => {
    const failure = new TypeError("Network unreachable");
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(failure));
    vi.spyOn(console, "error").mockImplementation(() => {});
    const published = vi.spyOn(
      RpcTrafficStore.prototype,
      "publishTransportError",
    );

    await connection(true).connect();

    expect(published).toHaveBeenCalledExactlyOnceWith(failure);
    const store = published.mock.contexts[0] as RpcTrafficStore;
    expect(store.exportEntries()).toMatchObject([
      {
        message: { transportEvent: "error", error: "Network unreachable" },
      },
    ]);
  });

  it("does not create traffic records when capture is disabled", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
    vi.spyOn(console, "error").mockImplementation(() => {});
    const published = vi.spyOn(
      RpcTrafficStore.prototype,
      "publishTransportError",
    );

    await connection(false).connect();

    expect(published).not.toHaveBeenCalled();
  });
});
