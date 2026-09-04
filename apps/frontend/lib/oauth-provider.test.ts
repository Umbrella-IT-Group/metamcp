/**
 * SSR safety for the MCP OAuth client provider.
 *
 * useConnection() constructs a DbOAuthClientProvider at render time, so the
 * constructor runs during the server render of every page that hosts an MCP
 * connection (the namespace detail page, the MCP server detail page, the MCP
 * inspector). The constructor used to write sessionStorage unconditionally,
 * which throws "sessionStorage is not defined" in the Node server runtime and
 * turned those routes into HTTP 500s that only recovered after client-side
 * hydration masked them.
 *
 * The frontend harness runs `environment: "node"` (see vitest.config.ts), so
 * there is no window and no sessionStorage here, matching the SSR runtime. That
 * makes this the exact condition that would have caught the regression.
 */

import { afterEach, describe, expect, it } from "vitest";

import { SESSION_KEYS } from "./constants";
import { createAuthProvider } from "./oauth-provider";

const UUID = "11111111-1111-1111-1111-111111111111";
const SERVER_URL = "/mcp-proxy/metamcp/x/sse";

afterEach(() => {
  // Remove any browser globals a test installed so the SSR assertion below
  // cannot be masked by leakage from the browser-path test.
  delete (globalThis as { window?: unknown }).window;
  delete (globalThis as { sessionStorage?: unknown }).sessionStorage;
});

describe("createAuthProvider under SSR", () => {
  it("does not throw when web storage is absent", () => {
    expect(typeof globalThis.window).toBe("undefined");
    expect(
      typeof (globalThis as { sessionStorage?: unknown }).sessionStorage,
    ).toBe("undefined");
    expect(() => createAuthProvider(UUID, SERVER_URL)).not.toThrow();
  });
});

describe("createAuthProvider in the browser", () => {
  it("still records the server URL when web storage exists", () => {
    const store = new Map<string, string>();
    const sessionStorage = {
      getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
      setItem: (k: string, v: string) => {
        store.set(k, v);
      },
      removeItem: (k: string) => {
        store.delete(k);
      },
    };
    (globalThis as { window?: unknown }).window = {};
    (globalThis as { sessionStorage?: unknown }).sessionStorage =
      sessionStorage;

    createAuthProvider(UUID, SERVER_URL);

    expect(store.get(SESSION_KEYS.SERVER_URL)).toBe(SERVER_URL);
  });
});
