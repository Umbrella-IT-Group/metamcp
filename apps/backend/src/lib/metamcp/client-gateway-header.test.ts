/**
 * The gateway backend trust header on the POOLED data-plane transports.
 *
 * `url-guard.test.ts` proves the guarded fetch stamps the header for an
 * internal destination and withholds it for a public one. This proves the
 * OTHER half the brief asks for: that BOTH remote transports the pool builds
 * (SSE and Streamable-HTTP) are actually wired with that guarded fetch, by
 * driving the fetch each transport was handed and asserting on what reaches
 * undici.
 *
 * undici is mocked so no socket opens; every URL is an IP literal so no
 * resolver is touched.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// `vi.mock` is hoisted above module-scope consts, so the fake fetch is created
// through `vi.hoisted` to be reachable both inside the factory and in the tests.
const { undiciFetch } = vi.hoisted(() => ({
  undiciFetch: vi.fn(
    async (_url: unknown, _init?: unknown) =>
      new Response("ok", { status: 200 }),
  ),
}));
vi.mock("undici", () => ({
  fetch: undiciFetch,
  Agent: class {
    constructor(..._args: unknown[]) {}
  },
}));

// client.ts's module-load chain reaches db/index (which throws on a missing
// DATABASE_URL); stub it out to keep this a pure unit test, matching
// client.test.ts.
vi.mock("../../db/repositories/index", () => ({ mcpServersRepository: {} }));
vi.mock("../../db/repositories/oauth-sessions.repo", () => ({
  oauthSessionsRepository: {},
}));
vi.mock("../config.service", () => ({
  configService: { getMcpMaxAttempts: vi.fn().mockResolvedValue(3) },
}));
vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import { createMetaMcpClient } from "./client";

const SECRET = "g".repeat(32);
const INTERNAL_URL = "http://10.0.0.5:3000/mcp";
const PUBLIC_URL = "http://93.184.216.34:3000/mcp";
const ORIGINAL_SECRET = process.env.GATEWAY_BACKEND_SECRET;
const ORIGINAL_TRANSFORM = process.env.TRANSFORM_LOCALHOST_TO_DOCKER_INTERNAL;

const asParams = (over: Record<string, unknown>) =>
  ({
    uuid: "srv-uuid",
    name: "some-server",
    description: "",
    status: "active",
    created_at: new Date().toISOString(),
    ...over,
  }) as never;

/**
 * The fetch each transport was constructed with, read as an SDK private the
 * same way client.test.ts reads `_fetch`. For SSE this is the fetch used for
 * the POST back-channel; for Streamable-HTTP it is the request fetch. Both are
 * the pool's guarded fetch.
 */
const installedFetch = (
  transport: unknown,
): ((url: URL, init?: RequestInit) => Promise<Response>) =>
  (transport as { _fetch: (url: URL, init?: RequestInit) => Promise<Response> })
    ._fetch;

const headerReachingUndici = (): string | null =>
  (undiciFetch.mock.calls[0][1] as { headers: Headers }).headers.get(
    "x-gateway-auth",
  );

beforeEach(() => {
  undiciFetch.mockClear();
  process.env.GATEWAY_BACKEND_SECRET = SECRET;
  // Leave IP literals exactly as written so the guard resolves no name.
  delete process.env.TRANSFORM_LOCALHOST_TO_DOCKER_INTERNAL;
});

afterEach(() => {
  if (ORIGINAL_SECRET === undefined) delete process.env.GATEWAY_BACKEND_SECRET;
  else process.env.GATEWAY_BACKEND_SECRET = ORIGINAL_SECRET;
  if (ORIGINAL_TRANSFORM === undefined) {
    delete process.env.TRANSFORM_LOCALHOST_TO_DOCKER_INTERNAL;
  } else {
    process.env.TRANSFORM_LOCALHOST_TO_DOCKER_INTERNAL = ORIGINAL_TRANSFORM;
  }
});

describe("gateway backend trust header on the pooled transports", () => {
  it("STREAMABLE_HTTP: the installed fetch stamps the header for an internal backend", async () => {
    const { transport } = createMetaMcpClient(
      asParams({ name: "s1", type: "STREAMABLE_HTTP", url: INTERNAL_URL }),
    );
    await installedFetch(transport)(new URL(INTERNAL_URL), {
      headers: { authorization: "Bearer row" },
    });
    expect(undiciFetch).toHaveBeenCalledTimes(1);
    expect(headerReachingUndici()).toBe(SECRET);
  });

  it("STREAMABLE_HTTP: stamps the TRIMMED secret when the env value has trailing whitespace", async () => {
    // readGatewayBackendSecret trims before it measures length and before it
    // returns, so a secret written with a trailing newline (echo, copy-paste)
    // cannot differ between the header the gateway stamps and the value a
    // backend was configured with. Without the trim the stamped header would
    // carry the newline and no backend comparing against the clean secret would
    // match.
    process.env.GATEWAY_BACKEND_SECRET = `${SECRET}\n`;
    const { transport } = createMetaMcpClient(
      asParams({ name: "s1b", type: "STREAMABLE_HTTP", url: INTERNAL_URL }),
    );
    await installedFetch(transport)(new URL(INTERNAL_URL), {
      headers: { authorization: "Bearer row" },
    });
    expect(undiciFetch).toHaveBeenCalledTimes(1);
    expect(headerReachingUndici()).toBe(SECRET);
  });

  it("SSE: the installed fetch stamps the header for an internal backend", async () => {
    const { transport } = createMetaMcpClient(
      asParams({ name: "s2", type: "SSE", url: "http://10.0.0.5:3000/sse" }),
    );
    await installedFetch(transport)(new URL("http://10.0.0.5:3000/sse"), {
      headers: { authorization: "Bearer row" },
    });
    expect(undiciFetch).toHaveBeenCalledTimes(1);
    expect(headerReachingUndici()).toBe(SECRET);
  });

  it("STREAMABLE_HTTP: does not stamp the header for a public backend", async () => {
    const { transport } = createMetaMcpClient(
      asParams({ name: "s3", type: "STREAMABLE_HTTP", url: PUBLIC_URL }),
    );
    await installedFetch(transport)(new URL(PUBLIC_URL), {});
    expect(undiciFetch).toHaveBeenCalledTimes(1);
    expect(headerReachingUndici()).toBeNull();
  });

  it("STREAMABLE_HTTP: sends nothing when the secret is unset, even to an internal backend", async () => {
    delete process.env.GATEWAY_BACKEND_SECRET;
    const { transport } = createMetaMcpClient(
      asParams({ name: "s4", type: "STREAMABLE_HTTP", url: INTERNAL_URL }),
    );
    await installedFetch(transport)(new URL(INTERNAL_URL), {});
    expect(undiciFetch).toHaveBeenCalledTimes(1);
    expect(headerReachingUndici()).toBeNull();
  });
});
