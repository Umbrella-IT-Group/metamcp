/**
 * The gateway-verified caller identity on the pooled data plane: which
 * backends receive `X-Umbrella-User-Id`, which requests carry it, whose id it
 * is, and that a value from anywhere but the gateway's own authentication
 * never reaches a named backend.
 *
 * `client-verified-caller.test.ts` proves both pooled transports are wired
 * with the wrapper; `routers/public-metamcp/verified-caller-forwarding.test.ts`
 * drives the public routes end to end. This file pins the module's own
 * contract.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import logger from "@/utils/logger";

import {
  requestNeedsUserToken,
  USER_ID_HEADER as M365_USER_ID_HEADER,
} from "../m365/injected-fetch";
import { runWithCallerContext } from "./caller-context-store";
import {
  assertVerifiedCallerConfig,
  getVerifiedCallerFetchForServer,
  getVerifiedCallerServerNames,
  isVerifiedCallerHeaderName,
  requestExecutesBackendCode,
  VERIFIED_CALLER_HEADER,
  verifiedCallerUserId,
  withoutVerifiedCallerHeader,
  withVerifiedCaller,
} from "./verified-caller";

const ok = () => new Response("ok", { status: 200 });

/** A base fetch that records the headers each request reached it with. */
function recordingFetch() {
  const seen: Headers[] = [];
  const fetchImpl = vi.fn(async (_url: string | URL, init?: RequestInit) => {
    seen.push(new Headers(init?.headers));
    return ok();
  });
  return { fetchImpl, seen };
}

const rpc = (method: string, extra: Record<string, unknown> = {}) =>
  JSON.stringify({ jsonrpc: "2.0", id: 1, method, ...extra });

/** A tools/call POST as the SDK's Streamable-HTTP client sends it. */
const toolCall = (headers: Record<string, string> = {}): RequestInit => ({
  method: "POST",
  headers: { "content-type": "application/json", ...headers },
  body: rpc("tools/call", { params: { name: "ask", arguments: {} } }),
});

const URL_INTERNAL = "http://10.0.0.5:3000/mcp";

const ENV_KEYS = [
  "VERIFIED_CALLER_SERVER_NAMES",
  "M365_INJECTED_SERVER_NAMES",
] as const;
const savedEnv: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const key of ENV_KEYS) savedEnv[key] = process.env[key];
  for (const key of ENV_KEYS) delete process.env[key];
  vi.mocked(logger.info).mockClear();
});

afterEach(() => {
  for (const key of ENV_KEYS) {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
  }
});

describe("the header name", () => {
  it("is the header the m365 injection sets, so one internal-only entry covers both", () => {
    expect(VERIFIED_CALLER_HEADER).toBe(M365_USER_ID_HEADER.toLowerCase());
  });
});

describe("getVerifiedCallerServerNames", () => {
  it.each([
    ["unset", undefined],
    ["empty", ""],
    ["only separators and spaces", " , ,, "],
  ])(
    "names no server when the variable is %s (inert by default)",
    (_l, raw) => {
      if (raw !== undefined) process.env.VERIFIED_CALLER_SERVER_NAMES = raw;
      expect(getVerifiedCallerServerNames().size).toBe(0);
    },
  );

  it("trims each name and drops empty entries", () => {
    process.env.VERIFIED_CALLER_SERVER_NAMES = "  team , ,other-team  ,";
    expect([...getVerifiedCallerServerNames()].sort()).toEqual([
      "other-team",
      "team",
    ]);
  });

  it("collapses duplicates", () => {
    process.env.VERIFIED_CALLER_SERVER_NAMES = "team,team, team";
    expect([...getVerifiedCallerServerNames()]).toEqual(["team"]);
  });

  it("matches names exactly, as the m365 list does (no case folding)", () => {
    process.env.VERIFIED_CALLER_SERVER_NAMES = "Team";
    const names = getVerifiedCallerServerNames();
    expect(names.has("Team")).toBe(true);
    expect(names.has("team")).toBe(false);
  });
});

describe("assertVerifiedCallerConfig (boot refusal)", () => {
  it("passes when no server is named", () => {
    expect(() => assertVerifiedCallerConfig()).not.toThrow();
  });

  it("passes when the named servers are disjoint from the m365 list", () => {
    process.env.VERIFIED_CALLER_SERVER_NAMES = "team";
    process.env.M365_INJECTED_SERVER_NAMES = "m365";
    expect(() => assertVerifiedCallerConfig()).not.toThrow();
  });

  it("logs which servers receive the verified caller, so the posture is in the boot log", () => {
    process.env.VERIFIED_CALLER_SERVER_NAMES = "team";
    assertVerifiedCallerConfig();
    expect(logger.info).toHaveBeenCalledWith(expect.stringContaining("team"));
  });

  it("refuses a server named in both lists, and names it", () => {
    process.env.VERIFIED_CALLER_SERVER_NAMES = "team, shared";
    process.env.M365_INJECTED_SERVER_NAMES = "m365,shared";
    expect(() => assertVerifiedCallerConfig()).toThrow(
      /VERIFIED_CALLER_SERVER_NAMES.*M365_INJECTED_SERVER_NAMES.*shared/s,
    );
  });

  it("refuses `m365` when M365_INJECTED_SERVER_NAMES is unset, because that is the m365 default", () => {
    process.env.VERIFIED_CALLER_SERVER_NAMES = "m365";
    expect(() => assertVerifiedCallerConfig()).toThrow(/m365/);
  });

  it("is called at module scope in index.ts, so an overlap stops the gateway before it serves", () => {
    // index.ts calls app.listen() at module scope and cannot be imported by a
    // test, so the wiring is pinned at the source: the call must exist and sit
    // above the first route registration.
    const source = readFileSync(join(__dirname, "../../index.ts"), "utf8");
    const call = source.indexOf("\nassertVerifiedCallerConfig();");
    expect(call).toBeGreaterThan(-1);
    expect(call).toBeLessThan(source.indexOf("app.use("));
  });
});

describe("requestExecutesBackendCode", () => {
  it.each([
    "tools/call",
    "resources/read",
    "prompts/get",
    "completion/complete",
    "logging/setLevel",
  ])("is true for a %s request", (method) => {
    expect(
      requestExecutesBackendCode({ method: "POST", body: rpc(method) }),
    ).toBe(true);
  });

  it.each([
    "initialize",
    "ping",
    "tools/list",
    "prompts/list",
    "resources/list",
    "resources/templates/list",
    "notifications/initialized",
    "notifications/cancelled",
  ])("is false for %s (handshake, listing, notification)", (method) => {
    expect(
      requestExecutesBackendCode({ method: "POST", body: rpc(method) }),
    ).toBe(false);
  });

  it.each(["GET", "HEAD", "OPTIONS", "DELETE", "PUT", "PATCH"])(
    "is false for an HTTP %s",
    (method) => {
      expect(
        requestExecutesBackendCode({ method, body: rpc("tools/call") }),
      ).toBe(false);
    },
  );

  it("is false with no init at all (a GET)", () => {
    expect(requestExecutesBackendCode()).toBe(false);
  });

  it("reads the HTTP method case-insensitively", () => {
    expect(
      requestExecutesBackendCode({ method: "post", body: rpc("tools/call") }),
    ).toBe(true);
  });

  it.each([
    ["an unparseable body", "{not json"],
    ["an empty batch", "[]"],
    [
      "a response to a server request",
      JSON.stringify({ jsonrpc: "2.0", id: 4, result: {} }),
    ],
    [
      "an error response",
      JSON.stringify({
        jsonrpc: "2.0",
        id: 4,
        error: { code: -1, message: "x" },
      }),
    ],
    [
      "a non-string method",
      JSON.stringify({ jsonrpc: "2.0", id: 1, method: 7 }),
    ],
    ["a JSON scalar", "42"],
    ["JSON null", "null"],
  ])("is false for %s (fail closed: no identity)", (_label, body) => {
    expect(requestExecutesBackendCode({ method: "POST", body })).toBe(false);
  });

  it("is false for a body that is not a string", () => {
    expect(
      requestExecutesBackendCode({
        method: "POST",
        body: new TextEncoder().encode(rpc("tools/call")),
      }),
    ).toBe(false);
  });

  it("is true for a batch with one executing request among token-free ones", () => {
    const body = JSON.stringify([
      { jsonrpc: "2.0", method: "notifications/initialized" },
      { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "ask" } },
    ]);
    expect(requestExecutesBackendCode({ method: "POST", body })).toBe(true);
  });

  it("parses a tool call of any size (an answer can be long)", () => {
    const body = rpc("tools/call", {
      params: { name: "answer", arguments: { text: "a".repeat(512 * 1024) } },
    });
    expect(requestExecutesBackendCode({ method: "POST", body })).toBe(true);
  });

  it("agrees with the m365 token gate on every request-shaped message", () => {
    // Both gates answer "can this request execute backend code". They differ
    // only on what neither can classify (a response, an unparseable or
    // non-string body, PUT and the like), where m365 mints and this sends no
    // identity. A method added to one gate's free list must be a deliberate
    // decision for the other, so this pins them together.
    const methods = [
      "initialize",
      "ping",
      "tools/list",
      "prompts/list",
      "resources/list",
      "resources/templates/list",
      "notifications/initialized",
      "notifications/progress",
      "tools/call",
      "resources/read",
      "resources/subscribe",
      "prompts/get",
      "completion/complete",
      "logging/setLevel",
    ];
    for (const method of methods) {
      const init = { method: "POST", body: rpc(method) };
      expect([method, requestExecutesBackendCode(init)]).toEqual([
        method,
        requestNeedsUserToken(init),
      ]);
    }
    for (const method of ["GET", "HEAD", "OPTIONS", "DELETE"]) {
      expect(requestExecutesBackendCode({ method })).toBe(
        requestNeedsUserToken({ method }),
      );
    }
  });
});

describe("verifiedCallerUserId", () => {
  it("is undefined outside any caller binding", () => {
    expect(verifiedCallerUserId(undefined)).toBeUndefined();
  });

  it("is the key owner for an api-key caller with no acts-as binding", () => {
    expect(
      verifiedCallerUserId({ authMethod: "api_key", userId: "user-owner" }),
    ).toBe("user-owner");
  });

  it("is the acts-as target for an api-key caller with a binding, not the owner", () => {
    expect(
      verifiedCallerUserId({
        authMethod: "api_key",
        userId: "user-admin",
        actsAsUserId: "user-bound",
      }),
    ).toBe("user-bound");
  });

  it("is the OAuth subject for an OAuth caller", () => {
    expect(
      verifiedCallerUserId({ authMethod: "oauth", userId: "user-oauth" }),
    ).toBe("user-oauth");
  });

  it("is undefined for a key with no owner and no binding", () => {
    expect(
      verifiedCallerUserId({ authMethod: "api_key", apiKeyUuid: "k-1" }),
    ).toBeUndefined();
  });

  it("never falls back to the owner when an acts-as binding is present but blank", () => {
    // `actsAsUserId ?? userId`, literally: a blank binding is a broken
    // binding, and the safe answer is no identity, not the key owner's.
    expect(
      verifiedCallerUserId({ userId: "user-admin", actsAsUserId: "" }),
    ).toBeUndefined();
  });

  it("ignores the caller-asserted actor entirely", () => {
    expect(
      verifiedCallerUserId({ assertedActor: "someone@example.com" }),
    ).toBeUndefined();
  });
});

describe("withVerifiedCaller", () => {
  it("sets the verified caller's id on a tool call", async () => {
    const { fetchImpl, seen } = recordingFetch();
    await runWithCallerContext(
      { authMethod: "api_key", userId: "user-1" },
      () => withVerifiedCaller(fetchImpl)(URL_INTERNAL, toolCall()),
    );
    expect(seen[0].get(VERIFIED_CALLER_HEADER)).toBe("user-1");
    // Everything else on the request is left as the transport built it.
    expect(seen[0].get("content-type")).toBe("application/json");
  });

  it("replaces a supplied value with the verified caller's id", async () => {
    const { fetchImpl, seen } = recordingFetch();
    await runWithCallerContext(
      { authMethod: "api_key", userId: "user-1" },
      () =>
        withVerifiedCaller(fetchImpl)(
          URL_INTERNAL,
          toolCall({ "X-Umbrella-User-Id": "user-victim" }),
        ),
    );
    expect(seen[0].get(VERIFIED_CALLER_HEADER)).toBe("user-1");
  });

  it("removes a supplied value when the caller has no identity", async () => {
    const { fetchImpl, seen } = recordingFetch();
    await runWithCallerContext(
      { authMethod: "api_key", apiKeyUuid: "k-1" },
      () =>
        withVerifiedCaller(fetchImpl)(
          URL_INTERNAL,
          toolCall({ "x-umbrella-user-id": "user-victim" }),
        ),
    );
    expect(seen[0].has(VERIFIED_CALLER_HEADER)).toBe(false);
  });

  it("removes a supplied value outside any caller binding (idle warm-up, probes, sweeps)", async () => {
    const { fetchImpl, seen } = recordingFetch();
    await withVerifiedCaller(fetchImpl)(
      URL_INTERNAL,
      toolCall({ "X-UMBRELLA-USER-ID": "user-victim" }),
    );
    expect(seen[0].has(VERIFIED_CALLER_HEADER)).toBe(false);
  });

  it("removes a supplied value from a Headers instance as well as a plain object", async () => {
    const { fetchImpl, seen } = recordingFetch();
    const headers = new Headers({ "X-Umbrella-User-Id": "user-victim" });
    await withVerifiedCaller(fetchImpl)(URL_INTERNAL, {
      ...toolCall(),
      headers,
    });
    expect(seen[0].has(VERIFIED_CALLER_HEADER)).toBe(false);
  });

  it.each([
    ["initialize", { method: "POST", body: rpc("initialize") }],
    ["tools/list", { method: "POST", body: rpc("tools/list") }],
    [
      "notifications/initialized",
      {
        method: "POST",
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "notifications/initialized",
        }),
      },
    ],
    ["the standing GET stream", { method: "GET" }],
    ["the session DELETE", { method: "DELETE" }],
    [
      "a response to a server request",
      {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 9, result: {} }),
      },
    ],
  ])(
    "carries no identity on %s, even inside a caller binding, and still strips a supplied one",
    async (_label, init) => {
      const { fetchImpl, seen } = recordingFetch();
      await runWithCallerContext(
        { authMethod: "oauth", userId: "user-1" },
        () =>
          withVerifiedCaller(fetchImpl)(URL_INTERNAL, {
            ...(init as RequestInit),
            headers: { "X-Umbrella-User-Id": "user-victim" },
          }),
      );
      expect(seen[0].has(VERIFIED_CALLER_HEADER)).toBe(false);
    },
  );

  it("gives each of two concurrent tool calls its own caller's id", async () => {
    const { fetchImpl, seen } = recordingFetch();
    const wrapped = withVerifiedCaller(fetchImpl);
    await Promise.all(
      ["user-1", "user-2"].map((userId) =>
        runWithCallerContext({ authMethod: "api_key", userId }, async () => {
          // Yield first, so both bindings are live before either request.
          await new Promise((resolve) => setTimeout(resolve, 0));
          return wrapped(URL_INTERNAL, toolCall());
        }),
      ),
    );
    expect(seen.map((h) => h.get(VERIFIED_CALLER_HEADER)).sort()).toEqual([
      "user-1",
      "user-2",
    ]);
  });

  it("passes the base fetch's response through unchanged", async () => {
    const response = new Response("body", { status: 201 });
    const result = await withVerifiedCaller(async () => response)(
      URL_INTERNAL,
      toolCall(),
    );
    expect(result).toBe(response);
  });
});

describe("getVerifiedCallerFetchForServer", () => {
  it("returns the base fetch itself for a server that is not named", () => {
    process.env.VERIFIED_CALLER_SERVER_NAMES = "team";
    const base = vi.fn();
    expect(getVerifiedCallerFetchForServer("other", base)).toBe(base);
  });

  it("returns the base fetch itself when the variable is unset", () => {
    const base = vi.fn();
    expect(getVerifiedCallerFetchForServer("team", base)).toBe(base);
  });

  it("does not touch a supplied header on an unnamed server", async () => {
    process.env.VERIFIED_CALLER_SERVER_NAMES = "team";
    const { fetchImpl, seen } = recordingFetch();
    await runWithCallerContext({ userId: "user-1" }, () =>
      getVerifiedCallerFetchForServer("other", fetchImpl)(
        URL_INTERNAL,
        toolCall({ "X-Umbrella-User-Id": "stored" }),
      ),
    );
    expect(seen[0].get(VERIFIED_CALLER_HEADER)).toBe("stored");
  });

  it("wraps a named server", async () => {
    process.env.VERIFIED_CALLER_SERVER_NAMES = "team";
    const { fetchImpl, seen } = recordingFetch();
    await runWithCallerContext({ userId: "user-1" }, () =>
      getVerifiedCallerFetchForServer("team", fetchImpl)(
        URL_INTERNAL,
        toolCall({ "X-Umbrella-User-Id": "stored" }),
      ),
    );
    expect(seen[0].get(VERIFIED_CALLER_HEADER)).toBe("user-1");
  });

  it("refuses a server that is also in the m365 list", () => {
    process.env.VERIFIED_CALLER_SERVER_NAMES = "m365";
    expect(() => getVerifiedCallerFetchForServer("m365", vi.fn())).toThrow(
      /M365_INJECTED_SERVER_NAMES/,
    );
  });
});

describe("the Inspector helpers", () => {
  it.each([
    "X-Umbrella-User-Id",
    "x-umbrella-user-id",
    "X-UMBRELLA-USER-ID",
    " X-Umbrella-User-Id ",
  ])("recognizes %j as the reserved header", (name) => {
    expect(isVerifiedCallerHeaderName(name)).toBe(true);
  });

  it.each(["X-Api-Key", "Authorization", "X-Umbrella-User", "", undefined, 3])(
    "does not reserve %j",
    (name) => {
      expect(isVerifiedCallerHeaderName(name)).toBe(false);
    },
  );

  it("drops the reserved header from stored headers in any casing and keeps the rest", () => {
    expect(
      withoutVerifiedCallerHeader({
        "X-Umbrella-User-Id": "a",
        "x-umbrella-user-id": "b",
        "x-vendor-api-key": "k",
      }),
    ).toEqual({ "x-vendor-api-key": "k" });
  });
});
