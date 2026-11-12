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
import type { CallerContext } from "./caller-context-store";
import { runWithCallerContext } from "./caller-context-store";
import {
  assertVerifiedCallerConfig,
  encodeVerifiedCaller,
  getVerifiedCallerFetchForServer,
  getVerifiedCallerServerNames,
  isVerifiedCallerHeaderName,
  requestExecutesBackendCode,
  VERIFIED_CALLER_HEADER,
  VERIFIED_CALLER_IDENTITY_HEADER,
  VERIFIED_CALLER_IDENTITY_LIMITS,
  VERIFIED_CALLER_IDENTITY_PREFIX,
  verifiedCallerCredential,
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
    // Both gates answer "can this request execute backend code". They agree
    // on every request and on every strictly shaped reply to a backend
    // request (the next tests). They differ only on what neither can
    // classify (a malformed message, an unparseable or non-string body, PUT
    // and the like), where m365 mints and this sends no identity; the
    // divergence test below lists those cases by name. A method added to one
    // gate's free list must be a deliberate decision for the other, so this
    // pins them together.
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

  // Replies to requests the backend sent complete a request the backend
  // already holds; they are not tool invocations, and the SDK sends them from
  // the async scope it reads the backend's stream in, which need not be the
  // scope of the caller whose call is in flight. Neither gate attaches anyone
  // to them, at any size.
  const reply = (fields: Record<string, unknown>) =>
    JSON.stringify({ jsonrpc: "2.0", ...fields });
  const pureReply = reply({ id: 4, result: {} });
  const errorReply = reply({
    id: "srv-1",
    error: { code: -32601, message: "Method not found" },
  });
  const largeReply = reply({ id: 5, result: { text: "a".repeat(70_000) } });

  it.each([
    ["a result reply", pureReply],
    ["an error reply", errorReply],
    ["a reply with id 0 and a null result", reply({ id: 0, result: null })],
    ["a reply above 65,536 code units", largeReply],
    ["a batch of replies", `[${pureReply}, ${errorReply}]`],
    ["a reply and a ping", `[${pureReply}, ${rpc("ping")}]`],
  ])("both gates attach nobody to %s", (_label, body) => {
    const init = { method: "POST", body };
    expect(requestExecutesBackendCode(init)).toBe(false);
    expect(requestNeedsUserToken(init)).toBe(false);
  });

  it("both gates attach the caller to a reply batched with an executing request", () => {
    const init = {
      method: "POST",
      body: `[${pureReply}, ${rpc("tools/call", { id: 2 })}]`,
    };
    expect(requestExecutesBackendCode(init)).toBe(true);
    expect(requestNeedsUserToken(init)).toBe(true);
  });

  it.each([
    ["an unparseable body", "{not json"],
    ["an empty batch", "[]"],
    ["a reply with a null id", reply({ id: null, result: {} })],
    ["a reply with no id", reply({ result: {} })],
    [
      "a reply with both result and error",
      reply({ id: 1, result: {}, error: { code: -1, message: "x" } }),
    ],
    ["a reply with neither result nor error", reply({ id: 1 })],
    ["a reply with no jsonrpc", JSON.stringify({ id: 1, result: {} })],
    [
      "a result carrying method ping",
      reply({ id: 1, method: "ping", result: {} }),
    ],
    [
      "a result carrying a null method",
      reply({ id: 1, method: null, result: {} }),
    ],
    [
      "a batch with one malformed reply",
      `[${pureReply}, ${reply({ id: null, result: {} })}]`,
    ],
  ])(
    "diverges on purpose for %s: m365 mints when unsure, this sends no identity",
    (_label, body) => {
      const init = { method: "POST", body };
      expect(requestNeedsUserToken(init)).toBe(true);
      expect(requestExecutesBackendCode(init)).toBe(false);
    },
  );
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

// ---------------------------------------------------------------------------
// X-Umbrella-Caller: the verified credential beside the verified user id.
// ---------------------------------------------------------------------------

const KEY_A = "00000000-0000-4000-8000-00000000000a";
const KEY_B = "00000000-0000-4000-8000-00000000000b";
const CLIENT_A = "mcp_client_AAAAAAAAAAAAAAAAAAAAAA";
const CLIENT_B = "mcp_client_BBBBBBBBBBBBBBBBBBBBBB";

interface CallerPayload {
  v: number;
  uid: string;
  cred: string;
  email: string | null;
  label: string | null;
  rid: string | null;
}

/** Decode an `X-Umbrella-Caller` value the way a strict reader would. */
function decodeIdentity(value: string | null | undefined): {
  json: string;
  payload: CallerPayload;
} {
  if (typeof value !== "string") throw new Error("no caller header value");
  expect(value.startsWith(VERIFIED_CALLER_IDENTITY_PREFIX)).toBe(true);
  const encoded = value.slice(VERIFIED_CALLER_IDENTITY_PREFIX.length);
  // Unpadded base64url only.
  expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
  const json = Buffer.from(encoded, "base64url").toString("utf8");
  return { json, payload: JSON.parse(json) as CallerPayload };
}

const pairOf = (caller: CallerContext) => {
  const { payload } = decodeIdentity(encodeVerifiedCaller(caller));
  return `${payload.uid} ${payload.cred}`;
};

describe("the structured caller header name", () => {
  it("is x-umbrella-caller, a different header from the user id", () => {
    expect(VERIFIED_CALLER_IDENTITY_HEADER).toBe("x-umbrella-caller");
    expect(VERIFIED_CALLER_IDENTITY_HEADER).not.toBe(VERIFIED_CALLER_HEADER);
  });

  it("is named beside the user id in the boot log line", () => {
    process.env.VERIFIED_CALLER_SERVER_NAMES = "team";
    assertVerifiedCallerConfig();
    expect(logger.info).toHaveBeenCalledWith(
      expect.stringMatching(/X-Umbrella-User-Id.*X-Umbrella-Caller.*team/),
    );
  });
});

describe("verifiedCallerCredential", () => {
  it("names an API key by its uuid", () => {
    expect(
      verifiedCallerCredential({ authMethod: "api_key", apiKeyUuid: KEY_A }),
    ).toBe(`api_key:${KEY_A}`);
  });

  it("names an OAuth token by the client it was issued to", () => {
    expect(
      verifiedCallerCredential({
        authMethod: "oauth",
        oauthClientId: CLIENT_A,
      }),
    ).toBe(`oauth:${CLIENT_A}`);
  });

  it("names the Inspector's signed-in admin as the session credential", () => {
    expect(verifiedCallerCredential({ authMethod: "session" })).toBe("session");
  });

  it.each([
    ["an API key with no uuid", { authMethod: "api_key" }],
    ["an OAuth token with no client id", { authMethod: "oauth" }],
    [
      "an OAuth caller that also carries a key uuid",
      { authMethod: "oauth", apiKeyUuid: KEY_A },
    ],
    [
      "an API-key caller that also carries an OAuth client id",
      { authMethod: "api_key", oauthClientId: CLIENT_A },
    ],
    ["an unknown auth method", { authMethod: "basic", apiKeyUuid: KEY_A }],
    ["no auth method", { apiKeyUuid: KEY_A, oauthClientId: CLIENT_A }],
    [
      "a key uuid that is not lowercase canonical",
      { authMethod: "api_key", apiKeyUuid: KEY_A.toUpperCase() },
    ],
    [
      "an OAuth client id outside the grammar",
      { authMethod: "oauth", oauthClientId: "client:one" },
    ],
  ] as Array<[string, CallerContext]>)(
    "is undefined for %s (chosen by the auth method, never by which fields are present)",
    (_label, caller) => {
      expect(verifiedCallerCredential(caller)).toBeUndefined();
    },
  );

  it("is undefined outside any caller binding", () => {
    expect(verifiedCallerCredential(undefined)).toBeUndefined();
  });
});

describe("encodeVerifiedCaller", () => {
  const full: CallerContext = {
    authMethod: "api_key",
    userId: "user-owner",
    apiKeyUuid: KEY_A,
    email: "owner@example.com",
    clientName: "build agent key",
    requestId: "req-0001",
  };

  it("writes v1 followed by unpadded base64url of one JSON object", () => {
    const value = encodeVerifiedCaller(full);
    expect(value).toMatch(/^v1\.[A-Za-z0-9_-]+$/);
    expect(decodeIdentity(value).payload).toEqual({
      v: 1,
      uid: "user-owner",
      cred: `api_key:${KEY_A}`,
      email: "owner@example.com",
      label: "build agent key",
      rid: "req-0001",
    });
  });

  it.each([
    ["every field present", full],
    [
      "only the identifying fields",
      { authMethod: "oauth", userId: "user-1", oauthClientId: CLIENT_A },
    ],
  ] as Array<[string, CallerContext]>)(
    "always writes the keys in the order v, uid, cred, email, label, rid (%s)",
    (_label, caller) => {
      const { json, payload } = decodeIdentity(encodeVerifiedCaller(caller));
      expect(Object.keys(payload)).toEqual([
        "v",
        "uid",
        "cred",
        "email",
        "label",
        "rid",
      ]);
      expect(json.startsWith('{"v":1,"uid":')).toBe(true);
    },
  );

  it("names the acts-as user as uid and the key as cred for a bound key", () => {
    const { payload } = decodeIdentity(
      encodeVerifiedCaller({
        authMethod: "api_key",
        userId: "user-admin",
        actsAsUserId: "user-bound",
        apiKeyUuid: KEY_A,
      }),
    );
    expect([payload.uid, payload.cred]).toEqual([
      "user-bound",
      `api_key:${KEY_A}`,
    ]);
  });

  it("uses exactly the user id the user id header carries", () => {
    const callers: CallerContext[] = [
      full,
      { ...full, actsAsUserId: "user-bound" },
      { authMethod: "oauth", userId: "user-oauth", oauthClientId: CLIENT_A },
      { authMethod: "session", userId: "user-admin" },
    ];
    for (const caller of callers) {
      expect(decodeIdentity(encodeVerifiedCaller(caller)).payload.uid).toBe(
        verifiedCallerUserId(caller),
      );
    }
  });

  it.each([
    ["outside any caller binding", undefined],
    ["a key with no owner", { authMethod: "api_key", apiKeyUuid: KEY_A }],
    [
      "a blank acts-as binding (no fallback to the owner)",
      {
        authMethod: "api_key",
        userId: "user-admin",
        actsAsUserId: "",
        apiKeyUuid: KEY_A,
      },
    ],
    [
      "an OAuth token with no client id",
      { authMethod: "oauth", userId: "user-oauth" },
    ],
    ["an API key with no uuid", { authMethod: "api_key", userId: "user-1" }],
    ["no auth method", { userId: "user-1", apiKeyUuid: KEY_A }],
    [
      "a user id outside the grammar",
      { authMethod: "api_key", userId: "user/one", apiKeyUuid: KEY_A },
    ],
    [
      "a user id over 64 characters",
      { authMethod: "api_key", userId: "u".repeat(65), apiKeyUuid: KEY_A },
    ],
    ["only a client-asserted actor", { assertedActor: "someone@example.com" }],
  ] as Array<[string, CallerContext | undefined]>)(
    "is undefined for %s",
    (_label, caller) => {
      expect(encodeVerifiedCaller(caller)).toBeUndefined();
    },
  );

  it("never carries the client-asserted actor", () => {
    const value = encodeVerifiedCaller({
      ...full,
      assertedActor: "asserted-person@example.com",
    });
    expect(decodeIdentity(value).json).not.toContain("asserted-person");
  });

  it("trims the descriptive fields", () => {
    const { payload } = decodeIdentity(
      encodeVerifiedCaller({
        ...full,
        email: "  owner@example.com ",
        clientName: "\tbuild agent key\n",
        requestId: " req-0001 ",
      }),
    );
    expect([payload.email, payload.label, payload.rid]).toEqual([
      "owner@example.com",
      "build agent key",
      "req-0001",
    ]);
  });

  it("shortens an over-long label visibly, by code points", () => {
    const { payload } = decodeIdentity(
      encodeVerifiedCaller({ ...full, clientName: "x".repeat(500) }),
    );
    expect(payload.label).toBe("x".repeat(199) + "…");
    expect(Array.from(payload.label ?? "")).toHaveLength(
      VERIFIED_CALLER_IDENTITY_LIMITS.label,
    );
  });

  it.each([
    [
      "an over-long email",
      { email: "a".repeat(243) + "@example.com" },
      "email",
    ],
    ["an over-long request id", { requestId: "r".repeat(65) }, "rid"],
  ] as Array<[string, Partial<CallerContext>, "email" | "rid"]>)(
    "sends %s as null rather than a shortened value",
    (_label, override, field) => {
      const { payload } = decodeIdentity(
        encodeVerifiedCaller({ ...full, ...override }),
      );
      expect(payload[field]).toBeNull();
    },
  );

  it.each([
    ["a control character", "key\u0000name"],
    ["an inner newline", "key\r\nname"],
    ["a right-to-left override", "key‮name"],
    ["a byte order mark inside", "key﻿name"],
    ["a line separator", "key name"],
    ["a lone surrogate", "key\udc00name"],
    ["an empty value", ""],
    ["only spaces", "   "],
  ])("sends a display value with %s as null", (_label, bad) => {
    const { payload } = decodeIdentity(
      encodeVerifiedCaller({
        ...full,
        email: bad,
        clientName: bad,
        requestId: bad,
      }),
    );
    expect([payload.email, payload.label, payload.rid]).toEqual([
      null,
      null,
      null,
    ]);
  });

  it("labels the Inspector's credential, whatever clientName holds", () => {
    const { payload } = decodeIdentity(
      encodeVerifiedCaller({ authMethod: "session", userId: "user-admin" }),
    );
    expect([payload.cred, payload.label]).toEqual(["session", "Inspector"]);
  });

  it("stays under the encoded limit at the largest values every field allows", () => {
    // Four UTF-8 bytes per code point, every field at its limit.
    const wide = "\u{1D400}";
    const value = encodeVerifiedCaller({
      authMethod: "oauth",
      userId: "u".repeat(64),
      oauthClientId: "c".repeat(128),
      email: wide.repeat(VERIFIED_CALLER_IDENTITY_LIMITS.email),
      clientName: wide.repeat(VERIFIED_CALLER_IDENTITY_LIMITS.label),
      requestId: wide.repeat(VERIFIED_CALLER_IDENTITY_LIMITS.rid),
    });
    expect(value).toBeDefined();
    expect((value ?? "").length).toBeLessThanOrEqual(
      VERIFIED_CALLER_IDENTITY_LIMITS.encoded,
    );
  });

  describe("the identifying pair separates every pair of credentials", () => {
    // The pair is the boundary a backend binds to. Each case below differs
    // in exactly one half, and must produce a different pair.
    it.each([
      [
        "the same user on two API keys",
        { authMethod: "api_key", userId: "user-1", apiKeyUuid: KEY_A },
        { authMethod: "api_key", userId: "user-1", apiKeyUuid: KEY_B },
      ],
      [
        "the same user on two OAuth clients",
        { authMethod: "oauth", userId: "user-1", oauthClientId: CLIENT_A },
        { authMethod: "oauth", userId: "user-1", oauthClientId: CLIENT_B },
      ],
      [
        "two users on the same OAuth client",
        { authMethod: "oauth", userId: "user-1", oauthClientId: CLIENT_A },
        { authMethod: "oauth", userId: "user-2", oauthClientId: CLIENT_A },
      ],
      [
        "one key acting as two different users",
        {
          authMethod: "api_key",
          userId: "user-admin",
          actsAsUserId: "user-1",
          apiKeyUuid: KEY_A,
        },
        {
          authMethod: "api_key",
          userId: "user-admin",
          actsAsUserId: "user-2",
          apiKeyUuid: KEY_A,
        },
      ],
      [
        "the same user on an API key and on the Inspector session",
        { authMethod: "api_key", userId: "user-1", apiKeyUuid: KEY_A },
        { authMethod: "session", userId: "user-1" },
      ],
      [
        "an acts-as key and its owner's own key",
        {
          authMethod: "api_key",
          userId: "user-admin",
          actsAsUserId: "user-1",
          apiKeyUuid: KEY_A,
        },
        { authMethod: "api_key", userId: "user-1", apiKeyUuid: KEY_B },
      ],
    ] as Array<[string, CallerContext, CallerContext]>)(
      "%s",
      (_label, first, second) => {
        expect(pairOf(first)).not.toBe(pairOf(second));
      },
    );

    it("keeps the pair when only the descriptive fields or the asserted actor change", () => {
      const base: CallerContext = {
        authMethod: "oauth",
        userId: "user-1",
        oauthClientId: CLIENT_A,
        email: "one@example.com",
        clientName: "one@example.com",
        requestId: "req-1",
        assertedActor: "one@example.com",
      };
      const changed: CallerContext = {
        ...base,
        email: "renamed@example.com",
        clientName: "another label",
        requestId: "req-2",
        assertedActor: "someone-else@example.com",
        callerIp: "198.51.100.9",
      };
      expect(pairOf(changed)).toBe(pairOf(base));
      expect(encodeVerifiedCaller(changed)).not.toBe(
        encodeVerifiedCaller(base),
      );
    });
  });
});

describe("withVerifiedCaller: X-Umbrella-Caller", () => {
  const oauthCaller: CallerContext = {
    authMethod: "oauth",
    userId: "user-1",
    oauthClientId: CLIENT_A,
    email: "one@example.com",
    requestId: "req-1",
  };

  it("sets the caller header beside the user id on a tool call, naming the same user", async () => {
    const { fetchImpl, seen } = recordingFetch();
    await runWithCallerContext(oauthCaller, () =>
      withVerifiedCaller(fetchImpl)(URL_INTERNAL, toolCall()),
    );
    expect(seen[0].get(VERIFIED_CALLER_IDENTITY_HEADER)).toBe(
      encodeVerifiedCaller(oauthCaller),
    );
    expect(
      decodeIdentity(seen[0].get(VERIFIED_CALLER_IDENTITY_HEADER)).payload.uid,
    ).toBe(seen[0].get(VERIFIED_CALLER_HEADER));
  });

  it.each(["X-Umbrella-Caller", "x-umbrella-caller", "X-UMBRELLA-CALLER"])(
    "replaces a supplied %s with the gateway's value",
    async (name) => {
      const { fetchImpl, seen } = recordingFetch();
      await runWithCallerContext(oauthCaller, () =>
        withVerifiedCaller(fetchImpl)(
          URL_INTERNAL,
          toolCall({ [name]: "v1.supplied" }),
        ),
      );
      expect(seen[0].get(VERIFIED_CALLER_IDENTITY_HEADER)).toBe(
        encodeVerifiedCaller(oauthCaller),
      );
    },
  );

  it("removes a supplied value outside any caller binding", async () => {
    const { fetchImpl, seen } = recordingFetch();
    await withVerifiedCaller(fetchImpl)(
      URL_INTERNAL,
      toolCall({ "X-Umbrella-Caller": "v1.supplied" }),
    );
    expect(seen[0].has(VERIFIED_CALLER_IDENTITY_HEADER)).toBe(false);
  });

  it("removes a supplied value from a Headers instance", async () => {
    const { fetchImpl, seen } = recordingFetch();
    await runWithCallerContext(oauthCaller, () =>
      withVerifiedCaller(fetchImpl)(URL_INTERNAL, {
        method: "POST",
        body: rpc("initialize"),
        headers: new Headers({ "X-Umbrella-Caller": "v1.supplied" }),
      }),
    );
    expect(seen[0].has(VERIFIED_CALLER_IDENTITY_HEADER)).toBe(false);
  });

  it("still sends the user id, but no caller header, when the credential does not resolve", async () => {
    // An OAuth token whose client id was not stamped: the user id keeps its
    // own rule, and the structured header is never half an identity.
    const { fetchImpl, seen } = recordingFetch();
    await runWithCallerContext({ authMethod: "oauth", userId: "user-1" }, () =>
      withVerifiedCaller(fetchImpl)(
        URL_INTERNAL,
        toolCall({ "X-Umbrella-Caller": "v1.supplied" }),
      ),
    );
    expect(seen[0].get(VERIFIED_CALLER_HEADER)).toBe("user-1");
    expect(seen[0].has(VERIFIED_CALLER_IDENTITY_HEADER)).toBe(false);
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
    ["an unparseable body", { method: "POST", body: "{not json" }],
    [
      "a response to a server request",
      {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 9, result: {} }),
      },
    ],
  ])(
    "carries no caller header on %s, even inside a caller binding, and strips a supplied one",
    async (_label, init) => {
      const { fetchImpl, seen } = recordingFetch();
      await runWithCallerContext(oauthCaller, () =>
        withVerifiedCaller(fetchImpl)(URL_INTERNAL, {
          ...(init as RequestInit),
          headers: { "X-Umbrella-Caller": "v1.supplied" },
        }),
      );
      expect(seen[0].has(VERIFIED_CALLER_IDENTITY_HEADER)).toBe(false);
    },
  );

  it("gives each of two concurrent tool calls its own credential", async () => {
    const { fetchImpl, seen } = recordingFetch();
    const wrapped = withVerifiedCaller(fetchImpl);
    await Promise.all(
      [KEY_A, KEY_B].map((apiKeyUuid) =>
        runWithCallerContext(
          { authMethod: "api_key", userId: "user-1", apiKeyUuid },
          async () => {
            await new Promise((resolve) => setTimeout(resolve, 0));
            return wrapped(URL_INTERNAL, toolCall());
          },
        ),
      ),
    );
    expect(
      seen
        .map(
          (h) => decodeIdentity(h.get(VERIFIED_CALLER_IDENTITY_HEADER)).payload,
        )
        .map((p) => p.cred)
        .sort(),
    ).toEqual([`api_key:${KEY_A}`, `api_key:${KEY_B}`]);
  });
});

describe("getVerifiedCallerFetchForServer: X-Umbrella-Caller", () => {
  it("leaves a supplied caller header on an unnamed server untouched", async () => {
    process.env.VERIFIED_CALLER_SERVER_NAMES = "team";
    const { fetchImpl, seen } = recordingFetch();
    await runWithCallerContext(
      { authMethod: "api_key", userId: "user-1", apiKeyUuid: KEY_A },
      () =>
        getVerifiedCallerFetchForServer("other", fetchImpl)(
          URL_INTERNAL,
          toolCall({ "X-Umbrella-Caller": "stored" }),
        ),
    );
    expect(seen[0].get(VERIFIED_CALLER_IDENTITY_HEADER)).toBe("stored");
  });

  it("replaces it on a named server", async () => {
    process.env.VERIFIED_CALLER_SERVER_NAMES = "team";
    const { fetchImpl, seen } = recordingFetch();
    const caller: CallerContext = {
      authMethod: "api_key",
      userId: "user-1",
      apiKeyUuid: KEY_A,
    };
    await runWithCallerContext(caller, () =>
      getVerifiedCallerFetchForServer("team", fetchImpl)(
        URL_INTERNAL,
        toolCall({ "X-Umbrella-Caller": "stored" }),
      ),
    );
    expect(seen[0].get(VERIFIED_CALLER_IDENTITY_HEADER)).toBe(
      encodeVerifiedCaller(caller),
    );
  });
});

describe("the Inspector helpers: X-Umbrella-Caller", () => {
  it.each([
    "X-Umbrella-Caller",
    "x-umbrella-caller",
    "X-UMBRELLA-CALLER",
    " X-Umbrella-Caller ",
  ])("recognizes %j as reserved", (name) => {
    expect(isVerifiedCallerHeaderName(name)).toBe(true);
  });

  it.each(["X-Umbrella-Callers", "X-Umbrella", "X-Caller"])(
    "does not reserve %j",
    (name) => {
      expect(isVerifiedCallerHeaderName(name)).toBe(false);
    },
  );

  it("drops both reserved headers from stored headers in any casing and keeps the rest", () => {
    expect(
      withoutVerifiedCallerHeader({
        "X-Umbrella-User-Id": "a",
        "X-Umbrella-Caller": "b",
        "x-umbrella-caller": "c",
        "x-vendor-api-key": "k",
      }),
    ).toEqual({ "x-vendor-api-key": "k" });
  });
});

/**
 * The shared test vectors. A reader in another language tests against the
 * same file, so the encoder must reproduce every recorded value byte for
 * byte, and every recorded value must decode to the recorded JSON text.
 */
describe("verified-caller-v1-vectors.json", () => {
  interface Vector {
    name: string;
    caller: CallerContext | null;
    json: string;
    payload: CallerPayload;
    value: string;
    user_id_header: string | null;
  }
  interface NoValueVector {
    name: string;
    caller: CallerContext | null;
    user_id_header: string | null;
  }
  const fixture = JSON.parse(
    readFileSync(join(__dirname, "verified-caller-v1-vectors.json"), "utf8"),
  ) as {
    header: string;
    user_id_header: string;
    prefix: string;
    key_order: string[];
    limits: Record<string, number>;
    vectors: Vector[];
    no_value: NoValueVector[];
  };

  it("describes this encoder's header names, prefix, key order and limits", () => {
    expect(fixture.header).toBe(VERIFIED_CALLER_IDENTITY_HEADER);
    expect(fixture.user_id_header).toBe(VERIFIED_CALLER_HEADER);
    expect(fixture.prefix).toBe(VERIFIED_CALLER_IDENTITY_PREFIX);
    expect(fixture.key_order).toEqual([
      "v",
      "uid",
      "cred",
      "email",
      "label",
      "rid",
    ]);
    expect(fixture.limits).toEqual({ ...VERIFIED_CALLER_IDENTITY_LIMITS });
    expect(fixture.vectors.length).toBeGreaterThan(20);
    expect(fixture.no_value.length).toBeGreaterThan(10);
  });

  it.each(fixture.vectors.map((v) => [v.name, v] as const))(
    "encodes: %s",
    (_name, vector) => {
      const caller = vector.caller ?? undefined;
      expect(encodeVerifiedCaller(caller)).toBe(vector.value);
      expect(verifiedCallerUserId(caller) ?? null).toBe(vector.user_id_header);
    },
  );

  it.each(fixture.vectors.map((v) => [v.name, v] as const))(
    "decodes to the recorded JSON text and payload: %s",
    (_name, vector) => {
      const { json, payload } = decodeIdentity(vector.value);
      expect(json).toBe(vector.json);
      expect(payload).toEqual(vector.payload);
      expect(Object.keys(payload)).toEqual(fixture.key_order);
    },
  );

  it.each(fixture.no_value.map((v) => [v.name, v] as const))(
    "sends no caller header: %s",
    (_name, vector) => {
      const caller = vector.caller ?? undefined;
      expect(encodeVerifiedCaller(caller)).toBeUndefined();
      expect(verifiedCallerUserId(caller) ?? null).toBe(vector.user_id_header);
    },
  );
});
