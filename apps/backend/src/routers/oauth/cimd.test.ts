/**
 * The client metadata document resolver and its transport.
 *
 * DNS and sockets are faked ONLY below the guard, through the `lookup` and
 * `baseFetch` seams, so the guard's own validation (range table, address
 * pinning, redirect handling, byte cap) runs on everything a test feeds it.
 * Time is the injected clock; the one deadline test uses fake timers. The
 * repository is an in-memory stand-in at the storage boundary; the real SQL
 * is exercised by oauth-cimd.integration.test.ts and cimd.integration.test.ts.
 *
 * Oracles. The fetch limits are mcp-use `clients.ts`: a 5 KiB body cap
 * (`CIMD_MAX_BYTES`, "metadata document is too large"), a 10 s deadline
 * (`CIMD_TIMEOUT_MS`), `redirect: "manual"` and `status !== 200` refused. The
 * MCP authorization spec says an authorization server fetching a client
 * identifier URL "SHOULD consider Server-Side Request Forgery (SSRF) risks".
 * Everything about caching, stale serving, the failure memory, the fetch
 * rate, the row cap and the audit bounds is a design decision with no outside
 * oracle and is marked as such.
 */
import { createHash } from "node:crypto";

import type { OAuthClient } from "@repo/zod-types";
import type express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { AuditEvent } from "@/lib/audit/audit-emitter";

const h = vi.hoisted(() => ({
  logger: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  upsertCimdClient: vi.fn(),
  countCimdClients: vi.fn(),
}));
vi.mock("@/utils/logger", () => ({ default: h.logger }));
vi.mock("../../db/repositories", () => ({
  oauthRepository: {
    upsertCimdClient: h.upsertCimdClient,
    countCimdClients: h.countCimdClients,
  },
}));

const { setAuditSinkForTesting } = await import("@/lib/audit/audit-emitter");
const {
  cimdStateSizesForTesting,
  resetCimdStateForTesting,
  resolveCimdClient,
  setCimdClockForTesting,
  setCimdTransportForTesting,
} = await import("./cimd");
const { OAUTH_CIMD_ALLOWED_CLIENTS_ENV, resetCimdConfigForTesting } =
  await import("./cimd-config");

const ORIGIN = "https://app.example.com";
const ID = `${ORIGIN}/oauth/client.json`;
const HOSTED = "https://claude.ai/api/mcp/auth_callback";
const PUBLIC_ADDRESS = "93.184.216.34";
const T0 = Date.UTC(2026, 10, 12, 12, 0, 0);
const MINUTE = 60_000;
const HOUR = 3_600_000;

const req = {
  headers: { "user-agent": "test-agent" },
  auditClientIp: "203.0.113.5",
  auditRequestId: "req-1",
} as unknown as express.Request;

let now = T0;
const events: AuditEvent[] = [];
const rows = new Map<string, OAuthClient>();
const baseFetch = vi.fn();
const lookup = vi.fn();

function documentFor(id: string, overrides: Record<string, unknown> = {}) {
  return JSON.stringify({
    client_id: id,
    client_name: "Example",
    redirect_uris: [HOSTED],
    ...overrides,
  });
}

const json = (text: string, init: ResponseInit = {}) =>
  new Response(text, { status: 200, ...init });

/** A row as the repository would have stored it. */
function rowFor(id: string, overrides: Partial<OAuthClient> = {}): OAuthClient {
  return {
    client_id: id,
    client_secret: null,
    client_name: "Example",
    redirect_uris: [HOSTED],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
    scope: "mcp",
    client_uri: null,
    logo_uri: null,
    contacts: null,
    tos_uri: null,
    policy_uri: null,
    software_id: null,
    software_version: null,
    registration_source: "cimd",
    approval_status: "approved",
    approved_by: null,
    approved_at: new Date(now),
    rejected_at: null,
    created_at: new Date(now),
    updated_at: new Date(now),
    ...overrides,
  };
}

const flush = async () => {
  for (let i = 0; i < 10; i += 1) await Promise.resolve();
};

async function auditRows(): Promise<AuditEvent[]> {
  await flush();
  return events.filter((e) => e.action === "oauth.cimd.resolve");
}

async function resolve(
  id: string,
  options: { existing?: OAuthClient | null; redirectUri?: string } = {},
) {
  return resolveCimdClient(id, {
    existing: options.existing ?? null,
    redirectUri: options.redirectUri ?? HOSTED,
    req,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  now = T0;
  events.length = 0;
  rows.clear();
  resetCimdStateForTesting();
  resetCimdConfigForTesting();
  process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = ORIGIN;
  delete process.env.MCP_PROXY_URL_ALLOWED_HOSTS;
  setCimdClockForTesting(() => now);
  setAuditSinkForTesting(async (event) => {
    events.push(event);
  });

  lookup.mockImplementation(async () => [PUBLIC_ADDRESS]);
  baseFetch.mockImplementation(async (url: URL) => json(documentFor(url.href)));
  setCimdTransportForTesting({ lookup, baseFetch });

  h.countCimdClients.mockImplementation(async () => rows.size);
  h.upsertCimdClient.mockImplementation(
    async (draft: Record<string, unknown>, at: Date) => {
      const existing = rows.get(draft.client_id as string);
      if (existing && existing.registration_source !== "cimd") return null;
      const row = rowFor(draft.client_id as string, {
        ...(draft as Partial<OAuthClient>),
        registration_source: "cimd",
        created_at: existing?.created_at ?? at,
        updated_at: at,
      });
      rows.set(row.client_id, row);
      return row;
    },
  );
});

afterEach(() => {
  vi.useRealTimers();
  setAuditSinkForTesting(undefined);
  delete process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV];
  resetCimdConfigForTesting();
  resetCimdStateForTesting();
});

describe("an id the allowlist does not admit makes no outbound call and changes nothing", () => {
  it("makes zero lookups, zero fetches, zero repository calls and no state change", async () => {
    const result = await resolve("https://other.example.org/client.json");

    expect(result).toEqual({ ok: false, reason: "not_allowlisted" });
    expect(lookup).not.toHaveBeenCalled();
    expect(baseFetch).not.toHaveBeenCalled();
    expect(h.upsertCimdClient).not.toHaveBeenCalled();
    expect(h.countCimdClients).not.toHaveBeenCalled();
    expect(cimdStateSizesForTesting()).toEqual({
      negativeCache: 0,
      redirectRefreshAt: 0,
      refusalAudited: 1, // the one bounded audit row for this refusal
      inFlight: 0,
    });
  });

  it("does the same for an id that is not canonical, even under a listed origin", async () => {
    for (const id of [
      `${ORIGIN}/a?x=random`,
      "https://APP.example.com/a",
      `${ORIGIN}/a/../b`,
      `${ORIGIN}/`,
    ]) {
      expect((await resolve(id)).ok).toBe(false);
    }
    expect(lookup).not.toHaveBeenCalled();
    expect(baseFetch).not.toHaveBeenCalled();
    expect(await auditRows()).toEqual([]);
  });

  it("is refused before any I/O when the allowlist is cleared, whatever is stored", async () => {
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = "";
    expect(await resolve(ID, { existing: rowFor(ID) })).toEqual({
      ok: false,
      reason: "not_allowlisted",
    });
    expect(baseFetch).not.toHaveBeenCalled();
  });
});

describe("the fetch goes through the guard", () => {
  it("refuses a name that resolves to a private address, without opening a connection", async () => {
    lookup.mockImplementation(async () => ["10.0.0.5"]);

    expect(await resolve(ID)).toEqual({ ok: false, reason: "blocked_address" });
    expect(baseFetch).not.toHaveBeenCalled();
    expect(h.upsertCimdClient).not.toHaveBeenCalled();
  });

  it.each(["127.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "fd00::1"])(
    "refuses a name that resolves into %s",
    async (address) => {
      lookup.mockImplementation(async () => [address]);
      expect(await resolve(ID)).toEqual({
        ok: false,
        reason: "blocked_address",
      });
      expect(baseFetch).not.toHaveBeenCalled();
    },
  );

  // The guard falls back to MCP_PROXY_URL_ALLOWED_HOSTS when no allowlist is
  // passed, and trusts a host named there without resolving or pinning it. A
  // metadata fetch passes an empty allowlist, so the env cannot exempt it.
  it("is not exempted by MCP_PROXY_URL_ALLOWED_HOSTS", async () => {
    process.env.MCP_PROXY_URL_ALLOWED_HOSTS = "app.example.com";
    lookup.mockImplementation(async () => ["10.0.0.5"]);

    expect(await resolve(ID)).toEqual({ ok: false, reason: "blocked_address" });
    expect(baseFetch).not.toHaveBeenCalled();
  });

  it("pins the connection to the addresses it checked", async () => {
    const seen: unknown[] = [];
    baseFetch.mockImplementation(
      async (url: URL, _init: unknown, agent: unknown) => {
        seen.push(agent);
        return json(documentFor(url.href));
      },
    );

    expect((await resolve(ID)).ok).toBe(true);
    // A pinned agent is supplied for a resolved (not allowlisted) host.
    expect(seen[0]).toBeDefined();
  });

  it("sends a GET for JSON with no credentials, and asks for no redirect to be followed", async () => {
    await resolve(ID);

    expect(baseFetch).toHaveBeenCalledTimes(1);
    const [url, init] = baseFetch.mock.calls[0] as [URL, RequestInit];
    expect(url.href).toBe(ID);
    expect(init.method).toBe("GET");
    expect(init.redirect).toBe("manual");
    const headers = init.headers as Headers;
    expect(headers.get("accept")).toBe("application/json");
    expect(headers.get("user-agent")).toBe(
      "metamcp-oauth-client-metadata-fetcher",
    );
    for (const name of [
      "authorization",
      "cookie",
      "x-gateway-auth",
      "x-umbrella-user-id",
    ]) {
      expect(headers.get(name)).toBeNull();
    }
    expect(init.body).toBeUndefined();
  });

  // mcp-use: redirect "manual", and a status other than 200 is refused.
  it.each([301, 302, 303, 307, 308])(
    "refuses a %s and never follows it, even to the same origin",
    async (status) => {
      baseFetch.mockImplementation(
        async () =>
          new Response(null, {
            status,
            headers: { location: `${ORIGIN}/elsewhere.json` },
          }),
      );

      expect(await resolve(ID)).toEqual({ ok: false, reason: "http_status" });
      expect(baseFetch).toHaveBeenCalledTimes(1);
      expect(h.upsertCimdClient).not.toHaveBeenCalled();
    },
  );

  it.each([204, 400, 403, 404, 410, 500, 503])(
    "refuses status %s",
    async (status) => {
      // A 204 may not carry a body, so no body is built for any of them.
      baseFetch.mockImplementation(async () => new Response(null, { status }));
      expect(await resolve(ID)).toEqual({ ok: false, reason: "http_status" });
      expect(h.upsertCimdClient).not.toHaveBeenCalled();
    },
  );

  // mcp-use CIMD_MAX_BYTES = 5 * 1024; the cap counts the decoded body.
  it("accepts a document of exactly 5120 bytes and refuses one of 5121", async () => {
    const pad = (bytes: number) => {
      const base = documentFor(ID, { pad: "" });
      return documentFor(ID, { pad: "x".repeat(bytes - base.length) });
    };
    const exact = pad(5120);
    expect(new TextEncoder().encode(exact).byteLength).toBe(5120);
    baseFetch.mockImplementation(async () => json(exact));
    expect((await resolve(ID)).ok).toBe(true);

    resetCimdStateForTesting();
    setCimdClockForTesting(() => now);
    setCimdTransportForTesting({ lookup, baseFetch });
    rows.clear();
    const over = pad(5121);
    expect(new TextEncoder().encode(over).byteLength).toBe(5121);
    baseFetch.mockImplementation(async () => json(over));
    expect(await resolve(ID)).toEqual({ ok: false, reason: "too_large" });
  });

  it("refuses a declared content-length over the cap without reading the body", async () => {
    const body = vi.fn();
    baseFetch.mockImplementation(async () => {
      const response = json("{}", { headers: { "content-length": "6000" } });
      body.mockImplementation(() => response.arrayBuffer());
      return response;
    });

    expect(await resolve(ID)).toEqual({ ok: false, reason: "too_large" });
    expect(body).not.toHaveBeenCalled();
  });

  // mcp-use CIMD_TIMEOUT_MS = 10_000. Driven by fake timers: a transport that
  // never answers is refused at the deadline, and not before it.
  it("refuses at the 10 second deadline when the transport never answers", async () => {
    vi.useFakeTimers();
    baseFetch.mockImplementation(() => new Promise(() => {}));

    let settled: unknown;
    const pending = resolve(ID).then((r) => {
      settled = r;
      return r;
    });
    await vi.advanceTimersByTimeAsync(9_999);
    expect(settled).toBeUndefined();
    await vi.advanceTimersByTimeAsync(1);
    expect(await pending).toEqual({ ok: false, reason: "timeout" });
  });

  it("refuses at the deadline when the name never resolves", async () => {
    vi.useFakeTimers();
    lookup.mockImplementation(() => new Promise(() => {}));

    const pending = resolve(ID);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(await pending).toEqual({ ok: false, reason: "timeout" });
    expect(baseFetch).not.toHaveBeenCalled();
  });

  it("refuses a transport error as fetch_failed", async () => {
    baseFetch.mockImplementation(async () => {
      throw new Error("socket hang up");
    });
    expect(await resolve(ID)).toEqual({ ok: false, reason: "fetch_failed" });
  });
});

describe("what a fetched document must be", () => {
  it.each([
    ["not JSON", "not json", "not_json"],
    [
      "a mismatched client_id",
      documentFor("https://app.example.com/other.json"),
      "client_id_mismatch",
    ],
    [
      "a confidential client",
      documentFor(ID, { client_secret: "x" }),
      "not_public_client",
    ],
    [
      "an off-allowlist callback",
      documentFor(ID, { redirect_uris: ["https://evil.example/cb"] }),
      "invalid_redirect_uri",
    ],
    [
      "a loopback callback",
      documentFor(ID, { redirect_uris: ["http://127.0.0.1:3000/cb"] }),
      "non_hosted_redirect_uri",
    ],
  ])("refuses %s and stores nothing", async (_name, text, reason) => {
    baseFetch.mockImplementation(async () => json(text));

    expect(await resolve(ID)).toEqual({ ok: false, reason });
    expect(h.upsertCimdClient).not.toHaveBeenCalled();
  });

  it("refuses bytes that are not UTF-8", async () => {
    baseFetch.mockImplementation(
      async () =>
        new Response(new Uint8Array([0x7b, 0xff, 0x7d]), { status: 200 }),
    );
    expect(await resolve(ID)).toEqual({ ok: false, reason: "not_json" });
  });
});

describe("resolution and caching (design decisions)", () => {
  it("fetches on a miss and stores an approved row, once", async () => {
    const result = await resolve(ID);

    expect(result).toMatchObject({ ok: true, source: "fetched" });
    expect(baseFetch).toHaveBeenCalledTimes(1);
    expect(h.upsertCimdClient).toHaveBeenCalledTimes(1);
    const [draft, at] = h.upsertCimdClient.mock.calls[0];
    expect(draft).toMatchObject({
      client_id: ID,
      client_secret: null,
      token_endpoint_auth_method: "none",
      redirect_uris: [HOSTED],
    });
    expect(at).toEqual(new Date(T0));
    expect(rows.get(ID)).toMatchObject({
      registration_source: "cimd",
      approval_status: "approved",
    });
  });

  it("serves a fresh row without fetching", async () => {
    const existing = rowFor(ID, { updated_at: new Date(now - 59 * MINUTE) });
    const result = await resolve(ID, { existing });

    expect(result).toEqual({ ok: true, client: existing, source: "cache" });
    expect(baseFetch).not.toHaveBeenCalled();
    expect(lookup).not.toHaveBeenCalled();
  });

  it("refetches a row that is an hour old, and counts one with no update time as stale", async () => {
    await resolve(ID, {
      existing: rowFor(ID, { updated_at: new Date(now - HOUR) }),
    });
    expect(baseFetch).toHaveBeenCalledTimes(1);

    resetCimdStateForTesting();
    setCimdClockForTesting(() => now);
    setCimdTransportForTesting({ lookup, baseFetch });
    await resolve(ID, {
      existing: rowFor(ID, { updated_at: undefined }),
    });
    expect(baseFetch).toHaveBeenCalledTimes(2);
  });

  it("refreshes once when a fresh row lacks the requested callback, and not again within a minute", async () => {
    const newCallback = "https://claude.ai/api/organizations/callback";
    baseFetch.mockImplementation(async () =>
      json(documentFor(ID, { redirect_uris: [HOSTED, newCallback] })),
    );
    const existing = rowFor(ID, { updated_at: new Date(now - MINUTE) });

    const first = await resolve(ID, { existing, redirectUri: newCallback });
    expect(first).toMatchObject({ ok: true, source: "fetched" });
    expect(first.ok && first.client.redirect_uris).toContain(newCallback);
    expect(baseFetch).toHaveBeenCalledTimes(1);

    // A callback the document still does not list: no second refresh inside
    // the minute that the first one started. The row is returned and the
    // authorize handler refuses the callback itself.
    const unknown = "https://claude.ai/not-listed";
    now += 30_000;
    const again = await resolve(ID, {
      existing: rows.get(ID),
      redirectUri: unknown,
    });
    expect(again).toMatchObject({ ok: true, source: "cache" });
    expect(baseFetch).toHaveBeenCalledTimes(1);

    now += 31_000;
    await resolve(ID, { existing: rows.get(ID), redirectUri: unknown });
    expect(baseFetch).toHaveBeenCalledTimes(2);
  });

  it("returns a row of another source untouched, with no fetch", async () => {
    const admin = rowFor(ID, { registration_source: "admin" });
    expect(await resolve(ID, { existing: admin })).toEqual({
      ok: true,
      client: admin,
      source: "cache",
    });
    expect(baseFetch).not.toHaveBeenCalled();
    expect(h.upsertCimdClient).not.toHaveBeenCalled();
  });

  it("never overwrites a row of another source that appeared since it was read", async () => {
    rows.set(ID, rowFor(ID, { registration_source: "admin" }));

    expect(await resolve(ID)).toEqual({ ok: false, reason: "conflict" });
    expect(rows.get(ID)?.registration_source).toBe("admin");
  });

  it("makes one fetch for concurrent callers of one id", async () => {
    let release!: (response: Response) => void;
    baseFetch.mockImplementation(
      () => new Promise<Response>((resolveFetch) => (release = resolveFetch)),
    );

    const calls = [resolve(ID), resolve(ID), resolve(ID)];
    await flush();
    release(json(documentFor(ID)));
    const results = await Promise.all(calls);

    expect(baseFetch).toHaveBeenCalledTimes(1);
    expect(h.upsertCimdClient).toHaveBeenCalledTimes(1);
    for (const result of results) expect(result.ok).toBe(true);
  });
});

describe("stale rows and failure memory (design decisions)", () => {
  const staleRow = (ageMs: number) =>
    rowFor(ID, { updated_at: new Date(now - ageMs) });

  it("serves a stale row through a transient failure", async () => {
    baseFetch.mockImplementation(
      async () => new Response("down", { status: 503 }),
    );
    const existing = staleRow(2 * HOUR);

    expect(await resolve(ID, { existing })).toEqual({
      ok: true,
      client: existing,
      source: "stale",
    });
  });

  it.each([
    [
      "a network error",
      async () => {
        throw new Error("reset");
      },
    ],
    ["a 429", async () => new Response("slow down", { status: 429 })],
  ])("serves a stale row through %s", async (_name, impl) => {
    baseFetch.mockImplementation(impl);
    expect(await resolve(ID, { existing: staleRow(2 * HOUR) })).toMatchObject({
      ok: true,
      source: "stale",
    });
  });

  it("serves a stale row when the name does not resolve, but not when it resolves into a refused range", async () => {
    lookup.mockImplementation(async () => {
      throw new Error("ENOTFOUND");
    });
    expect(await resolve(ID, { existing: staleRow(2 * HOUR) })).toMatchObject({
      ok: true,
      source: "stale",
    });

    resetCimdStateForTesting();
    setCimdClockForTesting(() => now);
    lookup.mockImplementation(async () => ["10.0.0.5"]);
    setCimdTransportForTesting({ lookup, baseFetch });
    expect(await resolve(ID, { existing: staleRow(2 * HOUR) })).toEqual({
      ok: false,
      reason: "blocked_address",
    });
  });

  it("does not serve a stale row past 24 hours", async () => {
    baseFetch.mockImplementation(
      async () => new Response("down", { status: 503 }),
    );

    expect(await resolve(ID, { existing: staleRow(24 * HOUR + 1) })).toEqual({
      ok: false,
      reason: "http_status",
    });
  });

  it.each([404, 410, 403])(
    "refuses a %s even when a stale row exists",
    async (status) => {
      baseFetch.mockImplementation(async () => new Response("no", { status }));
      expect(await resolve(ID, { existing: staleRow(2 * HOUR) })).toEqual({
        ok: false,
        reason: "http_status",
      });
    },
  );

  it.each([
    ["an invalid document", "not json", "not_json"],
    [
      "a document that now names a secret",
      documentFor(ID, { client_secret: "x" }),
      "not_public_client",
    ],
    [
      "a document that now mismatches",
      documentFor("https://app.example.com/x.json"),
      "client_id_mismatch",
    ],
  ])("refuses %s even when a stale row exists", async (_name, text, reason) => {
    baseFetch.mockImplementation(async () => json(text));
    expect(await resolve(ID, { existing: staleRow(2 * HOUR) })).toEqual({
      ok: false,
      reason,
    });
  });

  it("refuses an oversized document even when a stale row exists", async () => {
    baseFetch.mockImplementation(async () =>
      json("{}", { headers: { "content-length": "9999" } }),
    );
    expect(await resolve(ID, { existing: staleRow(2 * HOUR) })).toEqual({
      ok: false,
      reason: "too_large",
    });
  });

  it("does not fetch the same failing id again for a minute, then does", async () => {
    baseFetch.mockImplementation(
      async () => new Response("no", { status: 404 }),
    );

    await resolve(ID);
    expect(baseFetch).toHaveBeenCalledTimes(1);
    now += 59_999;
    expect(await resolve(ID)).toEqual({ ok: false, reason: "http_status" });
    expect(baseFetch).toHaveBeenCalledTimes(1);
    now += 1;
    await resolve(ID);
    expect(baseFetch).toHaveBeenCalledTimes(2);
  });

  it("serves a stale row from the failure memory for a transient failure, without refetching", async () => {
    baseFetch.mockImplementation(
      async () => new Response("down", { status: 503 }),
    );
    const existing = staleRow(2 * HOUR);

    await resolve(ID, { existing });
    const second = await resolve(ID, { existing });
    expect(second).toMatchObject({ ok: true, source: "stale" });
    expect(baseFetch).toHaveBeenCalledTimes(1);
  });

  it("serves a fresh row that has the callback even while the id is in the failure memory", async () => {
    baseFetch.mockImplementation(
      async () => new Response("no", { status: 404 }),
    );
    const unknown = "https://claude.ai/not-listed";
    const fresh = rowFor(ID, { updated_at: new Date(now - MINUTE) });
    await resolve(ID, { existing: fresh, redirectUri: unknown });
    expect(baseFetch).toHaveBeenCalledTimes(1);

    expect(await resolve(ID, { existing: fresh })).toEqual({
      ok: true,
      client: fresh,
      source: "cache",
    });
    expect(baseFetch).toHaveBeenCalledTimes(1);
  });

  it("forgets a failure once the id resolves", async () => {
    baseFetch.mockImplementation(
      async () => new Response("no", { status: 404 }),
    );
    await resolve(ID);
    now += MINUTE;
    baseFetch.mockImplementation(async (url: URL) =>
      json(documentFor(url.href)),
    );
    expect((await resolve(ID)).ok).toBe(true);
    expect(cimdStateSizesForTesting().negativeCache).toBe(0);
  });

  it("never holds more than 1000 failed ids in memory", async () => {
    baseFetch.mockImplementation(
      async () => new Response("no", { status: 404 }),
    );

    for (let i = 0; i < 1100; i += 1) {
      now += 1100; // inside the fetch rate, so every id really fetches
      await resolve(`${ORIGIN}/c/${i}`);
    }

    expect(baseFetch).toHaveBeenCalledTimes(1100);
    const sizes = cimdStateSizesForTesting();
    expect(sizes.negativeCache).toBe(1000);
    expect(sizes.refusalAudited).toBeLessThanOrEqual(1000);
  });
});

describe("load bounds (design decisions)", () => {
  it("refuses a 17th concurrent fetch as busy, and serves a stale row instead", async () => {
    const pending: Array<(r: Response) => void> = [];
    baseFetch.mockImplementation(
      () => new Promise<Response>((resolveFetch) => pending.push(resolveFetch)),
    );

    const inFlight = Array.from({ length: 16 }, (_, i) =>
      resolve(`${ORIGIN}/c/${i}`),
    );
    await flush();
    expect(cimdStateSizesForTesting().inFlight).toBe(16);

    expect(await resolve(`${ORIGIN}/c/new`)).toEqual({
      ok: false,
      reason: "busy",
    });
    const stale = rowFor(`${ORIGIN}/c/old`, {
      updated_at: new Date(now - 2 * HOUR),
    });
    expect(await resolve(`${ORIGIN}/c/old`, { existing: stale })).toEqual({
      ok: true,
      client: stale,
      source: "stale",
    });
    expect(baseFetch).toHaveBeenCalledTimes(16);

    for (const release of pending) release(new Response("no", { status: 404 }));
    await Promise.all(inFlight);
    expect(cimdStateSizesForTesting().inFlight).toBe(0);
  });

  it("refuses the 61st fetch in a minute as busy, and allows fetching again a minute later", async () => {
    for (let i = 0; i < 60; i += 1) await resolve(`${ORIGIN}/c/${i}`);
    expect(baseFetch).toHaveBeenCalledTimes(60);

    expect(await resolve(`${ORIGIN}/c/61`)).toEqual({
      ok: false,
      reason: "busy",
    });
    expect(baseFetch).toHaveBeenCalledTimes(60);

    // A refusal for load is not remembered as a refusal of the document.
    now += MINUTE;
    expect((await resolve(`${ORIGIN}/c/61`)).ok).toBe(true);
    expect(baseFetch).toHaveBeenCalledTimes(61);
  });

  it("refuses the 501st new client as too_many_clients, before fetching, and still refreshes an existing one", async () => {
    for (let i = 0; i < 500; i += 1) {
      rows.set(`${ORIGIN}/c/${i}`, rowFor(`${ORIGIN}/c/${i}`));
    }

    expect(await resolve(`${ORIGIN}/c/new`)).toEqual({
      ok: false,
      reason: "too_many_clients",
    });
    expect(baseFetch).not.toHaveBeenCalled();

    const stale = rowFor(`${ORIGIN}/c/7`, {
      updated_at: new Date(now - 2 * HOUR),
    });
    expect(await resolve(`${ORIGIN}/c/7`, { existing: stale })).toMatchObject({
      ok: true,
      source: "fetched",
    });
    expect(baseFetch).toHaveBeenCalledTimes(1);
  });

  it("answers a storage failure with the generic refusal and logs the cause", async () => {
    h.upsertCimdClient.mockRejectedValue(
      new Error(
        'new row violates check constraint "oauth_clients_registration_source_valid"',
      ),
    );

    expect(await resolve(ID)).toEqual({ ok: false, reason: "store_failed" });
    expect(h.logger.error).toHaveBeenCalled();
  });
});

describe("audit rows (design decisions)", () => {
  it("writes one success row for a created document, with the hash and no body", async () => {
    const text = documentFor(ID);
    baseFetch.mockImplementation(async () => json(text));
    await resolve(ID);

    const rowsOut = await auditRows();
    expect(rowsOut).toHaveLength(1);
    expect(rowsOut[0]).toMatchObject({
      action: "oauth.cimd.resolve",
      target_type: "oauth_client",
      target_id: ID,
      outcome: "success",
      actor_type: "anonymous",
      actor_ip: "203.0.113.5",
      request_id: "req-1",
    });
    expect(rowsOut[0].detail).toEqual({
      result: "created",
      host: "app.example.com",
      document_sha256: createHash("sha256").update(text).digest("hex"),
      document_bytes: new TextEncoder().encode(text).byteLength,
      redirect_uris: [HOSTED],
    });
    expect(JSON.stringify(rowsOut[0])).not.toContain("client_name");
  });

  it("clamps the callbacks recorded to 10 entries of 512 characters", async () => {
    const callbacks = Array.from(
      { length: 10 },
      (_, i) => `https://claude.ai/${i}`,
    );
    baseFetch.mockImplementation(async () =>
      json(documentFor(ID, { redirect_uris: callbacks })),
    );
    await resolve(ID);
    expect(
      ((await auditRows())[0].detail as { redirect_uris: string[] })
        .redirect_uris,
    ).toEqual(callbacks);
  });

  it("writes an 'updated' row when the document changed, and none when it did not or on a cache hit", async () => {
    await resolve(ID); // created
    now += 2 * HOUR;
    await resolve(ID, { existing: rows.get(ID) }); // unchanged
    now += 2 * HOUR;
    baseFetch.mockImplementation(async () =>
      json(documentFor(ID, { client_name: "Renamed" })),
    );
    await resolve(ID, { existing: rows.get(ID) }); // updated
    await resolve(ID, { existing: rows.get(ID) }); // cache hit

    const results = (await auditRows()).map(
      (e) => (e.detail as { result: string }).result,
    );
    expect(results).toEqual(["created", "updated"]);
  });

  it("writes a denied row for an unlisted id and a failure row after admission", async () => {
    await resolve("https://other.example.org/client.json");
    baseFetch.mockImplementation(
      async () => new Response("no", { status: 404 }),
    );
    await resolve(ID);

    const [denied, failure] = await auditRows();
    expect(denied).toMatchObject({
      outcome: "denied",
      http_status: 400,
      detail: {
        reason: "not_allowlisted",
        host: "other.example.org",
        served_stale: false,
      },
    });
    expect(failure).toMatchObject({
      outcome: "failure",
      detail: {
        reason: "http_status",
        http_status: 404,
        host: "app.example.com",
      },
    });
  });

  it("marks a refusal that was answered from a stale row", async () => {
    baseFetch.mockImplementation(
      async () => new Response("down", { status: 503 }),
    );
    await resolve(ID, {
      existing: rowFor(ID, { updated_at: new Date(now - 2 * HOUR) }),
    });
    expect((await auditRows())[0].detail).toMatchObject({ served_stale: true });
  });

  it("writes one refusal row per (id, reason) per hour", async () => {
    baseFetch.mockImplementation(
      async () => new Response("no", { status: 404 }),
    );
    for (let i = 0; i < 5; i += 1) {
      await resolve(ID);
      now += 61_000; // past the failure memory, inside the hour
    }
    expect(await auditRows()).toHaveLength(1);

    now += HOUR;
    await resolve(ID);
    expect(await auditRows()).toHaveLength(2);

    // A different reason for the same id is a different row.
    now += 61_000;
    baseFetch.mockImplementation(async () => json("not json"));
    await resolve(ID);
    expect(await auditRows()).toHaveLength(3);
  });

  it("writes at most 50 refusal rows an hour across ids and reasons, then logs only", async () => {
    for (let i = 0; i < 60; i += 1) {
      await resolve(`https://other.example.org/c/${i}`); // not listed
      now += 1000;
    }
    baseFetch.mockImplementation(
      async () => new Response("no", { status: 404 }),
    );
    await resolve(ID); // a failure row is refused by the same cap

    expect(await auditRows()).toHaveLength(50);
    expect(
      h.logger.warn.mock.calls.filter((c) => String(c[0]).includes("refused")),
    ).toHaveLength(61);

    now += HOUR;
    await resolve("https://other.example.org/c/again");
    expect(await auditRows()).toHaveLength(51);
  });

  it("writes nothing for an id that is not even client-metadata-shaped", async () => {
    for (const id of [
      "mcp_client_abc",
      "https://app.example.com/",
      "http://app.example.com/x",
    ]) {
      expect(await resolve(id)).toEqual({
        ok: false,
        reason: "invalid_client_id",
      });
    }
    expect(await auditRows()).toEqual([]);
  });
});
