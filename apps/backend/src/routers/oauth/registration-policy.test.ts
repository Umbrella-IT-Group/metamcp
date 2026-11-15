/**
 * The self-registration door's policy (migration 0042): which callbacks it
 * accepts, which status it writes, and how OAUTH_DCR_MODE changes the door,
 * its guidance and discovery.
 *
 *  - Every mode accepts only plain-http loopback callbacks (localhost,
 *    127.0.0.1, [::1], any port), after every shared rule has run. A refusal
 *    stores nothing and is audited with the refused hosts only.
 *  - `pending` (unset) stores the client pending; a body asking for any other
 *    status or approver is ignored.
 *  - `open` (development and test only) stores it approved, still loopback
 *    only.
 *  - `off` refuses with REGISTRATION_DISABLED_BODY before anything is minted,
 *    keeps the body and rate limits, says so on GET /oauth/register, drops
 *    registration_endpoint from discovery (bare and endpoint-suffixed forms)
 *    and stops pointing unknown clients at registration.
 *
 * Run over a real socket against the real routers with the repositories
 * mocked, so what is asserted is what an HTTP client receives and whether the
 * repository was asked to store anything.
 */

import { createHash } from "node:crypto";
import type { Server } from "node:http";

import express from "express";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const oauthRepositoryMock = {
  upsertClient: vi.fn(),
  getClient: vi.fn(),
};

vi.mock("../../db/repositories", () => ({
  oauthRepository: oauthRepositoryMock,
  endpointsRepository: {
    hasOAuthEnabledEndpoint: vi.fn().mockResolvedValue(true),
    findByName: vi.fn().mockResolvedValue({ enable_oauth: true }),
  },
  usersRepository: { isDisabled: vi.fn().mockResolvedValue(false) },
}));

vi.mock("../../auth", () => ({
  auth: {
    api: { getSession: vi.fn() },
    handler: vi.fn(async () => new Response("null", { status: 200 })),
  },
}));

process.env.APP_URL = "https://gateway.example.test";
process.env.BETTER_AUTH_SECRET = "test-secret-for-registration-policy";

// Policy approval of matching registrations (./dcr-auto-approval). Set before
// the routers load, so the policy is latched from the environment on first use
// and the cases below need nothing from that module. Written in canonical form
// (keys in order, networks canonical and sorted), so its SHA-256 is the
// expected policy_version. Each describe uses its own entry, so the entries'
// hourly budgets never interfere. Restored after the file.
const AUTO_APPROVE_ENV = "OAUTH_DCR_AUTO_APPROVE_POLICY";
const originalAutoApprove = process.env[AUTO_APPROVE_ENV];
const policyEntry = (
  id: string,
  clientName: string,
  host: string,
  allowedCidrs: string[],
  maxPerHour: number,
) => ({
  id,
  client_name: clientName,
  redirect: { host, path: "/callback", port_min: 1024, port_max: 65535 },
  allowed_cidrs: allowedCidrs,
  max_per_hour: maxPerHour,
});
const AUTO_APPROVE_POLICY = {
  version: 1,
  entries: [
    policyEntry(
      "desktop",
      "Example Desktop Client",
      "localhost",
      ["127.0.0.0/16", "203.0.113.0/26"],
      1000,
    ),
    policyEntry(
      "cli",
      "Example CLI Client",
      "127.0.0.1",
      ["203.0.113.0/26"],
      1000,
    ),
    policyEntry(
      "ipv6-host",
      "Example IPv6 Client",
      "[::1]",
      ["203.0.113.0/26"],
      1000,
    ),
    policyEntry(
      "capped",
      "Example Capped Client",
      "localhost",
      ["203.0.113.0/26"],
      2,
    ),
    policyEntry(
      "concurrent",
      "Example Concurrent Client",
      "localhost",
      ["203.0.113.0/26"],
      2,
    ),
    policyEntry(
      "fragile",
      "Example Fragile Client",
      "localhost",
      ["203.0.113.0/26"],
      1,
    ),
    policyEntry(
      "open-mode",
      "Example Open Client",
      "localhost",
      ["203.0.113.0/26"],
      1,
    ),
  ],
};
const AUTO_APPROVE_POLICY_TEXT = JSON.stringify(AUTO_APPROVE_POLICY);
const AUTO_APPROVE_POLICY_VERSION = createHash("sha256")
  .update(AUTO_APPROVE_POLICY_TEXT)
  .digest("hex");
process.env[AUTO_APPROVE_ENV] = AUTO_APPROVE_POLICY_TEXT;

const { setAuditSinkForTesting } = await import("@/lib/audit/audit-emitter");
const utils = await import("./utils");
const dcrMode = await import("./dcr-mode");
const { default: registrationRouter } = await import("./registration");
const { default: metadataRouter } = await import("./metadata");
const { default: authorizationRouter } = await import("./authorization");

const MODE_ENV = dcrMode.OAUTH_DCR_MODE_ENV;
const originalMode = process.env[MODE_ENV];

type AuditRow = Record<string, unknown> & { detail?: Record<string, unknown> };
let rows: AuditRow[] = [];

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  const app = express();
  app.use(utils.jsonParsingMiddleware);
  app.use(utils.urlencodedParsingMiddleware);
  app.use(metadataRouter);
  app.use(authorizationRouter);
  app.use(registrationRouter);
  server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  if (originalAutoApprove === undefined) delete process.env[AUTO_APPROVE_ENV];
  else process.env[AUTO_APPROVE_ENV] = originalAutoApprove;
});

function setMode(value: string | undefined) {
  if (value === undefined) delete process.env[MODE_ENV];
  else process.env[MODE_ENV] = value;
  dcrMode.resetOAuthDcrModeForTests();
}

beforeEach(() => {
  vi.clearAllMocks();
  oauthRepositoryMock.upsertClient.mockResolvedValue(undefined);
  oauthRepositoryMock.getClient.mockResolvedValue(null);
  utils.resetRegistrationRateLimitForTests();
  rows = [];
  setAuditSinkForTesting(async (event) => {
    rows.push(event as unknown as AuditRow);
  });
  setMode(undefined);
});

afterEach(() => {
  setAuditSinkForTesting(null);
  setMode(originalMode);
});

let ipCounter = 0;
const nextIp = () => `198.51.100.${(++ipCounter % 250) + 1}`;
const flush = () => new Promise((resolve) => setTimeout(resolve, 10));

async function postRegister(body: unknown, ip = nextIp()) {
  const res = await fetch(`${baseUrl}/oauth/register`, {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": ip },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
  await flush();
  return {
    status: res.status,
    body: (await res.json()) as Record<string, unknown>,
  };
}

async function getJson(path: string) {
  const res = await fetch(`${baseUrl}${path}`, {
    redirect: "manual",
    headers: { "cf-connecting-ip": nextIp() },
  });
  return {
    status: res.status,
    cacheControl: res.headers.get("cache-control"),
    body: (await res.json()) as Record<string, unknown>,
  };
}

function storedClient(): Record<string, unknown> {
  expect(oauthRepositoryMock.upsertClient).toHaveBeenCalledTimes(1);
  return oauthRepositoryMock.upsertClient.mock.calls[0][0];
}

const NON_LOOPBACK_BODY = {
  error: "invalid_redirect_uri",
  error_description:
    "This gateway registers only local callback addresses automatically. Hosted clients use a client an administrator creates.",
};

describe("self-registration accepts loopback callbacks only", () => {
  it.each([
    "http://localhost:53682/callback",
    "http://127.0.0.1:41000/callback",
    "http://[::1]:8080/cb",
    "http://localhost/cb",
    "http://127.0.0.1:65535/a/b/c?x=1",
  ])("accepts %s and stores it pending", async (uri) => {
    const res = await postRegister({
      client_name: "Claude Code",
      redirect_uris: [uri],
    });
    expect(res.status).toBe(201);
    expect(res.body.approval_status).toBe("pending");
    expect(storedClient()).toMatchObject({
      redirect_uris: [uri],
      registration_source: "dcr",
      approval_status: "pending",
      approved_at: null,
    });
  });

  it.each([
    ["claude.ai", ["https://claude.ai/api/mcp/auth_callback"]],
    ["claude.com", ["https://claude.com/api/mcp/auth_callback"]],
    ["another allowlisted https host", ["https://anthropic.com/cb"]],
    ["plain http off loopback", ["http://example.com/cb"]],
    [
      "a list with one hosted entry",
      [
        "http://localhost:53682/callback",
        "https://claude.ai/api/mcp/auth_callback",
      ],
    ],
    [
      "userinfo before a loopback-looking host",
      ["http://localhost@evil.example/cb"],
    ],
    ["a loopback label on another host", ["http://localhost.evil.com/cb"]],
    ["an IPv4-mapped IPv6 loopback", ["http://[::ffff:127.0.0.1]:8080/cb"]],
    ["another 127/8 address", ["http://127.0.0.2:8080/cb"]],
    ["https on localhost", ["https://localhost:8443/cb"]],
    ["https on 127.0.0.1", ["https://127.0.0.1/cb"]],
    ["a fragment", ["http://localhost:8080/cb#frag"]],
    ["the gateway's internal port", ["http://localhost:12009/cb"]],
  ])("refuses %s and stores nothing", async (_label, uris) => {
    const res = await postRegister({
      client_name: "Claude",
      redirect_uris: uris,
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_redirect_uri");
    expect(oauthRepositoryMock.upsertClient).not.toHaveBeenCalled();
  });

  it("answers a hosted callback with the documented body", async () => {
    const res = await postRegister({
      redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
    });
    expect(res.body).toEqual(NON_LOOPBACK_BODY);
  });

  it("audits the refusal with the refused hosts only, never a path or query", async () => {
    await postRegister({
      client_name: "Claude",
      redirect_uris: [
        "http://localhost:53682/callback",
        "https://claude.ai/api/mcp/auth_callback?secret=do-not-store",
      ],
    });
    const denied = rows.filter((r) => r.action === "oauth.dcr.register");
    expect(denied).toHaveLength(1);
    expect(denied[0]).toMatchObject({
      actor_type: "anonymous",
      outcome: "denied",
      target_id: null,
      http_status: 400,
    });
    expect(denied[0].detail).toEqual({
      dcr_mode: "pending",
      reason: "non_loopback_redirect_uri",
      refused_hosts: ["claude.ai"],
      redirect_uri_count: 2,
    });
    expect(JSON.stringify(denied[0])).not.toContain("do-not-store");
    expect(JSON.stringify(denied[0])).not.toContain("auth_callback");
  });

  it("ignores status and approver fields a caller sends", async () => {
    const res = await postRegister({
      client_name: "Claude Code",
      redirect_uris: ["http://localhost:53682/callback"],
      approval_status: "approved",
      approved_by: "someone",
      approved_at: "2026-01-01T00:00:00Z",
      rejected_at: null,
      registration_source: "admin",
    });
    expect(res.status).toBe(201);
    const stored = storedClient();
    expect(stored).toMatchObject({
      registration_source: "dcr",
      approval_status: "pending",
      approved_at: null,
    });
    expect(stored).not.toHaveProperty("approved_by");
    expect(stored).not.toHaveProperty("rejected_at");
  });
});

describe("OAUTH_DCR_MODE=open (development and test only)", () => {
  beforeEach(() => setMode("open"));

  it("stores a loopback registration approved, with a time and no approver", async () => {
    const res = await postRegister({
      redirect_uris: ["http://127.0.0.1:41000/cb"],
    });
    expect(res.status).toBe(201);
    expect(res.body.approval_status).toBe("approved");
    const stored = storedClient();
    expect(stored).toMatchObject({
      approval_status: "approved",
      registration_source: "dcr",
    });
    expect(stored.approved_at).toBeInstanceOf(Date);
    expect(stored).not.toHaveProperty("approved_by");
  });

  it("still refuses a hosted callback", async () => {
    const res = await postRegister({
      redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
    });
    expect(res.status).toBe(400);
    expect(res.body).toEqual(NON_LOOPBACK_BODY);
    expect(oauthRepositoryMock.upsertClient).not.toHaveBeenCalled();
  });
});

describe("OAUTH_DCR_MODE=off", () => {
  beforeEach(() => setMode("off"));

  it("refuses with the documented disabled body and stores nothing", async () => {
    const res = await postRegister({
      redirect_uris: ["http://localhost:53682/callback"],
    });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({
      error: "registration_disabled",
      error_description:
        "This gateway does not accept automatic client registration. Ask an administrator for a client.",
    });
    expect(oauthRepositoryMock.upsertClient).not.toHaveBeenCalled();
    const denied = rows.filter((r) => r.action === "oauth.dcr.register");
    expect(denied).toHaveLength(1);
    expect(denied[0]).toMatchObject({ outcome: "denied", target_id: null });
    expect(denied[0].detail).toEqual({
      dcr_mode: "off",
      reason: "registration_disabled",
    });
  });

  it("still applies the body limit before refusing", async () => {
    const res = await fetch(`${baseUrl}/oauth/register`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "cf-connecting-ip": nextIp(),
      },
      body: JSON.stringify({ client_name: "x".repeat(300 * 1024) }),
    });
    expect(res.status).toBe(413);
  });

  it("still applies the registration rate limit", async () => {
    const ip = "203.0.113.200";
    for (let i = 0; i < 30; i++) {
      expect((await postRegister({}, ip)).status).toBe(400);
    }
    expect((await postRegister({}, ip)).status).toBe(429);
  });

  it("says registration is off on GET /oauth/register", async () => {
    const res = await getJson("/oauth/register");
    expect(res.status).toBe(200);
    expect(res.body.registration_enabled).toBe(false);
    expect(res.body.registration_mode).toBe("off");
    expect(res.body).not.toHaveProperty("registration_endpoint");
  });

  it.each([
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-authorization-server/metamcp/example/mcp",
  ])("omits registration_endpoint from %s", async (path) => {
    const res = await getJson(path);
    expect(res.status).toBe(200);
    expect(res.body).not.toHaveProperty("registration_endpoint");
    expect(res.body.authorization_endpoint).toBe(
      "https://gateway.example.test/oauth/authorize",
    );
    // Cached for an hour, so a client can hold the old document that long
    // after the mode changes; the POST above refuses immediately anyway.
    expect(res.cacheControl).toBe("public, max-age=3600");
  });

  it("stops pointing an unknown client at registration", async () => {
    const res = await getJson(
      "/oauth/authorize?response_type=code&client_id=mcp_client_unknown" +
        "&redirect_uri=http%3A%2F%2Flocalhost%3A53682%2Fcallback" +
        "&code_challenge=abc&code_challenge_method=S256",
    );
    expect(res.status).toBe(400);
    expect(res.body).toEqual({
      error: "invalid_client",
      error_description:
        "Client not registered. Ask an administrator for a client.",
    });
  });
});

describe("guidance and discovery while registration is accepted", () => {
  it.each([
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-authorization-server/metamcp/example/mcp",
  ])("advertises registration_endpoint on %s", async (path) => {
    const res = await getJson(path);
    expect(res.body.registration_endpoint).toBe(
      "https://gateway.example.test/oauth/register",
    );
  });

  it("describes loopback registration and administrator approval", async () => {
    const res = await getJson("/oauth/register");
    expect(res.body.registration_mode).toBe("pending");
    expect(res.body.registration_enabled).toBe(true);
    const example = res.body.example_registration as {
      body: { redirect_uris: string[] };
    };
    expect(example.body.redirect_uris).toEqual([
      "http://127.0.0.1:33418/callback",
    ]);
    const text = JSON.stringify(res.body);
    expect(text).not.toContain("https://myapp.example.com");
    expect(text).toContain("administrator");
  });

  it("points an unknown client at loopback registration and approval", async () => {
    const res = await getJson(
      "/oauth/authorize?response_type=code&client_id=mcp_client_unknown" +
        "&redirect_uri=http%3A%2F%2Flocalhost%3A53682%2Fcallback" +
        "&code_challenge=abc&code_challenge_method=S256",
    );
    expect(res.status).toBe(400);
    expect(res.body.registration_endpoint).toBe(
      "https://gateway.example.test/oauth/register",
    );
    expect(String(res.body.documentation)).toContain(
      "administrator must approve",
    );
  });
});

describe("an unrecognized OAUTH_DCR_MODE fails closed", () => {
  it.each(["", "Pending", " pending", "closed"])(
    "treats %j as off",
    async (value) => {
      setMode(value);
      const res = await postRegister({
        redirect_uris: ["http://localhost:53682/callback"],
      });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("registration_disabled");
      expect(oauthRepositoryMock.upsertClient).not.toHaveBeenCalled();
    },
  );
});

describe("policy approval of matching registrations (OAUTH_DCR_AUTO_APPROVE_POLICY)", () => {
  const CALLBACK = "http://localhost:53682/callback";
  const OUTSIDE = "198.51.100.9";
  let insideCounter = 0;
  const insideIp = () => `203.0.113.${(++insideCounter % 60) + 1}`;

  const desktopBody = (extra: Record<string, unknown> = {}) => ({
    client_name: "Example Desktop Client",
    redirect_uris: [CALLBACK],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
    ...extra,
  });

  async function registerWith(
    body: unknown,
    headers: Record<string, string>,
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    const res = await fetch(`${baseUrl}/oauth/register`, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body: JSON.stringify(body),
    });
    const json = (await res.json()) as Record<string, unknown>;
    await new Promise((resolve) => setImmediate(resolve));
    return { status: res.status, body: json };
  }

  const registerRows = () =>
    rows.filter(
      (r) => r.action === "oauth.dcr.register" && r.outcome === "success",
    );

  it("stores a matching registration approved in its initial insert, with a time and no approver", async () => {
    const res = await registerWith(desktopBody(), {
      "cf-connecting-ip": insideIp(),
    });
    expect(res.status).toBe(201);
    expect(res.body.approval_status).toBe("approved");
    const stored = storedClient();
    expect(stored).toMatchObject({
      registration_source: "dcr",
      approval_status: "approved",
      redirect_uris: [CALLBACK],
    });
    expect(stored.approved_at).toBeInstanceOf(Date);
    expect(stored).not.toHaveProperty("approved_by");

    const [row] = registerRows();
    expect(row.target_id).toBe(res.body.client_id);
    expect(row.detail).toMatchObject({
      approval_status: "approved",
      dcr_mode: "pending",
      auto_approval: {
        entry_id: "desktop",
        policy_version: AUTO_APPROVE_POLICY_VERSION,
      },
    });
    expect(Object.keys(row.detail?.auto_approval as object).sort()).toEqual([
      "entry_id",
      "policy_version",
    ]);
    expect(row.detail).not.toHaveProperty("auto_approval_skipped");
    const text = JSON.stringify(row);
    expect(text).not.toContain("203.0.113.0/26");
    expect(text).not.toContain("127.0.0.0/16");
    expect(text).not.toContain("max_per_hour");
  });

  it.each([
    [
      "127.0.0.1",
      "cli",
      "Example CLI Client",
      "http://127.0.0.1:41000/callback",
    ],
    ["[::1]", "ipv6-host", "Example IPv6 Client", "http://[::1]:8080/callback"],
  ])(
    "approves the %s loopback host's family",
    async (_host, entryId, name, callback) => {
      const res = await registerWith(
        { client_name: name, redirect_uris: [callback] },
        { "cf-connecting-ip": insideIp() },
      );
      expect(res.status).toBe(201);
      expect(res.body.approval_status).toBe("approved");
      expect(storedClient().approval_status).toBe("approved");
      expect(registerRows()[0].detail?.auto_approval).toEqual({
        entry_id: entryId,
        policy_version: AUTO_APPROVE_POLICY_VERSION,
      });
    },
  );

  it("matches on the shared core's defaults when grant, response and auth fields are omitted", async () => {
    const res = await registerWith(
      { client_name: "Example Desktop Client", redirect_uris: [CALLBACK] },
      { "cf-connecting-ip": insideIp() },
    );
    expect(res.status).toBe(201);
    expect(res.body.approval_status).toBe("approved");
    expect(storedClient()).toMatchObject({
      approval_status: "approved",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      client_secret: null,
    });
  });

  it("leaves a valid non-matching registration pending, with no policy marker", async () => {
    const res = await registerWith(
      desktopBody({ client_name: "Example Desktop Client " }),
      { "cf-connecting-ip": insideIp() },
    );
    expect(res.status).toBe(201);
    expect(res.body.approval_status).toBe("pending");
    expect(storedClient()).toMatchObject({
      approval_status: "pending",
      approved_at: null,
    });
    const [row] = registerRows();
    expect(row.detail).toMatchObject({ approval_status: "pending" });
    expect(row.detail).not.toHaveProperty("auto_approval");
    expect(row.detail).not.toHaveProperty("auto_approval_skipped");
  });

  it.each([
    [
      "an unsupported grant type",
      { grant_types: ["password"] },
      "invalid_request",
    ],
    ["no callbacks", { redirect_uris: [] }, "invalid_redirect_uri"],
    [
      "the gateway's internal port",
      { redirect_uris: ["http://localhost:12009/callback"] },
      "invalid_redirect_uri",
    ],
  ])(
    "keeps %s a 400 with no row, even with a matching name and address",
    async (_label, extra, error) => {
      const res = await registerWith(desktopBody(extra), {
        "cf-connecting-ip": insideIp(),
      });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe(error);
      expect(oauthRepositoryMock.upsertClient).not.toHaveBeenCalled();
    },
  );

  it("gives approval, entry, source and address fields in the body no authority", async () => {
    const claims = {
      approval_status: "approved",
      approved_at: "2026-01-01T00:00:00Z",
      auto_approval: { entry_id: "desktop", policy_version: "0".repeat(64) },
      entry_id: "desktop",
      registration_source: "admin",
      cf_connecting_ip: insideIp(),
      "cf-connecting-ip": insideIp(),
      client_ip: insideIp(),
      actor_ip: insideIp(),
    };
    const otherName = await registerWith(
      desktopBody({ client_name: "Example Other Client", ...claims }),
      { "cf-connecting-ip": insideIp() },
    );
    expect(otherName.status).toBe(201);
    expect(otherName.body.approval_status).toBe("pending");
    expect(storedClient()).toMatchObject({
      approval_status: "pending",
      registration_source: "dcr",
      approved_at: null,
    });

    oauthRepositoryMock.upsertClient.mockClear();
    const noHeader = await registerWith(desktopBody(claims), {});
    expect(noHeader.status).toBe(201);
    expect(noHeader.body.approval_status).toBe("pending");
    expect(storedClient().approval_status).toBe("pending");
  });

  it.each([
    ["no CF-Connecting-IP (req.ip is loopback, inside the entry)", {}],
    [
      "no CF-Connecting-IP and an allowed X-Forwarded-For",
      { "x-forwarded-for": "203.0.113.5" },
    ],
    [
      "no CF-Connecting-IP and an allowed Forwarded",
      { forwarded: "for=203.0.113.5;proto=https" },
    ],
    [
      "no CF-Connecting-IP and an allowed X-Real-IP",
      { "x-real-ip": "203.0.113.5" },
    ],
    [
      "an outside CF-Connecting-IP with allowed forwarded headers",
      {
        "cf-connecting-ip": OUTSIDE,
        "x-forwarded-for": "203.0.113.5",
        forwarded: "for=203.0.113.5",
        "x-real-ip": "203.0.113.5",
      },
    ],
    ["an empty CF-Connecting-IP", { "cf-connecting-ip": "" }],
    ["an unparseable CF-Connecting-IP", { "cf-connecting-ip": "203.0.113" }],
  ])(
    "stores a matching registration pending with %s",
    async (_label, headers) => {
      const res = await registerWith(desktopBody(), headers);
      expect(res.status).toBe(201);
      expect(res.body.approval_status).toBe("pending");
      expect(storedClient()).toMatchObject({
        approval_status: "pending",
        approved_at: null,
      });
      expect(registerRows()[0].detail).not.toHaveProperty("auto_approval");
    },
  );

  it("approves on an allowed CF-Connecting-IP although req.ip (loopback) is a different address", async () => {
    const res = await registerWith(
      desktopBody({
        client_name: "Example CLI Client",
        redirect_uris: ["http://127.0.0.1:41000/callback"],
      }),
      { "cf-connecting-ip": "203.0.113.42", "x-forwarded-for": OUTSIDE },
    );
    expect(res.status).toBe(201);
    expect(res.body.approval_status).toBe("approved");
    expect(registerRows()[0].detail?.auto_approval).toMatchObject({
      entry_id: "cli",
    });
  });

  it("says on GET /oauth/register that approval_status decides, without naming any policy entry", async () => {
    const res = await getJson("/oauth/register");
    expect(res.body.registration_mode).toBe("pending");
    expect(String(res.body.approval)).toContain("approval_status");
    expect(String(res.body.approval)).toContain("by policy");
    const text = JSON.stringify(res.body);
    for (const value of [
      "Example Desktop Client",
      "203.0.113.0",
      "127.0.0.0/16",
      "desktop",
      "max_per_hour",
    ]) {
      expect(text).not.toContain(value);
    }
    const discovery = await getJson("/.well-known/oauth-authorization-server");
    expect(JSON.stringify(discovery.body)).not.toContain(
      "Example Desktop Client",
    );
    expect(JSON.stringify(discovery.body)).not.toContain("203.0.113.0");
  });

  describe("the hourly budget", () => {
    it("approves up to max_per_hour and stores the next match pending, audited as held", async () => {
      const body = desktopBody({ client_name: "Example Capped Client" });
      const statuses: unknown[] = [];
      for (let i = 0; i < 3; i++) {
        const res = await registerWith(body, {
          "cf-connecting-ip": insideIp(),
        });
        expect(res.status).toBe(201);
        statuses.push(res.body.approval_status);
      }
      expect(statuses).toEqual(["approved", "approved", "pending"]);
      expect(
        oauthRepositoryMock.upsertClient.mock.calls.map(
          ([client]) => client.approval_status,
        ),
      ).toEqual(["approved", "approved", "pending"]);
      const details = registerRows().map((r) => r.detail);
      expect(details[2]).toMatchObject({
        approval_status: "pending",
        auto_approval_skipped: "cap",
      });
      expect(details[2]).not.toHaveProperty("auto_approval");
      expect(details[0]).not.toHaveProperty("auto_approval_skipped");
    });

    it("reserves before the write: two concurrent matches against one remaining slot", async () => {
      const body = desktopBody({ client_name: "Example Concurrent Client" });
      const first = await registerWith(body, {
        "cf-connecting-ip": insideIp(),
      });
      expect(first.body.approval_status).toBe("approved");
      oauthRepositoryMock.upsertClient.mockClear();

      const releases: Array<() => void> = [];
      let bothWaiting: () => void = () => {};
      const arrived = new Promise<void>((resolve) => {
        bothWaiting = resolve;
      });
      oauthRepositoryMock.upsertClient.mockImplementation(
        () =>
          new Promise<void>((resolve) => {
            releases.push(resolve);
            if (releases.length === 2) bothWaiting();
          }),
      );

      const pending = [
        registerWith(body, { "cf-connecting-ip": insideIp() }),
        registerWith(body, { "cf-connecting-ip": insideIp() }),
      ];
      await arrived;
      const stamped = oauthRepositoryMock.upsertClient.mock.calls
        .map(([client]) => client.approval_status)
        .sort();
      expect(stamped).toEqual(["approved", "pending"]);
      expect(
        rows.filter((r) => r.action === "oauth.dcr.register"),
      ).toHaveLength(1);

      releases.forEach((release) => release());
      const results = await Promise.all(pending);
      expect(results.map((r) => r.status)).toEqual([201, 201]);
      expect(results.map((r) => r.body.approval_status).sort()).toEqual([
        "approved",
        "pending",
      ]);
      const later = registerRows()
        .slice(1)
        .map((r) => r.detail);
      expect(later.filter((d) => d?.auto_approval)).toHaveLength(1);
      expect(
        later.filter((d) => d?.auto_approval_skipped === "cap"),
      ).toHaveLength(1);
    });

    it("spends the slot of a failed insert and records no success for it", async () => {
      const body = desktopBody({ client_name: "Example Fragile Client" });
      oauthRepositoryMock.upsertClient.mockRejectedValueOnce(
        new Error("insert failed"),
      );
      const failed = await registerWith(body, {
        "cf-connecting-ip": insideIp(),
      });
      expect(failed.status).toBe(500);
      expect(
        oauthRepositoryMock.upsertClient.mock.calls[0][0].approval_status,
      ).toBe("approved");
      expect(registerRows()).toHaveLength(0);

      oauthRepositoryMock.upsertClient.mockClear();
      const next = await registerWith(body, { "cf-connecting-ip": insideIp() });
      expect(next.status).toBe(201);
      expect(next.body.approval_status).toBe("pending");
      expect(storedClient().approval_status).toBe("pending");
      expect(registerRows()).toHaveLength(1);
      expect(registerRows()[0].detail).toMatchObject({
        auto_approval_skipped: "cap",
      });
    });
  });

  describe("modes with a matching policy", () => {
    it("off refuses before the policy is consulted", async () => {
      setMode("off");
      const res = await registerWith(desktopBody(), {
        "cf-connecting-ip": insideIp(),
      });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("registration_disabled");
      expect(oauthRepositoryMock.upsertClient).not.toHaveBeenCalled();
    });

    it("open approves by its own stamp, with no policy marker and no policy budget spent", async () => {
      setMode("open");
      const body = desktopBody({ client_name: "Example Open Client" });
      for (let i = 0; i < 2; i++) {
        const res = await registerWith(body, {
          "cf-connecting-ip": insideIp(),
        });
        expect(res.status).toBe(201);
        expect(res.body.approval_status).toBe("approved");
      }
      for (const row of registerRows()) {
        expect(row.detail).toMatchObject({ dcr_mode: "open" });
        expect(row.detail).not.toHaveProperty("auto_approval");
        expect(row.detail).not.toHaveProperty("auto_approval_skipped");
      }

      setMode(undefined);
      rows = [];
      const res = await registerWith(body, { "cf-connecting-ip": insideIp() });
      expect(res.body.approval_status).toBe("approved");
      expect(registerRows()[0].detail?.auto_approval).toEqual({
        entry_id: "open-mode",
        policy_version: AUTO_APPROVE_POLICY_VERSION,
      });
    });
  });

  it("keeps every registration pending under a refused policy, and loading a policy changes no stored row", async () => {
    const policyModule = await import("./dcr-auto-approval");
    try {
      policyModule.initDcrAutoApproval({
        [AUTO_APPROVE_ENV]: AUTO_APPROVE_POLICY_TEXT.replace(
          '"max_per_hour":1000',
          '"max_per_hour":1000.0',
        ),
      });
      const res = await registerWith(desktopBody(), {
        "cf-connecting-ip": insideIp(),
      });
      expect(res.status).toBe(201);
      expect(res.body.approval_status).toBe("pending");
      expect(storedClient().approval_status).toBe("pending");
      expect(Object.keys(oauthRepositoryMock)).toEqual([
        "upsertClient",
        "getClient",
      ]);
    } finally {
      policyModule.initDcrAutoApproval();
    }
  });
});
