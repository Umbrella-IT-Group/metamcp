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
