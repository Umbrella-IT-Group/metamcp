/**
 * The OAuth plane's audit rows.
 *
 * Credential-theft abuse runs on this exact chain: an anonymously registered
 * client, a consent grant, an authorization code, a 24h access token and the
 * 365d refresh token behind it. Every step of it was silent — `/oauth/register`
 * accepts a client with no credential at all and left no durable record that it
 * had, and nothing anywhere recorded that a human had granted a client access
 * to their account.
 *
 * Driven the same way `authorization.test.ts` drives these handlers: the router
 * as express middleware against fake req/res objects, with the repositories and
 * `../../auth` mocked so neither `db/index.ts` nor better-auth's pg pool enters
 * the import graph.
 *
 * The assertions that matter most are the negative ones. An authorization code
 * and an access token are bearer credentials; `audit_log` is append-only and
 * has no prune path by design, so a credential written into it cannot be taken
 * back out. Every test here that mints something also asserts the mint is
 * absent from the row.
 */

import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ConsentRequestPayload } from "./consent-token";

const loggerMock = {
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
};

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

const oauthRepositoryMock = {
  getClient: vi.fn(),
  setAuthCode: vi.fn(),
  getAuthCode: vi.fn(),
  deleteAuthCode: vi.fn(),
  upsertClient: vi.fn(),
};

const usersRepositoryMock = { isDisabled: vi.fn() };

vi.mock("../../db/repositories", () => ({
  oauthRepository: oauthRepositoryMock,
  usersRepository: usersRepositoryMock,
}));

const authMock = { handler: vi.fn() };
vi.mock("../../auth", () => ({ auth: authMock }));

process.env.APP_URL = "https://mcp.example.test";
process.env.BETTER_AUTH_SECRET = "test-secret-for-consent-request-signing";

const { default: authorizationRouter } = await import("./authorization");
const { default: registrationRouter } = await import("./registration");
const { CONSENT_CSRF_COOKIE_HOST_PREFIXED, signConsentRequest } = await import(
  "./consent-token"
);
const { resetConsentDecisionRateLimitForTests } = await import("./utils");
const { setAuditSinkForTesting } = await import("@/lib/audit/audit-emitter");

const CLIENT_ID = "mcp_client_test";
const CLIENT_NAME = "Claude";
const REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback";
const USER_ID = "user-abc123";
const STATE = "opaque-client-state";
const CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const SESSION_COOKIE = "better-auth.session_token=session-value";
const CLIENT_IP = "203.0.113.9";
const REQUEST_ID = "req-oauth-under-test";

type AuditRow = {
  action: string;
  outcome: string;
  actor_type: string;
  actor_id?: string | null;
  actor_ip?: string | null;
  request_id?: string | null;
  http_status?: number | null;
  target_type?: string | null;
  target_id?: string | null;
  detail?: Record<string, unknown>;
};

let rows: AuditRow[];

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));
const serialized = () => JSON.stringify(rows);

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

interface FakeRes {
  statusCode: number;
  body: Record<string, unknown> | undefined;
  redirectedTo: string | undefined;
  settled: Promise<void>;
  status(code: number): FakeRes;
  json(payload: Record<string, unknown>): FakeRes;
  send(payload?: string): FakeRes;
  redirect(url: string): FakeRes;
  cookie(): FakeRes;
  clearCookie(): FakeRes;
}

let ipCounter = 0;
let cidCounter = 0;

function makeReq(init: {
  method: string;
  path: string;
  body?: Record<string, unknown>;
  cookie?: string;
}): express.Request {
  ipCounter += 1;
  return {
    method: init.method,
    url: init.path,
    originalUrl: init.path,
    baseUrl: "",
    path: init.path,
    query: {},
    body: init.body,
    // The two fields the audit-context middleware stamps in production. Set
    // directly here because that middleware is mounted on the app, not on
    // this router — the point of the assertions below is that the handlers
    // READ them, i.e. that an OAuth row can name a caller at all.
    auditRequestId: REQUEST_ID,
    auditClientIp: CLIENT_IP,
    headers: {
      "user-agent": "Claude/1.0",
      ...(init.cookie ? { cookie: init.cookie } : {}),
    },
    ip: `10.2.0.${ipCounter}`,
    socket: { remoteAddress: `10.2.0.${ipCounter}` },
  } as unknown as express.Request;
}

function makeRes(): FakeRes {
  let settle: () => void;
  const settled = new Promise<void>((resolve) => {
    settle = resolve;
  });

  const res: FakeRes = {
    statusCode: 200,
    body: undefined,
    redirectedTo: undefined,
    settled,
    status(code) {
      res.statusCode = code;
      return res;
    },
    json(payload) {
      res.body = payload;
      settle();
      return res;
    },
    send() {
      settle();
      return res;
    },
    redirect(url) {
      res.redirectedTo = url;
      settle();
      return res;
    },
    cookie() {
      return res;
    },
    clearCookie() {
      return res;
    },
  };

  return res;
}

async function dispatch(
  router: unknown,
  init: Parameters<typeof makeReq>[0],
): Promise<FakeRes> {
  const req = makeReq(init);
  const res = makeRes();

  await new Promise<void>((resolve, reject) => {
    (router as express.RequestHandler)(
      req,
      res as unknown as express.Response,
      (err?: unknown) => (err ? reject(err) : resolve()),
    );
    res.settled.then(resolve);
  });

  return res;
}

function sessionFor(userId: string | null) {
  authMock.handler.mockImplementation(
    async () =>
      new Response(JSON.stringify(userId ? { user: { id: userId } } : null), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
  );
}

function makeAreq(overrides: Partial<ConsentRequestPayload> = {}) {
  const csrf = overrides.csrf ?? "csrf-nonce-for-this-browser";
  cidCounter += 1;
  const cid = overrides.cid ?? `cid${cidCounter}`;
  const areq = signConsentRequest({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: "mcp",
    state: STATE,
    code_challenge: CODE_CHALLENGE,
    code_challenge_method: "S256",
    user_id: USER_ID,
    cid,
    csrf,
    exp: Date.now() + 10 * 60 * 1000,
    ...overrides,
  });
  return { areq, csrf, cid };
}

function decide(init: {
  areq: string;
  decision?: string;
  csrfCookie?: string | null;
  cid: string;
}) {
  const cookies = [SESSION_COOKIE];
  if (init.csrfCookie) {
    cookies.push(
      `${CONSENT_CSRF_COOKIE_HOST_PREFIXED}_${init.cid}=${init.csrfCookie}`,
    );
  }
  return dispatch(authorizationRouter, {
    method: "POST",
    path: "/oauth/authorize/decision",
    body:
      init.decision === undefined
        ? { areq: init.areq }
        : { areq: init.areq, decision: init.decision },
    cookie: cookies.join("; "),
  });
}

/** The authorization code the handler minted, out of the setAuthCode call. */
function mintedCode(): string {
  const call = oauthRepositoryMock.setAuthCode.mock.calls[0];
  if (!call) throw new Error("no authorization code was minted");
  return call[0] as string;
}

beforeEach(() => {
  vi.clearAllMocks();
  resetConsentDecisionRateLimitForTests();
  rows = [];
  setAuditSinkForTesting(async (event) => {
    rows.push(event as AuditRow);
  });
  oauthRepositoryMock.getClient.mockResolvedValue({
    client_id: CLIENT_ID,
    client_name: CLIENT_NAME,
    redirect_uris: [REDIRECT_URI],
  });
  oauthRepositoryMock.setAuthCode.mockResolvedValue(undefined);
  oauthRepositoryMock.deleteAuthCode.mockResolvedValue(undefined);
  oauthRepositoryMock.upsertClient.mockResolvedValue(undefined);
  usersRepositoryMock.isDisabled.mockResolvedValue(false);
  sessionFor(USER_ID);
});

afterEach(() => {
  setAuditSinkForTesting(undefined);
});

// ---------------------------------------------------------------------------
// oauth.dcr.register — the anonymous write
// ---------------------------------------------------------------------------

describe("oauth.dcr.register — anonymous dynamic client registration", () => {
  it("writes an anonymous row naming the client, attributed by IP alone", async () => {
    const res = await dispatch(registrationRouter, {
      method: "POST",
      path: "/oauth/register",
      body: {
        client_name: "Definitely Claude",
        // Loopback, because since the host allowlist that is the only shape an
        // anonymous caller can still register besides the Anthropic hosts —
        // and it makes the point better: the NAME is the lie the consent
        // screen shows, and no host allowlist constrains it.
        redirect_uris: ["http://localhost:8765/callback"],
      },
    });
    await flush();

    expect(res.statusCode).toBe(201);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "oauth.dcr.register",
      outcome: "success",
      // No session, no key, no prior client identity exists on this request —
      // the IP is the only attribution available, which is exactly why the
      // CF-Connecting-IP middleware had to land before this lane.
      actor_type: "anonymous",
      actor_id: null,
      actor_ip: CLIENT_IP,
      request_id: REQUEST_ID,
      target_type: "oauth_client",
      http_status: 201,
    });
    expect(rows[0].detail).toMatchObject({
      client_name: "Definitely Claude",
      redirect_uris: ["http://localhost:8765/callback"],
    });
  });

  it("never persists the issued client_secret", async () => {
    const res = await dispatch(registrationRouter, {
      method: "POST",
      path: "/oauth/register",
      body: {
        client_name: CLIENT_NAME,
        redirect_uris: [REDIRECT_URI],
        token_endpoint_auth_method: "client_secret_post",
      },
    });
    await flush();

    const secret = (res.body as { client_secret?: string } | undefined)
      ?.client_secret;
    expect(typeof secret).toBe("string");
    expect(secret).toBeTruthy();
    // The secret crosses the wire in the response exactly once. It must not
    // also be sitting in a table nobody can prune.
    expect(serialized()).not.toContain(secret as string);
    expect(rows[0].detail).toMatchObject({ has_client_secret: true });
  });

  it("CLAMPS the caller-supplied arrays — this endpoint takes no credential", async () => {
    // Without a clamp this emit is a write-amplification primitive: the JSON
    // body limit is 50mb, `buildClientRegistration` validates each URI's
    // scheme and host but bounds neither the array nor its elements, and
    // `rateLimitToken` keys on `req.ip` — the same loopback address for every
    // caller behind the in-container rewrite, i.e. one global bucket. The
    // target is a jsonb column in a table with DELETE/TRUNCATE triggers and
    // no prune path, so every byte written is permanent.
    //
    // One allowlisted host with 40 distinct long PATHS, because the
    // host allowlist refuses 40 distinct hosts — and the clamp this test
    // exists for bounds length, which the path carries just as well. The
    // amplification is real either way: the allowlist caps the host set, not
    // the number or size of URIs.
    const manyUris = Array.from(
      { length: 40 },
      (_, i) => `https://claude.ai/${i}/${"p".repeat(2000)}`,
    );

    const res = await dispatch(registrationRouter, {
      method: "POST",
      path: "/oauth/register",
      body: {
        client_name: "N".repeat(5000),
        redirect_uris: manyUris,
      },
    });
    await flush();

    expect(res.statusCode).toBe(201);
    expect(rows).toHaveLength(1);
    const detail = rows[0].detail as {
      client_name: string;
      redirect_uris: string[];
      redirect_uri_count: number;
    };
    expect(detail.client_name).toHaveLength(100);
    expect(detail.redirect_uris).toHaveLength(10);
    for (const uri of detail.redirect_uris) {
      expect(uri.length).toBeLessThanOrEqual(512);
    }
    // Truncation is recorded rather than hidden.
    expect(detail.redirect_uri_count).toBe(40);
    // The whole row stays small enough that a flood cannot fill a disk.
    expect(JSON.stringify(rows[0]).length).toBeLessThan(8000);
  });

  it("writes NOTHING when the registration is rejected before any write", async () => {
    await dispatch(registrationRouter, {
      method: "POST",
      path: "/oauth/register",
      body: { client_name: "no uris" },
    });
    await flush();

    expect(oauthRepositoryMock.upsertClient).not.toHaveBeenCalled();
    expect(rows).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// oauth.authorize.grant / .denied — the consent decision
// ---------------------------------------------------------------------------

describe("oauth.authorize.grant — a human approved a client", () => {
  it("writes the grant AFTER the code is stored, and never the code itself", async () => {
    const { areq, csrf, cid } = makeAreq();

    await decide({ areq, decision: "approve", csrfCookie: csrf, cid });
    await flush();

    expect(oauthRepositoryMock.setAuthCode).toHaveBeenCalledTimes(1);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "oauth.authorize.grant",
      outcome: "success",
      actor_type: "user",
      actor_id: USER_ID,
      actor_ip: CLIENT_IP,
      request_id: REQUEST_ID,
      target_type: "oauth_client",
      target_id: CLIENT_ID,
    });
    // Where the code was sent is the field that separates a legitimate grant
    // from one aimed at an attacker's host.
    expect(rows[0].detail).toMatchObject({ redirect_uri: REDIRECT_URI });
    expect(serialized()).not.toContain(mintedCode());
  });

  it("writes NOTHING when setAuthCode fails — no row for a grant that did not persist", async () => {
    oauthRepositoryMock.setAuthCode.mockRejectedValue(
      new Error("auth code table unavailable"),
    );
    const { areq, csrf, cid } = makeAreq();

    const res = await decide({
      areq,
      decision: "approve",
      csrfCookie: csrf,
      cid,
    });
    await flush();

    expect(res.statusCode).toBe(500);
    expect(rows).toEqual([]);
  });
});

describe("oauth.authorize.denied — the three refusal paths", () => {
  it("records an explicit user denial", async () => {
    const { areq, csrf, cid } = makeAreq();

    await decide({ areq, decision: "deny", csrfCookie: csrf, cid });
    await flush();

    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "oauth.authorize.denied",
      outcome: "denied",
      actor_id: USER_ID,
      target_id: CLIENT_ID,
    });
    expect(rows[0].detail).toMatchObject({ reason: "user_denied" });
  });

  it("records a failed CSRF check — the cross-site consent attempt", async () => {
    const { areq, cid } = makeAreq();

    await decide({
      areq,
      decision: "approve",
      csrfCookie: "wrong-nonce",
      cid,
    });
    await flush();

    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "oauth.authorize.denied",
      outcome: "denied",
      http_status: 403,
    });
    expect(rows[0].detail).toMatchObject({ reason: "csrf" });
  });

  it("records a disabled account completing a pre-lock consent", async () => {
    usersRepositoryMock.isDisabled.mockResolvedValue(true);
    const { areq, csrf, cid } = makeAreq();

    await decide({ areq, decision: "approve", csrfCookie: csrf, cid });
    await flush();

    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "oauth.authorize.denied",
      outcome: "denied",
    });
    expect(rows[0].detail).toMatchObject({ reason: "disabled" });
  });
});

// ---------------------------------------------------------------------------
// The safety property
// ---------------------------------------------------------------------------

describe("a broken audit sink cannot break the OAuth flow", () => {
  it("a REJECTING sink still lets a consent grant mint and redirect", async () => {
    // An unhandled rejection is process death under node's default
    // --unhandled-rejections=throw: the whole gateway, not one request.
    setAuditSinkForTesting(async () => {
      throw new Error("connection pool exhausted");
    });
    const { areq, csrf, cid } = makeAreq();

    const res = await decide({
      areq,
      decision: "approve",
      csrfCookie: csrf,
      cid,
    });
    await flush();

    expect(oauthRepositoryMock.setAuthCode).toHaveBeenCalledTimes(1);
    expect(res.redirectedTo).toBeTruthy();
    expect(new URL(res.redirectedTo as string).searchParams.get("code")).toBe(
      mintedCode(),
    );
  });

  it("a THROWING sink still lets a client register", async () => {
    setAuditSinkForTesting(() => {
      throw new Error("audit table is on fire");
    });

    const res = await dispatch(registrationRouter, {
      method: "POST",
      path: "/oauth/register",
      body: { client_name: CLIENT_NAME, redirect_uris: [REDIRECT_URI] },
    });
    await flush();

    expect(res.statusCode).toBe(201);
    expect(oauthRepositoryMock.upsertClient).toHaveBeenCalledTimes(1);
  });
});
