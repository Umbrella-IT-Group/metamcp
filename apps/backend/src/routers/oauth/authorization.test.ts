/**
 * Tests for the OAuth consent screen.
 *
 * What is being pinned is a negative: this authorization server must not mint
 * an authorization code because someone is merely signed in. It used to. Client
 * registration is anonymous, so an attacker could register a client pointing at
 * their own redirect_uri and phish a signed-in administrator into one top-level
 * navigation to /oauth/authorize; the session cookie is SameSite=Lax, so the
 * browser attached it, and a code bound to that administrator was handed to the
 * attacker's URL. /oauth/callback offered the same thing a second way, minting
 * from an unsigned base64 `params` blob that had round-tripped through the
 * client.
 *
 * So the assertions that matter most are the ones that check setAuthCode was
 * NOT called. Every guard on the decision endpoint gets one: a wrong or absent
 * CSRF cookie, a session belonging to someone else, an expired token, a forged
 * signature, a payload edited in flight, a redirect_uri that has since been
 * deregistered, and a decision that is not an explicit approval.
 *
 * The handlers are module-private, so the router is driven directly as express
 * middleware against fake req/res objects — no supertest dependency, and no DB
 * or auth stack: `../../db/repositories` and `../../auth` are both mocked,
 * which also keeps `db/index.ts` and better-auth's pg pool (each of which
 * throws without its environment) out of the import graph entirely.
 */

import express from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Type-only, so it is erased at compile time and does not pull the module in
// before the environment below is set.
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
};

// The `users.disabled` gate (migration 0027). Left deliberately un-defaulted
// here and set per-run in beforeEach: a bare `vi.fn()` resolves undefined,
// which is falsy, so a mock that silently lost its setup would read as
// "enabled" — the failing direction that mints. beforeEach makes the value
// explicit on every test.
const usersRepositoryMock = {
  isDisabled: vi.fn(),
};

vi.mock("../../db/repositories", () => ({
  oauthRepository: oauthRepositoryMock,
  usersRepository: usersRepositoryMock,
}));

// auth.handler is the session oracle for every endpoint under test, so mocking
// it is both what keeps better-auth out of the import graph and the lever that
// simulates a valid / absent / different-user session.
const authMock = { handler: vi.fn() };

vi.mock("../../auth", () => ({ auth: authMock }));

// Set before the router is imported: getBaseUrl prefers APP_URL, and the areq
// signer needs a key. Both are mandatory in a real process.
process.env.APP_URL = "https://mcp.example.test";
process.env.BETTER_AUTH_SECRET = "test-secret-for-consent-request-signing";

const { default: authorizationRouter } = await import("./authorization");
const {
  CONSENT_CSRF_COOKIE_HOST_PREFIXED,
  signConsentRequest,
  verifyConsentRequest,
} = await import("./consent-token");

const { getIssuerIdentifier, resetConsentDecisionRateLimitForTests } =
  await import("./utils");

// APP_URL is https here, as on the real deployment, so the cookie this server
// issues and reads carries the __Host- prefix. The name is per consent request:
// see ConsentRequestPayload.cid.
function csrfCookieName(cid: string): string {
  return `${CONSENT_CSRF_COOKIE_HOST_PREFIXED}_${cid}`;
}

const APP_URL = "https://mcp.example.test";
// The issuer identifier this server publishes: APP_URL normalised to a trailing
// slash. RFC 9207 requires the `iss` on the authorization response be
// byte-identical to the issuer the discovery metadata advertises, so this is
// derived from the SAME production helper metadata uses (getIssuerIdentifier)
// rather than a second hardcoded literal that could drift from it. See
// metadata.test.ts, which pins the advertised issuer to this same value.
const ISSUER = getIssuerIdentifier({
  headers: {},
} as unknown as express.Request);
const CLIENT_ID = "mcp_client_test";
const CLIENT_NAME = "Claude";
const REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback";
const USER_ID = "user-abc123";
const OTHER_USER_ID = "user-attacker999";
const STATE = "opaque-client-state";
const CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const SESSION_COOKIE = "better-auth.session_token=session-value";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

interface CookieWrite {
  name: string;
  value: string;
  options: Record<string, unknown>;
}

interface FakeRes {
  statusCode: number;
  body: Record<string, unknown> | undefined;
  redirectedTo: string | undefined;
  sentBody: string | undefined;
  cookies: CookieWrite[];
  clearedCookies: CookieWrite[];
  settled: Promise<void>;
  status(code: number): FakeRes;
  json(payload: Record<string, unknown>): FakeRes;
  send(payload?: string): FakeRes;
  redirect(url: string): FakeRes;
  cookie(
    name: string,
    value: string,
    options: Record<string, unknown>,
  ): FakeRes;
  clearCookie(name: string, options: Record<string, unknown>): FakeRes;
}

// Unique per request so the authorization endpoint's in-memory rate limiter
// (20 per IP per minute, shared process-wide because it lives at module scope
// in utils.ts) can never make one test's traffic fail another's.
let ipCounter = 0;

function makeReq(init: {
  method: string;
  path: string;
  query?: Record<string, string>;
  body?: Record<string, unknown>;
  cookie?: string;
}): express.Request {
  ipCounter += 1;
  const search = new URLSearchParams(init.query ?? {}).toString();
  const url = search ? `${init.path}?${search}` : init.path;

  return {
    method: init.method,
    url,
    originalUrl: url,
    baseUrl: "",
    path: init.path,
    // Express populates req.query from the app, not the router, so the router
    // under test is handed the parsed object directly.
    query: init.query ?? {},
    body: init.body,
    headers: init.cookie ? { cookie: init.cookie } : {},
    ip: `10.1.0.${ipCounter}`,
    socket: { remoteAddress: `10.1.0.${ipCounter}` },
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
    sentBody: undefined,
    cookies: [],
    clearedCookies: [],
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
    send(payload) {
      res.sentBody = payload;
      settle();
      return res;
    },
    redirect(url) {
      res.redirectedTo = url;
      settle();
      return res;
    },
    cookie(name, value, options) {
      res.cookies.push({ name, value, options });
      return res;
    },
    clearCookie(name, options) {
      res.clearedCookies.push({ name, value: "", options });
      return res;
    },
  };

  return res;
}

async function dispatch(init: Parameters<typeof makeReq>[0]): Promise<FakeRes> {
  const req = makeReq(init);
  const res = makeRes();

  await new Promise<void>((resolve, reject) => {
    (authorizationRouter as unknown as express.RequestHandler)(
      req,
      res as unknown as express.Response,
      (err?: unknown) => (err ? reject(err) : resolve()),
    );
    res.settled.then(resolve);
  });

  return res;
}

// ---------------------------------------------------------------------------
// Session + request fixtures
// ---------------------------------------------------------------------------

// A Response body can only be read once, so a single shared instance would
// make the SECOND session lookup in a request see an empty body — failing in
// the safe-looking direction (no user => refuse) and hiding a real regression.
// A fresh Response per call keeps that trap out of future tests.
function sessionFor(userId: string | null) {
  authMock.handler.mockImplementation(
    async () =>
      new Response(JSON.stringify(userId ? { user: { id: userId } } : null), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
  );
}

function registeredClient(redirectUris: string[] = [REDIRECT_URI]) {
  return {
    client_id: CLIENT_ID,
    client_name: CLIENT_NAME,
    redirect_uris: redirectUris,
  };
}

const AUTHORIZE_QUERY = {
  response_type: "code",
  client_id: CLIENT_ID,
  redirect_uri: REDIRECT_URI,
  scope: "admin",
  state: STATE,
  code_challenge: CODE_CHALLENGE,
  code_challenge_method: "S256",
};

function authorize(cookie?: string) {
  return dispatch({
    method: "GET",
    path: "/oauth/authorize",
    query: AUTHORIZE_QUERY,
    cookie,
  });
}

/** A consent request as /oauth/authorize would have issued it. */
let cidCounter = 0;
function makeAreq(overrides: Partial<ConsentRequestPayload> = {}): {
  areq: string;
  csrf: string;
  cid: string;
} {
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

/** The raw signed token a consent redirect carries. */
function areqFrom(res: FakeRes): string {
  const areq = redirectUrl(res).searchParams.get("areq");
  if (!areq) throw new Error("consent redirect carried no areq");
  return areq;
}

/**
 * The `Cookie` header a real browser would send after these responses.
 *
 * Modelled as a jar keyed by NAME, last write winning — which is the whole
 * point. A browser does not accumulate two cookies with the same name, path
 * and domain: the second Set-Cookie REPLACES the first. That replacement is
 * what broke the live connect, so a test that simply concatenated both
 * Set-Cookie values would quietly pass even against the broken server.
 */
function browserCookieHeader(...responses: FakeRes[]): string {
  const jar = new Map<string, string>([
    ["better-auth.session_token", "session-value"],
  ]);
  for (const res of responses) {
    for (const cookie of res.cookies) {
      jar.set(cookie.name, cookie.value);
    }
  }
  return [...jar].map(([name, value]) => `${name}=${value}`).join("; ");
}

/** Split an areq into its encoded payload and its hex MAC. */
function splitAreq(areq: string): { payload: string; mac: string } {
  const separator = areq.indexOf(".");
  if (separator <= 0) throw new Error("areq is not a signed token");
  return { payload: areq.slice(0, separator), mac: areq.slice(separator + 1) };
}

/** Re-encode an areq payload under its ORIGINAL signature, as an attacker would. */
function tamperPayload(
  areq: string,
  edit: (payload: Record<string, unknown>) => void,
): string {
  const { payload, mac } = splitAreq(areq);
  const decoded = JSON.parse(Buffer.from(payload, "base64url").toString());
  edit(decoded);
  return `${Buffer.from(JSON.stringify(decoded)).toString("base64url")}.${mac}`;
}

function decide(init: {
  areq: string;
  decision?: string;
  csrfCookie?: string | null;
  /** Extra values sent under the SAME cookie name, ahead of the real one. */
  plantedCsrfCookies?: string[];
}) {
  // The browser sends the cookie whose NAME belongs to this request. For an
  // unverifiable token the name is irrelevant — it is refused before the
  // cookie is ever read.
  const cid = verifyConsentRequest(init.areq)?.cid ?? "unverifiable";
  const cookies = [SESSION_COOKIE];
  for (const planted of init.plantedCsrfCookies ?? []) {
    cookies.push(`${csrfCookieName(cid)}=${planted}`);
  }
  if (init.csrfCookie !== null && init.csrfCookie !== undefined) {
    cookies.push(`${csrfCookieName(cid)}=${init.csrfCookie}`);
  }

  return dispatch({
    method: "POST",
    path: "/oauth/authorize/decision",
    body:
      init.decision === undefined
        ? { areq: init.areq }
        : { areq: init.areq, decision: init.decision },
    cookie: cookies.join("; "),
  });
}

/** The cookie the authorize endpoint wrote, asserted present. */
function issuedCsrfCookie(res: FakeRes): CookieWrite {
  const written = res.cookies.filter((c) =>
    c.name.startsWith(CONSENT_CSRF_COOKIE_HOST_PREFIXED),
  );
  expect(written).toHaveLength(1);
  const cookie = written[0];
  if (!cookie) throw new Error("no consent csrf cookie was written");
  return cookie;
}

/** The URL the handler redirected to, asserted present. */
function redirectUrl(res: FakeRes): URL {
  if (!res.redirectedTo) throw new Error("handler settled without a redirect");
  return new URL(res.redirectedTo);
}

/** The verified consent request carried by a redirect to the consent page. */
function consentPayloadFrom(res: FakeRes): ConsentRequestPayload {
  const payload = verifyConsentRequest(
    redirectUrl(res).searchParams.get("areq"),
  );
  if (!payload) throw new Error("consent redirect carried no valid areq");
  return payload;
}

/** The JSON body a handler returned, asserted present. */
function jsonBody(res: FakeRes): Record<string, unknown> {
  if (!res.body) throw new Error("handler settled without a JSON body");
  return res.body;
}

/** The single (code, data) pair handed to setAuthCode, asserted unique. */
function mintedAuthCode(): { code: string; stored: Record<string, unknown> } {
  const calls = oauthRepositoryMock.setAuthCode.mock.calls;
  expect(calls).toHaveLength(1);
  const call = calls[0];
  if (!call) throw new Error("setAuthCode was never called");
  return {
    code: call[0] as string,
    stored: call[1] as Record<string, unknown>,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  // The consent limiter is keyed per user and lives at module scope, so
  // without this the file's own decisions would eventually exhaust one
  // budget and later tests would 429 — which reads like a passing refusal.
  resetConsentDecisionRateLimitForTests();
  oauthRepositoryMock.getClient.mockResolvedValue(registeredClient());
  oauthRepositoryMock.setAuthCode.mockResolvedValue(undefined);
  oauthRepositoryMock.deleteAuthCode.mockResolvedValue(undefined);
  usersRepositoryMock.isDisabled.mockResolvedValue(false);
  sessionFor(USER_ID);
});

// ---------------------------------------------------------------------------
// 1. The authorize fast path no longer mints
// ---------------------------------------------------------------------------

describe("GET /oauth/authorize — being signed in is not consent", () => {
  it("does NOT mint an authorization code for a signed-in user", async () => {
    const res = await authorize(SESSION_COOKIE);

    // The whole fix in one assertion.
    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();

    // ...and nothing resembling a code reached the client's redirect_uri.
    expect(res.redirectedTo).toBeDefined();
    expect(res.redirectedTo).not.toContain(REDIRECT_URI);
    expect(res.redirectedTo).not.toContain("code=");
  });

  it("redirects to the consent page with a signed request bound to the session user", async () => {
    const res = await authorize(SESSION_COOKIE);

    const redirect = redirectUrl(res);
    expect(redirect.origin).toBe(APP_URL);
    expect(redirect.pathname).toBe("/consent");

    const payload = consentPayloadFrom(res);
    expect(payload.user_id).toBe(USER_ID);
    expect(payload.client_id).toBe(CLIENT_ID);
    expect(payload.redirect_uri).toBe(REDIRECT_URI);
    expect(payload.state).toBe(STATE);
    expect(payload.code_challenge).toBe(CODE_CHALLENGE);
    // Scope is server-decided, never the "admin" the caller asked for.
    expect(payload.scope).toBe("mcp");
  });

  it("sets the double-submit csrf cookie httpOnly, SameSite=Lax and Secure", async () => {
    const res = await authorize(SESSION_COOKIE);

    const cookie = issuedCsrfCookie(res);
    expect(cookie.options.httpOnly).toBe(true);
    expect(cookie.options.sameSite).toBe("lax");
    // APP_URL is https here, as it is on the real deployment.
    expect(cookie.options.secure).toBe(true);
    expect(cookie.options.path).toBe("/");
    // __Host- is only honoured with Secure, Path=/ and no Domain — the three
    // attributes asserted above. It is what stops a sibling subdomain from
    // planting a same-named cookie at all.
    expect(cookie.name).toMatch(/^__Host-oauth_consent_csrf_.+/);
    expect(cookie.options).not.toHaveProperty("domain");

    // The cookie carries exactly the nonce inside the signed token — that
    // pairing is what the decision endpoint checks.
    expect(cookie.value).toBe(consentPayloadFrom(res).csrf);
    // A nonce an attacker could guess would defeat the whole control.
    expect(cookie.value.length).toBeGreaterThanOrEqual(32);
  });

  it("sends an unauthenticated user to log in and back to /oauth/authorize, with no params blob", async () => {
    sessionFor(null);

    const res = await authorize(SESSION_COOKIE);

    const redirect = redirectUrl(res);
    expect(redirect.pathname).toBe("/login");

    const callbackUrl = redirect.searchParams.get("callbackUrl") ?? "";
    expect(callbackUrl.startsWith("/oauth/authorize?")).toBe(true);
    // The old flow returned to /oauth/callback carrying the parameters as an
    // unsigned base64 blob, which that endpoint then minted from.
    expect(callbackUrl).not.toContain("/oauth/callback");
    expect(callbackUrl).not.toContain("params=");
    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
  });

  it("still rejects a redirect_uri that is not registered for the client", async () => {
    oauthRepositoryMock.getClient.mockResolvedValue(
      registeredClient(["https://legit.example/cb"]),
    );

    const res = await authorize(SESSION_COOKIE);

    expect(res.statusCode).toBe(400);
    expect(res.body?.error).toBe("invalid_request");
    expect(res.cookies).toHaveLength(0);
    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// 2. The decision endpoint is the only mint site
// ---------------------------------------------------------------------------

describe("POST /oauth/authorize/decision — approval mints", () => {
  it("mints and redirects with the code when session, csrf and client all check out", async () => {
    const { areq, csrf } = makeAreq();

    const res = await decide({ areq, decision: "approve", csrfCookie: csrf });

    expect(oauthRepositoryMock.setAuthCode).toHaveBeenCalledTimes(1);

    const { code, stored } = mintedAuthCode();
    expect(code).toMatch(/^mcp_code_/);
    expect(stored).toMatchObject({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: "mcp",
      user_id: USER_ID,
      code_challenge: CODE_CHALLENGE,
      code_challenge_method: "S256",
    });

    const redirect = redirectUrl(res);
    expect(`${redirect.origin}${redirect.pathname}`).toBe(REDIRECT_URI);
    expect(redirect.searchParams.get("code")).toBe(code);
    expect(redirect.searchParams.get("state")).toBe(STATE);
    expect(redirect.searchParams.get("error")).toBeNull();
  });

  it("clears the csrf cookie once the request has been completed", async () => {
    const { areq, csrf, cid } = makeAreq();

    const res = await decide({ areq, decision: "approve", csrfCookie: csrf });

    expect(res.clearedCookies).toHaveLength(1);
    expect(res.clearedCookies[0]?.name).toBe(csrfCookieName(cid));
  });

  it("carries the RFC 9207 iss parameter on the granted redirect", async () => {
    // The issuer identifier lets the client detect an authorization-server
    // mix-up, and RFC 9207 2.4 has the client compare it against the discovery
    // issuer by simple string comparison. ISSUER is that advertised issuer
    // (trailing slash included); a strict client aborts if the two differ.
    const { areq, csrf } = makeAreq();

    const res = await decide({ areq, decision: "approve", csrfCookie: csrf });

    expect(redirectUrl(res).searchParams.get("iss")).toBe(ISSUER);
    // Guard against a regression to getBaseUrl (no trailing slash), which would
    // no longer match the discovery issuer.
    expect(ISSUER).toBe(`${APP_URL}/`);
  });

  it("carries the iss parameter on the access_denied redirect too", async () => {
    // RFC 9207 covers error responses, not just successful ones.
    const { areq, csrf } = makeAreq();

    const res = await decide({ areq, decision: "deny", csrfCookie: csrf });

    const redirect = redirectUrl(res);
    expect(redirect.searchParams.get("error")).toBe("access_denied");
    expect(redirect.searchParams.get("iss")).toBe(ISSUER);
    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
  });
});

describe("GET /oauth/authorize — PKCE method must be S256", () => {
  it("rejects code_challenge_method=plain with invalid_request", async () => {
    // The AS metadata advertises S256 only, and a plain challenge equals the
    // verifier in the query string, so it gives no interception protection.
    const res = await dispatch({
      method: "GET",
      path: "/oauth/authorize",
      query: { ...AUTHORIZE_QUERY, code_challenge_method: "plain" },
      cookie: SESSION_COOKIE,
    });

    expect(res.statusCode).toBe(400);
    expect(res.body?.error).toBe("invalid_request");
    expect(String(res.body?.error_description)).toContain("S256");
    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
  });

  it("still accepts S256 (regression guard)", async () => {
    // A check that refused every method would satisfy the assertion above.
    const res = await authorize(SESSION_COOKIE);

    expect(res.statusCode).toBe(200);
    expect(redirectUrl(res).pathname).toBe("/consent");
  });
});

describe("POST /oauth/authorize/decision — concurrent authorize flows", () => {
  it("completes the flow the user approved after the client hit /oauth/authorize twice", async () => {
    // Alex's live Claude.ai connect, exactly. The connector requested
    // /oauth/authorize twice in the same second (two `consent requested`
    // lines); with one shared cookie name the second Set-Cookie replaced the
    // first, so approving the page bound to request A compared A's signed
    // nonce against B's cookie and logged `consent rejected reason=csrf`.
    // Both cookies are in the header here because a browser sends every
    // unexpired cookie it holds for the origin.
    const flowA = await authorize(SESSION_COOKIE);
    const flowB = await authorize(SESSION_COOKIE);

    const res = await dispatch({
      method: "POST",
      path: "/oauth/authorize/decision",
      body: { areq: areqFrom(flowA), decision: "approve" },
      cookie: browserCookieHeader(flowA, flowB),
    });

    // The symptom Alex saw, asserted first: a 403 with no code minted.
    expect(res.statusCode).not.toBe(403);
    expect(oauthRepositoryMock.setAuthCode).toHaveBeenCalledTimes(1);
    expect(redirectUrl(res).searchParams.get("code")).toMatch(/^mcp_code_/);

    // And the mechanism behind it: two authorizations, two cookie names, so
    // the second Set-Cookie never displaced the first.
    const cookieA = issuedCsrfCookie(flowA);
    const cookieB = issuedCsrfCookie(flowB);
    expect(cookieA.name).not.toBe(cookieB.name);
    expect(cookieA.value).not.toBe(cookieB.value);
  });

  it("completes the SECOND flow just as well, with both cookies present", async () => {
    const flowA = await authorize(SESSION_COOKIE);
    const flowB = await authorize(SESSION_COOKIE);

    const res = await dispatch({
      method: "POST",
      path: "/oauth/authorize/decision",
      body: { areq: areqFrom(flowB), decision: "approve" },
      cookie: browserCookieHeader(flowA, flowB),
    });

    expect(oauthRepositoryMock.setAuthCode).toHaveBeenCalledTimes(1);
    expect(redirectUrl(res).searchParams.get("code")).toMatch(/^mcp_code_/);
  });

  it("still refuses flow A when only the OTHER flow's cookie is held", async () => {
    // The per-cid name must not become a way in: B's cookie is a different
    // name AND a different value, so it can never satisfy A.
    const flowA = await authorize(SESSION_COOKIE);
    const flowB = await authorize(SESSION_COOKIE);

    const res = await dispatch({
      method: "POST",
      path: "/oauth/authorize/decision",
      body: { areq: areqFrom(flowA), decision: "approve" },
      cookie: browserCookieHeader(flowB),
    });

    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });

  it("refuses a cookie holding the right nonce under another flow's name", async () => {
    // Belt and braces: the value alone must not be enough if it arrives under
    // a name that does not belong to the request being approved.
    const flowA = await authorize(SESSION_COOKIE);
    const flowB = await authorize(SESSION_COOKIE);

    const cookieA = issuedCsrfCookie(flowA);
    const cookieB = issuedCsrfCookie(flowB);

    const res = await dispatch({
      method: "POST",
      path: "/oauth/authorize/decision",
      body: { areq: areqFrom(flowA), decision: "approve" },
      cookie: [SESSION_COOKIE, `${cookieB.name}=${cookieA.value}`].join("; "),
    });

    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });
});

describe("POST /oauth/authorize/decision — CSRF double submit", () => {
  it("refuses to mint when the csrf cookie is absent", async () => {
    const { areq } = makeAreq();

    const res = await decide({ areq, decision: "approve", csrfCookie: null });

    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
    expect(res.body?.error).toBe("access_denied");
    expect(res.redirectedTo).toBeUndefined();
  });

  it("refuses to mint when the csrf cookie does not match the signed nonce", async () => {
    const { areq } = makeAreq();

    const res = await decide({
      areq,
      decision: "approve",
      csrfCookie: "csrf-nonce-for-other-browser",
    });

    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });

  it("accepts the real nonce even when a duplicate cookie is sent ahead of it", async () => {
    // A `Cookie` header may repeat a name — a more specific Path, or a
    // sibling subdomain's cookie, is sent first. Reading only the first value
    // would let anyone who can plant one deny consent to a user permanently.
    const { areq, csrf } = makeAreq();

    const res = await decide({
      areq,
      decision: "approve",
      csrfCookie: csrf,
      plantedCsrfCookies: ["planted-by-a-sibling-host", "another-planted-one"],
    });

    expect(oauthRepositoryMock.setAuthCode).toHaveBeenCalledTimes(1);
    expect(redirectUrl(res).searchParams.get("code")).toMatch(/^mcp_code_/);
  });

  it("still refuses when only planted values are present", async () => {
    const { areq } = makeAreq();

    const res = await decide({
      areq,
      decision: "approve",
      csrfCookie: null,
      plantedCsrfCookies: ["planted-by-a-sibling-host"],
    });

    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });

  it("does not clear a pending consent cookie on a failed verification", async () => {
    // Otherwise anyone able to replay a bad decision could cancel a victim's
    // pending authorization at will.
    const { areq } = makeAreq();

    const res = await decide({ areq, decision: "approve", csrfCookie: null });

    expect(res.clearedCookies).toHaveLength(0);
  });
});

describe("POST /oauth/authorize/decision — session binding", () => {
  it("refuses to mint when the session belongs to a different user", async () => {
    const { areq, csrf } = makeAreq();
    sessionFor(OTHER_USER_ID);

    const res = await decide({ areq, decision: "approve", csrfCookie: csrf });

    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
    expect(res.body?.error).toBe("access_denied");
  });

  it("refuses to mint when there is no session at all", async () => {
    const { areq, csrf } = makeAreq();
    sessionFor(null);

    const res = await decide({ areq, decision: "approve", csrfCookie: csrf });

    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });
});

describe("POST /oauth/authorize/decision — token integrity", () => {
  it("refuses to mint on an expired authorization request", async () => {
    const { areq, csrf } = makeAreq({ exp: Date.now() - 1000 });

    const res = await decide({ areq, decision: "approve", csrfCookie: csrf });

    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
    expect(res.body?.error).toBe("invalid_request");
  });

  it("refuses to mint on a forged signature", async () => {
    const { areq, csrf } = makeAreq();
    const { payload, mac } = splitAreq(areq);
    const forged = `${payload}.${mac.replace(/^./, (c) => (c === "a" ? "b" : "a"))}`;

    const res = await decide({
      areq: forged,
      decision: "approve",
      csrfCookie: csrf,
    });

    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
  });

  it("refuses to mint when the redirect_uri was edited and re-encoded in flight", async () => {
    // Keep the victim's user_id and csrf, swap the destination the code is
    // delivered to. Two independent guards refuse this one — the signature and
    // the redirect_uri re-check against the client record — which is the point
    // of re-validating rather than trusting the token alone.
    const { areq, csrf } = makeAreq();
    const tampered = tamperPayload(areq, (payload) => {
      payload.redirect_uri = "https://attacker.example/steal";
    });

    const res = await decide({
      areq: tampered,
      decision: "approve",
      csrfCookie: csrf,
    });

    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
  });

  it("refuses to mint when the PKCE challenge was edited and re-encoded in flight", async () => {
    // Only the signature stops this one. Nothing downstream re-derives the
    // code_challenge, so a caller who could swap it for one whose verifier they
    // hold would turn PKCE — the control that stops a stolen code from being
    // redeemed by anyone else — into decoration.
    const { areq, csrf } = makeAreq();
    const tampered = tamperPayload(areq, (payload) => {
      payload.code_challenge = "attacker-chosen-challenge-value-000000000000";
    });

    const res = await decide({
      areq: tampered,
      decision: "approve",
      csrfCookie: csrf,
    });

    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
  });

  it("refuses to mint on a missing areq", async () => {
    const res = await dispatch({
      method: "POST",
      path: "/oauth/authorize/decision",
      body: { decision: "approve" },
      cookie: SESSION_COOKIE,
    });

    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
  });
});

describe("POST /oauth/authorize/decision — denial and default deny", () => {
  it("redirects with error=access_denied and mints nothing on deny", async () => {
    const { areq, csrf } = makeAreq();

    const res = await decide({ areq, decision: "deny", csrfCookie: csrf });

    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();

    const redirect = redirectUrl(res);
    expect(`${redirect.origin}${redirect.pathname}`).toBe(REDIRECT_URI);
    expect(redirect.searchParams.get("error")).toBe("access_denied");
    expect(redirect.searchParams.get("state")).toBe(STATE);
    expect(redirect.searchParams.get("code")).toBeNull();
  });

  it("treats an absent decision as a denial rather than an approval", async () => {
    const { areq, csrf } = makeAreq();

    const res = await decide({ areq, csrfCookie: csrf });

    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    expect(redirectUrl(res).searchParams.get("error")).toBe("access_denied");
  });
});

describe("POST /oauth/authorize/decision — rate limiting is per user", () => {
  it("limits one user without spending another user's budget", async () => {
    // Keyed on req.ip this would be one bucket for the whole organisation:
    // `trust proxy` is not set and the backend is reached through the
    // frontend's in-container rewrite, so every human shares an address. A
    // 429 here is also uniquely bad — it strands someone who already clicked
    // Approve. Note each request below comes from a DIFFERENT fake IP, so an
    // IP-keyed limiter would never trip at all.
    const heavyUser = "user-rate-limit-subject";
    const bystander = "user-rate-limit-bystander";

    sessionFor(heavyUser);
    let limited: FakeRes | undefined;

    for (let attempt = 0; attempt < 30; attempt += 1) {
      const { areq, csrf } = makeAreq({
        user_id: heavyUser,
        csrf: `nonce-${attempt}`,
      });
      const res = await decide({ areq, decision: "deny", csrfCookie: csrf });
      if (res.statusCode === 429) {
        limited = res;
        break;
      }
    }

    expect(limited).toBeDefined();
    expect(limited?.body?.error).toBe("too_many_requests");

    // A different user is untouched and can still complete a consent.
    sessionFor(bystander);
    const { areq, csrf } = makeAreq({ user_id: bystander });
    const res = await decide({ areq, decision: "approve", csrfCookie: csrf });

    expect(res.statusCode).not.toBe(429);
    expect(oauthRepositoryMock.setAuthCode).toHaveBeenCalledTimes(1);
  });
});

describe("POST /oauth/authorize/decision — redirect_uri re-validation", () => {
  it("refuses to mint when the redirect_uri is no longer registered", async () => {
    // The client record can change between issuing the request and approving
    // it; the signature alone would not catch a deregistered URI.
    const { areq, csrf } = makeAreq();
    oauthRepositoryMock.getClient.mockResolvedValue(
      registeredClient(["https://claude.ai/some/other/callback"]),
    );

    const res = await decide({ areq, decision: "approve", csrfCookie: csrf });

    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
    expect(res.body?.error_description).toContain("not registered");
    expect(res.redirectedTo).toBeUndefined();
  });

  it("refuses to mint when the client has been deleted", async () => {
    const { areq, csrf } = makeAreq();
    oauthRepositoryMock.getClient.mockResolvedValue(null);

    const res = await decide({ areq, decision: "approve", csrfCookie: csrf });

    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// 3. The second door: /oauth/callback no longer mints
// ---------------------------------------------------------------------------

describe("GET /oauth/callback — the params blob no longer mints", () => {
  it("rejects an unsigned params blob instead of issuing a code from it", async () => {
    const params = Buffer.from(
      JSON.stringify({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: "admin",
        state: STATE,
      }),
    ).toString("base64url");

    const res = await dispatch({
      method: "GET",
      path: "/oauth/callback",
      query: { params },
      cookie: SESSION_COOKIE,
    });

    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
    expect(res.body?.error).toBe("invalid_request");
    expect(res.redirectedTo).toBeUndefined();
  });

  it("emits no HTML for a client that registered our own callback", async () => {
    // This case used to render a debug page that interpolated `code`, `state`
    // and the client's registered redirect_uri straight into HTML. `state` is
    // request input and redirect_uri is anonymous-registration input, so the
    // sink was both reflected and stored. The CSP blocks script today, but it
    // sets no form-action — an injected overlay could still post to an
    // attacker's host from this origin, and a CSP regression would turn it
    // into a way around the consent screen entirely.
    const payload = '"><img src=x onerror=alert(document.domain)>';
    const existingCode = "mcp_code_selfreferential";
    oauthRepositoryMock.getAuthCode.mockResolvedValue({
      code: existingCode,
      client_id: CLIENT_ID,
      redirect_uri: `${APP_URL}/oauth/callback`,
      scope: "mcp",
      user_id: USER_ID,
      expires_at: new Date(Date.now() + 5 * 60 * 1000),
    });

    const res = await dispatch({
      method: "GET",
      path: "/oauth/callback",
      query: { code: existingCode, state: payload },
    });

    // Nothing was rendered at all: no res.send body, JSON only.
    expect(res.sentBody).toBeUndefined();
    expect(res.statusCode).toBe(400);
    expect(res.body?.error).toBe("invalid_request");

    // And the payload appears nowhere in what was returned.
    expect(JSON.stringify(res.body)).not.toContain("<img");
    expect(JSON.stringify(res.body)).not.toContain(payload);
  });

  it("emits no HTML when a hostile redirect_uri was stored at registration", async () => {
    // The stored half: redirect_uri arrives verbatim from anonymous DCR.
    const hostile = `${APP_URL}/oauth/callback#"><script>alert(1)</script>`;
    oauthRepositoryMock.getAuthCode.mockResolvedValue({
      code: "mcp_code_hostileuri",
      client_id: CLIENT_ID,
      redirect_uri: hostile,
      scope: "mcp",
      user_id: USER_ID,
      expires_at: new Date(Date.now() + 5 * 60 * 1000),
    });

    const res = await dispatch({
      method: "GET",
      path: "/oauth/callback",
      query: { code: "mcp_code_hostileuri" },
    });

    expect(res.sentBody).toBeUndefined();
    expect(JSON.stringify(res.body)).not.toContain("<script");
  });

  it("still forwards a code that already exists (the lookup path is unchanged)", async () => {
    const existingCode = "mcp_code_alreadyissued";
    oauthRepositoryMock.getAuthCode.mockResolvedValue({
      code: existingCode,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: "mcp",
      user_id: USER_ID,
      expires_at: new Date(Date.now() + 5 * 60 * 1000),
    });

    const res = await dispatch({
      method: "GET",
      path: "/oauth/callback",
      query: { code: existingCode, state: STATE },
    });

    // Forwarding an existing code is a lookup, not a mint.
    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();

    const redirect = redirectUrl(res);
    expect(`${redirect.origin}${redirect.pathname}`).toBe(REDIRECT_URI);
    expect(redirect.searchParams.get("code")).toBe(existingCode);
  });

  it("carries the RFC 9207 iss parameter on the forwarded code", async () => {
    // The metadata advertises authorization_response_iss_parameter_supported,
    // so EVERY code-bearing authorization response must carry the issuer, this
    // legacy forwarder included, or a client that validates iss rejects the
    // code it just received. ISSUER is the SAME advertised value the discovery
    // metadata and the consent-decision redirect use, derived from
    // getIssuerIdentifier — the three must be byte-identical.
    const existingCode = "mcp_code_forwardediss";
    oauthRepositoryMock.getAuthCode.mockResolvedValue({
      code: existingCode,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: "mcp",
      user_id: USER_ID,
      expires_at: new Date(Date.now() + 5 * 60 * 1000),
    });

    const res = await dispatch({
      method: "GET",
      path: "/oauth/callback",
      query: { code: existingCode, state: STATE },
    });

    expect(redirectUrl(res).searchParams.get("iss")).toBe(ISSUER);
    // Guard against a regression to getBaseUrl (no trailing slash), which would
    // no longer match the discovery issuer.
    expect(ISSUER).toBe(`${APP_URL}/`);
  });
});

// ---------------------------------------------------------------------------
// 4. Consent screen data source
// ---------------------------------------------------------------------------

describe("GET /oauth/consent/info", () => {
  it("returns display fields to the user the request belongs to", async () => {
    const { areq } = makeAreq();

    const res = await dispatch({
      method: "GET",
      path: "/oauth/consent/info",
      query: { areq },
      cookie: SESSION_COOKIE,
    });

    expect(res.body).toEqual({
      client_id: CLIENT_ID,
      client_name: CLIENT_NAME,
      redirect_uri: REDIRECT_URI,
      scope: "mcp",
    });
  });

  it("never echoes the csrf nonce back to the page", async () => {
    // The nonce lives in an httpOnly cookie precisely so nothing script can
    // read ever carries it; returning it here would undo that.
    const { areq, csrf } = makeAreq();

    const res = await dispatch({
      method: "GET",
      path: "/oauth/consent/info",
      query: { areq },
      cookie: SESSION_COOKIE,
    });

    expect(JSON.stringify(res.body)).not.toContain(csrf);
  });

  it("refuses to describe a request belonging to another session", async () => {
    const { areq } = makeAreq();
    sessionFor(OTHER_USER_ID);

    const res = await dispatch({
      method: "GET",
      path: "/oauth/consent/info",
      query: { areq },
      cookie: SESSION_COOKIE,
    });

    expect(res.statusCode).toBe(403);
  });

  it("withholds the pending grant from a disabled account", async () => {
    // The window this closes: an areq signed while the account was still
    // enabled stays valid for its full ten-minute TTL, and the session with
    // it, so a lock pressed in between left this endpoint still describing
    // the pending grant. Nothing is minted here — but the client_id, the
    // display name and the full redirect_uri are real, and "disabled" has to
    // mean the same thing at every door on this flow.
    const { areq } = makeAreq();
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    const res = await dispatch({
      method: "GET",
      path: "/oauth/consent/info",
      query: { areq },
      cookie: SESSION_COOKIE,
    });

    expect(res.statusCode).toBe(403);
    expect(res.body?.error).toBe("access_denied");
    // Not one display field escaped.
    expect(JSON.stringify(res.body)).not.toContain(CLIENT_NAME);
    expect(JSON.stringify(res.body)).not.toContain(REDIRECT_URI);
    // The check ran against the SESSION user, not anything the caller supplied.
    expect(usersRepositoryMock.isDisabled).toHaveBeenCalledWith(USER_ID);
  });

  it("refuses BEFORE the client is looked up", async () => {
    // Fail-closed ordering: a locked account must not be able to drive a
    // database read off a token it still holds.
    const { areq } = makeAreq();
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    await dispatch({
      method: "GET",
      path: "/oauth/consent/info",
      query: { areq },
      cookie: SESSION_COOKIE,
    });

    expect(oauthRepositoryMock.getClient).not.toHaveBeenCalled();
  });

  it("answers a disabled account exactly as it answers the wrong session", async () => {
    // No oracle: whoever holds the session must not be able to tell "this
    // areq is not yours" from "your account has been locked".
    const { areq: mismatchAreq } = makeAreq();
    sessionFor(OTHER_USER_ID);
    const mismatch = await dispatch({
      method: "GET",
      path: "/oauth/consent/info",
      query: { areq: mismatchAreq },
      cookie: SESSION_COOKIE,
    });

    sessionFor(USER_ID);
    usersRepositoryMock.isDisabled.mockResolvedValue(true);
    const { areq: disabledAreq } = makeAreq();
    const disabled = await dispatch({
      method: "GET",
      path: "/oauth/consent/info",
      query: { areq: disabledAreq },
      cookie: SESSION_COOKIE,
    });

    expect(disabled.statusCode).toBe(mismatch.statusCode);
    expect(disabled.body).toEqual(mismatch.body);
  });

  it("clamps a hostile client_name from anonymous registration", async () => {
    // /oauth/register requires no authentication, so client_name is
    // attacker-controlled text rendered on a page the victim is asked to trust.
    const { areq } = makeAreq();
    oauthRepositoryMock.getClient.mockResolvedValue({
      ...registeredClient(),
      client_name: "A".repeat(500),
    });

    const res = await dispatch({
      method: "GET",
      path: "/oauth/consent/info",
      query: { areq },
      cookie: SESSION_COOKIE,
    });

    expect((jsonBody(res).client_name as string).length).toBe(100);
  });
});

// ---------------------------------------------------------------------------
// 5. A disabled account cannot reach either code-minting path
// ---------------------------------------------------------------------------

/**
 * `users.disabled` (migration 0027) re-homed onto the consent flow.
 *
 * The guards these tests pin used to sit on two different handlers — the old
 * authorize fast path and the old /oauth/callback mint — and the consent fix
 * deleted both. Re-homing them is not a refactor: an account disabled during
 * a live response that could still complete an authorization would walk away
 * with a fresh 30-day MCP access token, which is precisely the credential the
 * disable was pressed to take away.
 *
 * Both sites are covered because they fail differently. The GET is the door a
 * disabled account walks up to; the POST is the door someone disabled DURING
 * the ten-minute consent TTL is already standing inside, holding a valid
 * session, a valid areq and the matching nonce.
 */
describe("users.disabled closes both code-minting paths", () => {
  it("sends a disabled account to log in instead of issuing a consent request", async () => {
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    const res = await authorize(SESSION_COOKIE);

    // Answered as "not signed in" — the same redirect the unauthenticated
    // branch produces, so nothing about the account's state leaks here.
    const redirect = redirectUrl(res);
    expect(redirect.pathname).toBe("/login");
    expect(redirect.searchParams.get("callbackUrl") ?? "").toContain(
      "/oauth/authorize?",
    );

    // No areq was signed, so there is nothing to carry to /consent and
    // nothing to POST back to the decision endpoint later.
    expect(res.redirectedTo).not.toContain("areq=");
    expect(redirect.pathname).not.toBe("/consent");

    // ...and no CSRF cookie, which is the other half of a usable areq.
    expect(
      res.cookies.filter((c) =>
        c.name.startsWith(CONSENT_CSRF_COOKIE_HOST_PREFIXED),
      ),
    ).toHaveLength(0);

    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    // The check ran against the SESSION user, not against anything the caller
    // supplied in the query string.
    expect(usersRepositoryMock.isDisabled).toHaveBeenCalledWith(USER_ID);
  });

  it("refuses to mint when the account is disabled after the consent screen was issued", async () => {
    // Everything the four existing guards check is valid here: a signed,
    // unexpired areq, a session that is the same user, the matching nonce, and
    // a client still registered for the redirect_uri. Only the account changed.
    const { areq, csrf } = makeAreq();
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    const res = await decide({ areq, decision: "approve", csrfCookie: csrf });

    // The assertion that matters: no code exists.
    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    expect(res.redirectedTo).toBeUndefined();

    // The endpoint's own denial shape, not a new one.
    expect(res.statusCode).toBe(403);
    expect(res.body?.error).toBe("access_denied");

    expect(usersRepositoryMock.isDisabled).toHaveBeenCalledWith(USER_ID);
  });

  it("does not clear the pending consent cookie on the disabled deny", async () => {
    // Same rule the CSRF and session-mismatch branches follow: clearing a
    // cookie for a request that did not pass would let a replayed bad decision
    // cancel a consent the real user is still holding.
    const { areq, csrf } = makeAreq();
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    const res = await decide({ areq, decision: "approve", csrfCookie: csrf });

    expect(res.clearedCookies).toHaveLength(0);
  });

  it("still lets an enabled account through both doors to a minted code", async () => {
    // The regression guard. A check that refuses everyone would satisfy every
    // assertion above and break the product.
    const authorizeRes = await authorize(SESSION_COOKIE);

    expect(redirectUrl(authorizeRes).pathname).toBe("/consent");
    const cookie = issuedCsrfCookie(authorizeRes);

    const res = await dispatch({
      method: "POST",
      path: "/oauth/authorize/decision",
      body: { areq: areqFrom(authorizeRes), decision: "approve" },
      cookie: browserCookieHeader(authorizeRes),
    });

    expect(oauthRepositoryMock.setAuthCode).toHaveBeenCalledTimes(1);
    expect(redirectUrl(res).searchParams.get("code")).toMatch(/^mcp_code_/);
    // Both sites consulted the flag rather than one of them being dead code.
    expect(usersRepositoryMock.isDisabled).toHaveBeenCalledTimes(2);
    expect(cookie.name).toMatch(/^__Host-oauth_consent_csrf_.+/);
  });
});
