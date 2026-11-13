/**
 * Client metadata document (CIMD) clients through the authorize, consent info
 * and consent decision endpoints.
 *
 * The router is driven as express middleware against fake req/res, as in
 * authorization.test.ts, with the repository mocked at its seam and the
 * resolver REAL: DNS and the socket are faked only below the guard (the
 * `lookup` and `baseFetch` seams), so the allowlist, the guard and the
 * document validation all run for real.
 *
 * What is pinned, and why each is a design decision (there is no outside
 * oracle for gateway policy):
 *  - an allowlisted client reaches consent, and the Location stays under the
 *    4096 characters a browser or proxy will carry for a 512-character id;
 *  - every authorize-time refusal answers with one body (no oracle for
 *    allowlist membership or reachable addresses);
 *  - with the allowlist empty an https client id gets today's answer
 *    (characterization: passes on the parent);
 *  - a row that is not a `cimd` row is never resolved or touched;
 *  - a `cimd` row whose allowlist entry is gone is refused at authorize,
 *    consent info and the decision, and mints no code;
 *  - consent info adds the document host for a `cimd` row only, and every
 *    other client returns exactly today's key set.
 */
import type express from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { AuditEvent } from "@/lib/audit/audit-emitter";

import type { ConsentRequestPayload } from "./consent-token";

const h = vi.hoisted(() => ({
  logger: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));
vi.mock("@/utils/logger", () => ({ default: h.logger }));

const oauthRepositoryMock = {
  getClient: vi.fn(),
  setAuthCode: vi.fn(),
  getAuthCode: vi.fn(),
  deleteAuthCode: vi.fn(),
  withUserLock: vi.fn(),
  upsertCimdClient: vi.fn(),
  countCimdClients: vi.fn(),
};
const usersRepositoryMock = { isDisabled: vi.fn(), hasLiveSession: vi.fn() };
vi.mock("../../db/repositories", () => ({
  oauthRepository: oauthRepositoryMock,
  usersRepository: usersRepositoryMock,
}));
const authMock = { handler: vi.fn() };
vi.mock("../../auth", () => ({ auth: authMock }));

process.env.APP_URL = "https://mcp.example.test";
process.env.BETTER_AUTH_SECRET = "test-secret-for-consent-request-signing";

const { default: authorizationRouter } = await import("./authorization");
const { armUserLockFakes } = await import("./user-lock-test-fakes");
const { setAuditSinkForTesting } = await import("@/lib/audit/audit-emitter");
const {
  CONSENT_CSRF_COOKIE_HOST_PREFIXED,
  signConsentRequest,
  verifyConsentRequest,
} = await import("./consent-token");
const { resetConsentDecisionRateLimitForTests } = await import("./utils");
const {
  resetCimdStateForTesting,
  setCimdClockForTesting,
  setCimdTransportForTesting,
} = await import("./cimd");
const {
  CIMD_CLIENT_REFUSED_ERROR,
  OAUTH_CIMD_ALLOWED_CLIENTS_ENV,
  resetCimdConfigForTesting,
} = await import("./cimd-config");
const { CLIENT_NOT_APPROVED_ERROR } = await import(
  "./client-not-approved-page"
);

const ORIGIN = "https://app.example.com";
const CIMD_ID = `${ORIGIN}/oauth/client.json`;
const REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback";
const USER_ID = "user-abc123";
const STATE = "opaque-client-state";
const CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const SESSION_COOKIE = "better-auth.session_token=session-value";
const T0 = Date.UTC(2026, 10, 12, 12, 0, 0);

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

interface FakeRes {
  statusCode: number;
  body: Record<string, unknown> | undefined;
  redirectedTo: string | undefined;
  cookies: Array<{ name: string; value: string }>;
  clearedCookies: string[];
  settled: Promise<void>;
  status(code: number): FakeRes;
  json(payload: Record<string, unknown>): FakeRes;
  send(payload?: string): FakeRes;
  redirect(url: string): FakeRes;
  cookie(name: string, value: string): FakeRes;
  clearCookie(name: string): FakeRes;
  setHeader(): FakeRes;
}

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
    query: init.query ?? {},
    body: init.body,
    headers: init.cookie ? { cookie: init.cookie } : {},
    ip: `10.2.0.${ipCounter}`,
    socket: { remoteAddress: `10.2.0.${ipCounter}` },
  } as unknown as express.Request;
}

function makeRes(): FakeRes {
  let settle!: () => void;
  const settled = new Promise<void>((resolve) => (settle = resolve));
  const res: FakeRes = {
    statusCode: 200,
    body: undefined,
    redirectedTo: undefined,
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
    send() {
      settle();
      return res;
    },
    redirect(url) {
      res.redirectedTo = url;
      settle();
      return res;
    },
    cookie(name, value) {
      res.cookies.push({ name, value });
      return res;
    },
    clearCookie(name) {
      res.clearedCookies.push(name);
      return res;
    },
    setHeader() {
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
    void res.settled.then(resolve);
  });
  return res;
}

function sessionFor(userId: string) {
  authMock.handler.mockImplementation(
    async () =>
      new Response(
        JSON.stringify({
          user: { id: userId },
          session: { id: `s-${userId}` },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
  );
}

function authorize(clientId: string, redirectUri = REDIRECT_URI) {
  return dispatch({
    method: "GET",
    path: "/oauth/authorize",
    query: {
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      state: STATE,
      code_challenge: CODE_CHALLENGE,
      code_challenge_method: "S256",
    },
    cookie: SESSION_COOKIE,
  });
}

let cidCounter = 0;
function makeAreq(clientId: string) {
  cidCounter += 1;
  const csrf = "csrf-nonce-for-this-browser";
  const cid = `cid${cidCounter}`;
  const payload: ConsentRequestPayload = {
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    scope: "mcp",
    state: STATE,
    code_challenge: CODE_CHALLENGE,
    code_challenge_method: "S256",
    user_id: USER_ID,
    cid,
    csrf,
    exp: Date.now() + 10 * 60 * 1000,
  };
  return { areq: signConsentRequest(payload), csrf, cid };
}

function consentInfo(clientId: string) {
  return dispatch({
    method: "GET",
    path: "/oauth/consent/info",
    query: { areq: makeAreq(clientId).areq },
    cookie: SESSION_COOKIE,
  });
}

function decide(clientId: string, decision = "approve") {
  const { areq, csrf, cid } = makeAreq(clientId);
  const verified = verifyConsentRequest(areq);
  if (!verified) throw new Error("areq did not verify");
  return dispatch({
    method: "POST",
    path: "/oauth/authorize/decision",
    body: { areq, decision },
    cookie: `${SESSION_COOKIE}; ${CONSENT_CSRF_COOKIE_HOST_PREFIXED}_${cid}=${csrf}`,
  });
}

// ---------------------------------------------------------------------------
// Store and transport fakes
// ---------------------------------------------------------------------------

type Row = Record<string, unknown>;
const rows = new Map<string, Row>();
const events: AuditEvent[] = [];
const baseFetch = vi.fn();
const lookup = vi.fn();

function row(clientId: string, overrides: Row = {}): Row {
  return {
    client_id: clientId,
    client_name: "Example Client",
    redirect_uris: [REDIRECT_URI],
    approval_status: "approved",
    registration_source: "cimd",
    updated_at: new Date(T0),
    ...overrides,
  };
}

const documentFor = (id: string) =>
  JSON.stringify({
    client_id: id,
    client_name: "Example Client",
    redirect_uris: [REDIRECT_URI],
  });

beforeEach(() => {
  vi.clearAllMocks();
  resetConsentDecisionRateLimitForTests();
  resetCimdStateForTesting();
  resetCimdConfigForTesting();
  rows.clear();
  events.length = 0;
  process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = ORIGIN;
  setCimdClockForTesting(() => T0);
  setAuditSinkForTesting(async (event) => {
    events.push(event);
  });
  lookup.mockImplementation(async () => ["93.184.216.34"]);
  baseFetch.mockImplementation(
    async (url: URL) => new Response(documentFor(url.href), { status: 200 }),
  );
  setCimdTransportForTesting({ lookup, baseFetch });

  oauthRepositoryMock.getClient.mockImplementation(
    async (id: string) => rows.get(id) ?? null,
  );
  oauthRepositoryMock.countCimdClients.mockResolvedValue(0);
  oauthRepositoryMock.upsertCimdClient.mockImplementation(
    async (draft: Row, at: Date) => {
      const stored = row(draft.client_id as string, {
        ...draft,
        updated_at: at,
      });
      rows.set(draft.client_id as string, stored);
      return stored;
    },
  );
  oauthRepositoryMock.setAuthCode.mockResolvedValue(undefined);
  usersRepositoryMock.isDisabled.mockResolvedValue(false);
  usersRepositoryMock.hasLiveSession.mockResolvedValue(true);
  armUserLockFakes(oauthRepositoryMock);
  sessionFor(USER_ID);
});

const flush = async () => {
  for (let i = 0; i < 10; i += 1) await Promise.resolve();
};

// ---------------------------------------------------------------------------

describe("GET /oauth/authorize with an allowlisted client metadata URL", () => {
  it("fetches the document, stores the client and reaches consent", async () => {
    const res = await authorize(CIMD_ID);

    expect(res.redirectedTo).toBeDefined();
    const location = new URL(res.redirectedTo as string);
    expect(location.origin + location.pathname).toBe(
      "https://mcp.example.test/consent",
    );
    const payload = verifyConsentRequest(location.searchParams.get("areq"));
    expect(payload).toMatchObject({
      client_id: CIMD_ID,
      redirect_uri: REDIRECT_URI,
      user_id: USER_ID,
    });
    expect(baseFetch).toHaveBeenCalledTimes(1);
    expect(oauthRepositoryMock.upsertCimdClient).toHaveBeenCalledTimes(1);
    // Nothing was minted by merely reaching consent.
    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
  });

  it("serves the second request from the stored row, without a second fetch", async () => {
    await authorize(CIMD_ID);
    const second = await authorize(CIMD_ID);

    expect(second.redirectedTo).toBeDefined();
    expect(baseFetch).toHaveBeenCalledTimes(1);
  });

  it("keeps the consent redirect under 4096 characters for a 512-character client id", async () => {
    const longId = `${ORIGIN}/${"a".repeat(512 - ORIGIN.length - 1)}`;
    expect(longId).toHaveLength(512);

    const res = await authorize(longId);

    expect(res.redirectedTo).toBeDefined();
    expect((res.redirectedTo as string).length).toBeLessThan(4096);
    expect(
      verifyConsentRequest(
        new URL(res.redirectedTo as string).searchParams.get("areq"),
      )?.client_id,
    ).toBe(longId);
  });

  it("still refuses a callback the document does not list", async () => {
    const res = await authorize(CIMD_ID, "https://claude.ai/not-listed");

    expect(res.statusCode).toBe(400);
    expect(res.body).toMatchObject({
      error: "invalid_request",
      error_description: "redirect_uri is not registered for this client",
    });
  });
});

describe("every authorize-time refusal answers with the same body", () => {
  it("is identical for an unlisted URL, a failing fetch and a delisted stored row", async () => {
    const unlisted = await authorize("https://other.example.org/client.json");

    baseFetch.mockImplementation(
      async () => new Response("no", { status: 404 }),
    );
    const failing = await authorize(`${ORIGIN}/failing.json`);

    rows.set(CIMD_ID, row(CIMD_ID));
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] =
      "https://elsewhere.example.net";
    resetCimdConfigForTesting();
    const delisted = await authorize(CIMD_ID);

    for (const res of [unlisted, failing, delisted]) {
      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual(CIMD_CLIENT_REFUSED_ERROR);
      expect(res.redirectedTo).toBeUndefined();
      expect(res.cookies).toEqual([]);
    }
    expect(JSON.stringify(unlisted.body)).not.toContain(
      "registration_endpoint",
    );
  });

  it("does not tell a refused address from an unlisted URL", async () => {
    lookup.mockImplementation(async () => ["10.0.0.5"]);
    const refusedAddress = await authorize(`${ORIGIN}/internal.json`);
    const unlisted = await authorize("https://other.example.org/client.json");

    expect(refusedAddress.body).toEqual(unlisted.body);
    expect(baseFetch).not.toHaveBeenCalled();
  });

  it("makes no outbound call for an unlisted URL", async () => {
    await authorize("https://other.example.org/client.json");

    expect(lookup).not.toHaveBeenCalled();
    expect(baseFetch).not.toHaveBeenCalled();
    expect(oauthRepositoryMock.upsertCimdClient).not.toHaveBeenCalled();
  });
});

describe("with the allowlist empty, an https client id gets today's answer", () => {
  // Characterization: passes on the parent. The legacy unknown-client body,
  // including the registration hint, for a URL-shaped id too.
  it("answers the legacy unknown-client body and never fetches", async () => {
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = "";
    resetCimdConfigForTesting();

    const res = await authorize(CIMD_ID);

    expect(res.statusCode).toBe(400);
    expect(res.body).toMatchObject({
      error: "invalid_client",
      error_description:
        "Client not registered. Please register your client first.",
      registration_endpoint: "https://mcp.example.test/oauth/register",
    });
    expect(lookup).not.toHaveBeenCalled();
    expect(baseFetch).not.toHaveBeenCalled();
  });
});

describe("a row that is not a client metadata row is never resolved or touched", () => {
  it.each(["admin", "dcr", null])(
    "authorizes a %s row with a URL-shaped id exactly as before",
    async (source) => {
      rows.set(
        CIMD_ID,
        row(CIMD_ID, { registration_source: source, client_name: "Hand made" }),
      );

      const res = await authorize(CIMD_ID);

      expect(res.redirectedTo).toBeDefined();
      expect(baseFetch).not.toHaveBeenCalled();
      expect(lookup).not.toHaveBeenCalled();
      expect(oauthRepositoryMock.upsertCimdClient).not.toHaveBeenCalled();
      expect(rows.get(CIMD_ID)?.client_name).toBe("Hand made");
    },
  );

  it("does not give a pending row of another source the allowlist's approval", async () => {
    rows.set(
      CIMD_ID,
      row(CIMD_ID, { registration_source: "dcr", approval_status: "pending" }),
    );

    const res = await authorize(CIMD_ID);

    // Today's pending-client page, not a consent redirect.
    expect(res.redirectedTo).toBeUndefined();
    expect(baseFetch).not.toHaveBeenCalled();
  });
});

describe("a stored client metadata row whose allowlist entry is gone", () => {
  beforeEach(() => {
    rows.set(CIMD_ID, row(CIMD_ID));
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = "";
    resetCimdConfigForTesting();
  });

  it("is refused at authorize, with no fetch", async () => {
    const res = await authorize(CIMD_ID);

    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual(CIMD_CLIENT_REFUSED_ERROR);
    expect(baseFetch).not.toHaveBeenCalled();
  });

  it("is withheld at consent info", async () => {
    const res = await consentInfo(CIMD_ID);

    expect(res.statusCode).toBe(403);
    expect(res.body).toEqual(CLIENT_NOT_APPROVED_ERROR);
    expect(JSON.stringify(res.body)).not.toContain("Example Client");
  });

  it("mints no code at the decision, audits the refusal and clears the cookie", async () => {
    const res = await decide(CIMD_ID);
    await flush();

    expect(res.statusCode).toBe(403);
    expect(res.body).toEqual(CLIENT_NOT_APPROVED_ERROR);
    expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    expect(res.redirectedTo).toBeUndefined();
    expect(res.clearedCookies).toHaveLength(1);
    expect(
      events.find((e) => e.action === "oauth.authorize.denied")?.detail,
    ).toMatchObject({ reason: "cimd_not_admitted" });
  });

  it("proceeds again when the entry is restored, with the stored row unchanged", async () => {
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = CIMD_ID;
    resetCimdConfigForTesting();

    const info = await consentInfo(CIMD_ID);
    expect(info.statusCode).toBe(200);
    const minted = await decide(CIMD_ID);
    expect(minted.redirectedTo).toContain("code=");
    expect(oauthRepositoryMock.setAuthCode).toHaveBeenCalledTimes(1);
    expect(oauthRepositoryMock.setAuthCode.mock.calls[0][1]).toMatchObject({
      client_id: CIMD_ID,
      redirect_uri: REDIRECT_URI,
    });
  });

  it.each(["admin", "dcr", null])(
    "does not affect a %s row that happens to have a URL-shaped id",
    async (source) => {
      rows.set(CIMD_ID, row(CIMD_ID, { registration_source: source }));

      expect((await authorize(CIMD_ID)).redirectedTo).toBeDefined();
      expect((await consentInfo(CIMD_ID)).statusCode).toBe(200);
      expect((await decide(CIMD_ID)).redirectedTo).toContain("code=");
    },
  );
});

describe("GET /oauth/consent/info", () => {
  it("adds only the document host for an admitted client metadata row", async () => {
    rows.set(CIMD_ID, row(CIMD_ID));

    const res = await consentInfo(CIMD_ID);

    expect(res.body).toEqual({
      client_id: CIMD_ID,
      client_name: "Example Client",
      redirect_uri: REDIRECT_URI,
      scope: "mcp",
      client_id_host: "app.example.com",
    });
  });

  it("includes the port in the host when the id has one", async () => {
    const id = "https://app.example.com:8443/c.json";
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = id;
    resetCimdConfigForTesting();
    rows.set(id, row(id));

    expect((await consentInfo(id)).body).toMatchObject({
      client_id_host: "app.example.com:8443",
    });
  });

  it.each(["admin", "dcr", null])(
    "returns exactly today's keys for a %s client",
    async (source) => {
      rows.set(
        "mcp_client_abc",
        row("mcp_client_abc", { registration_source: source }),
      );

      const res = await consentInfo("mcp_client_abc");

      expect(Object.keys(res.body ?? {}).sort()).toEqual([
        "client_id",
        "client_name",
        "redirect_uri",
        "scope",
      ]);
    },
  );
});
