/**
 * `/oauth/authorize` re-applies the registration-time redirect_uri allowlist.
 *
 * WHY A SECOND CHECK. The allowlist (`isAllowedRedirectUri`) shipped at
 * registration time, which binds the rows written AFTER it and says nothing
 * about the rows already in `oauth_clients`. Registration is anonymous, so
 * anything stored before it existed reaches this endpoint with whatever
 * redirect_uri it holds, and the only other check on the way to a minted code
 * is that the URI is one of that client's OWN registered values — trivially
 * true for a client an attacker registered. The store was verified clean when
 * this landed; the point is that it stays irrelevant whether it is.
 *
 * The assertion that bites is `refuses an off-allowlist host EVEN when the
 * client has it registered`: the stored client below lists the attacker host,
 * so every pre-existing check passes and only the new one refuses.
 *
 * The connector half matters just as much and is asserted first — this
 * endpoint is how claude.ai pairs, and a redirect rule that refuses its
 * callback is an outage, not a control.
 */

import express from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";

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

const usersRepositoryMock = { isDisabled: vi.fn() };

vi.mock("../../db/repositories", () => ({
  oauthRepository: oauthRepositoryMock,
  usersRepository: usersRepositoryMock,
}));

// No session: an unauthenticated authorize redirects to /login, which is a
// clean "passed every parameter check" signal that needs no cookie plumbing.
const authMock = {
  handler: vi.fn(async () => new Response("null", { status: 200 })),
};

vi.mock("../../auth", () => ({ auth: authMock }));

process.env.APP_URL = "https://gateway.example.test";
process.env.BETTER_AUTH_SECRET = "test-secret-for-authorize-allowlist-suite";

const { default: authorizationRouter } = await import("./authorization");

const CLIENT_ID = "mcp_client_test";
const CLAUDE_AI_CALLBACK = "https://claude.ai/api/mcp/auth_callback";
const CLAUDE_COM_CALLBACK = "https://claude.com/api/mcp/auth_callback";
const LOOPBACK_CALLBACK = "http://127.0.0.1:53821/callback";
const LOCALHOST_CALLBACK = "http://localhost:53821/callback";
const ATTACKER_CALLBACK = "https://evil.example.com/collect";

interface FakeRes {
  statusCode: number;
  body: Record<string, unknown> | undefined;
  redirectedTo: string | undefined;
  settled: Promise<void>;
  status(code: number): FakeRes;
  json(payload: Record<string, unknown>): FakeRes;
  redirect(url: string): FakeRes;
  cookie(): FakeRes;
  send(): FakeRes;
}

// Unique per request: the authorize endpoint's limiter is 20 per IP per minute
// and lives at module scope, so a shared address would make one test's traffic
// fail another's.
let ipCounter = 0;

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
    redirect(url) {
      res.redirectedTo = url;
      settle();
      return res;
    },
    cookie() {
      return res;
    },
    send() {
      settle();
      return res;
    },
  };

  return res;
}

async function authorize(redirectUri: string): Promise<FakeRes> {
  ipCounter += 1;
  const query = {
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: redirectUri,
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    code_challenge_method: "S256",
  };
  const url = `/oauth/authorize?${new URLSearchParams(query).toString()}`;

  const req = {
    method: "GET",
    url,
    originalUrl: url,
    baseUrl: "",
    path: "/oauth/authorize",
    query,
    headers: {},
    ip: `10.2.0.${ipCounter}`,
    socket: { remoteAddress: `10.2.0.${ipCounter}` },
  } as unknown as express.Request;

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

/** A stored client that has EVERY uri under test registered to it. */
function clientRegisteringEverything() {
  return {
    client_id: CLIENT_ID,
    client_name: "Claude",
    redirect_uris: [
      CLAUDE_AI_CALLBACK,
      CLAUDE_COM_CALLBACK,
      LOOPBACK_CALLBACK,
      LOCALHOST_CALLBACK,
      ATTACKER_CALLBACK,
    ],
    token_endpoint_auth_method: "none",
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  usersRepositoryMock.isDisabled.mockResolvedValue(false);
  oauthRepositoryMock.getClient.mockResolvedValue(
    clientRegisteringEverything(),
  );
  authMock.handler.mockImplementation(
    async () => new Response("null", { status: 200 }),
  );
});

describe("GET /oauth/authorize — allowlisted redirect_uris still work", () => {
  it.each([
    ["claude.ai", CLAUDE_AI_CALLBACK],
    ["claude.com", CLAUDE_COM_CALLBACK],
    ["loopback by IP", LOOPBACK_CALLBACK],
    ["loopback by name", LOCALHOST_CALLBACK],
  ])("accepts the %s callback", async (_label, redirectUri) => {
    const res = await authorize(redirectUri);

    // Signed out, so a request that survived every check redirects to /login
    // carrying the original authorize URL. Anything refused would be a 400.
    expect(res.statusCode).toBe(200);
    expect(res.redirectedTo).toContain("/login");
    expect(res.body).toBeUndefined();
  });
});

describe("GET /oauth/authorize — off-allowlist redirect_uris are refused", () => {
  it("refuses an off-allowlist host EVEN when the client has it registered", async () => {
    // The stored client lists this URI, so the pre-existing
    // "redirect_uri is not registered for this client" check passes it. Only
    // the allowlist stands between an attacker-controlled host and a code.
    const res = await authorize(ATTACKER_CALLBACK);

    expect(res.statusCode).toBe(400);
    expect(res.body?.error).toBe("invalid_request");
    expect(String(res.body?.error_description)).toContain("host_not_allowed");
    expect(res.redirectedTo).toBeUndefined();
  });

  it.each([
    ["a lookalike host", "https://gateway.example.test.evil.example.com/cb"],
    ["a userinfo-disguised host", "https://claude.ai@evil.example.com/cb"],
    ["a subdomain of an allowlisted host", "https://user.claude.ai/cb"],
    ["a fragment on the callback", `${CLAUDE_AI_CALLBACK}#tail`],
  ])("refuses %s", async (_label, redirectUri) => {
    oauthRepositoryMock.getClient.mockResolvedValue({
      ...clientRegisteringEverything(),
      redirect_uris: [redirectUri],
    });

    const res = await authorize(redirectUri);

    expect(res.statusCode).toBe(400);
    expect(res.body?.error).toBe("invalid_request");
  });

  it("refuses a loopback callback aimed at the gateway's own listener", async () => {
    // The gateway is reached through the in-container rewrite, so
    // localhost:12009 is this server talking to itself — no external client
    // has a callback listener there.
    const selfCallback = "http://127.0.0.1:12009/callback";
    oauthRepositoryMock.getClient.mockResolvedValue({
      ...clientRegisteringEverything(),
      redirect_uris: [selfCallback],
    });

    const res = await authorize(selfCallback);

    expect(res.statusCode).toBe(400);
    expect(String(res.body?.error_description)).toContain(
      "gateway_internal_port",
    );
  });

  it("never reaches the client lookup for an off-allowlist uri", async () => {
    // The refusal is on the parameter, before any row is read. A check that
    // ran after the lookup would still pass the assertions above while doing
    // a database round trip for every hostile authorize request.
    await authorize(ATTACKER_CALLBACK);
    expect(oauthRepositoryMock.getClient).not.toHaveBeenCalled();
  });
});
