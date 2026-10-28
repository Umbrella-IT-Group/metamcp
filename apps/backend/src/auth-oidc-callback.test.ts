/**
 * The OIDC (Entra) sign-in round trip under better-auth 1.7.
 *
 * better-auth 1.7 rewrote the generic OAuth plugin as a core social provider
 * (upstream #9069), and nothing else in this suite drives the SSO path. What
 * this file pins, in the order a sign-in hits it:
 *
 *  1. the provider registers under `oidc`, the literal the login page sends;
 *  2. the redirect URI is `${APP_URL}/api/auth/callback/oidc`. Entra redirects
 *     only to a registered URI, so a silent change here locks every SSO user
 *     out of the admin UI; the 1.6 plugin route `/oauth2/callback/:providerId`
 *     must be gone, not shadowing the new one;
 *  3. the authorization request carries a PKCE S256 challenge and a nonce;
 *  4. the code exchange sends the same redirect URI and the PKCE verifier;
 *  5. the id_token is verified against discovery (issuer, JWKS, `aud`) and
 *     must echo the nonce, with an Entra-shaped JWKS whose keys carry no
 *     `alg` member (true of the live tenant JWKS, checked 2026-10-28);
 *  6. the account key is the token's `sub`, the key 1.6 stored, so existing
 *     `accounts` rows keep matching;
 *  7. the drizzle schema passes the init-time check 1.7.3 added, which fails
 *     every auth request on a mismatch;
 *  8. a bare id_token posted to `/sign-in/social` or `/link-social` is refused
 *     the way 1.6.23 refused it (our `hooks.before`), while the redirect flow
 *     and the callback are untouched;
 *  9. the two 1.7.8 fixes the version pin exists for: 30 s of clock tolerance
 *     on the id_token, and a discovery retry after a failed boot fetch.
 *
 * Harness as in auth-basic-auth-disabled.test.ts: configService, the users
 * repo, audit and logger are mocked and `db/index` is a stub. The flow's few
 * internal-adapter calls are spied on the live auth context, and a fetch stub
 * plays Entra's discovery, JWKS and token endpoints.
 */

import { createHash, generateKeyPairSync, KeyObject, sign } from "node:crypto";

import { afterAll, afterEach, describe, expect, it, vi } from "vitest";

vi.mock("./lib/config.service", () => ({
  configService: {
    isSignupDisabled: vi.fn().mockResolvedValue(false),
    isSsoSignupDisabled: vi.fn().mockResolvedValue(false),
    isBasicAuthDisabled: vi.fn().mockResolvedValue(false),
  },
}));

vi.mock("./db/repositories/users.repo", () => ({
  usersRepository: { isDisabled: vi.fn().mockResolvedValue(false) },
}));

// db/index builds a live pg Pool at import; the drizzle adapter only needs an
// object to hold on to. Every adapter call this flow makes is spied below.
vi.mock("./db/index", () => ({ db: {}, pool: {} }));

vi.mock("./lib/audit/auth-hook-audit", () => ({
  emitSignupDenied: vi.fn(),
  emitSignupCreated: vi.fn(),
  emitSessionCreated: vi.fn(),
  emitSessionRevoked: vi.fn(),
}));

vi.mock("./utils/logger", () => ({
  default: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

const APP_URL = "http://localhost:12008";
const CALLBACK_URI = `${APP_URL}/api/auth/callback/oidc`;
const TENANT = "00000000-0000-4000-8000-000000000001";
const ISSUER = `https://login.microsoftonline.com/${TENANT}/v2.0`;
const DISCOVERY_URL = `${ISSUER}/.well-known/openid-configuration`;
const AUTHORIZE_URL = `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/authorize`;
const TOKEN_URL = `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`;
const JWKS_URL = `https://login.microsoftonline.com/${TENANT}/discovery/v2.0/keys`;
const CLIENT_ID = "11111111-2222-4333-8444-555555555555";
const SUBJECT = "entra-pairwise-subject-0001";
const KID = "test-signing-key";

// The provider config mirrors production (Umbrella-MCP-Server docs/mcp-auth.md):
// tenant discovery plus an explicit authorization URL, PKCE on.
vi.stubEnv("BETTER_AUTH_SECRET", "test-secret-not-a-real-key");
vi.stubEnv("APP_URL", APP_URL);
vi.stubEnv("OIDC_CLIENT_ID", CLIENT_ID);
vi.stubEnv("OIDC_CLIENT_SECRET", "test-client-secret");
vi.stubEnv("OIDC_DISCOVERY_URL", DISCOVERY_URL);
vi.stubEnv("OIDC_AUTHORIZATION_URL", AUTHORIZE_URL);
vi.stubEnv("OIDC_PROVIDER_ID", "oidc");
vi.stubEnv("OIDC_SCOPES", "openid email profile");
vi.stubEnv("OIDC_PKCE", "true");

// The subset of Entra's tenant discovery document better-auth reads.
const DISCOVERY = {
  issuer: ISSUER,
  authorization_endpoint: AUTHORIZE_URL,
  token_endpoint: TOKEN_URL,
  userinfo_endpoint: "https://graph.microsoft.com/oidc/userinfo",
  jwks_uri: JWKS_URL,
  end_session_endpoint: `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/logout`,
  id_token_signing_alg_values_supported: ["RS256"],
  response_types_supported: ["code", "id_token", "code id_token"],
  scopes_supported: ["openid", "profile", "email", "offline_access"],
  subject_types_supported: ["pairwise"],
};

const signingKey = generateKeyPairSync("rsa", { modulusLength: 2048 });
const foreignKey = generateKeyPairSync("rsa", { modulusLength: 2048 });

// No `alg` member, as Entra publishes them.
const JWKS = {
  keys: [
    { ...signingKey.publicKey.export({ format: "jwk" }), kid: KID, use: "sig" },
  ],
};

function signIdToken(
  claims: Record<string, unknown>,
  privateKey: KeyObject = signingKey.privateKey,
): string {
  const encode = (value: unknown) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  const signingInput = `${encode({ alg: "RS256", typ: "JWT", kid: KID })}.${encode(claims)}`;
  const signature = sign(
    "sha256",
    Buffer.from(signingInput),
    privateKey,
  ).toString("base64url");
  return `${signingInput}.${signature}`;
}

// An Entra v2 id_token: iat and nbf are the issue time, no backdating.
function entraIdTokenClaims(nonce: string): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    ver: "2.0",
    iss: ISSUER,
    sub: SUBJECT,
    aud: CLIENT_ID,
    exp: now + 3600,
    iat: now,
    nbf: now,
    nonce,
    tid: TENANT,
    oid: "00000000-0000-4000-8000-0000000000aa",
    name: "Test User",
    preferred_username: "test.user@example.com",
    email: "test.user@example.com",
  };
}

// Network stub standing in for login.microsoftonline.com.
const network = {
  tokenRequests: [] as URLSearchParams[],
  idToken: "",
  // How many discovery fetches to fail before answering (discovery retry).
  discoveryFailures: 0,
};

vi.stubGlobal(
  "fetch",
  vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
    if (url === DISCOVERY_URL) {
      if (network.discoveryFailures > 0) {
        network.discoveryFailures -= 1;
        return new Response("service unavailable", { status: 503 });
      }
      return Response.json(DISCOVERY);
    }
    if (url === JWKS_URL) return Response.json(JWKS);
    if (url === TOKEN_URL) {
      network.tokenRequests.push(new URLSearchParams(String(init?.body ?? "")));
      return Response.json({
        token_type: "Bearer",
        scope: "openid email profile",
        expires_in: 3600,
        access_token: "entra-access-token",
        id_token: network.idToken,
      });
    }
    return new Response(`unexpected request in test: ${url}`, { status: 404 });
  }),
);

afterEach(() => {
  vi.restoreAllMocks();
  network.tokenRequests = [];
  network.idToken = "";
  network.discoveryFailures = 0;
});

afterAll(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

type InternalAdapter = Record<string, (...args: never[]) => Promise<unknown>>;

async function loadAuth() {
  const { auth } = await import("./auth");
  const ctx = await auth.$context;
  return {
    auth,
    ctx,
    adapter: ctx.internalAdapter as unknown as InternalAdapter,
  };
}

// Database-backed OAuth state (better-auth's default with a database) in a
// Map, so the sign-in and the callback share it the way the verification
// table would.
function spyStateStore(adapter: InternalAdapter): Map<string, string> {
  const rows = new Map<string, string>();
  vi.spyOn(adapter, "createVerificationValue").mockImplementation(
    (async (data: { identifier: string; value: string; expiresAt: Date }) => {
      rows.set(data.identifier, data.value);
      return {
        id: "verification-1",
        createdAt: new Date(),
        updatedAt: new Date(),
        ...data,
      };
    }) as never,
  );
  vi.spyOn(adapter, "findVerificationValue").mockImplementation((async (
    identifier: string,
  ) => {
    const value = rows.get(identifier);
    if (!value) return null;
    return {
      id: "verification-1",
      identifier,
      value,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000),
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }) as never);
  vi.spyOn(adapter, "deleteVerificationByIdentifier").mockResolvedValue(
    undefined as never,
  );
  return rows;
}

// POST /api/auth/sign-in/social as the login page does, returning what the
// callback needs: the authorization URL, the stored state and its cookie.
async function startSignIn() {
  const { auth, adapter } = await loadAuth();
  const rows = spyStateStore(adapter);

  const res = await auth.handler(
    new Request(`${APP_URL}/api/auth/sign-in/social`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: APP_URL },
      body: JSON.stringify({ provider: "oidc", callbackURL: "/" }),
    }),
  );
  expect(res.status).toBe(200);

  const authorize = new URL(((await res.json()) as { url: string }).url);
  const state = authorize.searchParams.get("state") ?? "";
  const storedRow = [...rows].find(([identifier]) =>
    identifier.endsWith(state),
  );
  expect(storedRow).toBeDefined();
  const stored = JSON.parse(storedRow?.[1] ?? "{}") as {
    codeVerifier: string;
    idTokenNonce?: string;
  };
  const stateCookie = res.headers
    .getSetCookie()
    .map((cookie) => cookie.split(";")[0] ?? "")
    .find((cookie) => cookie.startsWith("better-auth.state="));
  expect(stateCookie).toBeDefined();

  return {
    auth,
    adapter,
    authorize,
    state,
    stored,
    stateCookie: stateCookie ?? "",
  };
}

function callbackRequest(state: string, stateCookie: string): Request {
  return new Request(
    `${CALLBACK_URI}?code=entra-auth-code&state=${encodeURIComponent(state)}`,
    { headers: { cookie: stateCookie } },
  );
}

describe("OIDC provider registration", () => {
  it("registers the provider under the id the login page sends", async () => {
    const { ctx } = await loadAuth();

    expect(ctx.socialProviders.map((provider) => provider.id)).toContain(
      "oidc",
    );
  });

  it("passes the init-time drizzle schema check that gates every auth request", async () => {
    const { ctx } = await loadAuth();
    const { checkSchema } = ctx as unknown as {
      checkSchema?: () => Promise<void> | undefined;
    };

    // Registered by the drizzle adapter; a mismatch rejects here with the
    // missing or unexpected columns named.
    expect(checkSchema).toBeTypeOf("function");
    await expect(Promise.resolve(checkSchema?.())).resolves.toBeUndefined();
  });
});

describe("OIDC callback route", () => {
  it("serves /callback/:id and no longer registers the 1.6 plugin routes", async () => {
    const { auth } = await loadAuth();
    const paths = Object.values(auth.api).map(
      (endpoint) => (endpoint as { path?: string }).path,
    );

    expect(paths).toContain("/callback/:id");
    expect(paths).not.toContain("/oauth2/callback/:providerId");
    expect(paths).not.toContain("/sign-in/oauth2");
  });

  it("answers the new path through the router and 404s the old one", async () => {
    const { auth } = await loadAuth();

    // No state: the callback handler itself answers, by redirecting to the
    // error page, which proves the route resolves to it.
    const live = await auth.handler(new Request(CALLBACK_URI));
    expect(live.status).toBe(302);
    expect(live.headers.get("location")).toContain("error=state_not_found");

    const old = await auth.handler(
      new Request(`${APP_URL}/api/auth/oauth2/callback/oidc?code=x&state=y`),
    );
    expect(old.status).toBe(404);
  });
});

describe("OIDC sign-in round trip", () => {
  it("sends Entra the new redirect URI, a PKCE S256 challenge and a nonce", async () => {
    const { authorize, stored } = await startSignIn();

    expect(`${authorize.origin}${authorize.pathname}`).toBe(AUTHORIZE_URL);
    expect(authorize.searchParams.get("redirect_uri")).toBe(CALLBACK_URI);
    expect(authorize.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(authorize.searchParams.get("response_type")).toBe("code");
    expect(authorize.searchParams.get("scope")).toBe("openid email profile");
    expect(authorize.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorize.searchParams.get("code_challenge")).toBe(
      createHash("sha256").update(stored.codeVerifier).digest("base64url"),
    );
    expect(stored.idTokenNonce).toBeTruthy();
    expect(authorize.searchParams.get("nonce")).toBe(stored.idTokenNonce);
  });

  it("exchanges the code with the same redirect URI, verifies the id_token and keys the account on sub", async () => {
    const { auth, adapter, state, stored, stateCookie } = await startSignIn();
    network.idToken = signIdToken(
      entraIdTokenClaims(stored.idTokenNonce ?? ""),
    );
    // The first database read after identity is resolved. Stopping the flow
    // here keeps the test off the users and sessions tables; reaching it at
    // all means the id_token passed verification.
    const ownerLookup = vi
      .spyOn(adapter, "findAccountOwnerByKey")
      .mockRejectedValue(new Error("stop after identity resolution") as never);

    await auth.handler(callbackRequest(state, stateCookie));

    expect(network.tokenRequests).toHaveLength(1);
    const exchange = network.tokenRequests[0];
    expect(exchange?.get("grant_type")).toBe("authorization_code");
    expect(exchange?.get("code")).toBe("entra-auth-code");
    expect(exchange?.get("redirect_uri")).toBe(CALLBACK_URI);
    expect(exchange?.get("code_verifier")).toBe(stored.codeVerifier);
    expect(ownerLookup).toHaveBeenCalledWith({
      providerId: "oidc",
      accountId: SUBJECT,
    });
  });

  it.each([
    [
      "does not echo the sign-in nonce",
      () => signIdToken(entraIdTokenClaims("nonce-from-another-sign-in")),
    ],
    [
      "is signed by a key outside the discovery JWKS",
      (nonce: string) =>
        signIdToken(entraIdTokenClaims(nonce), foreignKey.privateKey),
    ],
  ])("refuses an id_token that %s", async (_label, makeToken) => {
    const { auth, adapter, state, stored, stateCookie } = await startSignIn();
    network.idToken = makeToken(stored.idTokenNonce ?? "");
    const ownerLookup = vi.spyOn(adapter, "findAccountOwnerByKey");

    const res = await auth.handler(callbackRequest(state, stateCookie));

    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain(
      "error=unable_to_get_user_info",
    );
    expect(ownerLookup).not.toHaveBeenCalled();
  });
});

type BeforeHook = (ctx: { path: string; body?: unknown }) => Promise<unknown>;

async function getBeforeHook(): Promise<BeforeHook> {
  const { auth } = await loadAuth();
  const hook = (auth.options as unknown as { hooks?: { before?: BeforeHook } })
    .hooks?.before;
  if (!hook) throw new Error("auth.options.hooks.before is not configured");
  return hook;
}

const ID_TOKEN_NOT_SUPPORTED = {
  code: "ID_TOKEN_NOT_SUPPORTED",
  message: "id_token not supported",
};

describe("bare id_token sign-in: refused, as better-auth 1.6.23 refused it", () => {
  it("answers POST /sign-in/social with an idToken 404 ID_TOKEN_NOT_SUPPORTED and no session", async () => {
    const { auth, adapter } = await loadAuth();
    const ownerLookup = vi.spyOn(adapter, "findAccountOwnerByKey");
    // A token that would pass every 1.7 check: right issuer, key, audience,
    // unexpired. The caller sends no nonce, so 1.7 would not check one.
    const claims = entraIdTokenClaims("unused");
    delete claims.nonce;

    const res = await auth.handler(
      new Request(`${APP_URL}/api/auth/sign-in/social`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: APP_URL },
        body: JSON.stringify({
          provider: "oidc",
          callbackURL: "/",
          idToken: { token: signIdToken(claims) },
        }),
      }),
    );

    expect(res.status).toBe(404);
    expect(await res.json()).toMatchObject(ID_TOKEN_NOT_SUPPORTED);
    expect(res.headers.get("set-cookie")).toBeNull();
    expect(ownerLookup).not.toHaveBeenCalled();
  });

  it.each([
    ["/sign-in/social", { provider: "oidc", idToken: { token: "a.b.c" } }],
    ["/link-social", { provider: "oidc", idToken: { token: "a.b.c" } }],
  ])("refuses %s with an idToken at the hook", async (path, body) => {
    const hook = await getBeforeHook();

    await expect(hook({ path, body })).rejects.toMatchObject({
      statusCode: 404,
      body: ID_TOKEN_NOT_SUPPORTED,
    });
  });

  it.each([
    [
      "/sign-in/social without an idToken",
      "/sign-in/social",
      { provider: "oidc", callbackURL: "/" },
    ],
    ["/link-social without an idToken", "/link-social", { provider: "oidc" }],
    ["/callback/:id", "/callback/:id", { code: "x", state: "y", idToken: "z" }],
    ["a request with no body", "/sign-in/social", undefined],
  ])("passes %s through", async (_label, path, body) => {
    const hook = await getBeforeHook();

    await expect(hook({ path, body })).resolves.toBeUndefined();
  });

  it("still starts the redirect flow when no idToken is sent", async () => {
    const { authorize } = await startSignIn();

    expect(`${authorize.origin}${authorize.pathname}`).toBe(AUTHORIZE_URL);
    expect(authorize.searchParams.get("redirect_uri")).toBe(CALLBACK_URI);
  });

  it("still completes the callback", async () => {
    const { auth, adapter, state, stored, stateCookie } = await startSignIn();
    network.idToken = signIdToken(
      entraIdTokenClaims(stored.idTokenNonce ?? ""),
    );
    const ownerLookup = vi
      .spyOn(adapter, "findAccountOwnerByKey")
      .mockRejectedValue(new Error("stop after identity resolution") as never);

    await auth.handler(callbackRequest(state, stateCookie));

    expect(ownerLookup).toHaveBeenCalledWith({
      providerId: "oidc",
      accountId: SUBJECT,
    });
  });
});

describe("the 1.7.8 fixes the version pin exists for", () => {
  it("accepts an id_token whose nbf is a few seconds ahead of this host's clock", async () => {
    // Upstream #11749. 1.7.7 had no clock tolerance, so a host clock lagging
    // Entra's by more than the round trip failed every sign-in.
    const { auth, adapter, state, stored, stateCookie } = await startSignIn();
    const claims = entraIdTokenClaims(stored.idTokenNonce ?? "");
    const now = Math.floor(Date.now() / 1000);
    claims.iat = now + 5;
    claims.nbf = now + 5;
    network.idToken = signIdToken(claims);
    const ownerLookup = vi
      .spyOn(adapter, "findAccountOwnerByKey")
      .mockRejectedValue(new Error("stop after identity resolution") as never);

    await auth.handler(callbackRequest(state, stateCookie));

    expect(ownerLookup).toHaveBeenCalledWith({
      providerId: "oidc",
      accountId: SUBJECT,
    });
  });

  it("retries discovery on a later sign-in after the boot fetch failed", async () => {
    // Upstream #11750. 1.7.7 skipped the provider for the life of the process.
    // A fresh auth instance whose boot-time discovery fetch fails:
    vi.resetModules();
    network.discoveryFailures = 1;
    const { ctx } = await loadAuth();
    expect(ctx.socialProviders.map((provider) => provider.id)).not.toContain(
      "oidc",
    );

    // The next sign-in naming the provider fetches discovery again and
    // proceeds to Entra.
    const { authorize } = await startSignIn();
    expect(`${authorize.origin}${authorize.pathname}`).toBe(AUTHORIZE_URL);
    expect(authorize.searchParams.get("redirect_uri")).toBe(CALLBACK_URI);
  });
});
