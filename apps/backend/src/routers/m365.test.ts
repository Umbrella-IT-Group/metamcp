/**
 * Integration tests for the M365 broker enrollment routes — the OAuth
 * attack surface itself. Drives a real express app over a real socket
 * (global fetch against an ephemeral port) with better-auth, the token
 * repository and the Entra token endpoint mocked at the module seam.
 *
 * Security behaviors pinned here:
 *  - reflected-XSS hardening on /m365/callback (the `error` branch is
 *    reachable PRE-AUTH; every dynamic value must be HTML-escaped and
 *    every HTML response must carry the no-script CSP)
 *  - state is single-use and TTL-bound
 *  - the callback must land on the SAME signed-in user that started
 *    the flow (anti account-grafting)
 *  - stored refresh tokens are envelopes, never plaintext
 */
import type { Server } from "node:http";

import express from "express";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

vi.mock("@/auth", () => ({
  auth: { api: { getSession: vi.fn() } },
}));
vi.mock("@/db/repositories/m365-tokens.repo", () => ({
  m365TokensRepository: {
    findByUserId: vi.fn(async () => undefined),
    upsertEnrollment: vi.fn(async () => ({})),
    deleteByUserId: vi.fn(async () => true),
  },
}));

import { auth } from "@/auth";
import { m365TokensRepository } from "@/db/repositories/m365-tokens.repo";

import { decryptRefreshToken } from "../lib/m365/crypto";
import m365Router, { escapeHtml } from "./m365";

// A stable 32-byte KEK for the whole suite.
const KEK_B64 = Buffer.alloc(32, 7).toString("base64");

const getSessionMock = auth.api.getSession as unknown as ReturnType<
  typeof vi.fn
>;
const repoMock = m365TokensRepository as unknown as {
  findByUserId: ReturnType<typeof vi.fn>;
  upsertEnrollment: ReturnType<typeof vi.fn>;
  deleteByUserId: ReturnType<typeof vi.fn>;
};

let server: Server;
let baseUrl: string;
const realFetch = globalThis.fetch;
/** Stub for the OUTBOUND Entra token-exchange call only. */
let entraExchange: ReturnType<
  typeof vi.fn<(url: string, init?: RequestInit) => Promise<Response>>
>;

beforeAll(async () => {
  const app = express();
  app.use(express.json());
  app.use(m365Router);
  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (typeof address === "object" && address) {
    baseUrl = `http://127.0.0.1:${address.port}`;
  }

  // Route outbound fetches: Entra token endpoint → stub; our own test
  // server → real fetch. (The router calls global fetch for the code
  // exchange; the test driver also uses fetch.)
  globalThis.fetch = ((url: string | URL, init?: RequestInit) => {
    const href = String(url);
    if (href.includes("login.microsoftonline.com")) {
      return entraExchange(href, init);
    }
    return realFetch(url as never, init as never);
  }) as typeof fetch;
});

afterAll(async () => {
  globalThis.fetch = realFetch;
  await new Promise((resolve) => server.close(resolve));
});

beforeEach(() => {
  vi.stubEnv("M365_TENANT_ID", "tid-1");
  vi.stubEnv("M365_CLIENT_ID", "cid-1");
  vi.stubEnv("M365_CLIENT_SECRET", "csecret-1");
  vi.stubEnv("M365_TOKEN_KEK", KEK_B64);
  vi.stubEnv("APP_URL", "https://mcp.example.com");
  getSessionMock.mockReset();
  repoMock.findByUserId.mockReset().mockResolvedValue(undefined);
  repoMock.upsertEnrollment.mockReset().mockResolvedValue({});
  repoMock.deleteByUserId.mockReset().mockResolvedValue(true);
  entraExchange = vi.fn();
});

function signInAs(userId: string, email = "alex@umbrellaitgroup.com") {
  getSessionMock.mockResolvedValue({ user: { id: userId, email } });
}
function signedOut() {
  getSessionMock.mockResolvedValue(null);
}

/** Run /m365/enroll and return the state Entra would echo back. */
async function startEnrollment(): Promise<string> {
  const response = await realFetch(`${baseUrl}/m365/enroll`, {
    redirect: "manual",
  });
  expect(response.status).toBe(302);
  const location = response.headers.get("location")!;
  expect(location).toContain("login.microsoftonline.com/tid-1");
  return new URL(location).searchParams.get("state")!;
}

function goodExchangeBody(overrides: Record<string, unknown> = {}) {
  const idTokenPayload = Buffer.from(
    JSON.stringify({
      oid: "oid-abc",
      tid: "tid-1",
      preferred_username: "alex@umbrellaitgroup.com",
    }),
  ).toString("base64url");
  return {
    access_token: "graph-at",
    refresh_token: "entra-rt-plaintext",
    id_token: `x.${idTokenPayload}.y`,
    scope: "User.Read Mail.ReadWrite",
    ...overrides,
  };
}

describe("escapeHtml", () => {
  it("neutralizes script/attribute injection", () => {
    expect(escapeHtml("<script>alert(1)</script>")).toBe(
      "&lt;script&gt;alert(1)&lt;/script&gt;",
    );
    expect(escapeHtml(`"onmouseover='x'`)).toBe(
      "&quot;onmouseover=&#39;x&#39;",
    );
  });
});

describe("GET /m365/enroll", () => {
  it("redirects signed-out users to the login page with a return path", async () => {
    signedOut();
    const response = await realFetch(`${baseUrl}/m365/enroll`, {
      redirect: "manual",
    });
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(
      "/login?callbackUrl=%2Fm365%2Fenroll",
    );
  });

  it("redirects signed-in users to Entra with PKCE + state", async () => {
    signInAs("user-1");
    const response = await realFetch(`${baseUrl}/m365/enroll`, {
      redirect: "manual",
    });
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location")!);
    expect(location.hostname).toBe("login.microsoftonline.com");
    expect(location.searchParams.get("code_challenge_method")).toBe("S256");
    expect(location.searchParams.get("code_challenge")).toBeTruthy();
    expect(location.searchParams.get("state")).toBeTruthy();
    expect(location.searchParams.get("redirect_uri")).toBe(
      "https://mcp.example.com/m365/callback",
    );
    expect(location.searchParams.get("prompt")).toBe("select_account");
  });

  it("answers 503 not_configured when broker env is absent", async () => {
    vi.stubEnv("M365_CLIENT_SECRET", "");
    signInAs("user-1");
    const response = await realFetch(`${baseUrl}/m365/enroll`);
    expect(response.status).toBe(503);
    const body = (await response.json()) as { error?: string };
    expect(body.error).toBe("not_configured");
  });
});

describe("GET /m365/callback — XSS hardening (pre-auth reachable)", () => {
  it("HTML-escapes a hostile `error` param and sets the no-script CSP", async () => {
    signedOut();
    const payload = "<script>alert(document.cookie)</script>";
    const response = await realFetch(
      `${baseUrl}/m365/callback?error=${encodeURIComponent(payload)}`,
    );
    expect(response.status).toBe(400);
    const body = await response.text();
    expect(body).not.toContain("<script>alert");
    expect(body).toContain("&lt;script&gt;");
    expect(response.headers.get("content-security-policy")).toContain(
      "default-src 'none'",
    );
    expect(response.headers.get("x-frame-options")).toBe("DENY");
  });

  it("escapes a hostile UPN on the success page", async () => {
    signInAs("user-1");
    const state = await startEnrollment();
    const evilUpn = `<img src=x onerror=alert(1)>@evil.test`;
    const idTokenPayload = Buffer.from(
      JSON.stringify({
        oid: "oid-abc",
        tid: "tid-1",
        preferred_username: evilUpn,
      }),
    ).toString("base64url");
    entraExchange.mockResolvedValue(
      new Response(
        JSON.stringify(goodExchangeBody({ id_token: `x.${idTokenPayload}.y` })),
        { status: 200 },
      ),
    );
    const response = await realFetch(
      `${baseUrl}/m365/callback?code=authcode&state=${encodeURIComponent(state)}`,
    );
    expect(response.status).toBe(200);
    const body = await response.text();
    expect(body).not.toContain("<img src=x");
    expect(body).toContain("&lt;img src=x");
  });
});

describe("GET /m365/callback — state + session binding", () => {
  it("rejects an unknown state", async () => {
    signInAs("user-1");
    const response = await realFetch(
      `${baseUrl}/m365/callback?code=c&state=never-issued`,
    );
    expect(response.status).toBe(400);
    expect(await response.text()).toContain("expired or was already used");
  });

  it("state is single-use: a replay after success is rejected", async () => {
    signInAs("user-1");
    const state = await startEnrollment();
    entraExchange.mockResolvedValue(
      new Response(JSON.stringify(goodExchangeBody()), { status: 200 }),
    );
    const first = await realFetch(
      `${baseUrl}/m365/callback?code=c&state=${encodeURIComponent(state)}`,
    );
    expect(first.status).toBe(200);
    const replay = await realFetch(
      `${baseUrl}/m365/callback?code=c&state=${encodeURIComponent(state)}`,
    );
    expect(replay.status).toBe(400);
    expect(repoMock.upsertEnrollment).toHaveBeenCalledTimes(1);
  });

  it("rejects a callback landing on a DIFFERENT signed-in user (anti-grafting)", async () => {
    signInAs("user-victim");
    const state = await startEnrollment();
    signInAs("user-attacker");
    const response = await realFetch(
      `${baseUrl}/m365/callback?code=c&state=${encodeURIComponent(state)}`,
    );
    expect(response.status).toBe(403);
    expect(repoMock.upsertEnrollment).not.toHaveBeenCalled();
    expect(entraExchange).not.toHaveBeenCalled();
  });

  it("rejects a callback with no live session at all", async () => {
    signInAs("user-1");
    const state = await startEnrollment();
    signedOut();
    const response = await realFetch(
      `${baseUrl}/m365/callback?code=c&state=${encodeURIComponent(state)}`,
    );
    expect(response.status).toBe(403);
  });
});

describe("GET /m365/callback — happy path custody", () => {
  it("persists an ENVELOPE (decryptable, never plaintext) and passes PKCE verifier", async () => {
    signInAs("user-1");
    const state = await startEnrollment();
    entraExchange.mockResolvedValue(
      new Response(JSON.stringify(goodExchangeBody()), { status: 200 }),
    );

    const response = await realFetch(
      `${baseUrl}/m365/callback?code=authcode-1&state=${encodeURIComponent(state)}`,
    );
    expect(response.status).toBe(200);

    // Outbound exchange carried the code + a verifier.
    const [, exchangeInit] = entraExchange.mock.calls[0];
    const params = new URLSearchParams(String(exchangeInit?.body));
    expect(params.get("grant_type")).toBe("authorization_code");
    expect(params.get("code")).toBe("authcode-1");
    expect(params.get("code_verifier")).toBeTruthy();

    // Stored value is an envelope that decrypts back to the RT.
    const stored = repoMock.upsertEnrollment.mock.calls[0][0];
    expect(stored.user_id).toBe("user-1");
    expect(stored.entra_oid).toBe("oid-abc");
    expect(stored.rt_ciphertext).not.toContain("entra-rt-plaintext");
    expect(decryptRefreshToken(stored.rt_ciphertext, Buffer.alloc(32, 7))).toBe(
      "entra-rt-plaintext",
    );
  });

  it("rejects an exchange that returns no refresh token", async () => {
    signInAs("user-1");
    const state = await startEnrollment();
    entraExchange.mockResolvedValue(
      new Response(
        JSON.stringify(goodExchangeBody({ refresh_token: undefined })),
        { status: 200 },
      ),
    );
    const response = await realFetch(
      `${baseUrl}/m365/callback?code=c&state=${encodeURIComponent(state)}`,
    );
    expect(response.status).toBe(400);
    expect(await response.text()).toContain("offline_access");
    expect(repoMock.upsertEnrollment).not.toHaveBeenCalled();
  });
});

describe("status + disconnect", () => {
  it("gates both behind a session", async () => {
    signedOut();
    const status = await realFetch(`${baseUrl}/m365/status`);
    expect(status.status).toBe(401);
    const disconnect = await realFetch(`${baseUrl}/m365/disconnect`, {
      method: "POST",
    });
    expect(disconnect.status).toBe(401);
  });

  it("disconnect deletes the grant for the session user", async () => {
    signInAs("user-1");
    const response = await realFetch(`${baseUrl}/m365/disconnect`, {
      method: "POST",
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { disconnected?: boolean };
    expect(body.disconnected).toBe(true);
    expect(repoMock.deleteByUserId).toHaveBeenCalledWith("user-1");
  });
});
