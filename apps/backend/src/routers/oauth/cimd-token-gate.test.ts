/**
 * The allowlist gate on the token endpoint for client metadata document
 * (`cimd`) clients: the analogue of the approval gate beside it
 * (client-approval-gate.test.ts), with the same shape and the same position.
 *
 * Design decisions, with no outside oracle (gateway policy):
 *  - a `cimd` row whose allowlist entry was removed exchanges no code and
 *    refreshes no token, and the refusal happens BEFORE the code is consumed
 *    or the refresh token claimed, so nothing is burnt and the same request
 *    works again once the entry is back;
 *  - the token endpoint never fetches a document (a fetch there would let an
 *    unauthenticated POST trigger one);
 *  - rows of any other source are never judged by the allowlist.
 *
 * Real router over a real socket, repositories mocked, the fetch transport
 * replaced by a spy that must stay unused.
 */
import { createHash, randomBytes } from "node:crypto";
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

import { armUserLockFakes } from "./user-lock-test-fakes";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const oauthRepositoryMock = {
  getClient: vi.fn(),
  getAuthCode: vi.fn(),
  deleteAuthCode: vi.fn(),
  consumeAuthCode: vi.fn(),
  setAccessToken: vi.fn(),
  getByRefreshToken: vi.fn(),
  getRotatedRefreshToken: vi.fn(),
  claimRefreshToken: vi.fn(),
  recordRotatedRefreshToken: vi.fn(),
  deleteAccessTokenByHash: vi.fn(),
  revokeFamily: vi.fn(),
  withUserLock: vi.fn(),
};
vi.mock("../../db/repositories", () => ({
  oauthRepository: oauthRepositoryMock,
  usersRepository: { isDisabled: vi.fn().mockResolvedValue(false) },
}));

process.env.APP_URL = "https://gateway.example.test";

const utils = await import("./utils");
const { default: tokenRouter } = await import("./token");
const { resetCimdConfigForTesting, OAUTH_CIMD_ALLOWED_CLIENTS_ENV } =
  await import("./cimd-config");
const { resetCimdStateForTesting, setCimdTransportForTesting } = await import(
  "./cimd"
);

const CIMD_ID = "https://app.example.com/oauth/client.json";
const REDIRECT = "https://claude.ai/api/mcp/auth_callback";
const USER_ID = "user-cimd";
const FAMILY_ID = "ffffffff-0000-4000-8000-000000000001";

let server: Server;
let baseUrl: string;
const baseFetch = vi.fn();
const lookup = vi.fn();

beforeAll(async () => {
  const app = express();
  app.use(utils.jsonParsingMiddleware);
  app.use(utils.urlencodedParsingMiddleware);
  app.use(tokenRouter);
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

function clientRow(overrides: Record<string, unknown> = {}) {
  return {
    client_id: CIMD_ID,
    client_name: "Example",
    redirect_uris: [REDIRECT],
    token_endpoint_auth_method: "none",
    client_secret: null,
    client_secret_salt: null,
    registration_source: "cimd",
    approval_status: "approved",
    ...overrides,
  };
}

function codeRow(verifier: string) {
  return {
    code: "hash",
    client_id: CIMD_ID,
    redirect_uri: REDIRECT,
    scope: "mcp",
    user_id: USER_ID,
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
    expires_at: new Date(Date.now() + 60_000),
    created_at: new Date(),
  };
}

function tokenRow() {
  return {
    access_token: "access-hash",
    access_token_last4: "abcd",
    client_id: CIMD_ID,
    user_id: USER_ID,
    scope: "mcp",
    expires_at: new Date(Date.now() + 60_000),
    refresh_token: "refresh-hash",
    refresh_token_expires_at: new Date(Date.now() + 86_400_000),
    family_id: FAMILY_ID,
    created_at: new Date(),
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  resetCimdConfigForTesting();
  resetCimdStateForTesting();
  delete process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV];
  setCimdTransportForTesting({ lookup, baseFetch });
  oauthRepositoryMock.setAccessToken.mockResolvedValue(undefined);
  oauthRepositoryMock.recordRotatedRefreshToken.mockResolvedValue(undefined);
  oauthRepositoryMock.getRotatedRefreshToken.mockResolvedValue(null);
  oauthRepositoryMock.consumeAuthCode.mockResolvedValue(true);
  armUserLockFakes(oauthRepositoryMock);
});

let ipCounter = 0;
const nextIp = () => `192.0.2.${(++ipCounter % 250) + 1}`;

async function postToken(params: Record<string, string>) {
  const res = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      "cf-connecting-ip": nextIp(),
    },
    body: new URLSearchParams(params).toString(),
  });
  return {
    status: res.status,
    body: (await res.json()) as Record<string, unknown>,
  };
}

function exchangeCode() {
  const verifier = randomBytes(32).toString("base64url");
  oauthRepositoryMock.getAuthCode.mockResolvedValue(codeRow(verifier));
  return postToken({
    grant_type: "authorization_code",
    code: "mcp_code_x",
    client_id: CIMD_ID,
    redirect_uri: REDIRECT,
    code_verifier: verifier,
  });
}

function refresh() {
  oauthRepositoryMock.getByRefreshToken.mockResolvedValue(tokenRow());
  return postToken({
    grant_type: "refresh_token",
    refresh_token: "mcp_refresh_x",
  });
}

describe("a client metadata row the allowlist does not admit", () => {
  beforeEach(() => {
    oauthRepositoryMock.getClient.mockResolvedValue(clientRow());
  });

  it.each([
    ["the list is empty", ""],
    [
      "its entry was replaced by another",
      "https://elsewhere.example.net/c.json",
    ],
  ])("exchanges no code when %s, and consumes nothing", async (_name, list) => {
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = list;

    const res = await exchangeCode();

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("unauthorized_client");
    expect(oauthRepositoryMock.withUserLock).not.toHaveBeenCalled();
    expect(oauthRepositoryMock.consumeAuthCode).not.toHaveBeenCalled();
    expect(oauthRepositoryMock.setAccessToken).not.toHaveBeenCalled();
  });

  it.each([
    ["the list is empty", ""],
    [
      "its entry was replaced by another",
      "https://elsewhere.example.net/c.json",
    ],
  ])("refreshes no token when %s, and claims nothing", async (_name, list) => {
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = list;

    const res = await refresh();

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("unauthorized_client");
    expect(oauthRepositoryMock.claimRefreshToken).not.toHaveBeenCalled();
    expect(
      oauthRepositoryMock.recordRotatedRefreshToken,
    ).not.toHaveBeenCalled();
    expect(oauthRepositoryMock.deleteAccessTokenByHash).not.toHaveBeenCalled();
    expect(oauthRepositoryMock.setAccessToken).not.toHaveBeenCalled();
  });

  it("never fetches a document, whatever the list says", async () => {
    for (const list of ["", "https://elsewhere.example.net/c.json", CIMD_ID]) {
      process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = list;
      await exchangeCode();
      await refresh();
    }

    expect(lookup).not.toHaveBeenCalled();
    expect(baseFetch).not.toHaveBeenCalled();
  });
});

describe("a client metadata row the allowlist admits", () => {
  beforeEach(() => {
    oauthRepositoryMock.getClient.mockResolvedValue(clientRow());
  });

  it.each([
    ["an exact entry", CIMD_ID],
    ["an origin entry", "https://app.example.com"],
  ])("exchanges a code under %s", async (_name, list) => {
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = list;

    const res = await exchangeCode();

    expect(res.status).toBe(200);
    expect(oauthRepositoryMock.consumeAuthCode).toHaveBeenCalledTimes(1);
    expect(oauthRepositoryMock.setAccessToken).toHaveBeenCalledTimes(1);
  });

  it("refreshes a token, and works again once the entry is restored after a refusal", async () => {
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = "";
    expect((await refresh()).status).toBe(400);

    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = CIMD_ID;
    const res = await refresh();

    expect(res.status).toBe(200);
    expect(oauthRepositoryMock.claimRefreshToken).toHaveBeenCalledTimes(1);
    expect(oauthRepositoryMock.setAccessToken).toHaveBeenCalledTimes(1);
  });
});

describe("a row of another source is never judged by the allowlist", () => {
  it.each(["admin", "dcr", null])(
    "a %s row with a URL-shaped id exchanges and refreshes with the list empty",
    async (source) => {
      oauthRepositoryMock.getClient.mockResolvedValue(
        clientRow({ registration_source: source }),
      );

      expect((await exchangeCode()).status).toBe(200);
      expect((await refresh()).status).toBe(200);
    },
  );
});
