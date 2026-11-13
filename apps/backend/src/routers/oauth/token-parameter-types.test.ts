/**
 * /oauth/token and /oauth/revoke read each RFC 6749 / RFC 7009 parameter as a
 * single string, and refuse anything else with 400 invalid_request BEFORE any
 * hashing, credential comparison or database access.
 *
 * Both endpoints accept JSON and form bodies, and both parsers can produce
 * arrays, objects, numbers and null for these names (the extended form parser
 * turns `token[]=a` or a repeated key into an array and `token[a]=b` into an
 * object). Such a value used to reach the hashed lookup on /oauth/revoke,
 * throw there, and come back as a 500 with an error line, uncounted by the
 * route's failure budget, so one address could repeat it without limit.
 *
 * Driven over HTTP through the real body parsers and the real token router,
 * with the repositories mocked so any database access is visible.
 */

import { createHash, randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";

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

const loggerMock = {
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
};
vi.mock("@/utils/logger", () => ({ default: loggerMock }));

const oauthRepositoryMock = {
  getAuthCode: vi.fn(),
  deleteAuthCode: vi.fn(),
  consumeAuthCode: vi.fn(),
  // Spent-code record (migration 0045): the handler writes one on a first
  // redemption and reads one for an unknown code; a bare mock answers "nothing
  // there", which is the pre-0045 behaviour these suites were written against.
  recordSpentCode: vi.fn(),
  getSpentCode: vi.fn(),
  consumeSpentCode: vi.fn(),
  countFamilyAccessTokens: vi.fn(),
  getClient: vi.fn(),
  getByRefreshToken: vi.fn(),
  setAccessToken: vi.fn(),
  deleteAccessToken: vi.fn(),
  deleteAccessTokenByHash: vi.fn(),
  getAccessToken: vi.fn(),
  recordRotatedRefreshToken: vi.fn(),
  getRotatedRefreshToken: vi.fn(),
  revokeFamily: vi.fn(),
  withUserLock: vi.fn(),
  claimRefreshToken: vi.fn(),
  deleteByRefreshToken: vi.fn(),
};
const usersRepositoryMock = { isDisabled: vi.fn() };

vi.mock("../../db/repositories", () => ({
  oauthRepository: oauthRepositoryMock,
  usersRepository: usersRepositoryMock,
}));
vi.mock("./introspection-auth", () => ({
  requireIntrospectionCredential: vi.fn(async () => ({
    ok: true,
    userId: null,
  })),
}));

const { default: tokenRouter } = await import("./token");
const utils = await import("./utils");
const { armUserLockFakes } = await import("./user-lock-test-fakes");
const { setAuditSinkForTesting } = await import("@/lib/audit/audit-emitter");

const CLIENT_ID = "mcp_client_parameter_types";
const USER_ID = "user-parameter-types";
const RIGHT_SECRET = "right-client-secret-value";
const REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback";
const AUTH_CODE = "mcp_code_parametertypes00000";
const REFRESH_TOKEN = "mcp_refresh_parametertypes000";
const verifier = randomBytes(32).toString("base64url");
const challenge = createHash("sha256").update(verifier).digest("base64url");

let base: string;
let server: import("node:http").Server;
let ipCounter = 0;
const freshIp = () => `2001:db8:77::${(++ipCounter).toString(16)}`;

beforeAll(async () => {
  setAuditSinkForTesting(null);
  const app = express();
  // Same parsers, same order, as routers/oauth/index.ts.
  app.use(utils.jsonParsingMiddleware);
  app.use(utils.urlencodedParsingMiddleware);
  app.use(tokenRouter);
  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", resolve);
  });
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  setAuditSinkForTesting(undefined);
  await new Promise((resolve) => server?.close(resolve));
});

function clientRow(
  method: "none" | "client_secret_post" | "client_secret_basic",
) {
  if (method === "none") {
    return {
      client_id: CLIENT_ID,
      approval_status: "approved",
      client_name: "Public",
      token_endpoint_auth_method: "none",
      client_secret: null,
      client_secret_salt: null,
    };
  }
  const hashed = utils.hashClientSecret(RIGHT_SECRET);
  return {
    client_id: CLIENT_ID,
    approval_status: "approved",
    client_name: "Confidential",
    token_endpoint_auth_method: method,
    client_secret: hashed.hash,
    client_secret_salt: hashed.salt,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  usersRepositoryMock.isDisabled.mockResolvedValue(false);
  oauthRepositoryMock.getClient.mockResolvedValue(clientRow("none"));
  oauthRepositoryMock.getAuthCode.mockResolvedValue({
    code: "stored-code-hash",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: "mcp",
    user_id: USER_ID,
    code_challenge: challenge,
    code_challenge_method: "S256",
    expires_at: new Date(Date.now() + 5 * 60 * 1000),
  });
  oauthRepositoryMock.consumeAuthCode.mockResolvedValue(true);
  oauthRepositoryMock.getByRefreshToken.mockResolvedValue({
    access_token: "stored-access-hash",
    access_token_last4: "abcd",
    refresh_token: "stored-refresh-hash",
    client_id: CLIENT_ID,
    user_id: USER_ID,
    scope: "mcp",
    created_at: new Date(),
    expires_at: new Date(Date.now() + 60 * 1000),
    refresh_token_expires_at: new Date(Date.now() + 86_400_000),
    family_id: "88888888-8888-4888-8888-888888888888",
  });
  oauthRepositoryMock.getAccessToken.mockResolvedValue(null);
  oauthRepositoryMock.getRotatedRefreshToken.mockResolvedValue(null);
  oauthRepositoryMock.setAccessToken.mockResolvedValue(undefined);
  oauthRepositoryMock.recordRotatedRefreshToken.mockResolvedValue(undefined);
  armUserLockFakes(oauthRepositoryMock);
});

type Encoding = "json" | "form";

async function post(
  path: string,
  body: string,
  encoding: Encoding,
  ip: string,
  headers: Record<string, string> = {},
) {
  const res = await fetch(`${base}${path}`, {
    method: "POST",
    headers: {
      "content-type":
        encoding === "json"
          ? "application/json"
          : "application/x-www-form-urlencoded",
      "cf-connecting-ip": ip,
      ...headers,
    },
    body,
  });
  const text = await res.text();
  return {
    status: res.status,
    body: text ? (JSON.parse(text) as Record<string, unknown>) : null,
  };
}

function expectNoDatabaseAccess() {
  for (const [name, fn] of Object.entries(oauthRepositoryMock)) {
    expect({ name, calls: fn.mock.calls.length }).toEqual({ name, calls: 0 });
  }
  expect(usersRepositoryMock.isDisabled).not.toHaveBeenCalled();
}

// Malformed bodies for one parameter, in each encoding the endpoints accept.
function malformedBodies(
  name: string,
  base: Record<string, string>,
): Array<[string, string, Encoding]> {
  const form = (extra: string) =>
    [new URLSearchParams(base).toString(), extra].filter(Boolean).join("&");
  return [
    ["a JSON array", JSON.stringify({ ...base, [name]: ["x"] }), "json"],
    ["a JSON object", JSON.stringify({ ...base, [name]: { a: "x" } }), "json"],
    ["JSON null", JSON.stringify({ ...base, [name]: null }), "json"],
    ["a JSON number", JSON.stringify({ ...base, [name]: 7 }), "json"],
    ["a JSON boolean", JSON.stringify({ ...base, [name]: true }), "json"],
    ["a form array", form(`${name}[]=x`), "form"],
    ["a form object", form(`${name}[a]=x`), "form"],
    ["a repeated form key", form(`${name}=x&${name}=y`), "form"],
  ];
}

describe("/oauth/revoke", () => {
  it.each(["token", "client_id", "client_secret"])(
    "refuses a non-string %s with 400 before any lookup",
    async (name) => {
      const baseBody: Record<string, string> =
        name === "token" ? {} : { token: "mcp_token_x" };
      for (const [label, body, encoding] of malformedBodies(name, baseBody)) {
        vi.clearAllMocks();
        const res = await post("/oauth/revoke", body, encoding, freshIp());
        expect({ label, status: res.status }).toEqual({ label, status: 400 });
        expect(res.body).toEqual({
          error: "invalid_request",
          error_description: `The ${name} parameter must be a single string value`,
        });
        expectNoDatabaseAccess();
      }
    },
  );

  it("refuses a JSON array body as malformed", async () => {
    const res = await post(
      "/oauth/revoke",
      JSON.stringify([{ token: "mcp_token_x" }]),
      "json",
      freshIp(),
    );
    expect(res.status).toBe(400);
    expect(res.body?.error).toBe("invalid_request");
    expectNoDatabaseAccess();
  });

  it("counts each refusal once, so one address is refused 429 after its budget, never 500", async () => {
    const ip = freshIp();
    const statuses: number[] = [];
    for (let i = 0; i < 25; i += 1) {
      statuses.push(
        (
          await post(
            "/oauth/revoke",
            JSON.stringify({ token: ["garbage"] }),
            "json",
            ip,
          )
        ).status,
      );
    }
    // The failure budget is 20 per minute per edge address and route.
    expect(statuses.slice(0, 20).every((s) => s === 400)).toBe(true);
    expect(statuses.slice(20).every((s) => s === 429)).toBe(true);
    expect(loggerMock.error).not.toHaveBeenCalled();
  });

  it("still revokes a real token sent as a string", async () => {
    oauthRepositoryMock.getAccessToken.mockResolvedValue({
      access_token: "stored-access-hash",
      client_id: CLIENT_ID,
      user_id: USER_ID,
      family_id: "88888888-8888-4888-8888-888888888888",
    });
    const res = await post(
      "/oauth/revoke",
      new URLSearchParams({ token: "mcp_token_real" }).toString(),
      "form",
      freshIp(),
    );
    expect(res.status).toBe(200);
    expect(oauthRepositoryMock.deleteAccessToken).toHaveBeenCalledTimes(1);
  });
});

describe("/oauth/token", () => {
  const codeGrant = {
    grant_type: "authorization_code",
    code: AUTH_CODE,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
    code_verifier: verifier,
  };
  const refreshGrant = {
    grant_type: "refresh_token",
    refresh_token: REFRESH_TOKEN,
    client_id: CLIENT_ID,
  };

  it.each([
    ["grant_type", codeGrant],
    ["code", codeGrant],
    ["redirect_uri", codeGrant],
    ["code_verifier", codeGrant],
    ["client_id", codeGrant],
    ["client_secret", codeGrant],
    ["refresh_token", refreshGrant],
    ["client_id", refreshGrant],
    ["client_secret", refreshGrant],
  ])(
    "refuses a non-string %s with 400 and consumes nothing",
    async (name, grant) => {
      const baseBody = Object.fromEntries(
        Object.entries(grant).filter(([key]) => key !== name),
      );
      for (const [label, body, encoding] of malformedBodies(name, baseBody)) {
        vi.clearAllMocks();
        const res = await post("/oauth/token", body, encoding, freshIp());
        expect({ label, status: res.status }).toEqual({ label, status: 400 });
        expect(res.body).toEqual({
          error: "invalid_request",
          error_description: `The ${name} parameter must be a single string value`,
        });
        expectNoDatabaseAccess();
      }
    },
  );

  it("refuses a JSON array body as malformed without logging it", async () => {
    const res = await post(
      "/oauth/token",
      JSON.stringify([codeGrant]),
      "json",
      freshIp(),
    );
    expect(res.status).toBe(400);
    expect(res.body?.error).toBe("invalid_request");
    expectNoDatabaseAccess();
    expect(loggerMock.error).not.toHaveBeenCalled();
  });

  it("is refused 429 by the token limiter after repeated malformed requests, never 500", async () => {
    const ip = freshIp();
    const statuses: number[] = [];
    for (let i = 0; i < 22; i += 1) {
      statuses.push(
        (
          await post(
            "/oauth/token",
            JSON.stringify({ ...refreshGrant, refresh_token: { a: 1 } }),
            "json",
            ip,
          )
        ).status,
      );
    }
    expect(statuses.slice(0, 20).every((s) => s === 400)).toBe(true);
    expect(statuses.slice(20).every((s) => s === 429)).toBe(true);
    expect(loggerMock.error).not.toHaveBeenCalled();
  });

  describe("well-formed clients are unaffected", () => {
    it("a public client redeems a code with no client_secret at all", async () => {
      const res = await post(
        "/oauth/token",
        new URLSearchParams(codeGrant).toString(),
        "form",
        freshIp(),
      );
      expect(res.status).toBe(200);
      expect(res.body?.access_token).toMatch(/^mcp_token_/);
    });

    it("a client_secret_post client authenticates with a string secret", async () => {
      oauthRepositoryMock.getClient.mockResolvedValue(
        clientRow("client_secret_post"),
      );
      const res = await post(
        "/oauth/token",
        JSON.stringify({ ...codeGrant, client_secret: RIGHT_SECRET }),
        "json",
        freshIp(),
      );
      expect(res.status).toBe(200);
    });

    it("a client_secret_basic client authenticates with only the header, no body client fields", async () => {
      oauthRepositoryMock.getClient.mockResolvedValue(
        clientRow("client_secret_basic"),
      );
      const { client_id: _omitted, ...withoutClientId } = codeGrant;
      const res = await post(
        "/oauth/token",
        new URLSearchParams(withoutClientId).toString(),
        "form",
        freshIp(),
        {
          authorization: `Basic ${Buffer.from(`${CLIENT_ID}:${RIGHT_SECRET}`).toString("base64")}`,
        },
      );
      expect(res.status).toBe(200);
    });

    it("a public client refreshes with string parameters", async () => {
      const res = await post(
        "/oauth/token",
        new URLSearchParams(refreshGrant).toString(),
        "form",
        freshIp(),
      );
      expect(res.status).toBe(200);
      expect(res.body?.refresh_token).toMatch(/^mcp_refresh_/);
    });
  });
});
