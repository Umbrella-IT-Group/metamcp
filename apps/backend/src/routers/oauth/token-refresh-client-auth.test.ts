/**
 * Confidential-client authentication on the refresh_token grant
 * (OAUTH_REFRESH_CLIENT_AUTH, RFC 6749 section 6).
 *
 * The defect: handleRefreshTokenGrant compared `client_id` when one was sent
 * but never verified a confidential client's secret, so a `client_secret_post`
 * or `client_secret_basic` client's refresh token alone minted access tokens.
 * The authorization_code grant has always verified it.
 *
 * Pinned here:
 *
 *  1. The setting: unset, empty and unrecognised values mean `log`; `log` and
 *     `enforce` are read case-insensitively; the boot line reports the value.
 *  2. Public (`none`) clients are untouched in both modes: the same response,
 *     no `client_auth` on the issued line or the audit row, no extra warning.
 *  3. `client_secret_post` and `client_secret_basic`, each with a right, a
 *     missing and a wrong secret, in both modes. `log` always issues and
 *     records the outcome; `enforce` issues only on `verified` and otherwise
 *     refuses 401 invalid_client with the authorization_code grant's own
 *     description, leaving the token row unrotated.
 *  4. No secret value, and no Basic header carrying one, ever reaches a log
 *     line or an audit row.
 *
 * Same harness as token-client-auth.test.ts: the router is driven as express
 * middleware against fake req/res, and the repositories are mocked so
 * db/index.ts never loads. Audit rows are captured through the test sink.
 */

import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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
  getClient: vi.fn(),
  getByRefreshToken: vi.fn(),
  setAccessToken: vi.fn(),
  deleteAccessToken: vi.fn(),
  deleteAccessTokenByHash: vi.fn(),
  getAccessToken: vi.fn(),
  recordRotatedRefreshToken: vi.fn(),
  getRotatedRefreshToken: vi.fn(),
  revokeFamily: vi.fn(),
};

const usersRepositoryMock = {
  isDisabled: vi.fn(),
};

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

const ENV = "OAUTH_REFRESH_CLIENT_AUTH";
const originalEnv = process.env[ENV];
// Unset for the import, so the boot line below reports the default.
delete process.env[ENV];

const {
  default: tokenRouter,
  OAUTH_REFRESH_CLIENT_AUTH_ENV,
  resolveRefreshClientAuthMode,
} = await import("./token");
// Dynamic for the same reason as in token.test.ts: a static import of ./utils
// would pull the logger in before the hoisted mock's object exists.
const { hashClientSecret } = await import("./utils");
const { setAuditSinkForTesting } = await import("@/lib/audit/audit-emitter");

// Taken before any beforeEach clears the mocks: the module-load log lines.
const bootInfoLines = loggerMock.info.mock.calls
  .flat()
  .filter((arg): arg is string => typeof arg === "string");

const CLIENT_ID = "mcp_client_confidential000";
const USER_ID = "user-refreshclientauth";
const SCOPE = "mcp";
const RIGHT_SECRET = "mcp_secret_the_real_one_refresh_0123";
const WRONG_SECRET = "mcp_secret_not_the_real_one_refresh_9";
const REFRESH_TOKEN = "mcp_refresh_refreshclientauth0000";
const PRIOR_ACCESS_TOKEN_HASH = "stored-access-token-hash-rca";

type AuditRow = {
  action: string;
  outcome: string;
  detail?: Record<string, unknown>;
};

let rows: AuditRow[];
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

interface FakeRes {
  statusCode: number;
  body: Record<string, string> | undefined;
  settled: Promise<void>;
  status(code: number): FakeRes;
  json(payload: Record<string, string>): FakeRes;
  send(): FakeRes;
}

function makeRes(): FakeRes {
  let settle: () => void;
  const settled = new Promise<void>((resolve) => {
    settle = resolve;
  });
  const res: FakeRes = {
    statusCode: 200,
    body: undefined,
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
  };
  return res;
}

// Unique per request so the module-scope token rate limiter (keyed by IP)
// never lets one case's traffic fail another's.
let ipCounter = 0;
async function post(
  body: Record<string, unknown>,
  authorization?: string,
): Promise<FakeRes> {
  ipCounter += 1;
  const req = {
    method: "POST",
    url: "/oauth/token",
    originalUrl: "/oauth/token",
    baseUrl: "",
    body,
    headers: authorization ? { authorization } : {},
    ip: `10.0.43.${ipCounter}`,
    socket: { remoteAddress: `10.0.43.${ipCounter}` },
  } as unknown as express.Request;
  const res = makeRes();
  await new Promise<void>((resolve, reject) => {
    (tokenRouter as unknown as express.RequestHandler)(
      req,
      res as unknown as express.Response,
      (err?: unknown) => (err ? reject(err) : resolve()),
    );
    res.settled.then(resolve);
  });
  await flush();
  return res;
}

/** RFC 6749 2.3.1: each half form-urlencoded, joined by a colon, base64. */
function basic(clientId: string, secret: string): string {
  const encode = (value: string) =>
    encodeURIComponent(value).replace(/%20/g, "+");
  return `Basic ${Buffer.from(`${encode(clientId)}:${encode(secret)}`).toString("base64")}`;
}

type Method = "none" | "client_secret_post" | "client_secret_basic";

const hashed = hashClientSecret(RIGHT_SECRET);
function clientRow(method: Method) {
  return method === "none"
    ? {
        client_id: CLIENT_ID,
        client_name: "Public Client",
        token_endpoint_auth_method: "none",
        client_secret: null,
        client_secret_salt: null,
      }
    : {
        client_id: CLIENT_ID,
        client_name: "Confidential Client",
        token_endpoint_auth_method: method,
        client_secret: hashed.hash,
        client_secret_salt: hashed.salt,
      };
}

const refreshBody = (extra: Record<string, unknown> = {}) => ({
  grant_type: "refresh_token",
  refresh_token: REFRESH_TOKEN,
  ...extra,
});

function loggedText(): string {
  return [
    ...loggerMock.debug.mock.calls,
    ...loggerMock.info.mock.calls,
    ...loggerMock.warn.mock.calls,
    ...loggerMock.error.mock.calls,
  ]
    .flat()
    .map((arg) => (typeof arg === "string" ? arg : JSON.stringify(arg)))
    .join("\n");
}

function warnLines(): string[] {
  return loggerMock.warn.mock.calls
    .flat()
    .filter((arg): arg is string => typeof arg === "string");
}

function issuedLine(): string {
  const lines = loggerMock.info.mock.calls
    .flat()
    .filter(
      (arg): arg is string =>
        typeof arg === "string" && arg.startsWith("[oauth] token issued"),
    );
  expect(lines).toHaveLength(1);
  return lines[0];
}

function refreshRow(): AuditRow {
  const refreshRows = rows.filter((r) => r.action === "oauth.token.refresh");
  expect(refreshRows).toHaveLength(1);
  return refreshRows[0];
}

/** A rotated pair was issued and the redeemed row was rotated out. */
function expectIssued(res: FakeRes) {
  expect(res.statusCode).toBe(200);
  expect(Object.keys(res.body ?? {}).sort()).toEqual([
    "access_token",
    "expires_in",
    "refresh_token",
    "scope",
    "token_type",
  ]);
  expect(res.body?.access_token).toMatch(/^mcp_token_/);
  expect(oauthRepositoryMock.setAccessToken).toHaveBeenCalledTimes(1);
  expect(oauthRepositoryMock.recordRotatedRefreshToken).toHaveBeenCalledTimes(
    1,
  );
  expect(oauthRepositoryMock.deleteAccessTokenByHash).toHaveBeenCalledWith(
    PRIOR_ACCESS_TOKEN_HASH,
  );
}

/** Refused 401 invalid_client, and the token row was left exactly as it was. */
function expectRefusedUntouched(res: FakeRes, description: string) {
  expect(res.statusCode).toBe(401);
  expect(res.body).toEqual({
    error: "invalid_client",
    error_description: description,
  });
  expect(oauthRepositoryMock.setAccessToken).not.toHaveBeenCalled();
  expect(oauthRepositoryMock.deleteAccessTokenByHash).not.toHaveBeenCalled();
  expect(oauthRepositoryMock.recordRotatedRefreshToken).not.toHaveBeenCalled();
  expect(rows.filter((r) => r.action === "oauth.token.refresh")).toEqual([]);
}

/** Nothing secret-bearing reached any log line or audit row. */
function expectNoSecretRecorded() {
  const recorded = `${loggedText()}\n${JSON.stringify(rows)}`;
  for (const value of [
    RIGHT_SECRET,
    WRONG_SECRET,
    basic(CLIENT_ID, RIGHT_SECRET).slice(6),
    basic(CLIENT_ID, WRONG_SECRET).slice(6),
    hashed.hash,
    REFRESH_TOKEN,
  ]) {
    expect(recorded).not.toContain(value);
  }
}

beforeEach(() => {
  vi.clearAllMocks();
  delete process.env[ENV];
  rows = [];
  setAuditSinkForTesting(async (event) => {
    rows.push(event as AuditRow);
  });
  oauthRepositoryMock.getByRefreshToken.mockResolvedValue({
    access_token: PRIOR_ACCESS_TOKEN_HASH,
    refresh_token: "stored-refresh-token-hash-rca",
    access_token_last4: "abcd",
    client_id: CLIENT_ID,
    user_id: USER_ID,
    scope: SCOPE,
    created_at: new Date(Date.now() - 60 * 1000),
    expires_at: new Date(Date.now() + 60 * 1000),
    refresh_token_expires_at: new Date(Date.now() + 365 * 24 * 3600 * 1000),
    family_id: "33333333-3333-3333-3333-333333333333",
  });
  oauthRepositoryMock.setAccessToken.mockResolvedValue(undefined);
  oauthRepositoryMock.deleteAccessTokenByHash.mockResolvedValue(undefined);
  oauthRepositoryMock.recordRotatedRefreshToken.mockResolvedValue(undefined);
  usersRepositoryMock.isDisabled.mockResolvedValue(false);
});

afterEach(() => {
  setAuditSinkForTesting(undefined);
  if (originalEnv === undefined) {
    delete process.env[ENV];
  } else {
    process.env[ENV] = originalEnv;
  }
});

describe("the OAUTH_REFRESH_CLIENT_AUTH setting", () => {
  it("is the documented env var name", () => {
    expect(OAUTH_REFRESH_CLIENT_AUTH_ENV).toBe("OAUTH_REFRESH_CLIENT_AUTH");
  });

  it("defaults to log when unset or blank", () => {
    expect(resolveRefreshClientAuthMode()).toBe("log");
    process.env[ENV] = "   ";
    expect(resolveRefreshClientAuthMode()).toBe("log");
    expect(loggerMock.warn).not.toHaveBeenCalled();
  });

  it.each([
    ["log", "log"],
    ["enforce", "enforce"],
    [" ENFORCE ", "enforce"],
    ["Log", "log"],
  ])("reads %j as %s", (raw, expected) => {
    process.env[ENV] = raw;
    expect(resolveRefreshClientAuthMode()).toBe(expected);
    expect(loggerMock.warn).not.toHaveBeenCalled();
  });

  it.each(["enforced", "true", "on", "1"])(
    "falls back to log on the unrecognised value %j and says so",
    (raw) => {
      process.env[ENV] = raw;
      expect(resolveRefreshClientAuthMode()).toBe("log");
      expect(warnLines()).toEqual([
        `[oauth] OAUTH_REFRESH_CLIENT_AUTH=${JSON.stringify(raw)} is not "log" or "enforce"; using log`,
      ]);
    },
  );

  it("reports the effective value at boot", () => {
    expect(bootInfoLines).toContain(
      "[oauth] refresh grant client auth: OAUTH_REFRESH_CLIENT_AUTH=log",
    );
  });
});

describe.each(["log", "enforce"] as const)(
  "public client (none), mode %s: unchanged",
  (mode) => {
    beforeEach(() => {
      process.env[ENV] = mode;
      oauthRepositoryMock.getClient.mockResolvedValue(clientRow("none"));
    });

    it("issues with no client_auth on the line or the audit row", async () => {
      const res = await post(refreshBody({ client_id: CLIENT_ID }));

      expectIssued(res);
      expect(issuedLine()).toBe(
        "[oauth] token issued grant=refresh_token " +
          `client=${CLIENT_ID} user=${USER_ID} ` +
          `token=...${res.body?.access_token.slice(-4)} rotated=true`,
      );
      expect(refreshRow().detail).not.toHaveProperty("client_auth");
      expect(warnLines()).toEqual([]);
    });

    it("issues with no client_id at all, as before", async () => {
      expectIssued(await post(refreshBody()));
      expect(warnLines()).toEqual([]);
    });

    it("ignores a stray client_secret, as before", async () => {
      expectIssued(
        await post(
          refreshBody({ client_id: CLIENT_ID, client_secret: WRONG_SECRET }),
        ),
      );
      expect(issuedLine()).not.toContain("client_auth");
      expect(warnLines()).toEqual([]);
      expectNoSecretRecorded();
    });

    it("loads the row of the client the token was issued to", async () => {
      await post(refreshBody());
      expect(oauthRepositoryMock.getClient).toHaveBeenCalledWith(CLIENT_ID);
    });
  },
);

describe("client_secret_post", () => {
  beforeEach(() => {
    oauthRepositoryMock.getClient.mockResolvedValue(
      clientRow("client_secret_post"),
    );
  });

  describe("mode log (default): records and proceeds", () => {
    it("right secret: issues, client_auth=verified, no warning", async () => {
      const res = await post(
        refreshBody({ client_id: CLIENT_ID, client_secret: RIGHT_SECRET }),
      );

      expectIssued(res);
      expect(issuedLine()).toBe(
        "[oauth] token issued grant=refresh_token " +
          `client=${CLIENT_ID} user=${USER_ID} ` +
          `token=...${res.body?.access_token.slice(-4)} rotated=true client_auth=verified`,
      );
      expect(refreshRow().detail?.client_auth).toBe("verified");
      expect(warnLines()).toEqual([]);
      expectNoSecretRecorded();
    });

    it("missing secret: still issues, client_auth=missing, warns", async () => {
      const res = await post(refreshBody({ client_id: CLIENT_ID }));

      expectIssued(res);
      expect(issuedLine()).toMatch(/ client_auth=missing$/);
      expect(refreshRow().detail?.client_auth).toBe("missing");
      expect(warnLines()).toEqual([
        "[oauth] refresh client auth outcome=missing mode=log " +
          `method=client_secret_post client=${CLIENT_ID} user=${USER_ID}`,
      ]);
      expectNoSecretRecorded();
    });

    it("wrong secret: still issues, client_auth=invalid, warns", async () => {
      const res = await post(
        refreshBody({ client_id: CLIENT_ID, client_secret: WRONG_SECRET }),
      );

      expectIssued(res);
      expect(issuedLine()).toMatch(/ client_auth=invalid$/);
      expect(refreshRow().detail?.client_auth).toBe("invalid");
      expect(warnLines()).toEqual([
        "[oauth] refresh client auth outcome=invalid mode=log " +
          `method=client_secret_post client=${CLIENT_ID} user=${USER_ID}`,
      ]);
      expectNoSecretRecorded();
    });

    it("the outcome is judged for the token's client even with no client_id sent", async () => {
      expectIssued(await post(refreshBody({ client_secret: RIGHT_SECRET })));
      expect(oauthRepositoryMock.getClient).toHaveBeenCalledWith(CLIENT_ID);
      expect(issuedLine()).toMatch(/ client_auth=verified$/);
    });
  });

  describe("mode enforce: refuses anything but verified", () => {
    beforeEach(() => {
      process.env[ENV] = "enforce";
    });

    it("right secret: issues, client_auth=verified", async () => {
      expectIssued(
        await post(
          refreshBody({ client_id: CLIENT_ID, client_secret: RIGHT_SECRET }),
        ),
      );
      expect(issuedLine()).toMatch(/ client_auth=verified$/);
      expect(refreshRow().detail?.client_auth).toBe("verified");
      expectNoSecretRecorded();
    });

    it("missing secret: 401 invalid_client, token row untouched", async () => {
      expectRefusedUntouched(
        await post(refreshBody({ client_id: CLIENT_ID })),
        "Invalid client secret",
      );
      expect(warnLines()).toEqual([
        "[oauth] token rejected reason=client_auth_missing grant=refresh_token " +
          `method=client_secret_post client=${CLIENT_ID} user=${USER_ID}`,
      ]);
      expectNoSecretRecorded();
    });

    it("wrong secret: 401 invalid_client, token row untouched", async () => {
      expectRefusedUntouched(
        await post(
          refreshBody({ client_id: CLIENT_ID, client_secret: WRONG_SECRET }),
        ),
        "Invalid client secret",
      );
      expect(warnLines()).toEqual([
        "[oauth] token rejected reason=client_auth_invalid grant=refresh_token " +
          `method=client_secret_post client=${CLIENT_ID} user=${USER_ID}`,
      ]);
      expectNoSecretRecorded();
    });

    it("authenticates the client before the disabled-account check", async () => {
      usersRepositoryMock.isDisabled.mockResolvedValue(true);

      expectRefusedUntouched(
        await post(refreshBody({ client_id: CLIENT_ID })),
        "Invalid client secret",
      );
      expect(usersRepositoryMock.isDisabled).not.toHaveBeenCalled();
    });
  });
});

describe.each(["log", "enforce"] as const)(
  "malformed POST client secret, mode %s",
  (mode) => {
    it.each([
      ["an object that cannot be coerced", { toString: "untrusted-value" }],
      ["an array containing the right secret", [RIGHT_SECRET]],
    ])("records %s as invalid without coercing it", async (_label, secret) => {
      process.env[ENV] = mode;
      oauthRepositoryMock.getClient.mockResolvedValue(
        clientRow("client_secret_post"),
      );
      // Express accepts JSON objects here. Coercing this one while hashing
      // throws, which used to turn the observational mode into a refusal.
      const res = await post(
        refreshBody({
          client_id: CLIENT_ID,
          client_secret: secret,
        }),
      );

      if (mode === "log") {
        expectIssued(res);
        expect(issuedLine()).toMatch(/ client_auth=invalid$/);
        expect(refreshRow().detail?.client_auth).toBe("invalid");
      } else {
        expectRefusedUntouched(res, "Invalid client secret");
      }
      expect(loggedText()).not.toContain("untrusted-value");
      expectNoSecretRecorded();
    });
  },
);

describe("client_secret_basic", () => {
  beforeEach(() => {
    oauthRepositoryMock.getClient.mockResolvedValue(
      clientRow("client_secret_basic"),
    );
  });

  describe("mode log (default): records and proceeds", () => {
    it("right header: issues, client_auth=verified, no warning", async () => {
      expectIssued(await post(refreshBody(), basic(CLIENT_ID, RIGHT_SECRET)));
      expect(issuedLine()).toMatch(/ client_auth=verified$/);
      expect(refreshRow().detail?.client_auth).toBe("verified");
      expect(warnLines()).toEqual([]);
      expectNoSecretRecorded();
    });

    it("no header: still issues, client_auth=missing, warns", async () => {
      expectIssued(await post(refreshBody({ client_id: CLIENT_ID })));
      expect(issuedLine()).toMatch(/ client_auth=missing$/);
      expect(refreshRow().detail?.client_auth).toBe("missing");
      expect(warnLines()).toEqual([
        "[oauth] refresh client auth outcome=missing mode=log " +
          `method=client_secret_basic client=${CLIENT_ID} user=${USER_ID}`,
      ]);
    });

    it("wrong secret in the header: still issues, client_auth=invalid", async () => {
      expectIssued(await post(refreshBody(), basic(CLIENT_ID, WRONG_SECRET)));
      expect(issuedLine()).toMatch(/ client_auth=invalid$/);
      expect(refreshRow().detail?.client_auth).toBe("invalid");
      expectNoSecretRecorded();
    });

    it("an unreadable header counts as invalid, not missing", async () => {
      const broken = `Basic ${Buffer.from(`${CLIENT_ID}:bad%ZZescape`).toString("base64")}`;

      expectIssued(await post(refreshBody({ client_id: CLIENT_ID }), broken));
      expect(issuedLine()).toMatch(/ client_auth=invalid$/);
    });
  });

  describe("mode enforce: refuses anything but verified", () => {
    beforeEach(() => {
      process.env[ENV] = "enforce";
    });

    it("right header: issues, client_auth=verified", async () => {
      expectIssued(await post(refreshBody(), basic(CLIENT_ID, RIGHT_SECRET)));
      expect(issuedLine()).toMatch(/ client_auth=verified$/);
      expectNoSecretRecorded();
    });

    it("no header: 401 with the code grant's description, untouched", async () => {
      expectRefusedUntouched(
        await post(refreshBody({ client_id: CLIENT_ID })),
        "Client authentication required via Basic auth",
      );
    });

    it("wrong secret in the header: 401 invalid_client, untouched", async () => {
      expectRefusedUntouched(
        await post(refreshBody(), basic(CLIENT_ID, WRONG_SECRET)),
        "Invalid client credentials",
      );
      expect(warnLines()).toEqual([
        "[oauth] token rejected reason=client_auth_invalid grant=refresh_token " +
          `method=client_secret_basic client=${CLIENT_ID} user=${USER_ID}`,
      ]);
      expectNoSecretRecorded();
    });

    it("a secret sent in the body does not stand in for the header", async () => {
      expectRefusedUntouched(
        await post(
          refreshBody({ client_id: CLIENT_ID, client_secret: RIGHT_SECRET }),
        ),
        "Client authentication required via Basic auth",
      );
      expectNoSecretRecorded();
    });
  });
});

describe("the client row is gone (a delete racing the refresh)", () => {
  beforeEach(() => {
    oauthRepositoryMock.getClient.mockResolvedValue(null);
  });

  it("log: proceeds as before and says so", async () => {
    expectIssued(await post(refreshBody({ client_id: CLIENT_ID })));
    expect(issuedLine()).not.toContain("client_auth");
    expect(warnLines()).toEqual([
      "[oauth] refresh client auth outcome=client_not_found mode=log " +
        `client=${CLIENT_ID} user=${USER_ID}`,
    ]);
  });

  it("enforce: refuses 401 invalid_client, untouched", async () => {
    process.env[ENV] = "enforce";

    expectRefusedUntouched(
      await post(refreshBody({ client_id: CLIENT_ID })),
      "Client not found or not registered",
    );
  });
});
