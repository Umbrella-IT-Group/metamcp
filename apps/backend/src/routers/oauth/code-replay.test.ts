/**
 * Authorization-code replay handling at the token endpoint (migration 0045).
 *
 * RFC 6749 section 4.1.2: "If an authorization code is used more than once, the
 * authorization server MUST deny the request and SHOULD revoke (when possible)
 * all tokens previously issued based on that authorization code." Denial was
 * already true, because redeeming a code deletes it. What was missing was the
 * second half: the delete also erased the only record of which tokens the code
 * produced, so a replay left whoever redeemed it first logged in, unrecorded.
 *
 * What is pinned here:
 *
 *  1. The first redemption records a spent code in the SAME transaction as the
 *     token pair, carrying the pair's family (R1), and a failed record write
 *     fails the grant rather than issuing a pair nothing could be tied back to
 *     (R10).
 *  2. A replay that proves possession of the original exchange (same client,
 *     same redirect, a verifier matching the stored challenge, and the secret
 *     for a confidential client) is audited and, under OAUTH_CODE_REPLAY=revoke,
 *     revokes the family. The caller's answer is the unchanged invalid_grant
 *     (R2, R2b, R6).
 *  3. A presentation that does NOT prove that possession changes nothing and
 *     writes nothing (R3, R4, R8): a code in a redirect URL is something an
 *     observer can have, and detection must not become a way to log someone out.
 *  4. One compromised code writes one audit row however often it is replayed
 *     (R5). The default mode audits without revoking (R7). `off` touches no
 *     table and writes no row (R11).
 *
 * Same harness as token.test.ts and refresh-token-reuse.test.ts: the router is
 * driven as express middleware against fake req/res, the repository is mocked
 * so db/index.ts never loads, and the audit sink is captured in process. The
 * SQL behaviour (atomicity, the single-replay gate, the user lock, expiry) is
 * pinned against a real Postgres in
 * ../../db/repositories/oauth-code-replay.integration.test.ts.
 *
 * The clock is pinned with fake timers that fake Date only, so the expiry
 * arithmetic is exact and no test reads the wall clock.
 */

import { createHash } from "crypto";
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
  withUserLock: vi.fn(),
  claimRefreshToken: vi.fn(),
  deleteByRefreshToken: vi.fn(),
  // The migration-0045 methods under test.
  recordSpentCode: vi.fn(),
  getSpentCode: vi.fn(),
  consumeSpentCode: vi.fn(),
  countFamilyAccessTokens: vi.fn(),
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

const {
  default: tokenRouter,
  resolveCodeReplayMode,
  s256Challenge,
  SPENT_CODE_MARGIN_MS,
} = await import("./token");
const { setAuditSinkForTesting } = await import("@/lib/audit/audit-emitter");
const { resolveErrorStatus } = await import(
  "../../middleware/error-handler.middleware"
);
const { armUserLockFakes, FAKE_OAUTH_TX } = await import(
  "./user-lock-test-fakes"
);
const { hashClientSecret } = await import("./utils");

const CLIENT_ID = "mcp_client_replay";
const USER_ID = "user-replay-1";
const FAMILY_ID = "f2222222-2222-4222-8222-222222222222";
const REDIRECT = "https://claude.ai/api/mcp/auth_callback";
const CODE = "mcp_code_replaytest0123456789abcdef";
// RFC 7636 Appendix B: this verifier and this challenge are the published pair,
// so the fixtures do not derive one from the code under test.
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const NOW = new Date("2026-11-12T12:00:00.000Z");
const CODE_TTL_MS = 10 * 60 * 1000;
const SECRET = "mcp_secret_the_real_one_replay_01";
const WRONG_SECRET = "mcp_secret_a_different_one_replay";

const LEGACY_REPLAY_BODY = {
  error: "invalid_grant",
  error_description: "Invalid or expired authorization code",
};

type AuditRow = {
  action: string;
  outcome: string;
  http_status?: number;
  actor_id?: string | null;
  target_id?: string | null;
  detail?: Record<string, unknown>;
};

let rows: AuditRow[];
let ipCounter = 0;

const sha256 = (value: string) =>
  createHash("sha256").update(value).digest("hex");

// The audit emitter is detached (`emit` never awaits its sink), so a row lands
// a few microtask turns after the request. A macrotask yield, not a timer, is
// enough and reads no clock.
const flush = () => new Promise<void>((resolve) => setImmediate(resolve));

interface FakeRes {
  statusCode: number;
  body: Record<string, unknown> | undefined;
  settled: Promise<void>;
  status(code: number): FakeRes;
  json(payload: Record<string, unknown>): FakeRes;
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

/**
 * POST /oauth/token. Resolves with the response, or with the error the handler
 * passed to `next` (a thrown handler reaches the terminal error handler in
 * production, which answers 500).
 */
async function postToken(
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
): Promise<{ res: FakeRes; error: unknown }> {
  ipCounter += 1;
  const req = {
    method: "POST",
    url: "/oauth/token",
    originalUrl: "/oauth/token",
    baseUrl: "",
    body,
    auditRequestId: "req-code-replay",
    auditClientIp: "203.0.113.20",
    headers: { "user-agent": "Claude/1.0", ...headers },
    ip: `10.7.0.${ipCounter}`,
    socket: { remoteAddress: `10.7.0.${ipCounter}` },
  } as unknown as express.Request;
  const res = makeRes();
  let error: unknown;
  await new Promise<void>((resolve) => {
    (tokenRouter as unknown as express.RequestHandler)(
      req,
      res as unknown as express.Response,
      (err?: unknown) => {
        error = err;
        resolve();
      },
    );
    res.settled.then(resolve);
  });
  await flush();
  return { res, error };
}

// An `undefined` override removes the parameter: the endpoint refuses a present
// parameter that is not a string (firstNonStringParameter), which would answer
// a different error than an absent one.
function exchangeBody(overrides: Record<string, unknown> = {}) {
  const body: Record<string, unknown> = {
    grant_type: "authorization_code",
    code: CODE,
    redirect_uri: REDIRECT,
    client_id: CLIENT_ID,
    code_verifier: VERIFIER,
    ...overrides,
  };
  for (const [key, value] of Object.entries(body)) {
    if (value === undefined) delete body[key];
  }
  return body;
}

function liveCodeRow() {
  return {
    code: sha256(CODE),
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT,
    scope: "mcp",
    user_id: USER_ID,
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    expires_at: new Date(NOW.getTime() + CODE_TTL_MS),
  };
}

function spentRow() {
  return {
    family_id: FAMILY_ID,
    client_id: CLIENT_ID,
    user_id: USER_ID,
    redirect_uri: REDIRECT,
    code_challenge: CHALLENGE,
    expires_at: new Date(NOW.getTime() + CODE_TTL_MS + SPENT_CODE_MARGIN_MS),
  };
}

function publicClient() {
  return {
    client_id: CLIENT_ID,
    client_name: "Replay Client",
    approval_status: "approved",
    token_endpoint_auth_method: "none",
    client_secret: null,
    client_secret_salt: null,
  };
}

function confidentialClient() {
  const hashed = hashClientSecret(SECRET);
  return {
    client_id: CLIENT_ID,
    client_name: "Replay Client",
    approval_status: "approved",
    token_endpoint_auth_method: "client_secret_post",
    client_secret: hashed.hash,
    client_secret_salt: hashed.salt,
  };
}

/** Arm the mocks for a replay: the live code is gone, its spent record is there. */
function armReplay() {
  oauthRepositoryMock.getAuthCode.mockResolvedValue(null);
  oauthRepositoryMock.getSpentCode.mockResolvedValue(spentRow());
  oauthRepositoryMock.consumeSpentCode.mockResolvedValue(spentRow());
  oauthRepositoryMock.countFamilyAccessTokens.mockResolvedValue(1);
  oauthRepositoryMock.revokeFamily.mockResolvedValue(1);
}

function auditText(): string {
  return JSON.stringify(rows);
}

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

function reuseRows(): AuditRow[] {
  return rows.filter((row) => row.action === "oauth.token.reuse");
}

/** Nothing about a replay was recorded, consumed or revoked. */
function expectReplayIgnored() {
  expect(oauthRepositoryMock.consumeSpentCode).not.toHaveBeenCalled();
  expect(oauthRepositoryMock.revokeFamily).not.toHaveBeenCalled();
  expect(oauthRepositoryMock.withUserLock).not.toHaveBeenCalled();
  expect(rows).toEqual([]);
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
  delete process.env.OAUTH_CODE_REPLAY;
  rows = [];
  setAuditSinkForTesting(async (event) => {
    rows.push(event as AuditRow);
  });
  oauthRepositoryMock.setAccessToken.mockResolvedValue(undefined);
  oauthRepositoryMock.consumeAuthCode.mockResolvedValue(true);
  oauthRepositoryMock.recordSpentCode.mockResolvedValue(undefined);
  oauthRepositoryMock.getSpentCode.mockResolvedValue(null);
  oauthRepositoryMock.consumeSpentCode.mockResolvedValue(null);
  oauthRepositoryMock.countFamilyAccessTokens.mockResolvedValue(0);
  oauthRepositoryMock.revokeFamily.mockResolvedValue(0);
  oauthRepositoryMock.getClient.mockResolvedValue(publicClient());
  usersRepositoryMock.isDisabled.mockResolvedValue(false);
  armUserLockFakes(oauthRepositoryMock);
});

afterEach(() => {
  setAuditSinkForTesting(undefined);
  vi.useRealTimers();
  delete process.env.OAUTH_CODE_REPLAY;
});

describe("the S256 transform", () => {
  it("matches the RFC 7636 Appendix B test vector", () => {
    // Oracle: RFC 7636 Appendix B publishes this verifier/challenge pair. The
    // redemption check and the replay check share this function, so a wrong
    // transform would either refuse every legitimate client or accept any
    // verifier.
    expect(s256Challenge(VERIFIER)).toBe(CHALLENGE);
  });
});

describe("OAUTH_CODE_REPLAY resolution", () => {
  it.each([
    [undefined, "log"],
    ["", "log"],
    ["   ", "log"],
    ["log", "log"],
    ["revoke", "revoke"],
    [" Revoke ", "revoke"],
    ["OFF", "off"],
    ["off", "off"],
  ])("reads %j as %s", (raw, expected) => {
    if (raw === undefined) delete process.env.OAUTH_CODE_REPLAY;
    else process.env.OAUTH_CODE_REPLAY = raw;
    expect(resolveCodeReplayMode()).toBe(expected);
    expect(loggerMock.warn).not.toHaveBeenCalled();
  });

  it("falls back to log, never revoke or off, on a value it does not know, and names it", () => {
    // A typo must not switch on session revocation, and must not silently drop
    // the audit trail either.
    process.env.OAUTH_CODE_REPLAY = "revke";
    expect(resolveCodeReplayMode()).toBe("log");
    expect(loggerMock.warn).toHaveBeenCalledWith(
      expect.stringContaining('OAUTH_CODE_REPLAY="revke"'),
    );
  });
});

describe("first redemption records the spent code (R1, R10)", () => {
  beforeEach(() => {
    oauthRepositoryMock.getAuthCode.mockResolvedValue(liveCodeRow());
  });

  it.each([
    ["the default (log) mode", undefined],
    ["revoke mode", "revoke"],
  ])(
    "records it through the pair's own transaction and family, in %s",
    async (_name, mode) => {
      if (mode) process.env.OAUTH_CODE_REPLAY = mode;

      const { res } = await postToken(exchangeBody());

      expect(res.statusCode).toBe(200);
      expect(oauthRepositoryMock.recordSpentCode).toHaveBeenCalledTimes(1);
      const [code, data, tx] =
        oauthRepositoryMock.recordSpentCode.mock.calls[0];
      const pairArgs = oauthRepositoryMock.setAccessToken.mock.calls[0];
      // Oracle: RFC 6749 section 4.1.2 can only be honoured if the code maps
      // to the tokens it produced, so the record names the pair's family.
      expect(code).toBe(CODE);
      expect(data).toEqual({
        family_id: pairArgs[1].family_id,
        client_id: CLIENT_ID,
        user_id: USER_ID,
        redirect_uri: REDIRECT,
        code_challenge: CHALLENGE,
        expires_at: new Date(
          NOW.getTime() + CODE_TTL_MS + SPENT_CODE_MARGIN_MS,
        ),
      });
      // Same transaction as the pair, and written after it: they commit
      // together or not at all.
      expect(tx).toBe(FAKE_OAUTH_TX);
      expect(pairArgs[2]).toBe(FAKE_OAUTH_TX);
      expect(
        oauthRepositoryMock.setAccessToken.mock.invocationCallOrder[0],
      ).toBeLessThan(
        oauthRepositoryMock.recordSpentCode.mock.invocationCallOrder[0],
      );
    },
  );

  it("fails the grant, and returns no pair, when the record cannot be written", async () => {
    // A missing table (a skipped migration) is the realistic cause. The grant
    // must fail loudly: a pair with no record is a session no replay could be
    // tied back to. The rejection rolls the consume back with it (pinned
    // against Postgres in the integration suite).
    oauthRepositoryMock.recordSpentCode.mockRejectedValue(
      Object.assign(
        new Error('relation "oauth_spent_authorization_codes" does not exist'),
        { code: "42P01" },
      ),
    );

    const { res, error } = await postToken(exchangeBody());

    expect(error).toBeInstanceOf(Error);
    // The terminal error handler answers an unrecognised error with a bare 500.
    expect(resolveErrorStatus(error)).toBe(500);
    expect(res.body).toBeUndefined();
    expect(loggerMock.info).not.toHaveBeenCalledWith(
      expect.stringContaining("[oauth] token issued"),
    );
    expect(rows.filter((row) => row.action === "oauth.token.issue")).toEqual(
      [],
    );
  });

  it("leaves a code alone when the verifier is wrong, and a later correct redemption works (R8)", async () => {
    // Characterization of the standing policy that a refused redemption does
    // not burn the code. Proven by the injected defect, not by red on parent.
    const refused = await postToken(
      exchangeBody({ code_verifier: "not-the-verifier" }),
    );
    expect(refused.res.statusCode).toBe(400);
    expect(oauthRepositoryMock.consumeAuthCode).not.toHaveBeenCalled();
    expect(oauthRepositoryMock.recordSpentCode).not.toHaveBeenCalled();

    const ok = await postToken(exchangeBody());
    expect(ok.res.statusCode).toBe(200);
    expect(oauthRepositoryMock.recordSpentCode).toHaveBeenCalledTimes(1);
  });
});

describe("a replay that proves possession is audited and, in revoke mode, revokes (R2, R2b)", () => {
  beforeEach(() => {
    armReplay();
    process.env.OAUTH_CODE_REPLAY = "revoke";
  });

  it("revokes the family, writes one audit row, and answers the unchanged invalid_grant", async () => {
    const { res } = await postToken(exchangeBody());

    // Oracle: RFC 6749 section 4.1.2 (deny, and revoke the tokens issued from
    // the code) and section 5.2 (the error is invalid_grant). The body is the
    // one an unknown code has always got, so a holder of a spent code cannot
    // tell detection from a plain miss.
    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual(LEGACY_REPLAY_BODY);

    expect(oauthRepositoryMock.withUserLock).toHaveBeenCalledTimes(1);
    expect(oauthRepositoryMock.withUserLock.mock.calls[0][0]).toBe(USER_ID);
    expect(oauthRepositoryMock.consumeSpentCode).toHaveBeenCalledTimes(1);
    expect(oauthRepositoryMock.consumeSpentCode).toHaveBeenCalledWith(
      CODE,
      FAKE_OAUTH_TX,
    );
    expect(oauthRepositoryMock.countFamilyAccessTokens).toHaveBeenCalledWith(
      FAMILY_ID,
      FAKE_OAUTH_TX,
    );
    expect(oauthRepositoryMock.revokeFamily).toHaveBeenCalledTimes(1);
    expect(oauthRepositoryMock.revokeFamily).toHaveBeenCalledWith(
      FAMILY_ID,
      FAKE_OAUTH_TX,
    );

    expect(reuseRows()).toHaveLength(1);
    expect(reuseRows()[0]).toMatchObject({
      action: "oauth.token.reuse",
      outcome: "denied",
      http_status: 400,
      actor_id: USER_ID,
      target_id: CLIENT_ID,
      detail: {
        reason: "authorization_code_reuse",
        token_type: "authorization_code",
        family_id: FAMILY_ID,
        mode: "revoke",
        tokens_live: 1,
        family_revoked: true,
        token_sha256: sha256(CODE),
      },
    });
  });

  it("never writes the plaintext code or verifier into an audit row or a log line", async () => {
    await postToken(exchangeBody());

    expect(auditText()).not.toContain(CODE);
    expect(auditText()).not.toContain(VERIFIER);
    expect(loggedText()).not.toContain(CODE);
    expect(loggedText()).not.toContain(VERIFIER);
  });

  it("records the audit row even when the revoke itself throws", async () => {
    // The row is emitted before the delete that destroys the family, so the
    // record survives the failure an operator would be investigating.
    oauthRepositoryMock.revokeFamily.mockRejectedValue(new Error("db down"));

    const { error } = await postToken(exchangeBody());

    expect(error).toBeInstanceOf(Error);
    expect(reuseRows()).toHaveLength(1);
  });

  it("revokes for a confidential client that presents the right secret", async () => {
    // Kills an implementation that refuses every confidential client.
    oauthRepositoryMock.getClient.mockResolvedValue(confidentialClient());

    const { res } = await postToken(exchangeBody({ client_secret: SECRET }));

    expect(res.body).toEqual(LEGACY_REPLAY_BODY);
    expect(oauthRepositoryMock.revokeFamily).toHaveBeenCalledTimes(1);
    expect(reuseRows()).toHaveLength(1);
  });

  it("reports no live tokens and no revoke when the family is already gone", async () => {
    // users.revokeAccess deletes a family's tokens but leaves the record. The
    // row must not claim a revoke that did nothing.
    oauthRepositoryMock.countFamilyAccessTokens.mockResolvedValue(0);

    await postToken(exchangeBody());

    expect(reuseRows()[0].detail).toMatchObject({
      tokens_live: 0,
      family_revoked: false,
    });
  });
});

describe("a presentation that does not prove possession changes nothing (R3, R4)", () => {
  beforeEach(() => {
    armReplay();
    process.env.OAUTH_CODE_REPLAY = "revoke";
  });

  // Characterization: these pass on the parent too (nothing happens there). They
  // are proven by the injected defect that drops each check.
  it.each([
    ["a wrong verifier", { code_verifier: "x".repeat(43) }],
    ["no verifier", { code_verifier: undefined }],
    ["a different client_id", { client_id: "mcp_client_other" }],
    ["a different redirect_uri", { redirect_uri: "https://claude.ai/other" }],
  ])(
    "%s gets the legacy answer, no revoke and no row",
    async (_name, overrides) => {
      // Oracle: RFC 6749 section 4.1.3 (the code is bound to its client and
      // redirect) and RFC 7636 section 4.6 (the verifier must hash to the
      // challenge). The narrowing of the section 4.1.2 SHOULD is a design
      // decision: without it a code seen in a redirect URL would be a way to end
      // someone's session.
      const { res } = await postToken(exchangeBody(overrides));

      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual(LEGACY_REPLAY_BODY);
      expectReplayIgnored();
    },
  );

  it.each([
    ["no secret", {}],
    ["the wrong secret", { client_secret: WRONG_SECRET }],
  ])(
    "a confidential client presenting %s gets the legacy answer, no revoke and no row",
    async (_name, extra) => {
      oauthRepositoryMock.getClient.mockResolvedValue(confidentialClient());

      const { res } = await postToken(exchangeBody(extra));

      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual(LEGACY_REPLAY_BODY);
      expectReplayIgnored();
    },
  );

  it("a code with no spent record writes nothing at all", async () => {
    oauthRepositoryMock.getSpentCode.mockResolvedValue(null);

    const { res } = await postToken(exchangeBody());

    expect(res.body).toEqual(LEGACY_REPLAY_BODY);
    expectReplayIgnored();
  });

  it("a client deleted since the redemption writes nothing", async () => {
    oauthRepositoryMock.getClient.mockResolvedValue(null);

    const { res } = await postToken(exchangeBody());

    expect(res.body).toEqual(LEGACY_REPLAY_BODY);
    expectReplayIgnored();
  });
});

describe("one compromised code produces one audit row (R5)", () => {
  it("a second validated replay finds the record consumed and acts on nothing", async () => {
    armReplay();
    process.env.OAUTH_CODE_REPLAY = "revoke";
    // Both replays read the record before either takes the lock; only the
    // first consume returns it.
    oauthRepositoryMock.consumeSpentCode
      .mockReset()
      .mockResolvedValueOnce(spentRow())
      .mockResolvedValue(null);

    const first = await postToken(exchangeBody());
    const second = await postToken(exchangeBody());

    expect(first.res.body).toEqual(LEGACY_REPLAY_BODY);
    expect(second.res.body).toEqual(LEGACY_REPLAY_BODY);
    expect(oauthRepositoryMock.consumeSpentCode).toHaveBeenCalledTimes(2);
    expect(oauthRepositoryMock.revokeFamily).toHaveBeenCalledTimes(1);
    expect(reuseRows()).toHaveLength(1);
  });
});

describe("a replay that lost the race for the live code (R6)", () => {
  beforeEach(() => {
    armReplay();
    // This request read the live code and passed every check; another request
    // consumed it first, so by the time the lock is granted the record exists.
    oauthRepositoryMock.getAuthCode.mockResolvedValue(liveCodeRow());
    oauthRepositoryMock.consumeAuthCode.mockResolvedValue(false);
    process.env.OAUTH_CODE_REPLAY = "revoke";
  });

  it("revokes the winner's family, audits once, and answers the bare invalid_grant", async () => {
    const { res } = await postToken(exchangeBody());

    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual(LEGACY_REPLAY_BODY);
    expect(oauthRepositoryMock.getSpentCode).toHaveBeenCalledWith(
      CODE,
      FAKE_OAUTH_TX,
    );
    expect(oauthRepositoryMock.revokeFamily).toHaveBeenCalledTimes(1);
    expect(oauthRepositoryMock.revokeFamily).toHaveBeenCalledWith(
      FAMILY_ID,
      FAKE_OAUTH_TX,
    );
    expect(reuseRows()).toHaveLength(1);
    // The loser mints nothing and records nothing.
    expect(oauthRepositoryMock.setAccessToken).not.toHaveBeenCalled();
    expect(oauthRepositoryMock.recordSpentCode).not.toHaveBeenCalled();
  });

  it("answers the plain refusal when the code vanished for another reason", async () => {
    // An administrator's revoke, a client delete or the reaper removed the code:
    // there is no record, so there is nothing to act on.
    oauthRepositoryMock.getSpentCode.mockResolvedValue(null);

    const { res } = await postToken(exchangeBody());

    expect(res.body).toEqual(LEGACY_REPLAY_BODY);
    expect(oauthRepositoryMock.revokeFamily).not.toHaveBeenCalled();
    expect(rows).toEqual([]);
  });
});

describe("the default mode audits without revoking (R7)", () => {
  beforeEach(() => {
    armReplay();
  });

  it("an unset OAUTH_CODE_REPLAY behaves as log: row written, record consumed, nothing revoked", async () => {
    delete process.env.OAUTH_CODE_REPLAY;

    const { res } = await postToken(exchangeBody());

    expect(res.body).toEqual(LEGACY_REPLAY_BODY);
    expect(oauthRepositoryMock.consumeSpentCode).toHaveBeenCalledTimes(1);
    expect(oauthRepositoryMock.revokeFamily).not.toHaveBeenCalled();
    expect(reuseRows()).toHaveLength(1);
    // tokens_live above zero is the baseline signal: a replay that, under
    // revoke, would have ended a live session.
    expect(reuseRows()[0].detail).toMatchObject({
      mode: "log",
      tokens_live: 1,
      family_revoked: false,
    });
  });

  it("an unrecognised value behaves as log and the warning names it", async () => {
    process.env.OAUTH_CODE_REPLAY = "revke";

    await postToken(exchangeBody());

    expect(oauthRepositoryMock.revokeFamily).not.toHaveBeenCalled();
    expect(reuseRows()[0].detail).toMatchObject({
      mode: "log",
      family_revoked: false,
    });
    expect(loggerMock.warn).toHaveBeenCalledWith(
      expect.stringContaining('OAUTH_CODE_REPLAY="revke"'),
    );
  });

  it("revoke revokes", async () => {
    process.env.OAUTH_CODE_REPLAY = "revoke";

    await postToken(exchangeBody());

    expect(oauthRepositoryMock.revokeFamily).toHaveBeenCalledTimes(1);
    expect(reuseRows()[0].detail).toMatchObject({
      mode: "revoke",
      family_revoked: true,
    });
  });
});

describe("OAUTH_CODE_REPLAY=off touches nothing (R11)", () => {
  beforeEach(() => {
    armReplay();
    process.env.OAUTH_CODE_REPLAY = "off";
  });

  function expectNoSpentCodeTraffic() {
    expect(oauthRepositoryMock.recordSpentCode).not.toHaveBeenCalled();
    expect(oauthRepositoryMock.getSpentCode).not.toHaveBeenCalled();
    expect(oauthRepositoryMock.consumeSpentCode).not.toHaveBeenCalled();
    expect(oauthRepositoryMock.countFamilyAccessTokens).not.toHaveBeenCalled();
    expect(oauthRepositoryMock.revokeFamily).not.toHaveBeenCalled();
    expect(rows.filter((row) => row.action === "oauth.token.reuse")).toEqual(
      [],
    );
  }

  it("a first redemption issues its pair and writes no record", async () => {
    oauthRepositoryMock.getAuthCode.mockResolvedValue(liveCodeRow());

    const { res } = await postToken(exchangeBody());

    expect(res.statusCode).toBe(200);
    expect(oauthRepositoryMock.setAccessToken).toHaveBeenCalledTimes(1);
    expectNoSpentCodeTraffic();
  });

  it("a sequential replay is the plain refusal and reads nothing", async () => {
    const { res } = await postToken(exchangeBody());

    expect(res.body).toEqual(LEGACY_REPLAY_BODY);
    expectNoSpentCodeTraffic();
  });

  it("a concurrent replay is the plain refusal and reads nothing", async () => {
    oauthRepositoryMock.getAuthCode.mockResolvedValue(liveCodeRow());
    oauthRepositoryMock.consumeAuthCode.mockResolvedValue(false);

    const { res } = await postToken(exchangeBody());

    expect(res.body).toEqual(LEGACY_REPLAY_BODY);
    expectNoSpentCodeTraffic();
  });
});
