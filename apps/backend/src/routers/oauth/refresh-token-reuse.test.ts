/**
 * Refresh-token family reuse detection at the token endpoint (migration 0037).
 *
 * Refresh tokens rotate on every use, so the legitimate client always holds
 * exactly one live refresh token per family. A presented refresh token that is
 * NOT live but WAS rotated out of a family is reuse: either a stolen token the
 * thief rotated, or a legitimate client a step behind. Both are handled the
 * same safe way — the whole family is revoked — because they are
 * indistinguishable at the wire and leaving the live chain running is the
 * failure that matters.
 *
 * Three properties are pinned here, plus the negatives that keep them honest:
 *
 *  1. NORMAL ROTATION is untouched: a live refresh token still mints a new pair,
 *     the outgoing token is recorded as rotated, and the new pair INHERITS the
 *     family so the chain stays one family.
 *  2. REUSE of a rotated-out token revokes the family and refuses the grant, and
 *     the still-live token in that family is dead afterwards (its family_id was
 *     the one revoked).
 *  3. An UNRELATED token — never issued, never rotated — is refused WITHOUT
 *     revoking anything, and reuse revokes ONLY the compromised family.
 *
 * The reuse refusal is byte-identical to the unknown-token refusal, so a holder
 * of a stolen token cannot tell detection from a plain miss. The audit row for
 * reuse carries the token as a fingerprint only, never the credential.
 *
 * Same harness as token.test.ts / token-audit.test.ts: the router is driven as
 * express middleware against fake req/res, the repository is mocked so
 * db/index.ts never loads, and the audit sink is captured in-process.
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
  // The three migration-0037 methods under test.
  recordRotatedRefreshToken: vi.fn(),
  getRotatedRefreshToken: vi.fn(),
  revokeFamily: vi.fn(),
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
const { setAuditSinkForTesting } = await import("@/lib/audit/audit-emitter");

const CLIENT_ID = "mcp_client_test";
const USER_ID = "user-abc123";
const SCOPE = "mcp";
const FAMILY_ID = "f1111111-1111-1111-1111-111111111111";
// The stored hash of the live refresh token, as getByRefreshToken returns it
// (migration 0036 hashes refresh tokens at rest). The rotation path passes this
// value straight to recordRotatedRefreshToken rather than re-hashing it.
const STORED_REFRESH_HASH = "a".repeat(64);

type AuditRow = {
  action: string;
  outcome: string;
  actor_type: string;
  actor_id?: string | null;
  target_id?: string | null;
  detail?: Record<string, unknown>;
};

let rows: AuditRow[];

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));
const serialized = () => JSON.stringify(rows);
const sha256 = (value: string) =>
  createHash("sha256").update(value).digest("hex");

let ipCounter = 0;

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

async function postRefresh(refreshToken: string): Promise<FakeRes> {
  ipCounter += 1;
  const req = {
    method: "POST",
    url: "/oauth/token",
    originalUrl: "/oauth/token",
    baseUrl: "",
    body: {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
    },
    auditRequestId: "req-reuse-under-test",
    auditClientIp: "203.0.113.9",
    headers: { "user-agent": "Claude/1.0" },
    ip: `10.4.0.${ipCounter}`,
    socket: { remoteAddress: `10.4.0.${ipCounter}` },
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
  return res;
}

function liveRow() {
  return {
    access_token: "stored-access-hash",
    access_token_last4: "0000",
    refresh_token: STORED_REFRESH_HASH,
    client_id: CLIENT_ID,
    user_id: USER_ID,
    scope: SCOPE,
    expires_at: new Date(Date.now() + 60 * 1000),
    refresh_token_expires_at: new Date(Date.now() + 365 * 24 * 3600 * 1000),
    family_id: FAMILY_ID,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  rows = [];
  setAuditSinkForTesting(async (event) => {
    rows.push(event as AuditRow);
  });
  oauthRepositoryMock.setAccessToken.mockResolvedValue(undefined);
  oauthRepositoryMock.deleteAccessTokenByHash.mockResolvedValue(undefined);
  oauthRepositoryMock.recordRotatedRefreshToken.mockResolvedValue(undefined);
  oauthRepositoryMock.revokeFamily.mockResolvedValue(0);
  usersRepositoryMock.isDisabled.mockResolvedValue(false);
});

afterEach(() => {
  setAuditSinkForTesting(undefined);
});

describe("refresh_token grant — normal rotation is untouched (migration 0037)", () => {
  beforeEach(() => {
    oauthRepositoryMock.getByRefreshToken.mockResolvedValue(liveRow());
  });

  it("records the outgoing refresh token as rotated, keyed on the stored hash", async () => {
    await postRefresh("mcp_refresh_livetoken0000");

    expect(oauthRepositoryMock.recordRotatedRefreshToken).toHaveBeenCalledTimes(
      1,
    );
    expect(oauthRepositoryMock.recordRotatedRefreshToken).toHaveBeenCalledWith({
      // The stored digest is passed straight through, not re-hashed.
      refreshTokenHash: STORED_REFRESH_HASH,
      familyId: FAMILY_ID,
      clientId: CLIENT_ID,
      userId: USER_ID,
      expiresAt: expect.any(Date),
    });
  });

  it("mints a new pair whose family INHERITS the rotated row's family", async () => {
    const res = await postRefresh("mcp_refresh_livetoken0000");

    expect(res.statusCode).toBe(200);
    expect(res.body?.access_token).toMatch(/^mcp_token_/);
    expect(res.body?.refresh_token).toMatch(/^mcp_refresh_/);
    // issueTokenPair threads the inherited family into setAccessToken.
    expect(oauthRepositoryMock.setAccessToken).toHaveBeenCalledTimes(1);
    const [, data] = oauthRepositoryMock.setAccessToken.mock.calls[0];
    expect(data.family_id).toBe(FAMILY_ID);
  });

  it("never consults the reuse table and never revokes on a live token", async () => {
    await postRefresh("mcp_refresh_livetoken0000");

    expect(oauthRepositoryMock.getRotatedRefreshToken).not.toHaveBeenCalled();
    expect(oauthRepositoryMock.revokeFamily).not.toHaveBeenCalled();
  });
});

describe("refresh_token grant — reuse of a rotated-out token revokes the family", () => {
  beforeEach(() => {
    // Not a live token any more...
    oauthRepositoryMock.getByRefreshToken.mockResolvedValue(null);
    // ...but it was rotated out of this family.
    oauthRepositoryMock.getRotatedRefreshToken.mockResolvedValue({
      family_id: FAMILY_ID,
      client_id: CLIENT_ID,
      user_id: USER_ID,
    });
    oauthRepositoryMock.revokeFamily.mockResolvedValue(2);
  });

  it("revokes exactly the compromised family and refuses invalid_grant", async () => {
    const res = await postRefresh("mcp_refresh_stolen0000");

    expect(oauthRepositoryMock.revokeFamily).toHaveBeenCalledTimes(1);
    expect(oauthRepositoryMock.revokeFamily).toHaveBeenCalledWith(FAMILY_ID);
    // The still-live token in that family dies with it: revokeFamily was called
    // with the family that the live token also belongs to, and no NEW pair was
    // minted on this path.
    expect(oauthRepositoryMock.setAccessToken).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
    expect(res.body).toMatchObject({
      error: "invalid_grant",
      error_description: "Invalid refresh token",
    });
  });

  it("emits a denied reuse audit row with the family and a fingerprint, no secret", async () => {
    const reused = "mcp_refresh_stolen0000";
    await postRefresh(reused);
    await flush();

    const reuseRows = rows.filter((r) => r.action === "oauth.token.reuse");
    expect(reuseRows).toHaveLength(1);
    const [row] = reuseRows;
    expect(row.outcome).toBe("denied");
    expect(row.actor_id).toBe(USER_ID);
    expect(row.target_id).toBe(CLIENT_ID);
    expect(row.detail?.reason).toBe("refresh_token_reuse");
    expect(row.detail?.family_id).toBe(FAMILY_ID);
    // The reused token appears only as its sha256 + last-4 fingerprint.
    expect(row.detail?.token_sha256).toBe(sha256(reused));
    expect(serialized()).not.toContain(reused);
  });

  it("logs the revoked-token count for the operator without echoing the token", async () => {
    const reused = "mcp_refresh_stolen0000";
    await postRefresh(reused);

    const warned = loggerMock.warn.mock.calls.map((c) => String(c[0])).join("");
    expect(warned).toContain("refresh token reuse detected");
    expect(warned).toContain("tokens_revoked=2");
    expect(warned).not.toContain(reused);
  });
});

describe("refresh_token grant — an unrelated token revokes nothing", () => {
  beforeEach(() => {
    // Never a live token, never rotated out of any family.
    oauthRepositoryMock.getByRefreshToken.mockResolvedValue(null);
    oauthRepositoryMock.getRotatedRefreshToken.mockResolvedValue(null);
  });

  it("refuses invalid_grant without revoking any family or emitting a reuse row", async () => {
    const res = await postRefresh("mcp_refresh_neverissued");
    await flush();

    expect(oauthRepositoryMock.revokeFamily).not.toHaveBeenCalled();
    expect(rows.filter((r) => r.action === "oauth.token.reuse")).toHaveLength(
      0,
    );
    expect(res.statusCode).toBe(400);
    expect(res.body).toMatchObject({
      error: "invalid_grant",
      error_description: "Invalid refresh token",
    });
  });

  it("is byte-identical to the reuse refusal, so detection is not observable", async () => {
    const unknown = await postRefresh("mcp_refresh_neverissued");

    // Re-arm as reuse and compare the wire responses.
    oauthRepositoryMock.getRotatedRefreshToken.mockResolvedValue({
      family_id: FAMILY_ID,
      client_id: CLIENT_ID,
      user_id: USER_ID,
    });
    const reuse = await postRefresh("mcp_refresh_stolen0000");

    expect(reuse.statusCode).toBe(unknown.statusCode);
    expect(reuse.body).toEqual(unknown.body);
  });
});
