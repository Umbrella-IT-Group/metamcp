/**
 * `GET /oauth/userinfo` is the second half of the token-metadata plane the
 * introspect tests in `token.test.ts` cover.
 *
 * It reads the access-token row and nothing else, so before `users.disabled`
 * (migration 0027) was checked here a locked-out account's outstanding token —
 * 24h TTL in this fork — kept answering with that account's identity claims to
 * whoever held it. The properties pinned below are that a disabled account
 * gets the handler's existing invalid-token 401 with NO claims in the body,
 * that the token row survives (disable is reversible; Revoke is what deletes),
 * and that an enabled account is unaffected.
 *
 * Driven directly as express middleware against fake req/res objects, the same
 * way `token.test.ts` drives the token router: no supertest, and no DB —
 * mocking the repository module keeps `db/index.ts`, which throws without
 * DATABASE_URL, out of the import graph.
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
  getAccessToken: vi.fn(),
  deleteAccessToken: vi.fn(),
};

const usersRepositoryMock = {
  isDisabled: vi.fn(),
};

vi.mock("../../db/repositories", () => ({
  oauthRepository: oauthRepositoryMock,
  usersRepository: usersRepositoryMock,
}));

const { default: userinfoRouter } = await import("./userinfo");

const USER_ID = "user-abc123";
const SCOPE = "admin";
const ACCESS_TOKEN = "mcp_token_userinfotest";

interface FakeRes {
  statusCode: number;
  body: Record<string, unknown> | undefined;
  settled: Promise<void>;
  status(code: number): FakeRes;
  json(payload: Record<string, unknown>): FakeRes;
}

function makeRes(): FakeRes {
  let settle: () => void;
  const settled = new Promise<void>((resolve) => {
    settle = resolve;
  });

  const res: FakeRes = {
    statusCode: 200,
    body: undefined,
    status(code) {
      res.statusCode = code;
      return res;
    },
    json(payload) {
      res.body = payload;
      settle();
      return res;
    },
    settled,
  };

  return res;
}

async function getUserinfo(authorization?: string): Promise<FakeRes> {
  const req = {
    method: "GET",
    url: "/oauth/userinfo",
    originalUrl: "/oauth/userinfo",
    baseUrl: "",
    headers: authorization ? { authorization } : {},
  } as unknown as express.Request;
  const res = makeRes();

  await new Promise<void>((resolve, reject) => {
    (userinfoRouter as unknown as express.RequestHandler)(
      req,
      res as unknown as express.Response,
      (err?: unknown) => (err ? reject(err) : resolve()),
    );
    res.settled.then(resolve);
  });

  return res;
}

const bearer = () => getUserinfo(`Bearer ${ACCESS_TOKEN}`);

beforeEach(() => {
  vi.clearAllMocks();
  oauthRepositoryMock.deleteAccessToken.mockResolvedValue(undefined);
  oauthRepositoryMock.getAccessToken.mockResolvedValue({
    access_token: ACCESS_TOKEN,
    client_id: "mcp_client_test",
    user_id: USER_ID,
    scope: SCOPE,
    expires_at: new Date(Date.now() + 60 * 60 * 1000),
    created_at: new Date(Date.now() - 60 * 1000),
  });
  // Default: the account is live, so a disabled test that forgot to arm its
  // own answer fails OPEN and its own assertion catches it.
  usersRepositoryMock.isDisabled.mockResolvedValue(false);
});

describe("GET /oauth/userinfo — disabled accounts get no claims", () => {
  it("answers 401 for a disabled account's still-valid token", async () => {
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    const res = await bearer();

    expect(res.statusCode).toBe(401);
    expect(usersRepositoryMock.isDisabled).toHaveBeenCalledWith(USER_ID);
  });

  it("returns no identity claim of any kind in that 401", async () => {
    // The body is the point, not just the status: sub, email, username and
    // scope are exactly what this endpoint exists to hand out.
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    const res = await bearer();

    expect(Object.keys(res.body ?? {}).sort()).toEqual([
      "error",
      "error_description",
    ]);
    expect(JSON.stringify(res.body)).not.toContain(USER_ID);
  });

  it("is indistinguishable from an unknown token", async () => {
    // A disabled account must not be identifiable by its error text.
    usersRepositoryMock.isDisabled.mockResolvedValue(true);
    const disabledRes = await bearer();

    usersRepositoryMock.isDisabled.mockResolvedValue(false);
    oauthRepositoryMock.getAccessToken.mockResolvedValue(null);
    const unknownRes = await bearer();

    expect(disabledRes.statusCode).toBe(unknownRes.statusCode);
    expect(disabledRes.body).toEqual(unknownRes.body);
  });

  it("leaves the token row in place", async () => {
    // Contrast the expired branch, which deletes. Disable is a reversible
    // lockout; deleting here would make it outlive Enable.
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    await bearer();

    expect(oauthRepositoryMock.deleteAccessToken).not.toHaveBeenCalled();
  });

  it("logs reason=disabled without echoing the token", async () => {
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    await bearer();

    const logged = [
      ...loggerMock.debug.mock.calls,
      ...loggerMock.info.mock.calls,
      ...loggerMock.warn.mock.calls,
      ...loggerMock.error.mock.calls,
    ]
      .flat()
      .map((arg) => (typeof arg === "string" ? arg : JSON.stringify(arg)))
      .join("\n");

    expect(logged).toContain("reason=disabled");
    expect(logged).toContain(`user=${USER_ID}`);
    expect(logged).not.toContain(ACCESS_TOKEN);
  });

  it("still serves claims for an ENABLED account (regression guard)", async () => {
    // A check that refused everyone would satisfy every assertion above.
    const res = await bearer();

    expect(res.statusCode).toBe(200);
    expect(res.body).toMatchObject({ sub: USER_ID, scope: SCOPE });
  });

  it("does not consult the account before the token itself is valid", async () => {
    // Order proof: an unknown token is answered from the token row alone, so
    // an anonymous prober cannot make this endpoint query the users table.
    oauthRepositoryMock.getAccessToken.mockResolvedValue(null);

    const res = await bearer();

    expect(res.statusCode).toBe(401);
    expect(usersRepositoryMock.isDisabled).not.toHaveBeenCalled();
  });
});
