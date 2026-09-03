/**
 * Two at-rest / cookie-scope settings on the configured better-auth instance.
 *
 * Both are single config flags whose effect lives inside better-auth, so
 * rather than stand up a real instance and a database this reaches into
 * `auth.options` — the exact object better-auth consumes — the same seam
 * `auth-disabled-login.test.ts` uses for the disabled-account hook. Flipping
 * either flag back fails here.
 *
 *  - `account.encryptOAuthTokens` must be on, so the provider tokens stored for
 *    SSO accounts are encrypted at rest instead of written in plaintext.
 *  - `advanced.crossSubDomainCookies.enabled` must be off, so the session
 *    cookie is host-only. With it on, better-auth 1.6.23 sets the cookie Domain
 *    to the APP_URL hostname and the session is sent to every subdomain of the
 *    gateway host; the frontend proxies the backend on localhost in one
 *    container, so nothing needs it shared.
 */

import { describe, expect, it, vi } from "vitest";

vi.mock("./db/repositories/users.repo", () => ({
  usersRepository: { isDisabled: vi.fn() },
}));

// db/index builds a live pg Pool at import; the drizzle adapter only needs an
// object to hold on to, since no query runs in this file.
vi.mock("./db/index", () => ({ db: {}, pool: {} }));

vi.mock("./lib/config.service", () => ({
  configService: {
    isSignupDisabled: vi.fn().mockResolvedValue(false),
    isSsoSignupDisabled: vi.fn().mockResolvedValue(false),
    isBasicAuthDisabled: vi.fn().mockResolvedValue(false),
  },
}));

vi.mock("./utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// better-auth throws at module load without these.
process.env.BETTER_AUTH_SECRET ??= "test-secret-not-a-real-key";
process.env.APP_URL ??= "http://localhost:12008";

type AuthOptionsShape = {
  account?: { encryptOAuthTokens?: boolean };
  advanced?: { crossSubDomainCookies?: { enabled?: boolean } };
};

async function getAuthOptions(): Promise<AuthOptionsShape> {
  const { auth } = await import("./auth");
  return auth.options as unknown as AuthOptionsShape;
}

describe("better-auth hardening configuration", () => {
  it("encrypts stored OAuth provider tokens", async () => {
    const options = await getAuthOptions();
    expect(options.account?.encryptOAuthTokens).toBe(true);
  });

  it("keeps the session cookie host-only", async () => {
    const options = await getAuthOptions();
    expect(options.advanced?.crossSubDomainCookies?.enabled).toBe(false);
  });
});
