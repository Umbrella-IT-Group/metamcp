/**
 * The `/api/auth` sign-in cap, and the four ways it could be wrong.
 *
 * It could fail to limit — `POST /api/auth/sign-in/email` had no limiter at
 * all, so passwords could be guessed as fast as a client could send them and
 * every refusal wrote an `auth.login.failure` row into an append-only table
 * with no prune path.
 *
 * It could limit the wrong CALLERS. Keying on `req.ip` would put every human
 * behind the in-container rewrite in one bucket, and bucketing the
 * no-CF-Connecting-IP class together would do the same thing one layer down —
 * either way the first caller to spend the budget locks the whole organisation
 * out of signing in, which is exactly why better-auth's own limiter is pinned
 * off in `auth.ts`.
 *
 * It could limit the wrong PATHS. SSO entry, SSO callbacks, session reads,
 * sign-out and dynamic client registration all live under the same `/api/auth`
 * prefix, and throttling any of them breaks a flow that carries no password.
 *
 * Or it could be written, exported and never MOUNTED, in which case every
 * assertion here still passes while nothing is limited at all. The last
 * describe reads `index.ts` to close that.
 */

import { readFileSync } from "node:fs";
import path from "node:path";

import express from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AuthRateLimiter } from "@/lib/auth-rate-limiter";

const { loggerMock } = vi.hoisted(() => ({
  loggerMock: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

// Imported dynamically, as in the sibling limiter suite, so the logger mock
// above is in place before the module under test resolves its own import of it
// — the env resolvers below warn through it.
const {
  AUTH_SIGNIN_RATE_LIMIT_MAX,
  AUTH_SIGNIN_RATE_LIMIT_MAX_CEILING,
  AUTH_SIGNIN_RATE_LIMIT_MAX_DEFAULT,
  AUTH_SIGNIN_RATE_LIMIT_WINDOW_MS,
  AUTH_SIGNIN_RATE_LIMIT_WINDOW_SECONDS_CEILING,
  AUTH_SIGNIN_RATE_LIMIT_WINDOW_SECONDS_DEFAULT,
  createAuthSigninRateLimitMiddleware,
  isCredentialSignInRequest,
  resetSigninRefusalReportingForTesting,
  resolveSigninRateLimitMax,
  resolveSigninRateLimitWindowSeconds,
  signinRateLimitDisabled,
} = await import("./auth-signin-rate-limit.middleware");

const SIGN_IN = "/api/auth/sign-in/email";

/** A caller as the middleware sees it: method, path and headers only. */
function request(fields: {
  clientIp?: string;
  path?: string;
  method?: string;
  ip?: string;
}): express.Request {
  return {
    method: fields.method ?? "POST",
    path: fields.path ?? SIGN_IN,
    headers:
      fields.clientIp === undefined
        ? {}
        : { "cf-connecting-ip": fields.clientIp },
    ip: fields.ip,
    socket: { remoteAddress: "127.0.0.1" },
  } as unknown as express.Request;
}

interface Result {
  passed: boolean;
  statusCode: number | undefined;
  body: Record<string, unknown> | undefined;
  headers: Record<string, string>;
}

function call(
  middleware: ReturnType<typeof createAuthSigninRateLimitMiddleware>,
  req: express.Request,
): Result {
  const result: Result = {
    passed: false,
    statusCode: undefined,
    body: undefined,
    headers: {},
  };
  const res = {
    status(code: number) {
      result.statusCode = code;
      return res;
    },
    json(payload: Record<string, unknown>) {
      result.body = payload;
      return res;
    },
    set(name: string, value: string) {
      result.headers[name] = value;
      return res;
    },
  };
  middleware(req, res as unknown as express.Response, () => {
    result.passed = true;
  });
  return result;
}

beforeEach(() => {
  vi.clearAllMocks();
  // The refusal reporter throttles to one line a minute PROCESS-WIDE, so
  // without this every case after the first would observe silence for the
  // wrong reason and assert nothing.
  resetSigninRefusalReportingForTesting();
});

describe("sign-in rate limit — refusing a guessing run", () => {
  it("serves exactly N attempts and refuses the N+1th", () => {
    // A small injected budget stands in for the shipped 20; driving 20 real
    // calls would test the loop, not the middleware. The exact boundary is the
    // assertion that matters — a limiter that both records and then checks
    // would silently serve two fewer.
    const middleware = createAuthSigninRateLimitMiddleware({
      limiter: new AuthRateLimiter(3, 60_000),
    });
    const guesser = () => request({ clientIp: "203.0.113.7" });

    expect(call(middleware, guesser()).passed).toBe(true);
    expect(call(middleware, guesser()).passed).toBe(true);
    expect(call(middleware, guesser()).passed).toBe(true);

    const refused = call(middleware, guesser());
    expect(refused.passed).toBe(false);
    expect(refused.statusCode).toBe(429);
    expect(refused.body).toMatchObject({ error: "too_many_requests" });
  });

  it("also caps the password-carrying sign-up POST", () => {
    // sign-up carries a password and, with signup disabled, each POST writes an
    // append-only audit_log row — the INSERT amplifier this bounds. Before it
    // joined the credential-path set, sign-up POSTs passed through uncapped.
    const middleware = createAuthSigninRateLimitMiddleware({
      limiter: new AuthRateLimiter(2, 60_000),
    });
    const signUp = () =>
      request({ clientIp: "203.0.113.9", path: "/api/auth/sign-up/email" });

    expect(call(middleware, signUp()).passed).toBe(true);
    expect(call(middleware, signUp()).passed).toBe(true);
    const refused = call(middleware, signUp());
    expect(refused.passed).toBe(false);
    expect(refused.statusCode).toBe(429);
  });

  it("shares one per-caller budget across sign-in and sign-up", () => {
    // One AuthRateLimiter instance keyed on the caller IP, so the two
    // password-carrying paths draw down the same bucket rather than two.
    const middleware = createAuthSigninRateLimitMiddleware({
      limiter: new AuthRateLimiter(2, 60_000),
    });
    const ip = "203.0.113.11";

    expect(
      call(middleware, request({ clientIp: ip, path: SIGN_IN })).passed,
    ).toBe(true);
    expect(
      call(
        middleware,
        request({ clientIp: ip, path: "/api/auth/sign-up/email" }),
      ).passed,
    ).toBe(true);
    const refused = call(middleware, request({ clientIp: ip, path: SIGN_IN }));
    expect(refused.passed).toBe(false);
    expect(refused.statusCode).toBe(429);
  });

  it("says something the login form can actually display", () => {
    // The better-auth client surfaces `message` to the page. Without it a
    // refused administrator sees the generic "sign in failed" copy and keeps
    // retrying — the worst outcome a limiter can produce.
    const middleware = createAuthSigninRateLimitMiddleware({
      limiter: new AuthRateLimiter(1, 60_000),
    });
    call(middleware, request({ clientIp: "203.0.113.7" }));

    const refused = call(middleware, request({ clientIp: "203.0.113.7" }));

    expect(refused.body?.message).toBe(
      "Too many sign-in attempts. Please try again later.",
    );
    expect(refused.body?.error_description).toBe(
      "Too many sign-in attempts. Please try again later.",
    );
  });

  it("tells a well-behaved client when to come back", () => {
    const middleware = createAuthSigninRateLimitMiddleware({
      limiter: new AuthRateLimiter(1, 60_000),
      windowMs: 60_000,
    });
    call(middleware, request({ clientIp: "203.0.113.7" }));

    const refused = call(middleware, request({ clientIp: "203.0.113.7" }));

    expect(refused.headers["Retry-After"]).toBe("60");
  });

  it("lets the caller back in once the window rolls over", () => {
    vi.useFakeTimers();
    try {
      const middleware = createAuthSigninRateLimitMiddleware({
        limiter: new AuthRateLimiter(1, 60_000),
      });
      const caller = () => request({ clientIp: "203.0.113.7" });

      expect(call(middleware, caller()).passed).toBe(true);
      expect(call(middleware, caller()).passed).toBe(false);

      vi.advanceTimersByTime(60_001);

      // A fixed window, so the budget comes back whole rather than trickling.
      expect(call(middleware, caller()).passed).toBe(true);
      expect(call(middleware, caller()).passed).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps refusing for the rest of the window, not only once", () => {
    const middleware = createAuthSigninRateLimitMiddleware({
      limiter: new AuthRateLimiter(1, 60_000),
    });
    const caller = () => request({ clientIp: "203.0.113.7" });
    call(middleware, caller());

    for (let i = 0; i < 5; i += 1) {
      expect(call(middleware, caller()).statusCode).toBe(429);
    }
  });
});

describe("sign-in rate limit — NOT locking out the organisation", () => {
  it("gives each client IP its own budget", () => {
    const middleware = createAuthSigninRateLimitMiddleware({
      limiter: new AuthRateLimiter(2, 60_000),
    });

    call(middleware, request({ clientIp: "203.0.113.7" }));
    call(middleware, request({ clientIp: "203.0.113.7" }));
    expect(call(middleware, request({ clientIp: "203.0.113.7" })).passed).toBe(
      false,
    );

    // A different administrator, mid-guessing-run, is unaffected.
    expect(call(middleware, request({ clientIp: "198.51.100.4" })).passed).toBe(
      true,
    );
  });

  it("ignores req.ip entirely — that key is the shared-bucket trap", () => {
    const middleware = createAuthSigninRateLimitMiddleware({
      limiter: new AuthRateLimiter(1, 60_000),
    });

    // Same loopback `req.ip` for both, as the in-container rewrite actually
    // presents them; only CF-Connecting-IP differs. Keyed on req.ip the second
    // caller would be refused for the first one's attempt.
    call(middleware, request({ clientIp: "203.0.113.7", ip: "127.0.0.1" }));

    expect(
      call(middleware, request({ clientIp: "198.51.100.4", ip: "127.0.0.1" }))
        .passed,
    ).toBe(true);
  });

  it("exempts the no-CF-IP class rather than collapsing it into one bucket", () => {
    // Direct-to-origin and local development have no CF-Connecting-IP. One
    // shared "unknown" key would let any of them refuse sign-in for all the
    // others — the org-wide lockout this keying exists to avoid.
    const middleware = createAuthSigninRateLimitMiddleware({
      limiter: new AuthRateLimiter(1, 60_000),
    });

    for (let i = 0; i < 25; i += 1) {
      expect(call(middleware, request({ ip: "127.0.0.1" })).passed).toBe(true);
    }
  });

  it("sets the shipped budget above any real human sign-in rate", () => {
    // 20 per ten minutes per caller IP. Sessions last 30 days, so a person
    // signs in rarely; a limiter that trips on normal use is one someone
    // deletes.
    expect(AUTH_SIGNIN_RATE_LIMIT_MAX).toBe(20);
    expect(AUTH_SIGNIN_RATE_LIMIT_WINDOW_MS).toBe(600_000);
  });

  it("passes everything through when explicitly disabled", () => {
    const middleware = createAuthSigninRateLimitMiddleware({
      limiter: new AuthRateLimiter(1, 60_000),
      enabled: false,
    });

    for (let i = 0; i < 25; i += 1) {
      expect(
        call(middleware, request({ clientIp: "203.0.113.7" })).passed,
      ).toBe(true);
    }
    expect(loggerMock.warn).not.toHaveBeenCalled();
  });
});

/**
 * Everything else under `/api/auth` carries no password, and several of those
 * paths are load-bearing for flows that must not be refused: the SSO entry
 * point and its callback, the session read every page render makes, sign-out,
 * and the dynamic client registration the loopback OAuth pairing depends on.
 *
 * Each case below exhausts the sign-in budget FIRST, so a middleware that
 * matched on the `/api/auth` prefix instead of the one credential path would
 * refuse them and fail here.
 */
describe("sign-in rate limit — the paths it must not touch", () => {
  const untouched = [
    ["SSO entry", "POST", "/api/auth/sign-in/social"],
    ["SSO entry (generic oauth2)", "POST", "/api/auth/sign-in/oauth2"],
    ["SSO callback", "GET", "/api/auth/callback/oidc"],
    ["session read", "GET", "/api/auth/get-session"],
    ["sign-out", "POST", "/api/auth/sign-out"],
    ["dynamic client registration", "POST", "/api/auth/register"],
    ["a GET on the sign-up path", "GET", "/api/auth/sign-up/email"],
    ["a GET on the sign-in path itself", "GET", SIGN_IN],
    ["a neighbouring router", "POST", "/oauth/token"],
  ] as const;

  it.each(untouched)("leaves %s alone", (_name, method, requestPath) => {
    const middleware = createAuthSigninRateLimitMiddleware({
      limiter: new AuthRateLimiter(1, 60_000),
    });
    const clientIp = "203.0.113.7";

    // Spend the whole sign-in budget for this caller.
    call(middleware, request({ clientIp }));
    expect(call(middleware, request({ clientIp })).statusCode).toBe(429);

    for (let i = 0; i < 5; i += 1) {
      expect(
        call(middleware, request({ clientIp, method, path: requestPath }))
          .passed,
      ).toBe(true);
    }
  });
});

/**
 * Under-matching the path is a bypass; over-matching costs a map entry on a
 * request this server answers with a 404. These pin the safe direction.
 */
describe("sign-in rate limit — path matching", () => {
  it("matches the credential sign-in POST and nothing adjacent", () => {
    expect(isCredentialSignInRequest("POST", SIGN_IN)).toBe(true);
    expect(isCredentialSignInRequest("GET", SIGN_IN)).toBe(false);
    expect(isCredentialSignInRequest("POST", "/api/auth/sign-in/social")).toBe(
      false,
    );
    expect(isCredentialSignInRequest("POST", "/api/auth/sign-in")).toBe(false);
    expect(
      isCredentialSignInRequest("POST", "/api/auth/sign-in/email/extra"),
    ).toBe(false);
    expect(isCredentialSignInRequest("POST", "/sign-in/email")).toBe(false);
  });

  it("matches the password-carrying sign-up POST as well", () => {
    // sign-up/email is now a credential path too; a GET (no password) and the
    // adjacent spellings are not, on the same over/under-match rules as sign-in.
    expect(isCredentialSignInRequest("POST", "/api/auth/sign-up/email")).toBe(
      true,
    );
    expect(isCredentialSignInRequest("GET", "/api/auth/sign-up/email")).toBe(
      false,
    );
    expect(isCredentialSignInRequest("POST", "/api/auth/sign-up")).toBe(false);
    // Dodged by neither a respelling nor a backslash the relay resolves.
    expect(
      isCredentialSignInRequest("POST", "/api/auth/x/../sign-up/email"),
    ).toBe(true);
    expect(isCredentialSignInRequest("POST", "/api/auth\\sign-up/email")).toBe(
      true,
    );
  });

  it("cannot be dodged by respelling the path", () => {
    expect(isCredentialSignInRequest("post", SIGN_IN)).toBe(true);
    expect(isCredentialSignInRequest("POST", `${SIGN_IN}/`)).toBe(true);
    expect(isCredentialSignInRequest("POST", "/api//auth/sign-in/email")).toBe(
      true,
    );
    expect(isCredentialSignInRequest("POST", "/API/AUTH/Sign-In/Email")).toBe(
      true,
    );
  });

  /**
   * Every spelling here is one the RELAY resolves to the credential path, so
   * matching it is not over-matching — it is the only way the limiter and
   * `routers/auth-relay` answer the same question. The relay rebuilds the
   * request with `new URL(req.url, ...)`, and that parser resolves dot
   * segments (percent-encoded ones included) and reads a backslash as a
   * slash, so each of these arrives at better-auth as
   * `/api/auth/sign-in/email`. Before the normaliser resolved them the same
   * way, each was an unbounded and unaudited sign-in path.
   *
   * The EMPTY-SEGMENT spellings below are the ones a list of dot segments
   * alone will not catch, and they are why this list is worth extending rather
   * than trusting: `..` consumes an empty segment exactly as it consumes a
   * named one, so any normaliser that squeezes `//` down to `/` before
   * resolving has already thrown away the segment the relay is standing on.
   */
  it("cannot be dodged by dot segments the relay resolves away", () => {
    const dodges = [
      "/api/auth/x/../sign-in/email",
      "/api/auth/./sign-in/email",
      "/api/auth/x/%2e%2e/sign-in/email",
      "/api/auth/x/%2E%2E/sign-in/email",
      "/api/auth/%2e/sign-in/email",
      "/api/auth/x/.%2e/sign-in/email",
      "/api/auth/x/y/../../sign-in/email",
      "/api/auth//../sign-in/email",
      "/api/auth//%2e%2e/sign-in/email",
      "/api/auth///../../sign-in/email",
      "/api/auth/x//../../sign-in/email",
    ];
    for (const path of dodges) {
      expect(
        new URL(path, "http://localhost").pathname,
        `${path} is only worth matching because the relay resolves it`,
      ).toBe(SIGN_IN);
      expect(isCredentialSignInRequest("POST", path), path).toBe(true);
    }
  });

  it("cannot be dodged by a backslash the relay reads as a slash", () => {
    const dodges = [
      "/api/auth\\sign-in/email",
      "/api/auth/sign-in\\email",
      "/api/auth/x/..\\sign-in/email",
      "/api\\auth\\sign-in\\email",
      // Backslash AND an empty segment in one spelling. The backslash folds to
      // a slash before the parse, so these carry the same empty segment the
      // dot-segment list covers and are the members of this class that a
      // collapse-before-parse normaliser waves through.
      "/api/auth//..\\sign-in/email",
      "/api/auth//%2e%2e\\sign-in/email",
    ];
    for (const path of dodges) {
      expect(
        new URL(path, "http://localhost").pathname,
        `${path} is only worth matching because the relay resolves it`,
      ).toBe(SIGN_IN);
      expect(isCredentialSignInRequest("POST", path), path).toBe(true);
    }
  });

  /**
   * The normaliser resolves the path with the WHATWG URL parser, which THROWS
   * on a protocol-relative input with an empty or malformed host. This runs
   * ahead of the relay on every request, so a throw would be a 500 — and on
   * `POST /\` a 500 in place of the 404 the route answers today. The rewrites
   * that make a leading `//` unreachable are what prevent it; these are the
   * shapes that would reach the authority state without them.
   */
  it("answers rather than throwing on a path that is not a URL", () => {
    const hostile = [
      "/\\",
      "/\\evil",
      "/\\?x",
      "/\t/e]",
      "/\t\\",
      "//",
      "///",
      "/api/auth/sign-in/email%",
      "/api/auth/sign-in/email%zz",
      "/api/auth/sign-in/em ail",
      "",
      "/",
    ];
    for (const path of hostile) {
      expect(() => isCredentialSignInRequest("POST", path), path).not.toThrow();
    }
  });

  it("refuses a respelled path through the middleware too", () => {
    const middleware = createAuthSigninRateLimitMiddleware({
      limiter: new AuthRateLimiter(1, 60_000),
    });
    const clientIp = "203.0.113.7";

    call(middleware, request({ clientIp }));

    // Same bucket as the canonical spelling, so a variant cannot buy a fresh
    // budget.
    expect(
      call(middleware, request({ clientIp, path: `${SIGN_IN}/` })).statusCode,
    ).toBe(429);
  });

  it("refuses a dot-segment dodge through the middleware too", () => {
    const middleware = createAuthSigninRateLimitMiddleware({
      limiter: new AuthRateLimiter(1, 60_000),
    });
    const clientIp = "203.0.113.7";

    // Spend the budget on the canonical spelling...
    call(middleware, request({ clientIp }));

    // ...and the traversal spelling lands in the SAME bucket rather than
    // buying a fresh one, which is what "the limiter and the relay agree"
    // has to mean at the middleware boundary and not only in the matcher.
    expect(
      call(
        middleware,
        request({ clientIp, path: "/api/auth/x/../sign-in/email" }),
      ).statusCode,
    ).toBe(429);

    // The empty-segment spelling of the same dodge, through the middleware
    // rather than the matcher, because this is the one the matcher answered
    // wrongly while every assertion above it still passed.
    expect(
      call(
        middleware,
        request({ clientIp, path: "/api/auth//../sign-in/email" }),
      ).statusCode,
    ).toBe(429);
  });
});

describe("sign-in rate limit — env tuning", () => {
  it("uses the shipped defaults when nothing is set", () => {
    expect(resolveSigninRateLimitMax(undefined)).toBe(
      AUTH_SIGNIN_RATE_LIMIT_MAX_DEFAULT,
    );
    expect(resolveSigninRateLimitMax("  ")).toBe(
      AUTH_SIGNIN_RATE_LIMIT_MAX_DEFAULT,
    );
    expect(resolveSigninRateLimitWindowSeconds(undefined)).toBe(
      AUTH_SIGNIN_RATE_LIMIT_WINDOW_SECONDS_DEFAULT,
    );
    expect(loggerMock.warn).not.toHaveBeenCalled();
  });

  it("honours a value an operator actually set", () => {
    expect(resolveSigninRateLimitMax("5")).toBe(5);
    expect(resolveSigninRateLimitWindowSeconds("120")).toBe(120);
    expect(loggerMock.warn).not.toHaveBeenCalled();
  });

  it("takes a tuned budget through to the middleware's behaviour", () => {
    // The parse is only worth anything if the number reaches the limiter, so
    // this drives the resolved value end to end rather than asserting on it.
    const middleware = createAuthSigninRateLimitMiddleware({
      limiter: new AuthRateLimiter(
        resolveSigninRateLimitMax("2"),
        resolveSigninRateLimitWindowSeconds("30") * 1000,
      ),
      windowMs: resolveSigninRateLimitWindowSeconds("30") * 1000,
    });
    const caller = () => request({ clientIp: "203.0.113.7" });

    expect(call(middleware, caller()).passed).toBe(true);
    expect(call(middleware, caller()).passed).toBe(true);

    const refused = call(middleware, caller());
    expect(refused.statusCode).toBe(429);
    expect(refused.headers["Retry-After"]).toBe("30");
  });

  it("falls back rather than honouring a typo that would lock everyone out", () => {
    // `Number.parseInt` is not a validator: unguarded, "20abc" would take
    // effect as 20 and "1e9" as 1.
    expect(resolveSigninRateLimitMax("20abc")).toBe(
      AUTH_SIGNIN_RATE_LIMIT_MAX_DEFAULT,
    );
    expect(resolveSigninRateLimitMax("1e9")).toBe(
      AUTH_SIGNIN_RATE_LIMIT_MAX_DEFAULT,
    );
    // Zero and negatives would refuse every sign-in; clamping them to 1 would
    // honour the typo as a one-attempt budget, so they fall back instead.
    expect(resolveSigninRateLimitMax("0")).toBe(
      AUTH_SIGNIN_RATE_LIMIT_MAX_DEFAULT,
    );
    expect(resolveSigninRateLimitMax("-5")).toBe(
      AUTH_SIGNIN_RATE_LIMIT_MAX_DEFAULT,
    );
    // A zero-length window expires on every request, i.e. removes the limit
    // silently — the one failure a limiter must never have.
    expect(resolveSigninRateLimitWindowSeconds("0")).toBe(
      AUTH_SIGNIN_RATE_LIMIT_WINDOW_SECONDS_DEFAULT,
    );
    expect(resolveSigninRateLimitWindowSeconds("not-a-number")).toBe(
      AUTH_SIGNIN_RATE_LIMIT_WINDOW_SECONDS_DEFAULT,
    );

    // Six warnings, one per rejected value: a setting that did not take effect
    // has to say so at boot or it is indistinguishable from one that did.
    expect(loggerMock.warn).toHaveBeenCalledTimes(6);
  });

  it("caps a value so large it is not a limit, and says the off switch exists", () => {
    expect(resolveSigninRateLimitMax("100000")).toBe(
      AUTH_SIGNIN_RATE_LIMIT_MAX_CEILING,
    );
    expect(resolveSigninRateLimitWindowSeconds("999999")).toBe(
      AUTH_SIGNIN_RATE_LIMIT_WINDOW_SECONDS_CEILING,
    );
    expect(loggerMock.warn.mock.calls[0]?.[0]).toContain(
      "AUTH_SIGNIN_RATE_LIMIT_DISABLED=true",
    );
  });

  it("opens the off switch only for the exact word", () => {
    // A gate that removes a brute-force bound must require someone to say so,
    // not merely to fail to say otherwise.
    expect(signinRateLimitDisabled("true")).toBe(true);
    expect(signinRateLimitDisabled(undefined)).toBe(false);
    expect(signinRateLimitDisabled("")).toBe(false);
    expect(signinRateLimitDisabled("TRUE")).toBe(false);
    expect(signinRateLimitDisabled("1")).toBe(false);
    expect(signinRateLimitDisabled("yes")).toBe(false);
  });
});

/**
 * A 429 writes no audit row on purpose — a row per refusal on the path whose
 * append-only write volume is part of what is being bounded moves the
 * amplifier one layer up. That makes the log the only place a guessing run
 * surfaces once the limiter has tripped, so these pin that it does surface,
 * and as one line rather than as the flood itself.
 */
describe("sign-in rate limit — a refusal is visible to an operator", () => {
  it("says nothing while attempts are being served", () => {
    const middleware = createAuthSigninRateLimitMiddleware({
      limiter: new AuthRateLimiter(2, 60_000),
    });

    call(middleware, request({ clientIp: "203.0.113.7" }));
    call(middleware, request({ clientIp: "203.0.113.7" }));

    expect(loggerMock.warn).not.toHaveBeenCalled();
  });

  it("warns on the FIRST refusal, naming the caller and the count", () => {
    const middleware = createAuthSigninRateLimitMiddleware({
      limiter: new AuthRateLimiter(1, 60_000),
    });
    call(middleware, request({ clientIp: "203.0.113.7" }));

    call(middleware, request({ clientIp: "203.0.113.7" }));

    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(loggerMock.warn.mock.calls[0]?.[0]).toContain(
      "1 sign-in attempt(s) refused",
    );
    expect(loggerMock.warn.mock.calls[0]?.[0]).toContain('"203.0.113.7"');
    // WARN and nothing louder: a refused attempt is this control working, and
    // an alert that pages on the control working is one someone turns off.
    expect(loggerMock.error).not.toHaveBeenCalled();
  });

  it("throttles a run to ONE line, then carries the FULL total forward", () => {
    // Only Date is faked; nothing here awaits a timer.
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      // An hour-long limiter window, far longer than the one-minute report
      // throttle, so advancing past the throttle does not also refill the
      // budget and turn the next call into a pass.
      const middleware = createAuthSigninRateLimitMiddleware({
        limiter: new AuthRateLimiter(1, 60 * 60_000),
      });
      const guesser = () => request({ clientIp: "203.0.113.7" });
      call(middleware, guesser());

      for (let i = 0; i < 50; i += 1) {
        expect(call(middleware, guesser()).statusCode).toBe(429);
      }

      expect(loggerMock.warn).toHaveBeenCalledTimes(1);

      vi.setSystemTime(Date.now() + 61_000);
      call(middleware, guesser());

      expect(loggerMock.warn).toHaveBeenCalledTimes(2);
      // 51, not 1. A per-window delta would have stranded the 50 the first
      // line could not carry, and stranded loss is silent loss.
      expect(loggerMock.warn.mock.calls[1]?.[0]).toContain(
        "51 sign-in attempt(s) refused",
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("cannot have a log line forged through the IP it names", () => {
    // The key is a header value. Interpolated raw, an embedded newline writes
    // whole log entries of the attacker's choosing.
    const middleware = createAuthSigninRateLimitMiddleware({
      limiter: new AuthRateLimiter(1, 60_000),
    });
    const forged = "203.0.113.7\n2026-01-01 INFO all clear";
    call(middleware, request({ clientIp: forged }));

    call(middleware, request({ clientIp: forged }));

    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(loggerMock.warn.mock.calls[0]?.[0]).not.toContain("\n");
  });
});

/**
 * The module-scope cleanup sweep must not own the process's lifetime.
 *
 * A timer that is not `unref`'d keeps the event loop alive for anything that
 * merely IMPORTS the module — a test run, a CLI script, a shutdown waiting for
 * the loop to drain — and it does so with no visible cause. The HTTP server in
 * `index.ts` is what keeps this service running; nothing here should.
 */
describe("sign-in rate limit — the sweep registered at import time", () => {
  it("unrefs every interval it registers", async () => {
    const unref = vi.fn();
    const setIntervalSpy = vi.fn((_handler: () => void, _ms?: number) => ({
      unref,
    }));
    vi.stubGlobal("setInterval", setIntervalSpy);
    vi.resetModules();

    try {
      await import("./auth-signin-rate-limit.middleware");

      // The spy firing at all is what keeps this from passing vacuously if the
      // sweep is ever moved out of module scope. `lib/auth-rate-limiter`
      // registers its own on the same import chain, so this asserts the
      // property over every call rather than a fixed count.
      expect(setIntervalSpy.mock.calls.length).toBeGreaterThan(0);
      for (const [, ms] of setIntervalSpy.mock.calls) {
        expect(ms).toBe(10 * 60 * 1000);
      }
      expect(unref).toHaveBeenCalledTimes(setIntervalSpy.mock.calls.length);
    } finally {
      vi.unstubAllGlobals();
      vi.resetModules();
    }
  });
});

/**
 * The limiter is MOUNTED, and mounted where the comments say it is.
 *
 * Everything above calls the middleware directly, so `index.ts` could drop
 * `app.use(authSigninRateLimitMiddleware)` and this whole suite would stay
 * green and typecheck-clean while `/api/auth/sign-in/email` went back to being
 * unbounded.
 *
 * Read from SOURCE rather than driven over a socket because importing
 * `index.ts` calls `app.listen()` and initialises the pool at module scope.
 * Same technique, and the same reason, as the mount guard at the end of
 * `trpc-rate-limit.middleware.test.ts`. What it proves is the wiring and its
 * ORDER; the behaviour is proved by the cases above.
 */
describe("sign-in rate limit — mounted on the app", () => {
  const INDEX_SOURCE = readFileSync(
    path.resolve(import.meta.dirname, "../index.ts"),
    "utf8",
  );

  it("finds the file it is meant to be guarding", () => {
    // A moved file or a renamed app would otherwise make every assertion below
    // pass without checking anything.
    expect(INDEX_SOURCE).toContain("const app = express()");
    expect(INDEX_SOURCE).toContain(
      "middleware/auth-signin-rate-limit.middleware",
    );
  });

  it("mounts the middleware on the app", () => {
    expect(INDEX_SOURCE).toMatch(
      /app\.use\(\s*authSigninRateLimitMiddleware\s*\)/,
    );
  });

  it("mounts it after the /api/auth CORS policy and before the relay", () => {
    const cors = INDEX_SOURCE.search(/app\.use\(\s*authApiCorsMiddleware\s*\)/);
    const limiter = INDEX_SOURCE.search(
      /app\.use\(\s*authSigninRateLimitMiddleware\s*\)/,
    );
    const relay = INDEX_SOURCE.search(/app\.use\(\s*authApiRelay\s*\)/);

    expect(cors).toBeGreaterThan(-1);
    expect(relay).toBeGreaterThan(-1);
    // AFTER cors: a 429 has to carry the headers a browser needs to surface it
    // as a 429 rather than as an opaque network failure.
    expect(limiter).toBeGreaterThan(cors);
    // BEFORE the relay: a request refused after `auth.handler` has run has
    // already spent the password check and written the append-only
    // `auth.login.failure` row this limiter exists to bound.
    expect(limiter).toBeLessThan(relay);
  });
});
