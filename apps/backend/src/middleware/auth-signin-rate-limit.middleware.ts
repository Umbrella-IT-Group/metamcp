import express from "express";

import { SIGN_IN_EMAIL_PATH } from "@/lib/audit/auth-relay-audit";
import { AuthRateLimiter } from "@/lib/auth-rate-limiter";
import { resolveClientIp } from "@/lib/client-ip";
import logger from "@/utils/logger";

/**
 * A per-caller cap on password sign-in attempts, which `/api/auth` had none of.
 *
 * WHY THIS SURFACE SPECIFICALLY. `routers/auth-relay.ts` hands `/api/auth/*`
 * straight to `auth.handler`, and better-auth's own limiter is pinned off in
 * `auth.ts` — deliberately, because its address resolution reads
 * `x-forwarded-for` only, and behind this deployment's proxy chain that header
 * carries more than one entry, so the address resolves to null and every caller
 * in the world lands in the literal bucket `no-trusted-ip`. Three sign-in
 * attempts per ten seconds SHARED GLOBALLY is not a brute-force control, it is
 * a lever any one caller can pull to lock everyone else out. Pinning it off was
 * correct and this is the other half: the per-caller-keyed limiter that pin's
 * comment names as the remedy.
 *
 * So until this middleware, `POST /api/auth/sign-in/email` was unbounded. Two
 * things follow from that, and the second is the one that is easy to miss.
 * Passwords could be guessed as fast as a client could send them; and every
 * refused attempt writes an `auth.login.failure` row through
 * `lib/audit/auth-relay-audit` into `audit_log`, which migration 0028 makes
 * append-only — no UPDATE, no DELETE, no TRUNCATE, and no prune path. An
 * unbounded sign-in path is therefore also an unbounded INSERT amplifier
 * against a table nothing can reclaim.
 *
 * KEYED ON CF-Connecting-IP through `lib/client-ip`, which is the same helper
 * the failed-auth limiter (`getAuthRateLimitIdentifier`), the registration
 * limiter (`routers/oauth/utils`) and the `/trpc` limiter all key on. `req.ip`
 * is deliberately NOT used: this fork leaves express `trust proxy` unset (see
 * `middleware/audit-context.middleware` for why), so behind the in-container
 * Next.js rewrite `req.ip` is the same loopback address for every human on
 * earth — the identical shared-bucket defect that made better-auth's own
 * limiter unusable here. Cloudflare OVERWRITES CF-Connecting-IP at the edge
 * rather than appending to it, so it is per-caller and not caller-forgeable
 * while the tunnel is the sole ingress.
 *
 * THE NO-HEADER CLASS IS EXEMPT, not collapsed into one shared "unknown"
 * bucket, and this is the decision most worth re-reading before changing it. A
 * request with no CF-Connecting-IP did not come through the tunnel: in
 * production that is in-container traffic, outside production it is local
 * development. Bucketing them together would hand every one of them a single
 * 20-per-10-minutes sign-in budget — which is precisely the global bucket this
 * middleware exists to avoid, rebuilt one layer down, and it would fail toward
 * an ORG-WIDE SIGN-IN OUTAGE the first time a deployment change stopped the
 * header arriving. The honest cost of exempting them: an attacker who reaches
 * the origin directly is not bounded by this. That attacker has already
 * defeated the ingress assumption every `actor_ip` in the audit archive rests
 * on, and re-opening a lockout of every administrator to cover a case that
 * already invalidates the trust model is the wrong trade. It is the same call,
 * for the same reason, as `middleware/trpc-rate-limit.middleware` and the
 * endpoint-probe limiter in `middleware/lookup-endpoint-middleware`.
 *
 * `getAuthRateLimitIdentifier` decides the OPPOSITE for its no-header class and
 * the divergence is deliberate: that limiter counts only FAILED credentials, so
 * a shared bucket there can inconvenience nobody except callers who are already
 * failing to authenticate. This one counts sign-in ATTEMPTS, successes
 * included, so a shared bucket here would refuse people who typed the right
 * password.
 *
 * SCOPE — ONE PATH, and every neighbour is excluded on purpose:
 *
 *  - `sign-in/social` and `sign-in/oauth2` do not carry a credential at all;
 *    a 200 from them means "here is the URL to redirect the browser to". They
 *    are the SSO entry point, and throttling them throttles logins that this
 *    server never verifies.
 *  - `callback/*` completes an SSO round trip the user is already mid-way
 *    through; refusing it strands them with no way forward but to restart.
 *  - `get-session` is read on essentially every page render, so any budget
 *    small enough to bound guessing would break the UI.
 *  - `sign-out` must never be refused: a user trying to end a session is the
 *    last request to answer with "try again later".
 *  - `/api/auth/register` is RFC 7591 dynamic client registration (the
 *    frontend rewrites `/register` onto it) and is already bounded by
 *    `rateLimitRegistration` in `routers/oauth/utils`. The loopback OAuth
 *    flow depends on it.
 *
 * `SIGN_IN_EMAIL_PATH` is imported rather than restated so this set cannot
 * drift from the one path where the HTTP status genuinely IS the credential
 * verdict — the same distinction `lib/audit/auth-relay-audit` already draws,
 * and it should stay drawn once.
 *
 * NO AUDIT ROW ON A 429, deliberately, and with a consequence worth stating.
 * Writing a row per refusal on the path whose append-only write volume is part
 * of what is being bounded moves the amplifier one layer up instead of closing
 * it. The consequence is that once a caller is refused, its attempts stop
 * producing `auth.login.failure` rows, so in `audit_log` alone a brute force
 * looks like it stopped. The throttled WARN below carries a running total so
 * that period is visible somewhere; an operator correlating a gap in login
 * failures with these lines is reading the same event from both ends.
 */

/** Sign-in attempts per window, per client IP. */
export const AUTH_SIGNIN_RATE_LIMIT_MAX_DEFAULT = 20;

/**
 * Above this a per-IP sign-in budget is not a limiter, and the honest way to
 * say "no limit" is the off switch below rather than a four-digit ceiling.
 */
export const AUTH_SIGNIN_RATE_LIMIT_MAX_CEILING = 1000;

/** Window length. Ten minutes, so 20 attempts is far above real human use. */
export const AUTH_SIGNIN_RATE_LIMIT_WINDOW_SECONDS_DEFAULT = 600;

/** A window longer than a day is a lockout, not a rate limit. */
export const AUTH_SIGNIN_RATE_LIMIT_WINDOW_SECONDS_CEILING = 24 * 60 * 60;

export const AUTH_SIGNIN_RATE_LIMIT_MAX_ENV = "AUTH_SIGNIN_RATE_LIMIT_MAX";
export const AUTH_SIGNIN_RATE_LIMIT_WINDOW_SECONDS_ENV =
  "AUTH_SIGNIN_RATE_LIMIT_WINDOW_SECONDS";
export const AUTH_SIGNIN_RATE_LIMIT_DISABLED_ENV =
  "AUTH_SIGNIN_RATE_LIMIT_DISABLED";

/**
 * Resolve the per-window attempt budget from a raw env value.
 *
 * Pure and exported so the clamp is testable without mounting express, the same
 * reason `lib/gateway-events/retention` and `lib/audit-storage/tripwire` export
 * theirs.
 *
 * An unparseable or under-range value falls back to the DEFAULT rather than
 * clamping to the floor. Clamping `AUTH_SIGNIN_RATE_LIMIT_MAX=0` up to 1 would
 * honour a typo as a one-attempt-per-window budget and lock out every
 * administrator; falling back keeps a mistyped setting from becoming an
 * outage, and turning the limiter off is what the off switch is for.
 */
export function resolveSigninRateLimitMax(raw: string | undefined): number {
  if (raw === undefined || raw.trim() === "") {
    return AUTH_SIGNIN_RATE_LIMIT_MAX_DEFAULT;
  }

  // Shape-checked BEFORE parsing, matching the retention and tripwire
  // resolvers. `Number.parseInt` is not a validator: it reads a leading integer
  // and discards the rest, so "20abc" becomes 20 and "1e9" becomes 1 — a typo
  // taking effect as a number nobody wrote.
  const parsed = /^-?\d+$/.test(raw.trim())
    ? Number.parseInt(raw, 10)
    : Number.NaN;

  if (!Number.isFinite(parsed)) {
    logger.warn(
      `[auth-signin] ${AUTH_SIGNIN_RATE_LIMIT_MAX_ENV}="${raw}" is not a number; using the ${AUTH_SIGNIN_RATE_LIMIT_MAX_DEFAULT}-attempt default`,
    );
    return AUTH_SIGNIN_RATE_LIMIT_MAX_DEFAULT;
  }

  if (parsed < 1) {
    logger.warn(
      `[auth-signin] ${AUTH_SIGNIN_RATE_LIMIT_MAX_ENV}=${parsed} would refuse every sign-in; using the ${AUTH_SIGNIN_RATE_LIMIT_MAX_DEFAULT}-attempt default instead. Set ${AUTH_SIGNIN_RATE_LIMIT_DISABLED_ENV}=true to turn the limiter off on purpose.`,
    );
    return AUTH_SIGNIN_RATE_LIMIT_MAX_DEFAULT;
  }

  if (parsed > AUTH_SIGNIN_RATE_LIMIT_MAX_CEILING) {
    logger.warn(
      `[auth-signin] ${AUTH_SIGNIN_RATE_LIMIT_MAX_ENV}=${parsed} is not a usable brute-force bound and has been capped to ${AUTH_SIGNIN_RATE_LIMIT_MAX_CEILING}. Set ${AUTH_SIGNIN_RATE_LIMIT_DISABLED_ENV}=true if the intent was to turn the limiter off.`,
    );
    return AUTH_SIGNIN_RATE_LIMIT_MAX_CEILING;
  }

  return parsed;
}

/**
 * Resolve the window length in seconds from a raw env value.
 *
 * Same fallback rule as the budget above: zero and negatives would expire the
 * fixed window on every request, i.e. silently remove the limit, so they fall
 * back to the default instead of being honoured.
 */
export function resolveSigninRateLimitWindowSeconds(
  raw: string | undefined,
): number {
  if (raw === undefined || raw.trim() === "") {
    return AUTH_SIGNIN_RATE_LIMIT_WINDOW_SECONDS_DEFAULT;
  }

  const parsed = /^-?\d+$/.test(raw.trim())
    ? Number.parseInt(raw, 10)
    : Number.NaN;

  if (!Number.isFinite(parsed)) {
    logger.warn(
      `[auth-signin] ${AUTH_SIGNIN_RATE_LIMIT_WINDOW_SECONDS_ENV}="${raw}" is not a number; using the ${AUTH_SIGNIN_RATE_LIMIT_WINDOW_SECONDS_DEFAULT}-second default`,
    );
    return AUTH_SIGNIN_RATE_LIMIT_WINDOW_SECONDS_DEFAULT;
  }

  if (parsed < 1) {
    logger.warn(
      `[auth-signin] ${AUTH_SIGNIN_RATE_LIMIT_WINDOW_SECONDS_ENV}=${parsed} would expire the window on every request and remove the limit; using the ${AUTH_SIGNIN_RATE_LIMIT_WINDOW_SECONDS_DEFAULT}-second default instead. Set ${AUTH_SIGNIN_RATE_LIMIT_DISABLED_ENV}=true to turn the limiter off on purpose.`,
    );
    return AUTH_SIGNIN_RATE_LIMIT_WINDOW_SECONDS_DEFAULT;
  }

  if (parsed > AUTH_SIGNIN_RATE_LIMIT_WINDOW_SECONDS_CEILING) {
    logger.warn(
      `[auth-signin] ${AUTH_SIGNIN_RATE_LIMIT_WINDOW_SECONDS_ENV}=${parsed} is longer than a day and has been capped to ${AUTH_SIGNIN_RATE_LIMIT_WINDOW_SECONDS_CEILING} seconds (24h), so a refused caller is never locked out for longer than that`,
    );
    return AUTH_SIGNIN_RATE_LIMIT_WINDOW_SECONDS_CEILING;
  }

  return parsed;
}

/**
 * Whether an operator has explicitly turned the limiter off.
 *
 * Phrased as DISABLED rather than ENABLED so that unset, empty and misspelled
 * all mean ON: a control that removes a brute-force bound must require someone
 * to say so, not merely to fail to say otherwise. Strict `"true"` for the same
 * reason `ALLOW_UNAUTHENTICATED_ENDPOINTS` is strict — `1`, `yes` and `TRUE`
 * are all still ON, because a security gate should not be openable by a
 * near-miss spelling.
 */
export function signinRateLimitDisabled(raw: string | undefined): boolean {
  return raw === "true";
}

export const AUTH_SIGNIN_RATE_LIMIT_MAX = resolveSigninRateLimitMax(
  process.env[AUTH_SIGNIN_RATE_LIMIT_MAX_ENV],
);

export const AUTH_SIGNIN_RATE_LIMIT_WINDOW_MS =
  resolveSigninRateLimitWindowSeconds(
    process.env[AUTH_SIGNIN_RATE_LIMIT_WINDOW_SECONDS_ENV],
  ) * 1000;

export const AUTH_SIGNIN_RATE_LIMIT_ENABLED = !signinRateLimitDisabled(
  process.env[AUTH_SIGNIN_RATE_LIMIT_DISABLED_ENV],
);

/**
 * `/api/auth/sign-up/email` carries a password too, and it is bounded here for
 * the same reason sign-in is. With self-registration disabled (this fork stores
 * `DISABLE_SIGNUP=true`) every POST to it is refused inside the better-auth
 * create hook, which writes a durable `audit_log` row via `emitSignupDenied`
 * (auth.ts, lib/audit/auth-hook-audit) — and migration 0028 makes `audit_log`
 * append-only with no prune path, so an unbounded sign-up POST is the same
 * INSERT amplifier ledger #126 closed for sign-in but left open here. It is
 * spelled out rather than imported from `lib/audit/auth-relay-audit` because
 * that module matches only the paths the relay itself audits; sign-up denial is
 * audited from the create hook, not the relay, so there is no relay answer to
 * stay in lockstep with here.
 */
const SIGN_UP_EMAIL_PATH = "/api/auth/sign-up/email";

/**
 * The `/api/auth` paths that carry a password and where this limiter must bound
 * the attempt rate. A Set rather than a single constant because better-auth
 * gains credential sub-paths over time (`sign-in/username` is one), and the
 * question "does this request try a password?" should have one answer here
 * rather than a growing chain of comparisons at the call site.
 *
 * `SIGN_IN_EMAIL_PATH` is the path where the HTTP status IS the credential
 * verdict; `SIGN_UP_EMAIL_PATH` is the account-creation twin above. Both share
 * one per-caller budget: a legitimate user drives one or the other, not both in
 * a burst, and sign-up is disabled anyway, so the shared bucket only ever costs
 * a determined caller and never a real one. The 429 copy stays sign-in framed
 * because that is the dominant human-facing path; a rate-limited sign-up is a
 * request that would have been refused regardless.
 */
export const CREDENTIAL_SIGN_IN_PATHS: ReadonlySet<string> = new Set([
  SIGN_IN_EMAIL_PATH,
  SIGN_UP_EMAIL_PATH,
]);

/**
 * Compare a request path against that set.
 *
 * THIS HAS TO NORMALISE THE WAY THE RELAY DOES, and that is the whole design
 * constraint. `routers/auth-relay` does not forward the raw path: it rebuilds
 * the request with `new URL(req.url, ...)` and hands better-auth
 * `url.pathname`. That is the WHATWG URL parser, which RESOLVES DOT SEGMENTS
 * and TREATS A BACKSLASH AS A SLASH. So a comparison here against the
 * unresolved `req.path` is a different question from the one the relay
 * answers, and every spelling where the two disagree is a bypass:
 * `POST /api/auth/x/../sign-in/email` and `POST /api/auth\sign-in/email` both
 * reach better-auth as `/api/auth/sign-in/email` while an unresolved match
 * sees a path that is not in the set and waves the attempt through — unbounded,
 * and unaudited too, because `lib/audit/auth-relay-audit` keys off the same
 * raw `req.path`. Resolving with the same parser the relay uses is what keeps
 * the two in step; a hand-rolled segment walker would have to re-derive
 * `%2e`, `.%2e` and backslash handling and would drift from it again.
 *
 * PARSE FIRST, COLLAPSE AFTER. That order is load-bearing, not stylistic. An
 * empty segment is not noise to the parser: `..` CONSUMES one, exactly as it
 * consumes a named segment. So collapsing runs of slashes BEFORE the parse
 * deletes a segment the relay's own resolution would still have been standing
 * on, and the two answers come apart — `/api/auth//../sign-in/email` reaches
 * better-auth as `/api/auth/sign-in/email`, while collapsing first leaves
 * `/api/auth/../sign-in/email`, which resolves to `/api/sign-in/email` and is
 * not in the set, so the attempt is waved through unbounded. Empty segments
 * paired with a dot segment are that whole class of spelling. Collapsing only
 * what the parser hands BACK cannot reopen it, because by then the dot
 * segments are already resolved away.
 *
 * What still has to run BEFORE the parse is only what makes the parse TOTAL:
 *
 *  - Tab, LF and CR are dropped because the URL parser drops them too, and it
 *    does so BEFORE parsing — so leaving them in lets `/<tab>/host` reach the
 *    parser as `//host`.
 *  - Backslashes fold to slashes because the parser reads them as slashes, so
 *    `/\` would otherwise reach it as `//`.
 *  - The LEADING run of slashes, and only the leading run, flattens to
 *    exactly one — prepended when the input carries none, so what reaches the
 *    parser is always an absolute path and never a relative reference.
 *
 * Together they guarantee the string handed to the parser begins with exactly
 * one slash and so cannot begin with `//`, which is what makes this call
 * TOTAL: a leading `//` is a protocol-relative URL, the parser reads what
 * follows as a HOST, and an empty or malformed one THROWS. On this path a
 * throw would be a 500 on the sign-in route, so the input is shaped such that
 * the parser stays in path state, which has no failure mode, rather than being
 * wrapped in a catch that would have to guess an answer. Flattening the
 * leading run is the one collapse that cannot lose a bypass, because a leading
 * empty segment has no `..` to its left that could have consumed it.
 *
 * OVER-MATCHING IS WHAT REMAINS, and it is the direction to prefer. Collapsing
 * after the parse means an interior `//` that the relay KEEPS — better-auth is
 * routed on `/api/auth//sign-in/email`, which is not the credential path — is
 * still counted here. That costs a rate-limit bucket entry and nothing else.
 * Under-matching is the failure that matters, because it is an unbounded
 * sign-in path and an unaudited one too: `lib/audit/auth-relay-audit` keys off
 * the resolved path this has to agree with. The comparison is case-insensitive
 * and drops a trailing slash for the same reason, neither of which the relay
 * does.
 */
export function isCredentialSignInRequest(
  method: string,
  path: string,
): boolean {
  if (method.toUpperCase() !== "POST") return false;
  const shaped =
    "/" +
    path
      .replace(/[\t\n\r]/g, "")
      .replace(/\\/g, "/")
      .replace(/^\/+/, "");
  // The origin is a throwaway: only `pathname` is read from it. It is here
  // because a path on its own is a relative reference and needs some base to
  // resolve against.
  const resolved = new URL(shaped, "http://localhost").pathname
    .replace(/\/{2,}/g, "/")
    .toLowerCase();
  const normalized =
    resolved.length > 1 && resolved.endsWith("/")
      ? resolved.slice(0, -1)
      : resolved;
  return CREDENTIAL_SIGN_IN_PATHS.has(normalized);
}

const signinRateLimiter = new AuthRateLimiter(
  AUTH_SIGNIN_RATE_LIMIT_MAX,
  AUTH_SIGNIN_RATE_LIMIT_WINDOW_MS,
);

// One Map entry per distinct client IP per window, so an address-rotating
// flood would otherwise leak memory for the life of the process. `unref`
// because a housekeeping sweep must never be the reason a test run or a
// shutdown hangs — this process's lifetime is owned by the HTTP server in
// `index.ts`. Same treatment, same reason, as the sibling sweeps in
// `lib/auth-rate-limiter` and `middleware/trpc-rate-limit.middleware`.
setInterval(() => signinRateLimiter.cleanup(), 10 * 60 * 1000).unref();

/** How long one reported refusal suppresses the next report. */
const REFUSAL_REPORT_INTERVAL_MS = 60 * 1000;

let refusalsTotal = 0;
let lastRefusalReportAt = 0;

/** Test seam: forget the counter and the throttle window. */
export function resetSigninRefusalReportingForTesting(): void {
  refusalsTotal = 0;
  lastRefusalReportAt = 0;
}

/**
 * Make a refusal detectable without re-creating the amplifier.
 *
 * Same shape and the same reasoning as `reportRefusal` in
 * `middleware/trpc-rate-limit.middleware`: the FIRST refusal reports
 * immediately because detection must not wait out a window, the count is a
 * RUNNING TOTAL since startup rather than a per-window delta (a delta is
 * stranded whenever the burst that produced it stops before the next report
 * fires), and it is WARN rather than ERROR because a refused request is this
 * control working.
 *
 * The IP is JSON-stringified rather than interpolated raw: it arrives as a
 * header value, and an embedded newline in an interpolated log line forges
 * whole log entries. Its length is already bounded where it is read
 * (`lib/client-ip`, AUDIT_IP_MAX), so it cannot pad the line either.
 */
function reportRefusal(clientIp: string): void {
  refusalsTotal += 1;
  const now = Date.now();
  // The `!== 0` half matters under a mocked clock: a suite that pins Date to
  // the epoch would otherwise have its very first refusal silently swallowed.
  if (
    lastRefusalReportAt !== 0 &&
    now - lastRefusalReportAt < REFUSAL_REPORT_INTERVAL_MS
  ) {
    return;
  }
  lastRefusalReportAt = now;
  logger.warn(
    `[auth-signin] rate limit refused ${JSON.stringify(clientIp)}, ` +
      `${refusalsTotal} sign-in attempt(s) refused since startup`,
  );
}

/**
 * Factory so a test can supply a small budget instead of driving 20 real
 * sign-ins through the middleware, and can exercise the off switch without
 * reloading the module.
 */
export function createAuthSigninRateLimitMiddleware(
  options: {
    limiter?: AuthRateLimiter;
    windowMs?: number;
    enabled?: boolean;
  } = {},
) {
  const limiter = options.limiter ?? signinRateLimiter;
  const windowMs = options.windowMs ?? AUTH_SIGNIN_RATE_LIMIT_WINDOW_MS;
  const enabled = options.enabled ?? AUTH_SIGNIN_RATE_LIMIT_ENABLED;

  return (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction,
  ) => {
    if (!enabled) {
      next();
      return;
    }

    if (!isCredentialSignInRequest(req.method, req.path)) {
      next();
      return;
    }

    const clientIp = resolveClientIp(req.headers);
    if (!clientIp) {
      next();
      return;
    }

    // `isRateLimited` counts the attempt AND answers in one call, which is what
    // makes the allowance exactly AUTH_SIGNIN_RATE_LIMIT_MAX: the Nth attempt
    // is served and the N+1th is refused. Calling `recordFailedAttempt` before
    // it would count twice and halve the budget silently — the defect the
    // failed-auth limiter carried. The `auth-signin:` prefix is descriptive
    // rather than load-bearing (this is its own AuthRateLimiter instance with
    // its own Map), kept so an identifier read out of a heap dump names where
    // it came from.
    if (limiter.isRateLimited(`auth-signin:${clientIp}`)) {
      // Retry-After is the window length rather than the exact remainder — the
      // limiter exposes no remainder, and an upper bound is the safe direction
      // to round for a client that honours it.
      res.set("Retry-After", String(Math.ceil(windowMs / 1000)));
      reportRefusal(clientIp);
      res.status(429).json({
        // `error` / `error_description` matches every other 429 this fork
        // answers. `message` is here as well because the better-auth client
        // surfaces exactly that field to the login form: without it a
        // rate-limited administrator sees the generic "sign in failed" copy
        // and keeps retrying, which is the worst outcome a limiter can produce.
        error: "too_many_requests",
        error_description: "Too many sign-in attempts. Please try again later.",
        message: "Too many sign-in attempts. Please try again later.",
      });
      return;
    }

    next();
  };
}

export const authSigninRateLimitMiddleware =
  createAuthSigninRateLimitMiddleware();
