import type { CorsOptions } from "cors";
import cors from "cors";
import express from "express";

/**
 * The origin allowlist every CREDENTIALED CORS surface on this gateway shares,
 * plus the `/api/auth` policy built on top of it.
 *
 * Two `cors()` shorthands must never appear on a route that answers to a
 * session cookie. `origin: "*"` emits the literal wildcard, which browsers
 * refuse to pair with credentials at all — so it is a policy that says
 * "anyone" while delivering nothing, and it hides the fact that no deliberate
 * policy was ever chosen. `origin: true` is worse: it reflects whatever
 * `Origin` the caller sent, so `Access-Control-Allow-Origin` becomes
 * attacker-controlled and, with `Access-Control-Allow-Credentials: true`
 * beside it, any site the victim visits can read a cookie-authenticated
 * response. Routes that need credentials call in here instead and get back a
 * specific, known origin or no `Access-Control-Allow-Origin` at all.
 *
 * The allowlist inputs deliberately mirror the ones better-auth's own
 * `trustedOrigins` is built from in ../auth (`APP_URL` plus the comma-separated
 * `EXTRA_TRUSTED_ORIGINS`) rather than importing that module: `auth.ts`
 * constructs the drizzle adapter at import time and throws without a database,
 * and a CORS decision must not be able to drag postgres into a router's import
 * graph.
 */

/**
 * Hostnames that mean "the browser's own machine". `URL.hostname` keeps the
 * brackets on an IPv6 literal, so the bracketed form is what actually matches;
 * the bare one is listed for anyone reading the set.
 */
const LOOPBACK_HOSTNAMES = new Set([
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "[::1]",
  "::1",
]);

/**
 * Reduce an origin-ish string to its canonical `scheme://host[:port]` form, or
 * null if it is not a parseable absolute URL.
 *
 * Everything downstream compares and ECHOES this normalised value rather than
 * the caller's bytes, so a header that differs only in case or trailing slash
 * still matches, and nothing the caller wrote is ever copied into a response
 * header verbatim.
 */
function normalizeOrigin(value: string | undefined): string | null {
  if (!value) return null;
  try {
    return new URL(value.trim()).origin;
  } catch {
    return null;
  }
}

function isLoopbackOrigin(origin: string): boolean {
  try {
    return LOOPBACK_HOSTNAMES.has(new URL(origin).hostname);
  } catch {
    return false;
  }
}

/**
 * The allowlisted form of `origin`, or null if it is not trusted.
 *
 * Env is read per call rather than captured at module load so the allowlist a
 * request is judged against is the one the process is configured with now —
 * and so a test can set `APP_URL` without controlling import order.
 */
export function resolveTrustedOrigin(
  origin: string | undefined,
): string | null {
  const candidate = normalizeOrigin(origin);
  if (!candidate) return null;

  const appOrigin = normalizeOrigin(process.env.APP_URL);
  if (appOrigin && candidate === appOrigin) return candidate;

  for (const extra of (process.env.EXTRA_TRUSTED_ORIGINS ?? "").split(",")) {
    if (normalizeOrigin(extra) === candidate) return candidate;
  }

  // Loopback is trusted only when the deployment ITSELF is loopback, i.e. a
  // developer running the stack on their own machine. On a deployed gateway
  // `APP_URL` is the public hostname, and there a blanket `http://localhost:*`
  // allowance would let any web server running on a victim's machine read
  // their authenticated responses — the same cross-site read this module
  // exists to prevent, wearing a friendlier hostname.
  if (appOrigin && isLoopbackOrigin(appOrigin) && isLoopbackOrigin(candidate)) {
    return candidate;
  }

  return null;
}

/**
 * `cors()` origin resolver for credentialed routes.
 *
 * Handing `false` to the callback is how the cors package is told to emit NO
 * `Access-Control-Allow-Origin`; it then calls `next()` and the route's own
 * authentication still decides the request. An untrusted caller therefore gets
 * a normal response with no CORS grant on it, which is what makes the browser
 * withhold it — not an error page that would leak whether the path exists.
 */
export const credentialedCorsOrigin: CorsOptions["origin"] = (
  requestOrigin,
  callback,
) => {
  callback(null, resolveTrustedOrigin(requestOrigin) ?? false);
};

/**
 * Response headers whose value is a CORS GRANT rather than payload.
 *
 * Used by the `/api/auth` relay in ../index to filter the header set it copies
 * out of better-auth's `Response`: the policy on that route is decided here,
 * and nothing downstream may overwrite it.
 */
export function isCorsResponseHeader(name: string): boolean {
  return name.toLowerCase().startsWith("access-control-");
}

/**
 * The `/api/auth` CORS policy.
 *
 * That route relays to better-auth, which answers with the session cookie and
 * with session contents — the exact response a cross-site read must not reach.
 * better-auth sets no `Access-Control-*` headers of its own, so without a
 * policy here the route had whatever an earlier-mounted router happened to
 * leave on the response.
 */
const authApiCors = cors({
  origin: credentialedCorsOrigin,
  credentials: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
});

/**
 * Mounted immediately ahead of the `/api/auth` relay in ../index.
 *
 * Clearing the two headers first is the belt to the path guard in
 * ../routers/oauth: `authApiCors` sets no `Access-Control-Allow-Origin` for an
 * untrusted origin, so anything an earlier router already wrote would survive
 * as this route's answer. Clearing makes "not trusted" mean no grant, whatever
 * ran before.
 */
export const authApiCorsMiddleware = (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) => {
  if (!req.path.startsWith("/api/auth")) return next();

  res.removeHeader("Access-Control-Allow-Origin");
  res.removeHeader("Access-Control-Allow-Credentials");

  return authApiCors(req, res, next);
};
