import { getAppUrl } from "./env";

/**
 * Reduce a caller-supplied `callbackUrl` to a safe SAME-ORIGIN relative path,
 * falling back to `fallback` ("/") for anything else.
 *
 * `callbackUrl` comes off the query string, which an attacker controls in a
 * crafted link. The login page navigates to it after a successful sign-in
 * (router.push, and better-auth's own callbackURL) and the cors-error page
 * builds a redirect from it. Without this a value like "//evil.com",
 * "@evil.com" or "https://evil" would land an already-authenticated user on an
 * attacker origin: an open redirect / phishing aid.
 *
 * A value is accepted only when ALL of these hold, checked cheapest first:
 *   - it begins with a single "/" — a relative path, not a scheme
 *     ("javascript:", "https://evil") or a bare host ("@evil.com",
 *     ".evil.com"), none of which start with "/";
 *   - it does not begin with "//" — a protocol-relative URL resolves to
 *     another host;
 *   - it contains no backslash — browsers treat "\" as "/", so "/\evil.com"
 *     would resolve to another host;
 *   - parsed against the app origin it resolves back to that SAME origin, so
 *     any authority a path still manages to smuggle is caught by the URL
 *     parser rather than by trying to pattern-match every trick.
 *
 * The returned value is the resolved path plus any query and hash the caller
 * supplied, all guaranteed same-origin by the check above.
 */
export function toSafeInternalPath(
  value: string | null | undefined,
  fallback = "/",
): string {
  if (!value) return fallback;
  if (!value.startsWith("/")) return fallback;
  if (value.startsWith("//")) return fallback;
  if (value.includes("\\")) return fallback;

  let appUrl: string;
  try {
    appUrl = getAppUrl();
  } catch {
    // No configured origin to validate against — refuse rather than guess.
    return fallback;
  }

  try {
    const appOrigin = new URL(appUrl).origin;
    const target = new URL(value, appUrl);
    if (target.origin !== appOrigin) return fallback;
    return target.pathname + target.search + target.hash;
  } catch {
    return fallback;
  }
}
