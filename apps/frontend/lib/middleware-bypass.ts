/**
 * The set of URL prefixes the Next middleware does not run on, and the single
 * source of truth for both the middleware body and its config.matcher.
 *
 * WHY SEGMENT-BOUNDARY MATCHING AND NOT A BARE `startsWith`. Each entry names a
 * ROUTE SEGMENT that belongs to something other than a localized page: a
 * framework internal (`/_next`), a backend route that next.config.js rewrites
 * to the API server (`/oauth`, `/trpc`, `/metamcp`, ...), or the M365 broker.
 * A bare prefix check (`pathname.startsWith("/oauth")`) also swallows any page
 * whose route merely BEGINS with one of those words. That is not hypothetical:
 * the fork's OAuth Clients admin page lives at `/[locale]/oauth-clients`, and
 * for the default locale the sidebar links to the locale-less `/oauth-clients`.
 * Under bare-prefix matching that path starts with `/oauth`, so the middleware
 * never ran, the locale redirect that would rewrite it to `/en/oauth-clients`
 * never fired, and Next has no locale-less route for it, so it 404'd on a hard
 * load. Matching on a segment boundary (the path IS the prefix, or continues
 * with `/`) keeps the backend `/oauth/authorize` and `/oauth/token` routes
 * bypassed while letting `/oauth-clients` route like any other page.
 */
export const MIDDLEWARE_BYPASS_PREFIXES = [
  "/_next",
  "/trpc",
  "/mcp-proxy",
  "/metamcp",
  "/oauth",
  "/.well-known",
  "/service",
  "/health",
  "/fe-oauth",
  // Umbrella fork: M365 broker routes live on the backend behind a
  // next.config.js rewrite; without this skip the i18n branch 307s
  // /m365/* to /en/m365/* before the rewrite runs (Entra redirects
  // to the EXACT registered callback URI, so that redirect breaks
  // enrollment).
  "/m365",
] as const;

/**
 * True when the middleware should skip this pathname entirely (static files and
 * the backend/framework routes above). Keep this in lockstep with the matcher
 * in middleware.ts: the matcher decides whether Next invokes the middleware at
 * all, and this function is the in-body early return; middleware-bypass.test.ts
 * asserts the two never drift apart.
 */
export function shouldBypassMiddleware(pathname: string): boolean {
  // /api/ is already slash-terminated: it names the API namespace, never a bare
  // /api page, so it keeps its trailing-slash form rather than a === /api match.
  if (pathname.startsWith("/api/")) {
    return true;
  }

  // Static files: any path carrying a dot (favicon.ico, *.js, *.png, ...).
  if (pathname.includes(".")) {
    return true;
  }

  return MIDDLEWARE_BYPASS_PREFIXES.some(
    (prefix) => pathname === prefix || pathname.startsWith(prefix + "/"),
  );
}
