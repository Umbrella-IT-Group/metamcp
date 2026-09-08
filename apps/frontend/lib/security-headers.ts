/**
 * The application-wide Content-Security-Policy for the Next.js pages.
 *
 * WHY THIS IS A MODULE AND NOT A LINE IN next.config.js. The policy has to be
 * strict on scripts (no `'unsafe-inline'`, no `'unsafe-eval'`) because the
 * authenticated UI transiently holds downstream MCP OAuth tokens in
 * sessionStorage, and an inline-script injection is exactly how those would be
 * read out. A static `headers()` entry in next.config cannot express that: the
 * app ships inline bootstrap scripts (Next's own hydration runtime, the
 * `next-runtime-env` beforeInteractive env script, and `next-themes`'
 * anti-flash script), so the only way to allow those specific scripts while
 * still banning arbitrary inline script is a per-request nonce. A nonce is not
 * a constant, so it cannot live in next.config; it is minted per request in
 * middleware.ts, the only layer that runs before the document is rendered. The
 * remaining, value-less headers (frame options, nosniff, referrer policy,
 * permissions policy) DO live in next.config `headers()` so they also cover
 * static assets. This module is the single source of truth for the policy
 * string so middleware and its test agree on exactly one thing.
 */

/**
 * The request header middleware stamps the per-request nonce onto. Next reads
 * the nonce out of the request's CSP header on its own to nonce the framework
 * scripts; this header is how the server components (the root layout) read the
 * same value to nonce the third-party inline scripts Next does not own.
 */
export const NONCE_HEADER = "x-nonce";

/**
 * Build the CSP for a document response, given the request's nonce.
 *
 * script-src is `'self'` plus the nonce and nothing else: no `'unsafe-inline'`
 * (that would defeat the whole control) and no `'unsafe-eval'` (production Next
 * needs neither). Every inline script the page emits carries the nonce, so
 * this bans injected inline script without breaking the app.
 *
 * style-src keeps `'unsafe-inline'` deliberately. The component layer (Radix
 * primitives, the toast library, the theme switch) sets inline `style="..."`
 * attributes at runtime, and a nonce cannot cover a style ATTRIBUTE, only a
 * `<style>` element, so the alternative to `'unsafe-inline'` here is a broken
 * layout, not a tighter policy. Style injection is not the credential-exfil
 * vector script injection is, which is why the script side is the one held
 * strict. A nonce next to `'unsafe-inline'` in style-src makes browsers ignore
 * `'unsafe-inline'`, so the two must not be combined.
 *
 * connect-src is `'self'`: every fetch, tRPC call and MCP inspector transport
 * goes to this same origin (the MCP proxy is reached at the app's own URL, not
 * the backend host directly). frame-ancestors and frame-src are `'none'`: the
 * app frames nothing and must not be framed. base-uri is `'self'`, object-src
 * is `'none'`.
 *
 * form-action is `'self'` plus whatever `options.formActionSources` adds, and
 * the ONE caller that adds anything is the middleware on the OAuth consent
 * document (lib/consent-form-action.ts). Chromium enforces form-action against
 * the redirect chain of a form submission, and the consent Approve's success
 * response is a 302 to the client's registered redirect_uri, so a bare `'self'`
 * made Chrome and Edge cancel that redirect after the code was already minted
 * (fork #150 regression, 2026-09-03 to 2026-09-08). The widening is exactly the
 * redirect target named in the request's own signed `areq`, nothing broader.
 *
 * script-src gains `'unsafe-eval'` OUTSIDE production only. `next dev`
 * (Turbopack, React Fast Refresh) evaluates modules with eval and cannot run
 * under a policy that forbids it, so a strict-in-every-env policy would break
 * local development. A production build never evals, so production keeps script
 * execution to `'self'` plus the per-request nonce with no eval escape. The
 * gate is read at call time so a test can pin either environment.
 */
export interface ContentSecurityPolicyOptions {
  /**
   * Extra `form-action` host-sources beyond `'self'`. Only the consent document
   * passes any (its redirect_uri origin, see lib/consent-form-action.ts); every
   * other document keeps `form-action 'self'`.
   */
  formActionSources?: readonly string[];
}

export function buildContentSecurityPolicy(
  nonce: string,
  options: ContentSecurityPolicyOptions = {},
): string {
  const devEval = process.env.NODE_ENV === "production" ? "" : " 'unsafe-eval'";
  const formAction = ["'self'", ...(options.formActionSources ?? [])].join(" ");
  return [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "frame-src 'none'",
    `form-action ${formAction}`,
    `script-src 'self' 'nonce-${nonce}'${devEval}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    "connect-src 'self'",
  ].join("; ");
}
