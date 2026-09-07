import { randomBytes } from "crypto";
import type express from "express";

/**
 * HTML-escape a value before it is interpolated into the page below.
 *
 * A local copy rather than an import of routers/m365.ts's identical helper:
 * the two routers are kept independent (importing across them to save five
 * lines couples the OAuth surface to the M365 broker's module graph), and the
 * escaper is small enough that the duplication is cheaper than the coupling.
 * Every dynamic value on this page — the authorization code and the full
 * callback URL — MUST pass through this: the page is reachable at the end of a
 * consent flow whose redirect_uri, though registered, is still attacker-chosen
 * for a self-registered client, so an unescaped interpolation would be XSS.
 */
export function escapeHtml(value: unknown): string {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Render and send the loopback consent success page (HTTP 200).
 *
 * The root fix for headless MCP OAuth. A loopback redirect_uri (RFC 8252 §7.3,
 * `http://127.0.0.1:<ephemeral>/callback`) means an installed client is
 * listening on loopback for its code. Two topologies reach this page and the
 * page serves both without knowing which it is:
 *
 *  1. Co-located (Claude Desktop): the listener is on the SAME machine as this
 *     browser, so the nonce-scoped script navigates to the full callback URL
 *     and the listener receives the code with no user action.
 *  2. Headless gateway: the browser that approved consent is a DIFFERENT
 *     machine from the box running the listener, so that navigation reaches
 *     nothing (or a dead port). The visible code and callback URL are the
 *     fallback — copy the code into the client, or open the URL on the box.
 *
 * The navigation is `window.location.assign` rather than `replace`, and the
 * code is rendered into the document BEFORE the script runs, precisely so the
 * headless floor holds: if the navigation lands on a refused port and the
 * browser shows its own error page, one Back press returns to the still-intact
 * code — no one is worse off than the bare 302 was. Under the CSP below a
 * background probe (fetch/img/iframe) is impossible — connect-src, img-src and
 * frame-src all inherit `default-src 'none'` — so a top-level navigation is the
 * only reach the script has, which is why the attempt is destructive at all.
 *
 * CSP: `default-src 'none'` (no external anything), `style-src 'unsafe-inline'`
 * (the mirrored inline page style), `script-src 'nonce-<per-request random>'`
 * so the one inline script runs and nothing an injection could add does. The
 * nonce is fresh per request (crypto.randomBytes); a static or reused nonce
 * would let injected markup carry it and defeat the control. The authorization
 * code is written to the response body only, never to a logger, here or in the
 * caller.
 */
export function sendLoopbackConsentSuccess(
  res: express.Response,
  callbackUrl: URL,
): void {
  const nonce = randomBytes(16).toString("base64");
  const fullUrl = callbackUrl.toString();
  const code = callbackUrl.searchParams.get("code") ?? "";

  res.setHeader(
    "Content-Security-Policy",
    `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'`,
  );
  // The page carries an authorization code in its markup; no cache, anywhere,
  // may retain it, and there is nothing here worth revalidating against.
  res.setHeader("Cache-Control", "no-store");
  // The next navigation is to the client's loopback URL, which itself carries
  // the code; the browser must not leak this gateway as its referrer.
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");

  const safeCode = escapeHtml(code);
  const safeUrl = escapeHtml(fullUrl);
  // The script receives the URL as a JSON string literal so a value carrying a
  // quote cannot break out of it; `<` is additionally unicode-escaped so no
  // interpolation can spell `</script>` and close the block early. The WHATWG
  // URL serializer already percent-encodes `<`/`>`, so this is defence in depth.
  const scriptUrl = JSON.stringify(fullUrl).replace(/</g, "\\u003c");

  res.status(200).send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorization complete</title>
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;color:#1a1a2e;line-height:1.5}h1{font-size:1.4rem}code{display:block;background:#f0f0f5;padding:.6rem .8rem;border-radius:6px;word-break:break-all;font-size:.9rem;margin:.4rem 0}.hint{color:#555}.label{font-weight:600;margin-top:1.2rem}</style>
</head><body>
<h1>Authorization complete</h1>
<p id="status">Handing the code to your client. If you see a connection error or nothing happens, your client is on another machine (this gateway is headless): copy the code below.</p>
<p class="hint">If nothing happened, your client is on another machine. Copy the values below into the client that is waiting for them.</p>
<div class="label">Authorization code</div>
<code>${safeCode}</code>
<div class="label">Full callback URL</div>
<code>${safeUrl}</code>
<p class="hint">Paste the authorization code into the client waiting for it, or open the callback URL on the machine running that client.</p>
<script nonce="${nonce}">
  // Co-located listener: this completes the flow. Headless: it reaches nothing
  // and the copy blocks above stand in. assign (not replace) keeps a history
  // entry so a refused navigation is recoverable with Back. A short delay lets
  // the code paint first so the headless user sees it before any bounce.
  var target = ${scriptUrl};
  setTimeout(function () { window.location.assign(target); }, 600);
</script>
</body></html>`);
}
