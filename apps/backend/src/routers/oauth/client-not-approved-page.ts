import type express from "express";

import { escapeHtml } from "./consent-success-page";

/**
 * The page `GET /oauth/authorize` shows instead of the consent screen when the
 * client is not approved (migration 0042): a self-registration still waiting
 * for an administrator, or one an administrator rejected.
 *
 * What it must and must not do:
 *  - It is rendered BEFORE any consent state exists: no signed request, no
 *    consent cookie, no redirect to consent, and never a redirect to the
 *    client's callback.
 *  - Every value on it (application name, client id, callback) came from
 *    whoever registered the client and is labelled that way. Each is
 *    HTML-escaped and rendered as text: the callback is not a link and no logo
 *    is loaded. The CSP allows no script, image, frame, connection or form.
 *  - A pending page tells the person to quote the client id to an
 *    administrator and to reload this same page after approval. Reloading
 *    repeats the identical authorization request, so the state, callback and
 *    PKCE challenge the application is waiting on are unchanged.
 *  - Wording is generic (this is a public fork): administrators approve in the
 *    gateway and never ask anyone for an authorization code.
 *
 * `no-store` because it describes one client's live status and should not be
 * served from any cache after an approval.
 */
export interface ClientNotApprovedPageDetails {
  /** "pending" renders the waiting page; anything else the rejected page. */
  status: string;
  clientName: string;
  clientId: string;
  redirectUri: string;
}

export const CLIENT_NOT_APPROVED_HTTP_STATUS = 403;

/**
 * The JSON refusal for a consent-info read, a consent decision or a token
 * request naming a client that is not approved (migration 0042). RFC 6749's
 * `unauthorized_client`: the client exists but may not use this flow. One
 * constant so the four places answer alike.
 */
export const CLIENT_NOT_APPROVED_ERROR = Object.freeze({
  error: "unauthorized_client",
  error_description:
    "This application is not approved for use on this gateway. An administrator must approve it first.",
});

export function sendClientNotApprovedPage(
  res: express.Response,
  details: ClientNotApprovedPageDetails,
): void {
  const pending = details.status === "pending";
  const safeName = escapeHtml(details.clientName);
  const safeId = escapeHtml(details.clientId);
  const safeCallback = escapeHtml(details.redirectUri);

  res.setHeader(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'",
  );
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");

  const title = pending
    ? "Waiting for administrator approval"
    : "Application rejected";

  const body = pending
    ? `<p>This application registered itself with this gateway, but it cannot be used until an administrator approves it.</p>
<p>Ask for approval only if you started this sign-in yourself, from an application on your own computer. If you did not, close this page.</p>
<p>To ask for approval, send your administrator the client ID below. After they approve it, reload this page to continue signing in.</p>`
    : `<p>An administrator rejected this application. It cannot be used to sign in to this gateway.</p>
<p>If you need this application, ask your administrator. A new registration will be needed.</p>`;

  res.status(CLIENT_NOT_APPROVED_HTTP_STATUS).send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;color:#1a1a2e;line-height:1.5}h1{font-size:1.4rem}.box{border:1px solid #d0d0dc;border-radius:6px;padding:.4rem 1rem;margin:1rem 0}.label{font-weight:600;margin-top:.8rem}.value{font-family:ui-monospace,monospace;background:#f0f0f5;padding:.4rem .6rem;border-radius:4px;word-break:break-all;margin:.2rem 0}.note{color:#555;font-size:.9rem}</style>
</head><body>
<h1 id="status" data-status="${pending ? "pending" : "rejected"}">${title}</h1>
${body}
<div class="box" id="supplied-details">
<p class="note">Supplied by whoever registered this application. The gateway has not verified these details.</p>
<div class="label">Application name</div>
<div class="value">${safeName}</div>
<div class="label">Client ID</div>
<div class="value" id="client-id">${safeId}</div>
<div class="label">Callback address</div>
<div class="value">${safeCallback}</div>
</div>
<p class="note">Administrators approve applications in the gateway's admin pages. Nobody needs an authorization code from you to approve one, and nobody will ask you for one.</p>
</body></html>`);
}
