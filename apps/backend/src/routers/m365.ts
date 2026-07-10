/**
 * M365 delegated-token broker — enrollment routes.
 *
 *   GET  /m365/enroll     start the Entra auth-code+PKCE round-trip
 *   GET  /m365/callback   Entra redirect target (code exchange + store)
 *   GET  /m365/status     connection status for the signed-in user
 *   POST /m365/disconnect delete the stored grant (user-side revocation)
 *   GET  /m365/me         TEMP: mint + Graph /me echo (live e2e check;
 *                         remove after the PR 2 pilot drills)
 *
 * All routes are better-auth SESSION-gated: the browser must hold a
 * signed-in gateway session (Entra SSO or email/password). `/enroll`
 * redirects to the login page when it doesn't — the SSO round-trip
 * lands right back here via `callbackUrl`.
 *
 * The PKCE verifier + state are held in an in-process map (10-minute
 * TTL, single-use). state ⇄ user binding: the callback re-validates the
 * live session AND requires it to be the same user that started the
 * flow, so a leaked/forged state can't graft one user's Microsoft
 * account onto another's gateway identity.
 *
 * The refresh token from the code exchange is AES-256-GCM enveloped
 * (`lib/m365/crypto.ts`) before touching Postgres. The id_token is
 * parsed WITHOUT signature validation — acceptable here because it
 * arrives directly from `login.microsoftonline.com` over TLS in a
 * confidential-client exchange, not from the user agent.
 *
 * Design doc: Umbrella-MCP-Server `docs/M365_DELEGATED_MCP_DESIGN.md`
 * §4.3 + §5.1.
 */
import { createHash, randomBytes } from "node:crypto";

import express from "express";

import { auth } from "@/auth";
import { m365TokensRepository } from "@/db/repositories/m365-tokens.repo";
import logger from "@/utils/logger";

import {
  entraAuthorizeUrl,
  entraTokenUrl,
  getM365BrokerConfig,
  isM365BrokerConfigured,
} from "../lib/m365/config";
import { constantTimeEquals, encryptRefreshToken } from "../lib/m365/crypto";
import { m365MintService } from "../lib/m365/mint-service";
import { securityHeaders } from "./oauth/utils";

const m365Router = express.Router();

// Same header hardening the sibling oauthRouter applies (X-Frame-Options,
// nosniff, referrer policy) — these routes render HTML on a
// session-cookie-bearing origin.
m365Router.use(securityHeaders);

// ---------------------------------------------------------------------------
// PKCE + state store (in-process; single-container deployment)
// ---------------------------------------------------------------------------

interface PendingEnrollment {
  userId: string;
  verifier: string;
  createdAt: number;
}

const STATE_TTL_MS = 10 * 60 * 1000;
const pendingEnrollments = new Map<string, PendingEnrollment>();

function sweepExpiredStates(): void {
  const cutoff = Date.now() - STATE_TTL_MS;
  for (const [state, pending] of pendingEnrollments) {
    if (pending.createdAt < cutoff) pendingEnrollments.delete(state);
  }
}

const b64u = (buf: Buffer) => buf.toString("base64url");

// ---------------------------------------------------------------------------
// Session gating
// ---------------------------------------------------------------------------

function webHeadersFromExpress(req: express.Request): Headers {
  const headers = new Headers();
  Object.entries(req.headers).forEach(([key, value]) => {
    if (value) headers.set(key, Array.isArray(value) ? value[0] : value);
  });
  return headers;
}

async function getSessionUser(
  req: express.Request,
): Promise<{ id: string; email: string } | undefined> {
  try {
    const session = await auth.api.getSession({
      headers: webHeadersFromExpress(req),
    });
    if (session?.user?.id) {
      return { id: session.user.id, email: session.user.email };
    }
  } catch (error) {
    logger.warn("M365 broker: better-auth session lookup failed:", error);
  }
  return undefined;
}

/** Login redirect preserving the requested return path. */
function redirectToLogin(res: express.Response, returnTo: string): void {
  res.redirect(`/login?callbackUrl=${encodeURIComponent(returnTo)}`);
}

function notConfiguredResponse(res: express.Response): void {
  res.status(503).json({
    error: "not_configured",
    message:
      "The M365 broker is not configured on this gateway yet (metamcp-m365 env file missing).",
  });
}

/**
 * HTML-escape a value before interpolation into a page. Every dynamic
 * value rendered by these routes (Entra error strings, UPNs, emails)
 * MUST pass through this — `/m365/callback?error=...` is reachable
 * pre-auth, so unescaped interpolation is reflected XSS on a
 * session-cookie-bearing origin.
 */
export function escapeHtml(value: unknown): string {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Tiny self-contained HTML page (no external assets). Callers must
 * escape dynamic values via `escapeHtml` — titles here are static. */
function sendHtml(
  res: express.Response,
  status: number,
  title: string,
  body: string,
): void {
  // Belt-and-braces beyond escaping: no scripts, no external loads.
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'unsafe-inline'",
  );
  res.status(status).send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>${title}</title>
<style>body{font-family:system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem;color:#1a1a2e}h1{font-size:1.4rem}code{background:#f0f0f5;padding:.1rem .3rem;border-radius:4px}</style>
</head><body><h1>${title}</h1>${body}</body></html>`);
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

m365Router.get("/m365/enroll", async (req, res) => {
  if (!isM365BrokerConfigured()) return notConfiguredResponse(res);

  const user = await getSessionUser(req);
  if (!user) return redirectToLogin(res, "/m365/enroll");

  const config = getM365BrokerConfig();
  sweepExpiredStates();

  const state = b64u(randomBytes(32));
  const verifier = b64u(randomBytes(48));
  pendingEnrollments.set(state, {
    userId: user.id,
    verifier,
    createdAt: Date.now(),
  });

  const challenge = b64u(createHash("sha256").update(verifier).digest());
  const authorizeParams = new URLSearchParams({
    client_id: config.clientId,
    response_type: "code",
    redirect_uri: `${config.appUrl}/m365/callback`,
    response_mode: "query",
    scope: config.scopes,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    prompt: "select_account",
    login_hint: user.email,
  });

  logger.info(
    `M365 broker: enrollment started for user ${user.id} (${user.email})`,
  );
  res.redirect(
    `${entraAuthorizeUrl(config.tenantId)}?${authorizeParams.toString()}`,
  );
});

m365Router.get("/m365/callback", async (req, res) => {
  if (!isM365BrokerConfigured()) return notConfiguredResponse(res);

  const { code, state, error, error_description } = req.query as Record<
    string,
    string | undefined
  >;

  if (error) {
    logger.warn(
      `M365 broker: Entra returned error on callback: ${error} — ${error_description}`,
    );
    sendHtml(
      res,
      400,
      "Microsoft 365 connection failed",
      `<p>Microsoft reported: <code>${escapeHtml(error)}</code>.</p><p>Close this tab and start again from <code>/m365/enroll</code>.</p>`,
    );
    return;
  }

  if (!code || !state) {
    sendHtml(
      res,
      400,
      "Microsoft 365 connection failed",
      "<p>Missing authorization code or state. Start again from <code>/m365/enroll</code>.</p>",
    );
    return;
  }

  // Single-use state lookup (constant-time key comparison).
  sweepExpiredStates();
  let pending: PendingEnrollment | undefined;
  for (const [storedState, candidate] of pendingEnrollments) {
    if (constantTimeEquals(storedState, state)) {
      pending = candidate;
      pendingEnrollments.delete(storedState);
      break;
    }
  }
  if (!pending) {
    sendHtml(
      res,
      400,
      "Microsoft 365 connection failed",
      "<p>This enrollment link expired or was already used. Start again from <code>/m365/enroll</code>.</p>",
    );
    return;
  }

  // The callback must arrive on the SAME signed-in gateway user that
  // started the flow — defends against grafting a Microsoft account
  // onto someone else's gateway identity.
  const user = await getSessionUser(req);
  if (!user || user.id !== pending.userId) {
    logger.warn(
      `M365 broker: callback session mismatch (flow user ${pending.userId}, session user ${user?.id ?? "none"})`,
    );
    sendHtml(
      res,
      403,
      "Microsoft 365 connection failed",
      "<p>Your gateway session changed during enrollment. Sign in and start again from <code>/m365/enroll</code>.</p>",
    );
    return;
  }

  const config = getM365BrokerConfig();
  let tokenBody: {
    access_token?: string;
    refresh_token?: string;
    id_token?: string;
    scope?: string;
    error?: string;
    error_description?: string;
  };
  try {
    const tokenResponse = await fetch(entraTokenUrl(config.tenantId), {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: config.clientId,
        client_secret: config.clientSecret,
        grant_type: "authorization_code",
        code,
        redirect_uri: `${config.appUrl}/m365/callback`,
        code_verifier: pending.verifier,
        scope: config.scopes,
      }).toString(),
    });
    tokenBody = (await tokenResponse.json()) as typeof tokenBody;
  } catch (fetchError) {
    logger.error("M365 broker: code exchange fetch failed:", fetchError);
    sendHtml(
      res,
      502,
      "Microsoft 365 connection failed",
      "<p>Could not reach the Microsoft identity platform. Try again shortly.</p>",
    );
    return;
  }

  if (!tokenBody.access_token || !tokenBody.refresh_token) {
    logger.error(
      `M365 broker: code exchange rejected for user ${user.id}: ${tokenBody.error} — ${tokenBody.error_description?.split("\n")[0]}`,
    );
    sendHtml(
      res,
      400,
      "Microsoft 365 connection failed",
      `<p>The code exchange was rejected${tokenBody.error ? ` (<code>${escapeHtml(tokenBody.error)}</code>)` : ""}. ${
        tokenBody.refresh_token
          ? ""
          : "No refresh token was issued — check that <code>offline_access</code> is consented."
      }</p>`,
    );
    return;
  }

  // Entra account identity from the id_token payload (see file-top note
  // on why signature validation is skipped here).
  let entraOid = "";
  let entraTid = "";
  let entraUpn: string | undefined;
  try {
    const idTokenPayload = JSON.parse(
      Buffer.from(
        (tokenBody.id_token ?? "").split(".")[1] ?? "",
        "base64url",
      ).toString("utf8"),
    ) as { oid?: string; tid?: string; preferred_username?: string };
    entraOid = idTokenPayload.oid ?? "";
    entraTid = idTokenPayload.tid ?? "";
    entraUpn = idTokenPayload.preferred_username;
  } catch {
    // Non-fatal: fall through with empty oid/tid and log below.
  }
  if (!entraOid || !entraTid) {
    logger.warn(
      `M365 broker: id_token missing oid/tid for user ${user.id} — storing grant with empty identity fields`,
    );
  }

  // Audit-visibility: a re-enrollment that lands on a DIFFERENT
  // Microsoft account than the one previously stored is legal (the
  // user may genuinely switch accounts) but worth a loud trace — it is
  // the account-grafting shape the session⇄state binding defends
  // against, so log when it happens through the legitimate path too.
  try {
    const existing = await m365TokensRepository.findByUserId(user.id);
    if (
      existing &&
      existing.entra_oid &&
      entraOid &&
      existing.entra_oid !== entraOid
    ) {
      logger.warn(
        `M365 broker: re-enrollment for user ${user.id} switched Microsoft accounts (oid ${existing.entra_oid} → ${entraOid}, upn ${existing.entra_upn ?? "?"} → ${entraUpn ?? "?"})`,
      );
      logger.info(
        JSON.stringify({
          event: "m365_enroll_account_switch",
          user_id: user.id,
          previous_oid: existing.entra_oid,
          new_oid: entraOid,
        }),
      );
    }
  } catch (lookupError) {
    logger.warn(
      `M365 broker: pre-enrollment row lookup failed for user ${user.id} (continuing):`,
      lookupError,
    );
  }

  try {
    await m365TokensRepository.upsertEnrollment({
      user_id: user.id,
      entra_oid: entraOid,
      tenant_id: entraTid,
      entra_upn: entraUpn,
      rt_ciphertext: encryptRefreshToken(
        tokenBody.refresh_token,
        config.kek,
        config.kekId,
      ),
      kek_id: config.kekId,
      scopes_granted: tokenBody.scope ?? config.scopes,
    });
  } catch (dbError) {
    logger.error(
      `M365 broker: failed to persist enrollment for user ${user.id}:`,
      dbError,
    );
    sendHtml(
      res,
      500,
      "Microsoft 365 connection failed",
      "<p>The gateway could not store your credential. The operator has been signaled in logs.</p>",
    );
    return;
  }

  // Fresh grant supersedes any cached/held token state.
  m365MintService.invalidateUser(user.id);

  logger.info(
    JSON.stringify({
      event: "m365_enroll",
      user_id: user.id,
      entra_oid: entraOid,
      entra_upn: entraUpn,
      outcome: "connected",
    }),
  );
  sendHtml(
    res,
    200,
    "Microsoft 365 connected",
    `<p>Your Microsoft 365 account${entraUpn ? ` (<code>${escapeHtml(entraUpn)}</code>)` : ""} is now connected for <code>${escapeHtml(user.email)}</code>.</p><p>You can close this tab and return to Claude — retry the tool call that sent you here.</p>`,
  );
});

m365Router.get("/m365/status", async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) {
    res.status(401).json({ error: "authentication_required" });
    return;
  }
  const row = await m365TokensRepository.findByUserId(user.id);
  res.json({
    configured: isM365BrokerConfigured(),
    connected: Boolean(row && row.status === "active"),
    status: row?.status ?? "not_enrolled",
    entra_upn: row?.entra_upn ?? null,
    scopes_granted: row?.scopes_granted ?? null,
    created_at: row?.created_at ?? null,
    rotated_at: row?.rotated_at ?? null,
    last_used_at: row?.last_used_at ?? null,
  });
});

m365Router.post("/m365/disconnect", async (req, res) => {
  const user = await getSessionUser(req);
  if (!user) {
    res.status(401).json({ error: "authentication_required" });
    return;
  }
  const deleted = await m365TokensRepository.deleteByUserId(user.id);
  m365MintService.invalidateUser(user.id);
  logger.info(
    JSON.stringify({
      event: "m365_disconnect",
      user_id: user.id,
      outcome: deleted ? "deleted" : "no_grant",
    }),
  );
  // Note: Entra offers no self-service per-app RT revocation endpoint
  // for confidential clients — deleting the ciphertext row makes the
  // grant unusable BY THIS GATEWAY immediately; org-side kill switch is
  // Entra account disable / revokeSignInSessions (design doc §5.6).
  res.json({ disconnected: deleted });
});

// TEMPORARY live e2e check for the morning gate: proves session →
// stored grant → mint → Graph round-trip without any MCP machinery.
// Remove with the PR 2 pilot drills.
m365Router.get("/m365/me", async (req, res) => {
  if (!isM365BrokerConfigured()) return notConfiguredResponse(res);
  const user = await getSessionUser(req);
  if (!user) {
    res.status(401).json({ error: "authentication_required" });
    return;
  }
  try {
    const accessToken = await m365MintService.getAccessToken(user.id);
    const graphResponse = await fetch(
      "https://graph.microsoft.com/v1.0/me?$select=displayName,userPrincipalName,mail",
      { headers: { Authorization: `Bearer ${accessToken}` } },
    );
    const profile = (await graphResponse.json()) as Record<string, unknown>;
    res.status(graphResponse.ok ? 200 : 502).json({
      graph_status: graphResponse.status,
      profile,
    });
  } catch (error) {
    const isBroker = error instanceof Error && error.name === "M365BrokerError";
    const code = isBroker
      ? (error as { code?: string }).code
      : "internal_error";
    const enrollUrl = isBroker
      ? (error as { enrollUrl?: string }).enrollUrl
      : undefined;
    if (!isBroker) {
      logger.error("M365 broker: /m365/me failed unexpectedly:", error);
    }
    res.status(isBroker ? 409 : 500).json({
      error: code,
      message: error instanceof Error ? error.message : String(error),
      ...(enrollUrl ? { enroll_url: enrollUrl } : {}),
    });
  }
});

export default m365Router;
