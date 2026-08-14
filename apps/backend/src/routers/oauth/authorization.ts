import { randomBytes } from "crypto";
import express from "express";

import logger from "@/utils/logger";

import { auth } from "../../auth";
import { oauthRepository, usersRepository } from "../../db/repositories";
import {
  CONSENT_REQUEST_TTL_MS,
  consentCsrfCookieName,
  readCookieValues,
  safeEquals,
  signConsentRequest,
  verifyConsentRequest,
} from "./consent-token";
import {
  generateSecureAuthCode,
  getBaseUrl,
  GRANTED_OAUTH_SCOPE,
  isConsentDecisionRateLimited,
  type OAuthParams,
  rateLimitAuth,
  validateRedirectUri,
} from "./utils";

const authorizationRouter = express.Router();

/**
 * Frontend path of the consent screen.
 *
 * Deliberately NOT `/oauth/consent`: `apps/frontend/next.config.js` rewrites
 * `/oauth/:path*` to this backend, so any frontend page under `/oauth/` is
 * shadowed by the proxy and never renders. The frontend middleware likewise
 * skips i18n and its auth gate for anything starting with `/oauth`. A path
 * outside that prefix gets the normal locale redirect and session check.
 */
const CONSENT_PAGE_PATH = "/consent";

/** Authorization codes live 10 minutes, matching the consent request TTL. */
const AUTH_CODE_TTL_MS = 10 * 60 * 1000;

/**
 * Longest client_name echoed to the consent screen. `client_name` is
 * attacker-controlled — `/oauth/register` is anonymous dynamic registration —
 * so it is clamped for the same reason token.ts clamps it in log lines: a
 * caller does not get to decide how much of someone else's screen it occupies.
 */
const MAX_DISPLAYED_CLIENT_NAME = 100;

/**
 * Resolve the better-auth session user for a request, or null.
 *
 * Every consent-flow endpoint re-resolves the session itself rather than
 * trusting anything carried in the request: the whole point of the fix is that
 * a code is bound to the human who is signed in at the moment of approval.
 */
async function resolveSessionUserId(
  req: express.Request,
): Promise<string | null> {
  if (!req.headers.cookie) return null;

  try {
    const sessionUrl = new URL("/api/auth/get-session", getBaseUrl(req));
    const headers = new Headers();
    headers.set("cookie", req.headers.cookie);

    const sessionResponse = await auth.handler(
      new Request(sessionUrl.toString(), { method: "GET", headers }),
    );

    if (!sessionResponse.ok) return null;

    const sessionData = (await sessionResponse.json()) as {
      user?: { id: string };
    };

    return sessionData?.user?.id ?? null;
  } catch (error) {
    logger.info("OAuth session verification failed:", error);
    return null;
  }
}

/**
 * `Secure` is derived from the resolved base URL rather than hardcoded: APP_URL
 * is mandatory (auth.ts hard-fails without it) and server-controlled, so this
 * is `true` on the real deployment and `false` only for a plain-http local
 * stack — where a hardcoded `Secure` would make the browser drop the cookie and
 * every consent silently fail the CSRF check.
 */
function consentCookieOptions(req: express.Request) {
  return {
    httpOnly: true,
    sameSite: "lax" as const,
    secure: getBaseUrl(req).startsWith("https://"),
    // `__Host-` requires exactly this path and no Domain attribute.
    path: "/",
  };
}

/** The cookie name for one consent request — see consentCsrfCookieName. */
function consentCookieName(req: express.Request, cid: string): string {
  return consentCsrfCookieName(getBaseUrl(req).startsWith("https://"), cid);
}

function clearConsentCookie(
  req: express.Request,
  res: express.Response,
  cid: string,
) {
  res.clearCookie(consentCookieName(req, cid), consentCookieOptions(req));
}

/**
 * OAuth 2.0 Authorization Endpoint
 * Handles authorization requests from MCP clients
 */
authorizationRouter.get("/oauth/authorize", rateLimitAuth, async (req, res) => {
  try {
    const {
      response_type,
      client_id,
      redirect_uri,
      scope,
      state,
      code_challenge,
      code_challenge_method,
    } = req.query;

    logger.info("OAuth authorize request:", {
      response_type,
      client_id,
      redirect_uri,
      scope,
      state,
      code_challenge_method,
    });

    // Validate required parameters
    if (response_type !== "code") {
      return res.status(400).json({
        error: "unsupported_response_type",
        error_description: "Only 'code' response type is supported",
      });
    }

    if (!client_id || !redirect_uri) {
      return res.status(400).json({
        error: "invalid_request",
        error_description:
          "Missing required parameters: client_id or redirect_uri",
      });
    }

    // OAuth 2.1 Security: Enforce PKCE for all clients
    if (!code_challenge || !code_challenge_method) {
      return res.status(400).json({
        error: "invalid_request",
        error_description:
          "PKCE parameters (code_challenge and code_challenge_method) are required per OAuth 2.1",
      });
    }

    // Validate PKCE method (OAuth 2.1 recommends S256)
    if (code_challenge_method !== "S256" && code_challenge_method !== "plain") {
      return res.status(400).json({
        error: "invalid_request",
        error_description:
          "Unsupported code_challenge_method. Supported: S256, plain",
      });
    }

    // OAuth 2.1 Security: Validate redirect URI format
    if (!validateRedirectUri(redirect_uri as string)) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Invalid redirect_uri format or insecure scheme",
      });
    }

    // Validate client_id against registered clients
    const clientData = await oauthRepository.getClient(client_id as string);
    const finalClientId = client_id as string; // Track which client_id to use

    if (!clientData) {
      // Client not found - direct them to use dynamic client registration
      const baseUrl = getBaseUrl(req);
      return res.status(400).json({
        error: "invalid_client",
        error_description:
          "Client not registered. Please register your client first.",
        registration_endpoint: `${baseUrl}/oauth/register`,
        documentation:
          "Use the registration endpoint to dynamically register your OAuth client before authorization.",
      });
    } else {
      // Validate redirect_uri against registered redirect_uris for existing clients
      if (!clientData.redirect_uris.includes(redirect_uri as string)) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "redirect_uri is not registered for this client",
        });
      }
    }

    // Store OAuth parameters for later use (using the correct client_id)
    const oauthParams: OAuthParams = {
      client_id: finalClientId,
      redirect_uri: redirect_uri as string,
      // Granted scope is server-decided, never taken from req.query — the
      // requested `scope` above is logged for diagnostics only. See
      // GRANTED_OAUTH_SCOPE in ./utils.
      scope: GRANTED_OAUTH_SCOPE,
      state: state ? (state as string) : undefined,
      code_challenge: code_challenge ? (code_challenge as string) : undefined,
      code_challenge_method: code_challenge_method
        ? (code_challenge_method as string)
        : undefined,
    };

    logger.info(
      `Using client_id: ${finalClientId} (original: ${client_id}) for redirect_uri: ${redirect_uri}`,
    );

    const baseUrl = getBaseUrl(req);
    const userId = await resolveSessionUserId(req);

    if (!userId) {
      // Not signed in: log in, then RE-ENTER this same authorize request.
      //
      // This used to hand the browser a base64 blob of the OAuth parameters
      // and send it to /oauth/callback, which minted a code from that blob —
      // unsigned data that had round-tripped through the client. Returning to
      // /oauth/authorize keeps every parameter under the validation above and
      // leaves exactly one place in this server that mints codes.
      const loginUrl = new URL("/login", baseUrl);
      loginUrl.searchParams.set("callbackUrl", req.originalUrl);
      return res.redirect(loginUrl.toString());
    }

    // `users.disabled` enforcement (migration 0027). This handler resolves the
    // session itself through auth.handler, so neither the tRPC context guard
    // nor the auth.ts sign-in hook is on this path: without this check a
    // locked-out account still gets a signed areq and a consent screen, one
    // click away from an authorization code and the 30-day access token behind
    // it. Being disabled has to close the OAuth door too, or it only closes the
    // one nobody was using.
    //
    // Answered exactly like "not signed in" above — same /login redirect, no
    // areq signed, no CSRF cookie set — rather than with an error of its own.
    // The account learns nothing here about why, and the login it lands on is
    // where the auth.ts hook refuses it.
    if (await usersRepository.isDisabled(userId)) {
      logger.warn(
        `[oauth] authorize rejected reason=disabled client=${oauthParams.client_id} user=${userId}`,
      );
      const loginUrl = new URL("/login", baseUrl);
      loginUrl.searchParams.set("callbackUrl", req.originalUrl);
      return res.redirect(loginUrl.toString());
    }

    // Signed in — and this is the fix. Being signed in is NOT consent.
    //
    // Previously this branch minted an authorization code on the spot for any
    // registered client. Registration is anonymous, so one top-level
    // navigation to a crafted /oauth/authorize URL was enough to mint a code
    // bound to whoever happened to be signed in, delivered straight to the
    // attacker's redirect_uri. The session cookie is SameSite=Lax, so the
    // browser sends it on exactly that navigation.
    //
    // No code is minted here any more. The request is signed, tied to this
    // user with a fresh CSRF nonce, and handed to a page a human has to act
    // on; POST /oauth/authorize/decision is the only place a code appears.
    const csrf = randomBytes(32).toString("base64url");
    // Names this request's cookie. Not a secret — it only has to be unique
    // enough that two authorizations from the same browser never share a
    // cookie name. The secret is `csrf`, which lives in the cookie's value.
    const cid = randomBytes(9).toString("base64url");
    const areq = signConsentRequest({
      client_id: oauthParams.client_id,
      redirect_uri: oauthParams.redirect_uri,
      scope: GRANTED_OAUTH_SCOPE,
      state: oauthParams.state,
      code_challenge: oauthParams.code_challenge,
      code_challenge_method: oauthParams.code_challenge_method,
      user_id: userId,
      cid,
      csrf,
      exp: Date.now() + CONSENT_REQUEST_TTL_MS,
    });

    // Per-cid name: a second authorize from the same browser adds a cookie
    // rather than replacing this one, so whichever consent page the user
    // actually approves still finds its own nonce. Abandoned flows leave a
    // ~90-byte cookie behind until the TTL expires them.
    res.cookie(consentCookieName(req, cid), csrf, {
      ...consentCookieOptions(req),
      maxAge: CONSENT_REQUEST_TTL_MS,
    });

    logger.info(
      `[oauth] consent requested client=${oauthParams.client_id} user=${userId}`,
    );

    const consentUrl = new URL(CONSENT_PAGE_PATH, baseUrl);
    consentUrl.searchParams.set("areq", areq);
    res.redirect(consentUrl.toString());
  } catch (error) {
    logger.error("Error in OAuth authorize endpoint:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Internal server error",
    });
  }
});

/**
 * Consent screen data source.
 *
 * Returns the few fields the consent page shows, and only to the signed-in user
 * the request belongs to. It deliberately does NOT echo the token's internals —
 * above all the csrf nonce, whose whole value is that nothing readable by
 * script ever carries it.
 */
authorizationRouter.get("/oauth/consent/info", async (req, res) => {
  try {
    const consentRequest = verifyConsentRequest(req.query.areq);

    if (!consentRequest) {
      return res.status(400).json({
        error: "invalid_request",
        error_description:
          "Authorization request is missing, invalid, or expired",
      });
    }

    const userId = await resolveSessionUserId(req);

    if (!userId || !safeEquals(userId, consentRequest.user_id)) {
      return res.status(403).json({
        error: "access_denied",
        error_description:
          "This authorization request belongs to a different session",
      });
    }

    const clientData = await oauthRepository.getClient(
      consentRequest.client_id,
    );

    if (!clientData) {
      return res.status(400).json({
        error: "invalid_client",
        error_description: "Client is no longer registered",
      });
    }

    // Re-checked here as well as at decision time so the page can never show a
    // destination the client is no longer registered for.
    if (!clientData.redirect_uris.includes(consentRequest.redirect_uri)) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "redirect_uri is not registered for this client",
      });
    }

    res.json({
      client_id: consentRequest.client_id,
      client_name: (clientData.client_name || consentRequest.client_id).slice(
        0,
        MAX_DISPLAYED_CLIENT_NAME,
      ),
      // The FULL redirect target, not just its host. client_name is whatever
      // an anonymous registration asked to be called, so a "Claude" claiming
      // host "claude-ai.example.com" is trivial to arrange; the destination is
      // the field that actually decides where the code goes, and a human can
      // only judge it if they see all of it.
      redirect_uri: consentRequest.redirect_uri,
      scope: consentRequest.scope,
    });
  } catch (error) {
    logger.error("Error in OAuth consent info endpoint:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Internal server error",
    });
  }
});

/**
 * OAuth 2.0 Consent Decision Endpoint — the ONLY place this server mints an
 * authorization code.
 *
 * Four things must all hold before a code exists, and each closes a distinct
 * door:
 *   1. the areq token verifies and has not expired — the parameters are the
 *      ones /oauth/authorize validated, not ones edited in flight;
 *   2. the current session is the same user the token was issued to — one
 *      user cannot finish another's authorization;
 *   3. the oauth_consent_csrf cookie equals the nonce inside the token — the
 *      approval came from the browser this request was issued to, on a
 *      same-site POST, which is what a cross-site attacker cannot produce;
 *   4. the redirect_uri is still registered for the client — the client
 *      record may have changed since the token was signed.
 */
authorizationRouter.post("/oauth/authorize/decision", async (req, res) => {
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const consentRequest = verifyConsentRequest(body.areq);

    if (!consentRequest) {
      return res.status(400).json({
        error: "invalid_request",
        error_description:
          "Authorization request is missing, invalid, or expired. Please start the connection again from your application.",
      });
    }

    // Keyed on the user inside the verified token rather than req.ip — see
    // isConsentDecisionRateLimited. Checked after verification because that
    // is the first point a trustworthy user id exists; an unsigned body
    // costs one HMAC and never reaches the database.
    if (isConsentDecisionRateLimited(consentRequest.user_id)) {
      logger.info(
        `[RATE LIMIT] Consent decision rate limited for user: ${consentRequest.user_id}`,
      );
      return res.status(429).json({
        error: "too_many_requests",
        error_description:
          "Too many consent decisions. Please try again shortly.",
      });
    }

    const userId = await resolveSessionUserId(req);

    if (!userId || !safeEquals(userId, consentRequest.user_id)) {
      return res.status(403).json({
        error: "access_denied",
        error_description:
          "This authorization request belongs to a different session",
      });
    }

    // Double submit. The cookie is httpOnly and SameSite=Lax, so a
    // cross-site page can neither read the nonce nor get the browser to
    // attach the cookie to its own POST.
    //
    // Every value sent under the name is considered, not just the first: a
    // browser will send a more specific cookie ahead of ours, so taking one
    // value would let a planted duplicate deny consent to the real user
    // forever. Accepting a match on any is not weaker — the nonce still has
    // to be produced — and `__Host-` blocks the planting route outright.
    //
    // Nothing is cleared on this branch on purpose: clearing the cookie for
    // a request that failed verification would let anyone cancel a victim's
    // pending consent by replaying a bad decision.
    // The name comes from the VERIFIED token, so the browser's other pending
    // consent cookies are simply different names and cannot interfere.
    const presentedCsrf = readCookieValues(
      req.headers.cookie,
      consentCookieName(req, consentRequest.cid),
    );

    if (!presentedCsrf.some((v) => safeEquals(v, consentRequest.csrf))) {
      logger.warn(
        `[oauth] consent rejected reason=csrf client=${consentRequest.client_id} user=${userId}`,
      );
      return res.status(403).json({
        error: "access_denied",
        error_description:
          "Consent could not be verified. Please start the connection again from your application.",
      });
    }

    const clientData = await oauthRepository.getClient(
      consentRequest.client_id,
    );

    if (
      !clientData ||
      !clientData.redirect_uris.includes(consentRequest.redirect_uri)
    ) {
      clearConsentCookie(req, res, consentRequest.cid);
      return res.status(400).json({
        error: "invalid_request",
        error_description: "redirect_uri is not registered for this client",
      });
    }

    // `users.disabled` enforcement (migration 0027), and the one that actually
    // has to hold: this is the only place a code is minted. The four checks
    // above all pass for someone disabled after the consent screen was issued —
    // the session, the areq and the nonce stay valid for the full ten-minute
    // TTL — so guarding only the authorize GET would leave a ten-minute window
    // in which an already-revoked account can still complete a grant. Whoever
    // pressed disable expects the door shut then, not when the areq expires.
    //
    // Same 403 access_denied shape as the checks above, and like every other
    // failed check here the consent cookie is deliberately left alone: clearing
    // it for a request that did not pass would hand anyone a way to cancel a
    // victim's pending consent.
    if (await usersRepository.isDisabled(userId)) {
      logger.warn(
        `[oauth] consent rejected reason=disabled client=${consentRequest.client_id} user=${userId}`,
      );
      return res.status(403).json({
        error: "access_denied",
        error_description:
          "Consent could not be verified. Please start the connection again from your application.",
      });
    }

    clearConsentCookie(req, res, consentRequest.cid);

    const redirectUrl = new URL(consentRequest.redirect_uri);
    if (consentRequest.state) {
      redirectUrl.searchParams.set("state", consentRequest.state);
    }

    // Default deny: only the exact string "approve" grants. Anything else —
    // a missing field, a truncated body, a decision this server does not
    // recognise — is refused.
    if (body.decision !== "approve") {
      redirectUrl.searchParams.set("error", "access_denied");
      logger.info(
        `[oauth] consent denied client=${consentRequest.client_id} user=${userId}`,
      );
      return res.redirect(redirectUrl.toString());
    }

    const code = generateSecureAuthCode();

    await oauthRepository.setAuthCode(code, {
      client_id: consentRequest.client_id,
      redirect_uri: consentRequest.redirect_uri,
      scope: GRANTED_OAUTH_SCOPE,
      user_id: userId,
      code_challenge: consentRequest.code_challenge || null,
      code_challenge_method: consentRequest.code_challenge_method || null,
      expires_at: Date.now() + AUTH_CODE_TTL_MS,
    });

    redirectUrl.searchParams.set("code", code);

    logger.info(
      `[oauth] consent granted client=${consentRequest.client_id} user=${userId}`,
    );

    res.redirect(redirectUrl.toString());
  } catch (error) {
    logger.error("Error in OAuth consent decision endpoint:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Internal server error",
    });
  }
});

/**
 * OAuth 2.0 Callback Handler
 *
 * Looks up an authorization code that already exists and forwards it. It does
 * NOT mint. The branch that used to live here decoded an unsigned base64
 * `params` blob — which had round-tripped through the client's browser — and
 * minted a code from whatever it contained; that was the second way to get a
 * code without consent. Minting now happens only in
 * POST /oauth/authorize/decision, and the post-login return path goes back to
 * /oauth/authorize instead of here.
 */
authorizationRouter.get("/oauth/callback", async (req, res) => {
  try {
    if (req.query.params) {
      // A client still holding a pre-consent-screen URL. Retrying from the
      // client re-enters /oauth/authorize and completes normally.
      return res.status(400).json({
        error: "invalid_request",
        error_description:
          "This authorization flow is no longer supported. Please start the connection again from your application.",
      });
    }

    // Handle direct callback with individual query parameters
    // This is likely from an external OAuth flow or direct URL access
    const { code, state } = req.query;

    if (!code) {
      return res.status(400).send("Missing authorization code");
    }

    // If we receive a code directly, look up the code data to get the original parameters
    const codeData = await oauthRepository.getAuthCode(code as string);
    if (codeData) {
      // Check if code has expired
      if (Date.now() > codeData.expires_at.getTime()) {
        await oauthRepository.deleteAuthCode(code as string);
        return res.status(400).send("Authorization code has expired");
      }

      // A client that registered THIS server's callback as its own
      // redirect_uri would be redirected to itself forever, so that case still
      // has to terminate here — but it no longer renders anything.
      //
      // What used to be here was a development convenience page that
      // interpolated `code`, `state` and `codeData.redirect_uri` into HTML
      // unescaped. `state` made it reflected; `redirect_uri` made it stored,
      // since that value arrives verbatim from anonymous dynamic client
      // registration. The CSP on these routes blocks script execution today,
      // but it sets no form-action, so an injected full-page overlay could
      // still post to an attacker's host from this origin — and a CSP
      // regression would turn the sink into a way around the consent screen
      // this endpoint now depends on. A JSON error breaks the loop and leaves
      // no HTML sink at all.
      const ourCallbackUrl = `${getBaseUrl(req)}/oauth/callback`;

      if (
        codeData.redirect_uri === ourCallbackUrl ||
        codeData.redirect_uri.includes("/oauth/callback")
      ) {
        return res.status(400).json({
          error: "invalid_request",
          error_description:
            "This client's redirect_uri points back at the authorization server. Register a redirect_uri that belongs to the client.",
        });
      }

      // Code exists and is valid, redirect back to the original redirect_uri
      const redirectUrl = new URL(codeData.redirect_uri);
      redirectUrl.searchParams.set("code", code as string);
      if (state) {
        redirectUrl.searchParams.set("state", state as string);
      }
      return res.redirect(redirectUrl.toString());
    } else {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Invalid authorization parameters",
      });
    }
  } catch (error) {
    logger.error("Error in OAuth callback:", error);
    res.status(500).send("OAuth callback error");
  }
});

export default authorizationRouter;
