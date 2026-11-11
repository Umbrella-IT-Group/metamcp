import { isOAuthClientApproved } from "@repo/zod-types";
import { randomUUID } from "crypto";
import express from "express";

import { CREDENTIAL_NOT_PERMITTED_MESSAGE } from "@/lib/api-key-ip-policy";
import {
  auditRequestContext,
  credentialFingerprint,
  emit,
} from "@/lib/audit/audit-emitter";
import {
  authRateLimiter,
  getPublicOAuthRateLimitIdentifier,
} from "@/lib/auth-rate-limiter";
import logger from "@/utils/logger";

import { oauthRepository, usersRepository } from "../../db/repositories";
import type {
  OAuthDbExecutor,
  OAuthTx,
} from "../../db/repositories/oauth-user-lock";
import { CLIENT_NOT_APPROVED_ERROR } from "./client-not-approved-page";
import { requireIntrospectionCredential } from "./introspection-auth";
import {
  generateSecureAccessToken,
  generateSecureRefreshToken,
  rateLimitToken,
  verifyClientSecret,
} from "./utils";

const tokenRouter = express.Router();

// Umbrella fork: TTLs are env-var configurable. Defaults are tuned for max
// connectivity from clients that lack revoke-friendly UX (e.g. Claude.ai
// connectors): 24h access tokens with 365d refresh tokens. Refresh tokens
// rotate on every use (single-use), so a stolen refresh self-reveals when
// the legit client redeems the rotated copy and gets `invalid_grant`.
function readTtl(envName: string, fallbackSeconds: number): number {
  const raw = process.env[envName];
  if (!raw) return fallbackSeconds;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isFinite(parsed) && parsed > 0) return parsed;
  logger.warn(
    `[oauth] ${envName}=${raw} is not a positive integer; using default ${fallbackSeconds}s`,
  );
  return fallbackSeconds;
}

const ACCESS_TOKEN_EXPIRY = readTtl(
  "OAUTH_ACCESS_TOKEN_TTL_SECONDS",
  24 * 60 * 60, // 24h default (was 1h upstream)
);
const REFRESH_TOKEN_EXPIRY = readTtl(
  "OAUTH_REFRESH_TOKEN_TTL_SECONDS",
  365 * 24 * 60 * 60, // 365d default (was 7d in PR #276)
);

logger.info(
  `[oauth] token TTLs: access=${ACCESS_TOKEN_EXPIRY}s refresh=${REFRESH_TOKEN_EXPIRY}s`,
);

/**
 * Client authentication on the refresh_token grant, for a confidential client
 * (`client_secret_post` or `client_secret_basic`). RFC 6749 section 6 requires
 * such a client to authenticate when it refreshes; this handler did not check,
 * so possession of a confidential client's refresh token alone minted access
 * tokens. Public (`none`) clients hold no secret and are never affected.
 *
 * - `log` (default): evaluate the presented credentials exactly as the
 *   authorization_code grant does and RECORD the outcome (`verified`,
 *   `missing`, `invalid`), never the value, then proceed as before. Whether the
 *   production confidential client sends its secret on refresh is not known,
 *   so this phase measures before anything is refused.
 * - `enforce`: refuse anything but `verified` with 401 invalid_client, before
 *   the token is rotated, so a refused request leaves the chain intact.
 *
 * Read per call, like resolveDcrAllowedHosts in ./utils, so a test can switch
 * modes inside one file and the value in effect is the value in the env.
 */
export const OAUTH_REFRESH_CLIENT_AUTH_ENV = "OAUTH_REFRESH_CLIENT_AUTH";

export type RefreshClientAuthMode = "log" | "enforce";

export function resolveRefreshClientAuthMode(): RefreshClientAuthMode {
  const raw = process.env[OAUTH_REFRESH_CLIENT_AUTH_ENV];
  if (raw === undefined || raw.trim() === "") {
    return "log";
  }
  const value = raw.trim().toLowerCase();
  if (value === "log" || value === "enforce") {
    return value;
  }
  // An unrecognised value falls back to `log`, not `enforce`: `log` is the
  // behaviour every client already has, while guessing `enforce` from a typo
  // could lock the confidential client out with nothing in the env saying so.
  // The warning names the value so the operator can see the setting did not
  // take.
  logger.warn(
    `[oauth] ${OAUTH_REFRESH_CLIENT_AUTH_ENV}=${JSON.stringify(raw.slice(0, 40))} is not "log" or "enforce"; using log`,
  );
  return "log";
}

// The effective value at boot, so an operator can confirm the setting was read
// (not only set) from the startup log.
logger.info(
  `[oauth] refresh grant client auth: ${OAUTH_REFRESH_CLIENT_AUTH_ENV}=${resolveRefreshClientAuthMode()}`,
);

// Umbrella fork: success-path grant observability. Until now the token endpoint
// logged only FAILURES, so nothing in `app.log` distinguished "the connector
// refreshed on schedule" from "the connector never refreshed and silently died
// when its access token expired" — the open question behind the 2026-08
// Claude.ai disconnect investigation. One grep-friendly line per issued token
// answers it from the log file alone: `grep '\[oauth\] token issued'`.
//
// SECRETS DISCIPLINE: the access token's LAST FOUR CHARACTERS only, and nothing
// else credential-shaped. Four characters are enough to tie an issued token to a
// later introspect/revoke line while being useless to an attacker who reads the
// log. Full access tokens, refresh tokens, authorization codes, and client
// secrets are never logged at any level.
function lastFour(secret: string): string {
  // Guard instead of trusting the caller: `slice(-4)` on a string shorter than
  // four characters returns the WHOLE string, which for a credential is a leak.
  // Generated tokens are always long, so this only fires on a caller bug.
  return secret.length >= 4 ? secret.slice(-4) : "????";
}

/**
 * Emit one line per successfully issued access token.
 *
 * `clientName` is passed only on the authorization_code path. The refresh path
 * also loads the client row now (for confidential-client authentication, see
 * OAUTH_REFRESH_CLIENT_AUTH_ENV) but still leaves the name out: it is not
 * needed, since every refresh chain begins with an authorization_code grant
 * and the id-to-name mapping is already in the same log file, and adding it
 * would change every existing refresh line that operators grep.
 */
function logTokenIssued(fields: {
  grantType: "authorization_code" | "refresh_token";
  clientId: string;
  clientName?: string | null;
  userId: string;
  accessToken: string;
  // Set only on the refresh path, where redemption always mints a replacement
  // refresh token (see handleRefreshTokenGrant). Omitted on the initial grant
  // because there was no prior refresh token to rotate, and `rotated=false`
  // there would read as "rotation is off".
  rotatedRefreshToken?: true;
  // Set only on the refresh path and only for a confidential client (see
  // OAUTH_REFRESH_CLIENT_AUTH_ENV). Omitted for a public client, whose line
  // stays byte-identical to what it was before the field existed.
  clientAuth?: ClientAuthOutcome;
}) {
  const parts = [
    "[oauth] token issued",
    `grant=${fields.grantType}`,
    `client=${fields.clientId}`,
  ];
  if (fields.clientName) {
    // JSON.stringify, not naive quoting: client_name arrives verbatim from the
    // UNAUTHENTICATED /oauth/register DCR endpoint, so an embedded newline or
    // quote would otherwise forge whole "[oauth] token issued" lines in this
    // log. stringify escapes both and supplies the surrounding quotes, keeping
    // benign output byte-identical. Length-clamped so a hostile registration
    // cannot bloat the log line.
    parts.push(
      `client_name=${JSON.stringify(fields.clientName.slice(0, 100))}`,
    );
  }
  parts.push(`user=${fields.userId}`);
  parts.push(`token=...${lastFour(fields.accessToken)}`);
  if (fields.rotatedRefreshToken) {
    parts.push("rotated=true");
  }
  if (fields.clientAuth) {
    parts.push(`client_auth=${fields.clientAuth}`);
  }

  logger.info(parts.join(" "));
}

/**
 * Record an issued or refreshed access token in `audit_log`.
 *
 * The durable twin of `logTokenIssued` above: that writes a grep-friendly
 * line to a ring buffer that dies on restart, this writes a queryable row
 * that cannot be cleared. The 2026-08-13 credential chain ran through here
 * and left nothing durable behind it.
 *
 * The token appears ONLY as a `credentialFingerprint` — sha256 plus last-4,
 * the same shape the MCP bearer detector records on refused requests, which
 * is deliberate: it means a token minted here and later refused there can be
 * matched across the two by hash, without either row holding anything usable.
 */
function emitTokenIssued(
  req: express.Request,
  fields: {
    action: "oauth.token.issue" | "oauth.token.refresh";
    grantType: string;
    clientId: string;
    clientName?: string | null;
    userId: string;
    accessToken: string;
    // Refresh path, confidential client only; see logTokenIssued.
    clientAuth?: ClientAuthOutcome;
  },
): void {
  const audit = auditRequestContext(req);
  const fingerprint = credentialFingerprint(fields.accessToken);
  emit({
    actor_type: "user",
    actor_id: fields.userId,
    actor_label: null,
    actor_ip: audit.actor_ip,
    actor_user_agent: audit.actor_user_agent,
    action: fields.action,
    target_type: "oauth_client",
    target_id: fields.clientId,
    outcome: "success",
    request_id: audit.request_id,
    http_status: 200,
    detail: {
      grant_type: fields.grantType,
      // Clamped for the same reason logTokenIssued clamps it: client_name
      // arrives verbatim from the UNAUTHENTICATED /oauth/register endpoint.
      client_name: fields.clientName ? fields.clientName.slice(0, 100) : null,
      access_token_sha256: fingerprint.sha256,
      access_token_last4: fingerprint.last4,
      // The outcome word only. Absent for a public client, so its row keeps
      // the shape it had before this key existed.
      ...(fields.clientAuth ? { client_auth: fields.clientAuth } : {}),
    },
  });
}

/**
 * Issue a new access token + refresh token pair and store them.
 *
 * `familyId` ties the pair into a refresh-token family (migration 0037). The
 * authorization_code grant omits it, starting a NEW family; the refresh grant
 * passes the rotated row's `family_id`, so a whole rotation chain shares one
 * family and reuse of any rotated-out member can revoke the entire lineage. The
 * id is a random uuid, unguessable, so it is never a value a caller can present.
 */
async function issueTokenPair(
  clientId: string,
  userId: string,
  scope: string,
  familyId: string,
  // Both grants pass the transaction that holds the user's credential lock,
  // so the new pair commits or rolls back with the code or refresh token it
  // replaces. See ../../db/repositories/oauth-user-lock.
  executor: OAuthDbExecutor,
) {
  const accessToken = generateSecureAccessToken();
  const refreshToken = generateSecureRefreshToken();

  await oauthRepository.setAccessToken(
    accessToken,
    {
      client_id: clientId,
      user_id: userId,
      scope,
      expires_at: Date.now() + ACCESS_TOKEN_EXPIRY * 1000,
      family_id: familyId,
      // The refresh token and its expiry travel as one pair, so a token can never
      // be stored with a refresh token but no expiry — the never-reaped,
      // never-expiring shape migration 0035's CHECK also forbids at the column
      // level.
      refresh: {
        token: refreshToken,
        expires_at: Date.now() + REFRESH_TOKEN_EXPIRY * 1000,
      },
    },
    executor,
  );

  return { accessToken, refreshToken };
}

/**
 * Client credentials carried in an `Authorization: Basic` header.
 *
 * RFC 6749 section 2.3.1: the client id and secret are each encoded with the
 * application/x-www-form-urlencoded algorithm, then used as the Basic username
 * and password. So the decoded header splits at its FIRST colon (RFC 7617: a
 * user-id cannot contain one, a password can) and each half is form-decoded.
 * Every id and secret this server issues is base64url, which that decoding
 * leaves unchanged, so clients that skip the encoding step still verify.
 *
 * Returns `undefined` when there is no Basic header at all, and `null` when
 * there is one that cannot be read (no colon, empty id, or a broken percent
 * escape), so callers can tell "did not try" from "tried and failed".
 */
function parseBasicClientCredentials(
  authorization: string | undefined,
): { clientId: string; clientSecret: string } | null | undefined {
  // RFC 9110 11.1 makes auth schemes case-insensitive. Using an exact-case
  // match would ignore a valid Basic identity on the refresh grant.
  if (!authorization || !/^Basic /i.test(authorization)) {
    return undefined;
  }
  const decoded = Buffer.from(authorization.substring(6), "base64").toString();
  const colon = decoded.indexOf(":");
  if (colon <= 0) {
    return null;
  }
  const formDecode = (value: string) =>
    decodeURIComponent(value.replace(/\+/g, " "));
  try {
    return {
      clientId: formDecode(decoded.substring(0, colon)),
      clientSecret: formDecode(decoded.substring(colon + 1)),
    };
  } catch {
    // A malformed percent escape. Unreadable, not absent.
    return null;
  }
}

/**
 * Work out which client a token request speaks for.
 *
 * The body's `client_id` is what this endpoint has always read, and when it is
 * present it is still the answer, so a `none` or `client_secret_post` client
 * (every production connector today) takes exactly the path it took before.
 * A client registered for `client_secret_basic` may send its id ONLY in the
 * Basic header (RFC 6749 section 2.3.1), so when the body has none, a readable
 * Basic header supplies it (upstream metatool-ai/metamcp issue #342). Without
 * this the authorization_code grant refused every such client, and the
 * refresh_token grant skipped its client check for them.
 *
 * When the body and a readable Basic header BOTH name a client and the two
 * differ, the request is refused with 401 invalid_client, whatever method the
 * client registered. RFC 6749 section 2.3 says a client MUST NOT use more than
 * one authentication method in a request, and a request carrying two
 * different identities has no answer to "which client is this" that is not a
 * guess: preferring the body would let the header be ignored while it names
 * someone else, and preferring the header would let a body id be overridden.
 * The same id in both places is one identity and passes. An unreadable Basic
 * header is not treated as a conflict: it supplies no identity, so the body
 * decides as it always has, and a `client_secret_basic` client is still
 * refused by its own verification below.
 */
function resolveRequestClientId(req: express.Request) {
  // Passed on untouched (not coerced to a string) when it decides the answer,
  // so a body that worked before reaches the same comparisons with the same
  // value.
  const bodyClientId = req.body.client_id;
  const basic = parseBasicClientCredentials(req.headers.authorization);
  if (!basic) {
    return { ok: true as const, clientId: bodyClientId };
  }
  if (!bodyClientId) {
    return { ok: true as const, clientId: basic.clientId };
  }
  if (bodyClientId !== basic.clientId) {
    return { ok: false as const };
  }
  return { ok: true as const, clientId: bodyClientId };
}

function refuseConflictingClientIds(res: express.Response) {
  return res.status(401).json({
    error: "invalid_client",
    error_description:
      "client_id in the request body does not match the Authorization header",
  });
}

/**
 * What a confidential client's presented credentials amounted to. A word, never
 * the value: this is what the refresh grant logs and audits.
 */
type ClientAuthOutcome = "verified" | "missing" | "invalid";

/**
 * Evaluate the client credentials a token request carries against the client's
 * registered `token_endpoint_auth_method`. The ONE implementation both grants
 * use, so the refresh grant judges a confidential client exactly as the
 * authorization_code grant always has, and the two cannot drift apart.
 *
 * Returns `null` for any method other than `client_secret_basic` and
 * `client_secret_post` (in practice `none`): such a client holds no secret,
 * so there is nothing to evaluate and it proceeds as before. Otherwise the
 * outcome, plus the 401 description the authorization_code grant has always
 * answered with for it (kept byte-identical).
 *
 * `missing` is "no credential for the registered method was sent"; `invalid`
 * is "one was sent and it did not verify", which includes an unreadable Basic
 * header and a Basic header naming a different client. The secret half is
 * verified against the salted hash at rest (migration 0036) in constant time
 * (verifyClientSecret -> timingSafeEqualSecret), so the token endpoint is not a
 * timing oracle for a confidential client's secret.
 */
function evaluateClientCredentials(
  req: express.Request,
  client: {
    client_id: string;
    token_endpoint_auth_method: string;
    client_secret: string | null;
    client_secret_salt?: string | null;
  },
): { outcome: ClientAuthOutcome; refusal: string } | null {
  if (client.token_endpoint_auth_method === "client_secret_basic") {
    // The same parser resolveRequestClientId used, so the id that picked this
    // client and the credentials verified here can never be read differently.
    const credentials = parseBasicClientCredentials(req.headers.authorization);
    if (credentials === undefined) {
      return {
        outcome: "missing",
        refusal: "Client authentication required via Basic auth",
      };
    }
    // The client_id half is not a secret, so a plain compare is fine.
    if (
      credentials === null ||
      credentials.clientId !== client.client_id ||
      !verifyClientSecret(
        credentials.clientSecret,
        client.client_secret,
        client.client_secret_salt,
      )
    ) {
      return { outcome: "invalid", refusal: "Invalid client credentials" };
    }
    return { outcome: "verified", refusal: "" };
  }
  if (client.token_endpoint_auth_method === "client_secret_post") {
    const { client_secret } = req.body;
    if (!client_secret) {
      return { outcome: "missing", refusal: "Invalid client secret" };
    }
    if (
      !verifyClientSecret(
        client_secret,
        client.client_secret,
        client.client_secret_salt,
      )
    ) {
      return { outcome: "invalid", refusal: "Invalid client secret" };
    }
    return { outcome: "verified", refusal: "" };
  }
  return null;
}

/**
 * Request parameters the token and revocation endpoints read, each defined by
 * RFC 6749 and RFC 7009 as a single string value.
 *
 * Both endpoints accept JSON and form bodies, and both parsers can hand a
 * handler something else for these names: JSON allows arrays, objects, numbers
 * and null, and the extended form parser turns `token[]=a` or a repeated key
 * into an array and `token[a]=b` into an object. Before this check such a
 * value reached hashing, string comparison or a database query. Hashing an
 * array or object throws, so /oauth/revoke answered 500 and wrote an error
 * line on every request without counting it against its failure budget, and
 * an array holding the right string could compare equal after coercion.
 */
const OAUTH_STRING_PARAMETERS = [
  "grant_type",
  "code",
  "redirect_uri",
  "code_verifier",
  "refresh_token",
  "client_id",
  "client_secret",
  "token",
] as const;

/** A parsed body the endpoints can read parameters from: a plain object. */
function isParameterObject(body: unknown): body is Record<string, unknown> {
  return typeof body === "object" && body !== null && !Array.isArray(body);
}

/**
 * The first supplied parameter from OAUTH_STRING_PARAMETERS whose value is not
 * a string, or null when every supplied one is a string. An absent parameter
 * is fine here; each grant decides for itself which ones it requires. The
 * returned name is one of the fixed names above, never request text, so it is
 * safe to echo in an error description.
 */
function firstNonStringParameter(body: Record<string, unknown>): string | null {
  for (const name of OAUTH_STRING_PARAMETERS) {
    if (Object.prototype.hasOwnProperty.call(body, name)) {
      if (typeof body[name] !== "string") {
        return name;
      }
    }
  }
  return null;
}

function refuseNonStringParameter(res: express.Response, name: string) {
  return res.status(400).json({
    error: "invalid_request",
    error_description: `The ${name} parameter must be a single string value`,
  });
}

/**
 * OAuth 2.0 Token Endpoint
 * Handles token exchange requests from MCP clients
 * Supports authorization_code and refresh_token grant types
 */
tokenRouter.post("/oauth/token", rateLimitToken, async (req, res) => {
  try {
    // Check if body was parsed correctly
    if (!req.body || typeof req.body !== "object") {
      logger.error("Token endpoint: req.body is undefined or invalid", {
        body: req.body,
        bodyType: typeof req.body,
        contentType: req.headers["content-type"],
        method: req.method,
      });
      return res.status(400).json({
        error: "invalid_request",
        error_description:
          "Request body is missing or malformed. Ensure Content-Type is application/json or application/x-www-form-urlencoded",
      });
    }

    // A JSON array is an object to `typeof` but carries no named parameters.
    // Refused here with the same answer as a missing body, and without
    // logging the body, which may hold credentials.
    if (!isParameterObject(req.body)) {
      return res.status(400).json({
        error: "invalid_request",
        error_description:
          "Request body is missing or malformed. Ensure Content-Type is application/json or application/x-www-form-urlencoded",
      });
    }

    // Before any parameter is hashed, compared or looked up, so a malformed
    // value can neither throw nor consume a code or refresh token. This route
    // keeps its request limiter (rateLimitToken) for repeated refusals.
    const nonString = firstNonStringParameter(req.body);
    if (nonString) {
      return refuseNonStringParameter(res, nonString);
    }

    const { grant_type } = req.body;

    if (grant_type === "refresh_token") {
      return handleRefreshTokenGrant(req, res);
    }

    if (grant_type === "authorization_code") {
      return handleAuthorizationCodeGrant(req, res);
    }

    return res.status(400).json({
      error: "unsupported_grant_type",
      error_description:
        "Supported grant types: authorization_code, refresh_token",
    });
  } catch (error) {
    logger.error("Error in OAuth token endpoint:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Internal server error",
    });
  }
});

/**
 * Handle grant_type=authorization_code
 */
async function handleAuthorizationCodeGrant(
  req: express.Request,
  res: express.Response,
) {
  const { code, redirect_uri, code_verifier } = req.body;

  // Resolved before anything is read, so a request naming two different
  // clients is refused without touching the code (see resolveRequestClientId).
  const resolvedClient = resolveRequestClientId(req);
  if (!resolvedClient.ok) {
    return refuseConflictingClientIds(res);
  }
  const client_id = resolvedClient.clientId;

  // Validate authorization code
  if (!code) {
    return res.status(400).json({
      error: "invalid_request",
      error_description: "Missing authorization code",
    });
  }

  // Look up the authorization code
  const codeData = await oauthRepository.getAuthCode(code);
  if (!codeData) {
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Invalid or expired authorization code",
    });
  }

  // Both expiry checks use the same event, before deleting the expired code:
  // it is the surviving evidence that the credential existed. The first
  // check precedes client authentication but is bounded by a real stored code.
  const emitCodeExpired = () => {
    emitTokenLifecycle(req, {
      action: "oauth.token.issue",
      clientId: codeData.client_id,
      userId: codeData.user_id,
      token: code,
      outcome: "failure",
      httpStatus: 400,
      detail: {
        reason: "authorization_code_expired",
        token_type: "authorization_code",
        grant_type: "authorization_code",
        created_at: isoOrNull(codeData.created_at),
        expires_at: isoOrNull(codeData.expires_at),
      },
    });
  };

  // Check if code has expired (the lifetime is set when it is minted, see
  // authorizationCodeTtlMs in ./authorization).
  if (Date.now() > codeData.expires_at.getTime()) {
    emitCodeExpired();
    await oauthRepository.deleteAuthCode(code);
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Authorization code has expired",
    });
  }

  // Validate client_id and redirect_uri match the original request
  if (codeData.client_id !== client_id) {
    return res.status(400).json({
      error: "invalid_client",
      error_description: "Client ID does not match",
    });
  }

  if (codeData.redirect_uri !== redirect_uri) {
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Redirect URI does not match",
    });
  }

  // Validate client_id against registered clients
  const clientData = await oauthRepository.getClient(client_id);
  if (!clientData) {
    return res.status(400).json({
      error: "invalid_client",
      error_description: "Client not found or not registered",
    });
  }

  // Client approval (migration 0042), from the live row, before the code is
  // consumed: a refused exchange leaves the code where it was. The consent
  // decision does not mint a code for a client that is not approved, so a
  // code reaching here for one predates a status change or was written
  // outside that path; either way it buys nothing. Approval only moves
  // pending to approved or rejected, so an approved row read here stays
  // approved through the consume below.
  if (!isOAuthClientApproved(clientData)) {
    logger.warn(
      `[oauth] token rejected reason=client_not_approved grant=authorization_code client=${codeData.client_id} user=${codeData.user_id}`,
    );
    return res.status(400).json(CLIENT_NOT_APPROVED_ERROR);
  }

  // Validate client authentication based on registered auth method. The row was
  // loaded by `client_id`, which already matched the code's client above, so
  // the Basic header's id is compared against the same value it always was.
  // For the "none" auth method there is nothing to evaluate (null).
  const clientAuth = evaluateClientCredentials(req, clientData);
  if (clientAuth && clientAuth.outcome !== "verified") {
    return res.status(401).json({
      error: "invalid_client",
      error_description: clientAuth.refusal,
    });
  }

  // OAuth 2.1 Security: PKCE is mandatory for all clients
  if (!codeData.code_challenge) {
    return res.status(400).json({
      error: "invalid_grant",
      error_description:
        "Authorization code was not issued with PKCE challenge",
    });
  }

  if (!code_verifier) {
    return res.status(400).json({
      error: "invalid_request",
      error_description: "PKCE code verifier is required",
    });
  }

  // Verify code challenge. Only S256 is honored — the "plain" method is
  // rejected rather than verified. The AS metadata advertises S256 only, and a
  // "plain" challenge equals the verifier and travels in the /oauth/authorize
  // query string (logged, left in browser history), so it gives no protection
  // against code interception. The authorize handler refuses to mint a "plain"
  // code, so a stored one is not reachable through the normal flow; this branch
  // is the defense-in-depth twin that refuses it here too.
  const crypto = await import("crypto");
  let challengeFromVerifier: string;

  if (codeData.code_challenge_method === "S256") {
    const hash = crypto.createHash("sha256").update(code_verifier).digest();
    challengeFromVerifier = hash.toString("base64url");
  } else {
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Unsupported code challenge method",
    });
  }

  if (challengeFromVerifier !== codeData.code_challenge) {
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "PKCE verification failed",
    });
  }

  // `users.disabled` enforcement (migration 0027). The authorize handler
  // already refuses to MINT a code for a disabled account, but a code minted
  // in the seconds before the admin pressed disable stays redeemable for its
  // full 10-minute TTL — and one redemption here buys a 24h access token plus
  // a 365d refresh token. Guarding only the mint would leave that ten-minute
  // window open on the exact credential chain the abuse turns on.
  //
  // Placed before the single-use delete below for the same reason as the
  // refresh path: a refused grant leaves no wreckage, so re-enabling the
  // account inside the TTL restores a working flow instead of a burnt code.
  if (await usersRepository.isDisabled(codeData.user_id)) {
    logger.warn(
      `[oauth] token rejected reason=disabled grant=authorization_code client=${codeData.client_id} user=${codeData.user_id}`,
    );
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Invalid or expired authorization code",
    });
  }

  // Code is valid; consume it atomically. Single-use is enforced by the DELETE
  // itself (consumeAuthCode is DELETE ... RETURNING), not by the earlier read:
  // on two concurrent redemptions of the same code only one delete removes the
  // row, so exactly one caller proceeds and the loser is refused invalid_grant
  // rather than both minting a token pair for the same code.
  //
  // The consume and the insert of the new pair run in ONE transaction under
  // the user's OAuth credential lock, the lock users.revokeAccess takes before
  // it deletes codes and tokens. Without it a code consumed just before a
  // revoke committed could still insert its pair after the revoke, leaving a
  // live credential the administrator was told was gone. A failed insert rolls
  // the consume back with it. A new authorization code grant starts a new
  // refresh-token family.
  const issued = await oauthRepository.withUserLock(
    codeData.user_id,
    async (tx) => {
      // Waiting for the user lock can outlast the code or an administrator's
      // disable. Re-check both here before consuming it; a disabled account
      // keeps its code so re-enabling it within the TTL restores the flow.
      if (Date.now() > codeData.expires_at.getTime()) {
        emitCodeExpired();
        await oauthRepository.consumeAuthCode(code, tx);
        return null;
      }
      if (await usersRepository.isDisabled(codeData.user_id, tx)) {
        logger.warn(
          `[oauth] token rejected reason=disabled grant=authorization_code client=${codeData.client_id} user=${codeData.user_id}`,
        );
        return null;
      }
      const consumed = await oauthRepository.consumeAuthCode(code, tx);
      if (!consumed) {
        return null;
      }
      return issueTokenPair(
        codeData.client_id,
        codeData.user_id,
        codeData.scope,
        randomUUID(),
        tx,
      );
    },
  );
  if (!issued) {
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Invalid or expired authorization code",
    });
  }
  const { accessToken, refreshToken } = issued;

  logTokenIssued({
    grantType: "authorization_code",
    clientId: codeData.client_id,
    clientName: clientData.client_name,
    userId: codeData.user_id,
    accessToken,
  });

  // After the transaction above committed the row: a token that failed to
  // persist must not leave a row saying it was issued.
  emitTokenIssued(req, {
    action: "oauth.token.issue",
    grantType: "authorization_code",
    clientId: codeData.client_id,
    clientName: clientData.client_name,
    userId: codeData.user_id,
    accessToken,
  });

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_EXPIRY,
    refresh_token: refreshToken,
    scope: codeData.scope,
  });
}

/**
 * Handle grant_type=refresh_token
 * Issues a new access token + refresh token pair (token rotation).
 *
 * ATOMIC ROTATION. A refresh token is single-use, and a rotation is three
 * writes: claim the presented token, record it as rotated out, insert the new
 * pair. All three run in ONE transaction under the user's OAuth credential
 * lock (../../db/repositories/oauth-user-lock), and the claim is a
 * DELETE ... RETURNING on the presented token's hash, so of two requests
 * presenting the same token exactly one gets a row back and only that one
 * mints. users.revokeAccess, reuse detection's family revoke and /oauth/revoke
 * take the same lock before deleting, so a refresh in flight can no longer
 * insert a pair after a revoke committed: it waits, re-reads, and finds
 * nothing to rotate.
 *
 * The unlocked lookup at the top only identifies whose lock to take. Every
 * check that decides the outcome (expiry, client binding, client
 * authentication, disabled account) runs again on the row re-read under the
 * lock, before the claim, so a refused request never consumes the token.
 *
 * STRICT REUSE, KEPT ON PURPOSE. A request that loses the race for a token
 * finds it already rotated out and takes the reuse path, which revokes the
 * whole family, including the pair the winner just received. So a client
 * that retries a refresh whose reply it lost must sign in again. That is the
 * existing reuse policy (migration 0037) applied consistently: the server
 * cannot tell a lost reply from a stolen token presented twice, and a grace
 * window for replays would hand the thief the same window.
 */
async function handleRefreshTokenGrant(
  req: express.Request,
  res: express.Response,
) {
  const { refresh_token } = req.body;

  // Before the token is read, so a request naming two different clients
  // neither rotates nor revokes anything (see resolveRequestClientId). A
  // `client_secret_basic` client's id now comes from its header, which is what
  // makes the client check below apply to it instead of being skipped.
  const resolvedClient = resolveRequestClientId(req);
  if (!resolvedClient.ok) {
    return refuseConflictingClientIds(res);
  }
  const client_id = resolvedClient.clientId;

  if (!refresh_token) {
    return res.status(400).json({
      error: "invalid_request",
      error_description: "Missing refresh_token parameter",
    });
  }

  // Whose lock to take. A live row or a rotated-out marker both name the
  // owning user; nothing else is decided from this unlocked read.
  const preliminary = await oauthRepository.getByRefreshToken(refresh_token);
  const ownerId =
    preliminary?.user_id ??
    (await oauthRepository.getRotatedRefreshToken(refresh_token))?.user_id;
  if (!ownerId) {
    return refuseInvalidRefreshToken(res);
  }

  const clientAuthMode = resolveRefreshClientAuthMode();
  const outcome = await oauthRepository.withUserLock(ownerId, (tx) =>
    rotateRefreshTokenLocked(req, tx, refresh_token, client_id, clientAuthMode),
  );

  switch (outcome.kind) {
    case "invalid":
      // Byte-identical for an unknown token, a detected reuse and a disabled
      // account: a holder of a stolen or stale refresh token learns only "this
      // no longer works", never that they tripped detection.
      return refuseInvalidRefreshToken(res);
    case "expired":
      return res.status(400).json({
        error: "invalid_grant",
        error_description: "Refresh token has expired",
      });
    case "client_mismatch":
      return res.status(400).json({
        error: "invalid_client",
        error_description: "Client ID does not match",
      });
    case "client_refused":
      return res.status(401).json({
        error: "invalid_client",
        error_description: outcome.refusal,
      });
    case "client_not_approved":
      return res.status(400).json(CLIENT_NOT_APPROVED_ERROR);
    case "issued":
      break;
  }

  const { tokenData, accessToken, refreshToken, clientAuth } = outcome;

  // Everything below runs after the transaction committed, so a pair that
  // failed to persist never leaves an issued line or audit row behind.
  //
  // `rotated=true` is unconditional here because this handler always mints a
  // replacement refresh token and deletes the redeemed one above. It is logged
  // anyway so the 48h traffic read can tell a rotating client from a client that
  // is somehow reusing a refresh token, without re-reading this file.
  logTokenIssued({
    grantType: "refresh_token",
    clientId: tokenData.client_id,
    userId: tokenData.user_id,
    accessToken,
    rotatedRefreshToken: true,
    clientAuth: clientAuth?.outcome,
  });

  emitTokenIssued(req, {
    action: "oauth.token.refresh",
    grantType: "refresh_token",
    clientId: tokenData.client_id,
    userId: tokenData.user_id,
    accessToken,
    clientAuth: clientAuth?.outcome,
  });

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_EXPIRY,
    refresh_token: refreshToken,
    scope: tokenData.scope,
  });
}

function refuseInvalidRefreshToken(res: express.Response) {
  return res.status(400).json({
    error: "invalid_grant",
    error_description: "Invalid refresh token",
  });
}

type RefreshRotationOutcome =
  | { kind: "invalid" }
  | { kind: "expired" }
  | { kind: "client_mismatch" }
  | { kind: "client_refused"; refusal: string }
  | { kind: "client_not_approved" }
  | {
      kind: "issued";
      tokenData: { client_id: string; user_id: string; scope: string };
      accessToken: string;
      refreshToken: string;
      clientAuth: ReturnType<typeof evaluateClientCredentials>;
    };

/**
 * Reuse detection (migration 0037), run under the owner's credential lock.
 *
 * The presented token is not live, but it may be one this family already
 * rotated OUT. Refresh tokens are single-use, so a rotated-out token presented
 * again is reuse: either the legitimate client is a step behind (its rotation
 * reply was lost, or it lost a race with its own duplicate request) or the
 * token was stolen and the thief rotated it. Both are handled the safe way,
 * revoke the whole family, because the two are indistinguishable at the wire
 * and leaving the live chain running is the failure that matters. The reuse
 * row is emitted BEFORE the revoke, and never awaited, for the reason
 * emitTokenLifecycle documents: the record has to survive a delete that
 * throws, and the delete is exactly what destroys the family being
 * investigated. Collapsing the family (live rows AND markers) makes a replay
 * after revocation find no marker and fall through to the unknown-token
 * response: one reuse row per family compromise, not one per replay.
 *
 * The family revoke reuses the caller's `tx`; it must not open a second
 * transaction for a user whose lock this one already holds.
 */
async function revokeReusedFamilyLocked(
  req: express.Request,
  tx: OAuthTx,
  refreshToken: string,
): Promise<void> {
  const reused = await oauthRepository.getRotatedRefreshToken(refreshToken, tx);
  if (!reused) {
    return;
  }
  emitTokenLifecycle(req, {
    action: "oauth.token.reuse",
    clientId: reused.client_id,
    userId: reused.user_id,
    token: refreshToken,
    outcome: "denied",
    httpStatus: 400,
    detail: {
      reason: "refresh_token_reuse",
      family_id: reused.family_id,
    },
  });
  const revoked = await oauthRepository.revokeFamily(reused.family_id, tx);
  logger.warn(
    `[oauth] refresh token reuse detected; family revoked ` +
      `client=${reused.client_id} user=${reused.user_id} tokens_revoked=${revoked}`,
  );
}

/**
 * The refresh grant's decisions and writes, inside the owner's credential lock.
 * Every query goes through `tx`: a query on the shared pool from inside this
 * callback would hold one pool connection while waiting for another, and
 * enough concurrent refreshes doing that would exhaust the pool.
 */
async function rotateRefreshTokenLocked(
  req: express.Request,
  tx: OAuthTx,
  refresh_token: string,
  client_id: string | undefined,
  clientAuthMode: RefreshClientAuthMode,
): Promise<RefreshRotationOutcome> {
  // Re-read under the lock: every row committed before the lock was granted
  // is visible now, so a rotation or revoke that won the race shows here.
  const tokenData = await oauthRepository.getByRefreshToken(refresh_token, tx);
  if (!tokenData) {
    await revokeReusedFamilyLocked(req, tx, refresh_token);
    return { kind: "invalid" };
  }

  // Check refresh token expiry. A NULL expiry is treated as expired, NOT as
  // "valid forever": a row with a refresh token and no expiry is the
  // never-reaped shape (see migration 0035), and honoring it would
  // make it an immortal credential. Migration 0035's CHECK makes that shape
  // unrepresentable going forward; this guard is the defense-in-depth twin that
  // refuses a legacy row if one ever presents it.
  if (
    !tokenData.refresh_token_expires_at ||
    Date.now() > tokenData.refresh_token_expires_at.getTime()
  ) {
    // Emitted BEFORE the delete, and never awaited — `emit` is fire-and-forget
    // by contract (see lib/audit/audit-emitter). Ordering it first is what
    // makes the record survive a delete that throws: the whole point of the
    // row is that the credential it describes no longer exists to be looked
    // up, so writing it after the destruction would lose it in exactly the
    // case an operator is investigating.
    emitTokenLifecycle(req, {
      action: "oauth.token.refresh",
      clientId: tokenData.client_id,
      userId: tokenData.user_id,
      // The refresh token as PRESENTED — `token_sha256` in the row. It is a
      // different string from the access token in the same row, which is
      // recorded separately below.
      token: refresh_token,
      outcome: "failure",
      httpStatus: 400,
      detail: {
        reason: "refresh_token_expired",
        token_type: "refresh_token",
        // The destroyed row's ACCESS token, under the same keys
        // `emitTokenIssued` writes — this is the join back to the
        // `oauth.token.issue` / `oauth.token.refresh` row that minted the
        // chain, which is the only place its age is now recorded. Since
        // migration 0036 the stored `access_token` IS the sha256 the audit log
        // records, and `access_token_last4` its tail, so they are used directly
        // passing the stored hash through credentialFingerprint would hash it
        // a second time and break the join.
        access_token_sha256: tokenData.access_token,
        access_token_last4: tokenData.access_token_last4,
        created_at: isoOrNull(tokenData.created_at),
        expires_at: isoOrNull(tokenData.expires_at),
        refresh_token_expires_at: isoOrNull(tokenData.refresh_token_expires_at),
      },
    });
    await oauthRepository.deleteAccessTokenByHash(tokenData.access_token, tx);
    return { kind: "expired" };
  }

  // Validate client_id matches (if provided)
  if (client_id && tokenData.client_id !== client_id) {
    return { kind: "client_mismatch" };
  }

  // Confidential-client authentication (RFC 6749 section 6), per
  // OAUTH_REFRESH_CLIENT_AUTH_ENV. The client is the one the token was ISSUED
  // to, not whatever the request names: a request that named a different
  // client was refused just above, and one that named none is still the
  // token's client, so this is the row whose secret must be shown.
  //
  // Before the disabled check and the claim below, for the reason the
  // disabled check gives: a refusal here must leave the token row intact, so a
  // misconfigured client that is fixed can still refresh.
  const clientData = await oauthRepository.getClient(tokenData.client_id, tx);
  if (!clientData) {
    // Unreachable except in a race: access tokens reference oauth_clients with
    // ON DELETE CASCADE, so a token cannot outlive its client row. Without a
    // row there is no method to judge by and no approval to check. `enforce`
    // keeps its own refusal; `log` falls through to the approval check below,
    // which refuses a missing row in every mode (before, `log` proceeded and
    // the mint failed on the foreign key, rolling the claim back).
    logger.warn(
      `[oauth] refresh client auth outcome=client_not_found mode=${clientAuthMode} client=${tokenData.client_id} user=${tokenData.user_id}`,
    );
    if (clientAuthMode === "enforce") {
      return {
        kind: "client_refused",
        refusal: "Client not found or not registered",
      };
    }
  }

  // Client approval (migration 0042), from the row the TOKEN names, so a
  // request that omits client_id is still judged against its client, and in
  // both OAUTH_REFRESH_CLIENT_AUTH modes. Before the claim, the rotated
  // marker and the mint, so a refusal consumes, records and deletes nothing
  // and the row stays exactly as it was. Not audited, by the doctrine on
  // emitTokenLifecycle: a refusal that destroys nothing would write a row
  // per replay. The log line is the record.
  if (!isOAuthClientApproved(clientData)) {
    logger.warn(
      `[oauth] token rejected reason=client_not_approved grant=refresh_token client=${tokenData.client_id} user=${tokenData.user_id}`,
    );
    return { kind: "client_not_approved" };
  }

  // client_secret is a string or absent here: the endpoint refuses any other
  // type before a grant handler runs (firstNonStringParameter).
  const clientAuth = clientData
    ? evaluateClientCredentials(req, clientData)
    : null;
  if (clientAuth && clientAuth.outcome !== "verified") {
    if (clientAuthMode === "enforce") {
      // Not audited, by the doctrine on emitTokenLifecycle: the refusal
      // destroys nothing, so it is not self-limiting and a replay would write
      // a row per attempt. The log line is the record, matching the disabled
      // refusal below.
      logger.warn(
        `[oauth] token rejected reason=client_auth_${clientAuth.outcome} grant=refresh_token ` +
          `method=${clientData?.token_endpoint_auth_method} client=${tokenData.client_id} user=${tokenData.user_id}`,
      );
      return { kind: "client_refused", refusal: clientAuth.refusal };
    }
    // `log`: record and proceed. The issued line and the audit row below carry
    // the same outcome; this WARN is what makes an unauthenticated refresh
    // stand out before enforcement is switched on.
    logger.warn(
      `[oauth] refresh client auth outcome=${clientAuth.outcome} mode=log ` +
        `method=${clientData?.token_endpoint_auth_method} client=${tokenData.client_id} user=${tokenData.user_id}`,
    );
  }

  // `users.disabled` enforcement (migration 0027) — the plane the 2026-08-13
  // attacker actually held. Refresh tokens live 365 days in this fork and the
  // authorize handler is nowhere on this path, so without this check a
  // disabled account keeps minting fresh 24h access tokens for a year from a
  // credential it already has. Disable has to mean the NEXT request fails, and
  // this is the request it makes.
  //
  // Deliberately placed BEFORE the claim below: disable is a reversible
  // lockout, not a revocation. Rejecting after the claim would destroy the
  // token row and permanently break the connector even after an admin presses
  // Enable, quietly turning Disable into Revoke. Leaving the row intact costs
  // nothing — this check re-runs and refuses on every retry for as long as the
  // account stays disabled.
  //
  // The response is byte-identical to the unknown-refresh-token branch. A
  // holder of a stolen refresh token learns only "this no longer works", not
  // that they tripped an admin lock — the `reason=disabled` distinction lives
  // in the server log, where the operator reads it and the attacker does not.
  if (await usersRepository.isDisabled(tokenData.user_id, tx)) {
    logger.warn(
      `[oauth] token rejected reason=disabled grant=refresh_token client=${tokenData.client_id} user=${tokenData.user_id}`,
    );
    return { kind: "invalid" };
  }

  // The single-use gate. Only a caller that gets exactly one live row back
  // may mint. Under the lock the row read above is still there, unless a
  // writer that does not take the lock (the expiry sweeper, a client-delete
  // cascade) removed it in between; that case takes the reuse path like any
  // other missing token.
  const claimed = await oauthRepository.claimRefreshToken(refresh_token, tx);
  if (claimed.length !== 1) {
    await revokeReusedFamilyLocked(req, tx, refresh_token);
    return { kind: "invalid" };
  }
  const row = claimed[0];

  // Record the rotated-out refresh token so a later presentation of it is
  // detected as reuse (migration 0037). The marker is keyed on the stored hash
  // (row.refresh_token is already that digest), so it is passed through
  // unchanged rather than re-hashed. The row was claimed BY its refresh token
  // and passed the expiry guard above, so both values are present; the guard
  // only satisfies the nullable column types. Same transaction as the claim,
  // so there is no instant at which the token is neither live nor marked.
  if (row.refresh_token && row.refresh_token_expires_at) {
    await oauthRepository.recordRotatedRefreshToken(
      {
        refreshTokenHash: row.refresh_token,
        familyId: row.family_id,
        clientId: row.client_id,
        userId: row.user_id,
        expiresAt: row.refresh_token_expires_at,
      },
      tx,
    );
  }

  // Issue the new pair. It inherits the rotated row's family, so reuse of any
  // rotated-out member revokes the whole chain.
  const { accessToken, refreshToken } = await issueTokenPair(
    row.client_id,
    row.user_id,
    row.scope,
    row.family_id,
    tx,
  );

  return {
    kind: "issued",
    tokenData: row,
    accessToken,
    refreshToken,
    clientAuth,
  };
}

/**
 * Render a row timestamp for `detail`, tolerating a missing or null value.
 *
 * `refresh_token_expires_at` is genuinely nullable in the schema, and the
 * remaining columns are only NOT NULL as far as the type system is concerned —
 * an emitter that called `.toISOString()` straight would turn one unexpected
 * null into a throw on a rejection path, i.e. a 500 on a request that was
 * already being refused. A null in the column is also honest output: it says
 * the row carried no such instant.
 */
function isoOrNull(value: Date | null | undefined): string | null {
  return value instanceof Date ? value.toISOString() : null;
}

/**
 * Record a lifecycle event for a credential that ACTUALLY EXISTS — issued,
 * refreshed, introspected, revoked, or REJECTED AND DESTROYED.
 *
 * WHAT IS AND IS NOT EMITTED HERE, because /oauth/revoke is unauthenticated
 * and `audit_log` has no prune path. The two public endpoints carry a
 * FAILURE-only limiter (see isPublicOAuthEndpointLimited below), which bounds
 * unresolvable-token spam but deliberately does NOT bound the success paths —
 * so every "is this branch replayable?" judgement below still stands
 * unchanged:
 *
 *  - UNKNOWN token, either endpoint: NOTHING. One anonymous request would
 *    equal one permanent INSERT recording a string the caller invented, and
 *    RFC 7009 requires /oauth/revoke to answer 200 to garbage, so the flood is
 *    not even distinguishable at the wire.
 *  - REVOKE of a real token: emitted. It is self-limiting — revocation
 *    DELETES the row, so a replay of the same token finds nothing and writes
 *    nothing. One row per credential killed, which is the forensic record.
 *  - INTROSPECT reporting ACTIVE: deliberately NOT emitted. Introspection does
 *    not consume the token, so unlike revoke it is unbounded: whoever holds
 *    one stolen credential — the 2026-08-13 scenario exactly — can replay it
 *    forever, each replay a permanent row. And the event has little to add:
 *    `oauth.token.issue` already recorded that this credential exists, under
 *    the same fingerprint. The failure-only limiter does not change this: a
 *    caller replaying a REAL token never scores against it, by design, so the
 *    branch is exactly as unbounded as it was. Bounding the ROW COUNT needs a
 *    prune path on `audit_log`, not a limiter on the endpoint.
 *  - INTROSPECT reporting INACTIVE because the ACCOUNT IS DISABLED: emitted.
 *    That one is bounded by the same argument in reverse — it requires a real
 *    token belonging to a locked-out account, i.e. a credential an
 *    administrator has already acted against, and a relying party still asking
 *    about it is exactly what an operator wants to see.
 *  - REVOKE refused because the CLIENT DOES NOT MATCH: emitted, and it is the
 *    highest-signal event either endpoint produces. Same bound as the two
 *    above: it cannot be reached without presenting a REAL, currently-issued
 *    token, and it is rate-limited on top, so it is not replay amplification.
 *    A caller naming a different client than the token was issued to is not a
 *    confused client.
 *  - REFRESH-TOKEN REUSE that revokes a family (migration 0037): emitted, and
 *    it is the highest-signal event on the grant half of /oauth/token. It is
 *    reachable only by presenting a refresh token that was already rotated OUT
 *    of a live family, and detection COLLAPSES the family — the live rows and
 *    the rotated-token markers alike — so a replay of the same token afterwards
 *    finds no marker and falls through to the silent unknown-token path. That
 *    is the bound: one reuse row per family compromise, not one per replay,
 *    which is tighter than the destroy-attempt bound below. `outcome` is
 *    `denied` rather than `failure`, so a query for active attacks filters on
 *    it. Emit-first here too — the revoke is the delete that must not be able to
 *    lose the record.
 *  - A REJECTION THAT DESTROYS THE ROW IT JUST READ: emitted. Three branches
 *    qualify — an EXPIRED AUTHORIZATION CODE and an EXPIRED REFRESH TOKEN on
 *    /oauth/token, and an EXPIRED ACCESS TOKEN on /oauth/introspect. Each is
 *    bounded by exactly the argument that admits revoke above: it cannot be
 *    reached without presenting a REAL, currently-stored credential, and
 *    reaching it DELETES that credential, so a replay of the same string finds
 *    nothing and writes nothing. One row per credential destroyed. These were
 *    the only deletes in this file that left no trace anywhere — not even a
 *    `logger` line — so a stale credential simply vanished, and with it the
 *    only evidence of when the chain behind it was minted. That is what the
 *    `created_at` / `expires_at` / `refresh_token_expires_at` values in
 *    `detail` are for: they date the chain that just ended, and the destroyed
 *    row's `access_token_sha256` joins this row to the `oauth.token.issue` row
 *    that minted it.
 *  - Every OTHER refusal on the grant half of /oauth/token — missing or
 *    mismatched client, bad client secret (on either grant, including the
 *    refresh grant's `OAUTH_REFRESH_CLIENT_AUTH=enforce` refusal), PKCE
 *    failure, unknown code, unknown refresh token, disabled account: still
 *    NOTHING here. None of them
 *    destroys a row, so none is self-limiting; an invented code or refresh
 *    token can be replayed forever. The two disabled-account refusals also
 *    leave the row deliberately intact, because disable must stay reversible,
 *    and they already carry a `logger.warn`.
 *
 * THE RESIDUAL ON THAT BOUND, STATED PLAINLY RATHER THAN IMPLIED AWAY: it is
 * one row per destroy ATTEMPT, not per credential. Read-then-delete is not
 * atomic and neither delete reports whether it removed anything —
 * `deleteAccessToken` and `deleteAuthCode` both return void — so N concurrent
 * presentations of the SAME expired credential each read the row before the
 * first delete commits, and each writes a row. /oauth/token is per-edge-IP
 * limited by `rateLimitToken`, /oauth/introspect sits behind the failure
 * limiter plus the RFC 7662 credential gate, and GET /oauth/userinfo now
 * carries the same failure-only limiter (see userinfo.ts) — but that limiter
 * counts failures rather than successes, so a burst of the SAME expired token
 * can still spend a window's worth of destroy-emits before the bucket fills.
 * Emit-first is the half of
 * that trade being kept ON PURPOSE: the record has to survive a delete that
 * throws, which is the case an operator is investigating, and buying
 * exactly-once instead would mean gating the emit on a delete that returns a
 * row count — trading the forensic guarantee for a counting one. So the bound
 * is one BURST per real credential, once, where the same burst wrote zero rows
 * before these emitters existed. Bounding it further needs the prune path on
 * `audit_log`, same as the introspect-active case above.
 *
 * GET /oauth/userinfo has the same destroy-on-expiry branch and emits the same
 * shape, but from ./userinfo.ts — this emitter is private to the token router.
 *
 * A FAILURE ROW REUSES THE VERB OF THE OPERATION IT REFUSED (`oauth.token.issue`
 * for a dead authorization code, `oauth.token.refresh` for a dead refresh
 * token) rather than inventing a `*.expired` verb, matching the revoke
 * client-mismatch row above. `outcome` is what separates them, so any query
 * counting successful grants must filter on `outcome = 'success'` and not on
 * `action` alone.
 *
 * The credential is recorded as a fingerprint only, matching `emitTokenIssued`,
 * so an operator can follow one credential from mint to destruction by hash.
 */
function emitTokenLifecycle(
  req: express.Request,
  fields: {
    action:
      | "oauth.token.issue"
      | "oauth.token.refresh"
      | "oauth.token.introspect"
      | "oauth.token.revoke"
      | "oauth.token.reuse";
    clientId: string;
    userId: string;
    token: string;
    // `denied` is the reuse verb's outcome (migration 0037): a refused request
    // that also acted against the caller (it revoked the family), which a query
    // for active attacks can filter on distinctly from a plain `failure`.
    outcome: "success" | "failure" | "denied";
    /**
     * Defaults to 200 because every other caller here answers 200 — including
     * the refusals, which is the point of RFC 7662's `{active:false}` and RFC
     * 7009's 200-to-garbage. The client-mismatch refusal is the one that does
     * not, and a row claiming 200 for a 400 would misreport the only wire fact
     * the table carries about that request.
     */
    httpStatus?: number;
    detail?: Record<string, unknown>;
  },
): void {
  const audit = auditRequestContext(req);
  const fingerprint = credentialFingerprint(fields.token);
  emit({
    actor_type: "user",
    actor_id: fields.userId,
    actor_label: null,
    actor_ip: audit.actor_ip,
    actor_user_agent: audit.actor_user_agent,
    action: fields.action,
    target_type: "oauth_client",
    target_id: fields.clientId,
    outcome: fields.outcome,
    request_id: audit.request_id,
    http_status: fields.httpStatus ?? 200,
    detail: {
      token_sha256: fingerprint.sha256,
      token_last4: fingerprint.last4,
      ...(fields.detail ?? {}),
    },
  });
}

/**
 * Failure-only rate limiting for /oauth/introspect and /oauth/revoke.
 *
 * /oauth/revoke takes no credential and cannot: the clients are secretless
 * public PKCE clients, revocation already requires the token value, and
 * destroying a credential is the safe direction to fail. Bounding that traffic
 * by FAILURE is the substitute, and it has to be by failure rather than by
 * request: a request-count budget would refuse a busy client's legitimate
 * revocations along with everything else from its address.
 *
 * /oauth/introspect now DOES require one (see ./introspection-auth, which
 * carries the RFC 7662 §2.1 reasoning). It keeps this limiter regardless,
 * running ahead of the credential check so that anonymous spraying is bounded
 * by the same budget as unresolvable tokens instead of being free.
 *
 * A caller presenting a token this server issued therefore never scores, no
 * matter how often it asks. Only tokens that resolve to nothing — invented,
 * expired, or presented with a client_id they were not issued to — count.
 *
 * KEYED PER EDGE CLIENT ADDRESS (CF-Connecting-IP), per route; see
 * getPublicOAuthRateLimitIdentifier in lib/auth-rate-limiter for the keying,
 * its fallback chain and the tunnel-only-ingress assumption it rests on.
 * `trust proxy` is off, so `req.ip` alone would be one in-container address
 * for every caller, and these routes keyed on it until that function moved to
 * the edge address.
 *
 * THE RESIDUAL, STATED PLAINLY: failure-only makes legitimate traffic
 * incapable of filling a bucket, but a bucket is per source address, so
 * clients sharing one egress address (an office NAT) share its budget, and a
 * client over budget is refused even when it then presents a valid token.
 * That is accepted because the gateway's own traffic no longer arrives here at
 * all: `api-key-oauth.middleware.ts` reads the token row in-process, so no MCP
 * client depends on this endpoint answering. Anything that reintroduces an
 * internal caller must revisit this decision first.
 *
 * Split into check and record on purpose: the check runs BEFORE the database
 * lookup, so refusing costs nothing, and `isCurrentlyLimited` is used rather
 * than `isRateLimited` because the latter counts the question it is asked.
 */
function isPublicOAuthEndpointLimited(
  req: express.Request,
  route: "introspect" | "revoke",
): boolean {
  return authRateLimiter.isCurrentlyLimited(
    getPublicOAuthRateLimitIdentifier(req, route),
  );
}

function recordPublicOAuthEndpointFailure(
  req: express.Request,
  route: "introspect" | "revoke",
): void {
  authRateLimiter.recordFailedAttempt(
    getPublicOAuthRateLimitIdentifier(req, route),
  );
}

function sendPublicOAuthEndpointRateLimited(
  res: express.Response,
  route: "introspect" | "revoke",
): express.Response {
  logger.info(
    `[RATE LIMIT] /oauth/${route} rate limited after repeated unresolvable tokens`,
  );
  return res.status(429).json({
    error: "too_many_requests",
    error_description: "Too many failed token lookups. Please try again later.",
  });
}

/**
 * OAuth 2.0 Token Introspection Endpoint
 * Allows first-party resource servers to introspect access tokens
 */
tokenRouter.post("/oauth/introspect", async (req, res) => {
  try {
    if (isPublicOAuthEndpointLimited(req, "introspect")) {
      return sendPublicOAuthEndpointRateLimited(res, "introspect");
    }

    // RFC 7662 §2.1: this endpoint MUST require authorization, and until now
    // it required none — an anonymous caller could ask it whether any token
    // value was live and get back `scope`, `client_id` and `sub`. See
    // ./introspection-auth for what credential is required, why an API key is
    // the right one, and why /oauth/revoke is deliberately left public.
    //
    // Placed AFTER the limiter check and counted as a failure, so anonymous
    // requests are bounded by the same per-client budget as unresolvable
    // tokens rather than being free. The residual is the one already
    // documented on isPublicOAuthEndpointLimited (clients sharing an egress
    // address share a budget); it was accepted when no legitimate caller
    // depended on this route, and gating it does not change who depends on it.
    const credential = await requireIntrospectionCredential(req);
    // A real key refused by its IP policy (migration 0041): 403 with the
    // generic body, and NOT recorded against the failed-lookup limiter, ahead
    // of the invalid-credential branch below, mirroring the data plane. No
    // audit row here: the policy module already wrote the throttled one.
    if (!credential.ok && credential.reason === "ip_not_allowed") {
      return res.status(403).json({
        error: "access_denied",
        error_description: CREDENTIAL_NOT_PERMITTED_MESSAGE,
      });
    }
    if (!credential.ok) {
      recordPublicOAuthEndpointFailure(req, "introspect");
      logger.info(
        `[oauth] introspect refused reason=${credential.reason} — RFC 7662 requires an authenticated caller`,
      );
      // 401 with a challenge, per RFC 7662 §2.3. No audit row: the request
      // carries no identity to attribute one to, and an anonymous caller who
      // can be refused for free must not be able to write to `audit_log`,
      // which has no prune path.
      return res
        .status(401)
        .set("WWW-Authenticate", 'Bearer realm="oauth-introspection"')
        .json({
          error: "invalid_client",
          error_description:
            "Token introspection requires a first-party API key",
        });
    }

    // Check if body was parsed correctly
    if (!req.body || typeof req.body !== "object") {
      recordPublicOAuthEndpointFailure(req, "introspect");
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Request body is missing or malformed",
      });
    }

    const { token } = req.body;

    if (!token) {
      recordPublicOAuthEndpointFailure(req, "introspect");
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Missing token parameter",
      });
    }

    // Check if token exists and is valid
    const tokenData = await oauthRepository.getAccessToken(token);

    if (!tokenData || !token.startsWith("mcp_token_")) {
      recordPublicOAuthEndpointFailure(req, "introspect");
      return res.json({
        active: false,
      });
    }

    // Check if token has expired
    if (Date.now() > tokenData.expires_at.getTime()) {
      // Counted: an expired token is still a token that resolves to nothing,
      // and a caller replaying one indefinitely is the shape being bounded. A
      // real client hits this at most once, when its own token ages out.
      recordPublicOAuthEndpointFailure(req, "introspect");
      // Emitted before the delete, same reasoning as the grant-half branches.
      // No `httpStatus`: RFC 7662 answers an inactive token with 200 and
      // `{active:false}`, which is the emitter's default.
      //
      // `refresh_token_expires_at` is in the row deliberately. This delete
      // takes the WHOLE row, so a refresh token that had not itself expired
      // dies with the access token — the record has to show what was
      // destroyed, not just what was asked about.
      emitTokenLifecycle(req, {
        action: "oauth.token.introspect",
        clientId: tokenData.client_id,
        userId: tokenData.user_id,
        token,
        outcome: "failure",
        detail: {
          active: false,
          reason: "access_token_expired",
          token_type: "access_token",
          created_at: isoOrNull(tokenData.created_at),
          expires_at: isoOrNull(tokenData.expires_at),
          refresh_token_expires_at: isoOrNull(
            tokenData.refresh_token_expires_at,
          ),
        },
      });
      await oauthRepository.deleteAccessToken(token);
      return res.json({
        active: false,
      });
    }

    // `users.disabled` enforcement (migration 0027). Introspection is the
    // authoritative "is this credential live?" answer a resource server asks
    // for, and the token row knows nothing about the account behind it — so
    // without this check a locked-out account's still-unexpired token reports
    // `active: true` along with its scope, client_id and `sub`. That both
    // tells a relying party to honour a credential every other plane now
    // refuses, and confirms to whoever holds the token that the account is
    // still there.
    //
    // `{ active: false }` alone is the correct wire answer rather than an
    // error: RFC 7662 §2.2 defines `active` as covering a token that has been
    // revoked or otherwise invalidated by the resource owner, and requires
    // that no other member be returned for an inactive token.
    //
    // The row is deliberately NOT deleted here (contrast the expiry branch
    // above): disable is a reversible lockout, and deleting would turn it
    // into a revocation that outlives Enable.
    //
    // The check lives in this handler rather than in the introspection helper
    // `middleware/api-key-oauth.middleware.ts` calls, which stays a pure
    // token-row lookup — the data plane it feeds does its own isDisabled
    // check on the resolved identity, and one plane's account policy has no
    // business hiding inside the other's lookup.
    //
    // Deliberately NOT counted against the failure limiter: the credential is
    // real and was issued by this server, so a relying party asking about it
    // is a legitimate caller doing the right thing. Counting it would let one
    // locked-out account's still-running client spend the per-address budget
    // and refuse everyone sharing its address, which this limiter is shaped
    // to avoid.
    if (await usersRepository.isDisabled(tokenData.user_id)) {
      logger.warn(
        `[oauth] introspect reported inactive reason=disabled client=${tokenData.client_id} user=${tokenData.user_id}`,
      );
      emitTokenLifecycle(req, {
        action: "oauth.token.introspect",
        clientId: tokenData.client_id,
        userId: tokenData.user_id,
        token,
        outcome: "failure",
        detail: { active: false, reason: "disabled" },
      });
      return res.json({
        active: false,
      });
    }

    // No audit row on this branch — see emitTokenLifecycle's header. An
    // active introspection does not consume the token, so it is the one
    // outcome in this file an attacker can replay without limit.

    // Token is active, return introspection details
    res.json({
      active: true,
      scope: tokenData.scope,
      client_id: tokenData.client_id,
      token_type: "Bearer",
      exp: Math.floor(tokenData.expires_at.getTime() / 1000),
      iat: Math.floor(tokenData.created_at.getTime() / 1000),
      sub: tokenData.user_id,
    });
  } catch (error) {
    logger.error("Error in OAuth introspect endpoint:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Internal server error",
    });
  }
});

/**
 * OAuth 2.0 Token Revocation Endpoint
 * Allows clients to revoke access tokens or refresh tokens
 *
 * DELIBERATELY UNAUTHENTICATED, and it is the only public OAuth endpoint left
 * that way after `/oauth/introspect` was gated. That asymmetry is a decision,
 * not an oversight, so it is recorded here where the next reviewer will look
 * rather than only in ./introspection-auth.ts.
 *
 * The two endpoints ask opposite questions. Introspection HANDS OUT the answer
 * to "is this credential live, and whose is it?", which RFC 7662 §2.1 says
 * MUST be authorized — it is a validation oracle for a stolen token and a
 * user-id disclosure, and it is replayable. Revocation DESTROYS a credential,
 * and it cannot be reached without already presenting the token value, so an
 * attacker gains nothing they did not already have. Failing in the direction
 * of destroying credentials is the safe direction to fail.
 *
 * RFC 7009 §2.1 asks the server to verify the token was issued to the
 * requesting client, and the CLIENT REALITY here is why that cannot become a
 * gate: these are secretless public PKCE clients
 * (`token_endpoint_auth_method: "none"`), so they hold nothing to authenticate
 * WITH. Requiring a credential would break revocation for exactly the clients
 * least able to protect a token in the first place — the claude.ai and Claude
 * Code connectors among them. The non-blocking `client_id` comparison below is
 * what is achievable, and what it buys is a signal rather than a barrier; see
 * its own comment.
 *
 * The compensating controls are the failure-only rate limiter this handler
 * opens with (`isPublicOAuthEndpointLimited`) and the audited client-mismatch
 * branch. Revisit this only if revocation ever stops requiring the token value.
 */
tokenRouter.post("/oauth/revoke", async (req, res) => {
  try {
    if (isPublicOAuthEndpointLimited(req, "revoke")) {
      return sendPublicOAuthEndpointRateLimited(res, "revoke");
    }

    // Check if body was parsed correctly. A JSON array is an object to
    // `typeof` but names no parameters, so it is refused the same way.
    if (!isParameterObject(req.body)) {
      recordPublicOAuthEndpointFailure(req, "revoke");
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Request body is missing or malformed",
      });
    }

    // Before any lookup: a token or client_id that is not a single string is
    // refused with 400 and counted ONCE against this route's failure budget,
    // like every other refusal here. It used to throw inside the hashed
    // lookup and answer 500 without being counted, so one address could
    // repeat it without limit, writing an error line each time.
    const nonString = firstNonStringParameter(req.body);
    if (nonString) {
      recordPublicOAuthEndpointFailure(req, "revoke");
      return refuseNonStringParameter(res, nonString);
    }

    const { token, client_id } = req.body as {
      token?: string;
      client_id?: string;
    };

    if (!token) {
      recordPublicOAuthEndpointFailure(req, "revoke");
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Missing token parameter",
      });
    }

    /**
     * RFC 7009 §2.1 asks the server to "verify whether the token was issued to
     * the client making the revocation request". This check is NON-BLOCKING
     * when client_id is absent, mirroring handleRefreshTokenGrant above, so
     * BE CLEAR ABOUT WHAT IT DOES AND DOES NOT BUY: it does not stop anyone
     * holding a stolen token from revoking it, because omitting client_id
     * skips the comparison entirely. The MUST is not satisfied and cannot be
     * satisfied here — these are secretless public PKCE clients, so a supplied
     * client_id is an unauthenticated claim either way, and refusing the
     * clients that omit it would break revocation for the ones least able to
     * protect a token in the first place. Revocation destroying a credential
     * is also the safe direction to fail.
     *
     * What it does buy is a signal: a caller that names a DIFFERENT client
     * than the token was issued to is not a confused client, and that mismatch
     * is the highest-value event either of these endpoints produces.
     */
    const clientMismatch = (tokenClientId: string): boolean =>
      Boolean(client_id) && tokenClientId !== client_id;

    /**
     * Refuse a revocation whose client_id names someone else, loudly.
     *
     * This branch IS audited, unlike the other refusals on these two endpoints,
     * and the reason is the one that governs every emit decision in this file
     * (see emitTokenLifecycle): replay amplification. An unknown-token refusal
     * records a string the caller invented and can be repeated forever. This
     * one requires a REAL, currently-issued token presented under the wrong
     * client — it cannot be produced without already holding a live credential,
     * and it is rate-limited on top. Bounded, and it answers the question an
     * operator actually asks: "did anyone use this credential from somewhere it
     * was not issued to?"
     */
    const refuseClientMismatch = (
      tokenData: { client_id: string; user_id: string },
      tokenType: "access_token" | "refresh_token",
    ): express.Response => {
      recordPublicOAuthEndpointFailure(req, "revoke");
      logger.warn(
        `[oauth] revoke rejected reason=client_mismatch token_client=${tokenData.client_id} presented_client=${JSON.stringify(String(client_id).slice(0, 100))} user=${tokenData.user_id}`,
      );
      emitTokenLifecycle(req, {
        action: "oauth.token.revoke",
        clientId: tokenData.client_id,
        userId: tokenData.user_id,
        token,
        outcome: "failure",
        httpStatus: 400,
        detail: {
          reason: "client_mismatch",
          token_type: tokenType,
          // Clamped: `client_id` is unauthenticated request text on an
          // endpoint that takes no credential, and `audit_log` has no prune
          // path, so an unbounded value here is a write-amplification
          // primitive. Recorded because "which client did they claim to be" is
          // the whole content of the event.
          presented_client_id: String(client_id).slice(0, 100),
        },
      });
      return res.status(400).json({
        error: "invalid_client",
        error_description: "Client ID does not match",
      });
    };

    // Every delete below runs under the token owner's OAuth credential lock
    // (../../db/repositories/oauth-user-lock), the lock the refresh grant holds
    // while it rotates. The unlocked lookups only identify the row and its
    // owner, client and family; that identity is kept while waiting for the
    // lock, because a refresh of the same row can commit in between. When the
    // row is gone once the lock is held, the rotation won, so the family it
    // belongs to is revoked instead, taking the pair that rotation just
    // inserted. A row-only delete would report success and leave that pair
    // live.
    //
    // Try revoking as access token
    const accessTokenData = await oauthRepository.getAccessToken(token);
    if (accessTokenData) {
      if (clientMismatch(accessTokenData.client_id)) {
        return refuseClientMismatch(accessTokenData, "access_token");
      }
      const familyRevoked = await oauthRepository.withUserLock(
        accessTokenData.user_id,
        async (tx) => {
          if ((await oauthRepository.deleteAccessToken(token, tx)) > 0) {
            return null;
          }
          return oauthRepository.revokeFamily(accessTokenData.family_id, tx);
        },
      );
      emitTokenLifecycle(req, {
        action: "oauth.token.revoke",
        clientId: accessTokenData.client_id,
        userId: accessTokenData.user_id,
        token,
        outcome: "success",
        detail: {
          token_type: "access_token",
          ...(familyRevoked === null
            ? {}
            : { family_tokens_revoked: familyRevoked }),
        },
      });
    } else {
      // Try revoking as refresh token
      const tokenData = await oauthRepository.getByRefreshToken(token);
      if (tokenData) {
        if (clientMismatch(tokenData.client_id)) {
          return refuseClientMismatch(tokenData, "refresh_token");
        }
        const familyRevoked = await oauthRepository.withUserLock(
          tokenData.user_id,
          async (tx) => {
            if ((await oauthRepository.deleteByRefreshToken(token, tx)) > 0) {
              return null;
            }
            return oauthRepository.revokeFamily(tokenData.family_id, tx);
          },
        );
        emitTokenLifecycle(req, {
          action: "oauth.token.revoke",
          clientId: tokenData.client_id,
          userId: tokenData.user_id,
          token,
          outcome: "success",
          detail: {
            token_type: "refresh_token",
            ...(familyRevoked === null
              ? {}
              : { family_tokens_revoked: familyRevoked }),
          },
        });
      } else {
        // Not live, but possibly a refresh token its family already rotated
        // out: a refresh that committed before this request's first lookup
        // leaves only the marker. Resolving it revokes the family, so a
        // revoke racing the client's own refresh still ends the grant.
        // revokeFamily also deletes the family's markers, so a replay of the
        // same token finds nothing and is counted below like any unknown
        // token: one audit row per family, not one per request. An access
        // token that was rotated out is recorded nowhere, so it stays an
        // unknown token here.
        const rotated = await oauthRepository.getRotatedRefreshToken(token);
        if (rotated) {
          if (clientMismatch(rotated.client_id)) {
            return refuseClientMismatch(rotated, "refresh_token");
          }
          const familyRevoked = await oauthRepository.withUserLock(
            rotated.user_id,
            (tx) => oauthRepository.revokeFamily(rotated.family_id, tx),
          );
          emitTokenLifecycle(req, {
            action: "oauth.token.revoke",
            clientId: rotated.client_id,
            userId: rotated.user_id,
            token,
            outcome: "success",
            detail: {
              token_type: "refresh_token",
              rotated: true,
              family_tokens_revoked: familyRevoked,
            },
          });
        } else {
          // RFC 7009: return success even if token doesn't exist — but count it.
          // The 200 is what makes this endpoint an unauthenticated oracle worth
          // spraying, and a caller whose tokens never resolve is not a client.
          recordPublicOAuthEndpointFailure(req, "revoke");
        }
      }
    }

    // RFC 7009 specifies that revocation endpoint should return 200 OK
    res.status(200).send();
  } catch (error) {
    logger.error("Error in OAuth revoke endpoint:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Internal server error",
    });
  }
});

export default tokenRouter;
