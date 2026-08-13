import {
  OAuthClientCreateInput,
  OAuthGrantTypeEnum,
  OAuthResponseTypeEnum,
  OAuthTokenEndpointAuthMethodEnum,
} from "@repo/zod-types";

import {
  generateSecureClientId,
  generateSecureClientSecret,
  validateRedirectUri,
} from "./utils";

/**
 * Shared OAuth 2.1 client-registration core.
 *
 * Lifted out of the RFC 7591 dynamic-registration express handler when the
 * admin UI gained a "create OAuth client" flow, so both mint paths run ONE
 * set of rules. Two entry points each carrying their own copy would drift,
 * and the drift would be silent in the dangerous direction: a UI-minted
 * client that skipped `validateRedirectUri` is an open redirect, and one that
 * skipped the auth-method check could be stored with a method the token
 * endpoint refuses to honour.
 *
 * Deliberately free of express and of the database — it takes an untrusted
 * object and returns either a row ready to persist or an RFC 7591 error pair.
 * Callers own the transport (`registration.ts` maps the error to a 400 JSON
 * body, the tRPC impl maps it to a BAD_REQUEST) and own the write. That keeps
 * it directly unit-testable without standing up a server or a DB, the same
 * shape `requireAdmin` uses for the RBAC gate.
 *
 * It lives beside `utils.ts` rather than under `lib/` because the credential
 * generators and the redirect-URI validator it composes live here; nothing in
 * `lib/` currently imports from `routers/`, and inverting that layering for
 * three helpers would be a bigger change than this feature warrants.
 */

/** Raw, untrusted registration parameters (an express body or a tRPC input). */
export interface ClientRegistrationInput {
  redirect_uris?: unknown;
  grant_types?: unknown;
  response_types?: unknown;
  token_endpoint_auth_method?: unknown;
  client_name?: unknown;
  scope?: unknown;
  client_uri?: unknown;
  logo_uri?: unknown;
  contacts?: unknown;
  tos_uri?: unknown;
  policy_uri?: unknown;
  software_id?: unknown;
  software_version?: unknown;
}

/** Caller-supplied entitlements. See `allowElevatedScope`. */
export interface ClientRegistrationOptions {
  /**
   * Whether the CALLER is entitled to hand the new client an elevated scope
   * (see `ELEVATED_SCOPES`). Defaults to false, because the caller that must
   * be safe without opting in is the anonymous one: `POST /oauth/register` is
   * unauthenticated. The admin-gated tRPC create passes true explicitly.
   */
  allowElevatedScope?: boolean;
}

export type ClientRegistrationResult =
  | { ok: true; client: OAuthClientCreateInput }
  | { ok: false; error: string; error_description: string };

const VALID_GRANT_TYPES: readonly string[] = OAuthGrantTypeEnum.options;
const VALID_RESPONSE_TYPES: readonly string[] = OAuthResponseTypeEnum.options;
const VALID_AUTH_METHODS: readonly string[] =
  OAuthTokenEndpointAuthMethodEnum.options;

/**
 * Scope tokens a self-registered client may never hold. `admin` is the only
 * scope this server names anywhere (`routers/oauth/metadata.ts` advertises it
 * as the whole `scopes_supported` vocabulary) and the only one whose name
 * asserts full access, so today it is the entire elevated set.
 */
const ELEVATED_SCOPES: readonly string[] = ["admin"];

/**
 * Validate a registration request and mint the client row for it.
 *
 * Validation order matches the original handler exactly (redirect URIs, then
 * grant types, response types, auth method) so error responses are unchanged
 * for existing DCR callers. The scope check is appended AFTER those four for
 * the same reason: it is the only new rejection, so no request that used to be
 * refused with one error code is now refused with another.
 *
 * Not pure — it generates the client id and, where the auth method calls for
 * one, the client secret. It performs no I/O, so tests drive it directly.
 */
export function buildClientRegistration(
  input: ClientRegistrationInput,
  options: ClientRegistrationOptions = {},
): ClientRegistrationResult {
  const {
    redirect_uris,
    response_types,
    grant_types,
    client_name,
    client_uri,
    logo_uri,
    scope,
    contacts,
    tos_uri,
    policy_uri,
    token_endpoint_auth_method,
    software_id,
    software_version,
  } = input;

  if (
    !redirect_uris ||
    !Array.isArray(redirect_uris) ||
    redirect_uris.length === 0
  ) {
    return {
      ok: false,
      error: "invalid_redirect_uri",
      error_description:
        "redirect_uris is required and must be a non-empty array",
    };
  }

  // OAuth 2.1 Security: Validate redirect URIs
  for (const uri of redirect_uris) {
    if (typeof uri !== "string" || !validateRedirectUri(uri)) {
      return {
        ok: false,
        error: "invalid_redirect_uri",
        error_description: `Invalid redirect URI: ${uri}. Must use secure scheme and valid format.`,
      };
    }
  }

  // OAuth 2.1 Security: Set secure defaults for optional parameters
  const clientGrantTypes =
    grant_types && Array.isArray(grant_types)
      ? grant_types
      : ["authorization_code"]; // Only authorization_code by default

  const clientResponseTypes =
    response_types && Array.isArray(response_types) ? response_types : ["code"];

  // OAuth 2.1 Security: Default to PKCE (none auth method)
  const clientTokenEndpointAuthMethod =
    (token_endpoint_auth_method as string) || "none";

  for (const grantType of clientGrantTypes) {
    if (!VALID_GRANT_TYPES.includes(grantType)) {
      return {
        ok: false,
        error: "invalid_request",
        error_description: `Unsupported grant type: ${grantType}`,
      };
    }
  }

  for (const responseType of clientResponseTypes) {
    if (!VALID_RESPONSE_TYPES.includes(responseType)) {
      return {
        ok: false,
        error: "invalid_request",
        error_description: `Unsupported response type: ${responseType}`,
      };
    }
  }

  if (!VALID_AUTH_METHODS.includes(clientTokenEndpointAuthMethod)) {
    return {
      ok: false,
      error: "invalid_request",
      error_description: `Unsupported token endpoint auth method: ${clientTokenEndpointAuthMethod}`,
    };
  }

  // Scope is validated like the value sets above instead of being stored
  // verbatim, and there is NO "admin" fallback any more. This core's busiest
  // caller is the UNAUTHENTICATED `POST /oauth/register`, so the old
  // `scope || "admin"` recorded every anonymous self-registrant as fully
  // privileged. Nothing reads `oauth_clients.scope` for authorization today —
  // real RBAC is the better-auth session role — so that default granted no
  // access; the row is the hazard. It is exactly what a future scope-based
  // check would consult, and such a check would silently inherit "anyone who
  // can reach /oauth/register is an admin". A client that asks for nothing now
  // gets NULL, the honest record of what it was granted.
  const requestedScope = typeof scope === "string" ? scope.trim() : "";

  if (requestedScope && !options.allowElevatedScope) {
    // Token-wise, not substring: "read:administration" is an ordinary scope
    // and must not be refused because "admin" appears inside it. RFC 6749 §3.3
    // defines a scope as space-delimited tokens, so that is how it is split.
    const elevated = requestedScope
      .split(/\s+/)
      .filter((token) => ELEVATED_SCOPES.includes(token));

    if (elevated.length > 0) {
      return {
        ok: false,
        // RFC 7591 §3.2.2's code for a metadata VALUE the server refuses —
        // the value-set failures above predate this file and keep their
        // historical `invalid_request`, but a brand-new rejection has no
        // back-compat debt, so it uses the code the RFC actually specifies.
        error: "invalid_client_metadata",
        error_description: `Scope not available to self-registered clients: ${elevated.join(" ")}`,
      };
    }
  }

  const clientId = generateSecureClientId();

  // OAuth 2.1 Security: Generate client secret only if auth method requires it
  // Recommend PKCE (none) for public clients per OAuth 2.1
  let clientSecret: string | null = null;
  if (clientTokenEndpointAuthMethod !== "none") {
    clientSecret = generateSecureClientSecret();
  }

  return {
    ok: true,
    client: {
      client_id: clientId,
      client_secret: clientSecret,
      client_name: (client_name as string) || "Unnamed MCP Client",
      redirect_uris: redirect_uris as string[],
      grant_types: clientGrantTypes as string[],
      response_types: clientResponseTypes as string[],
      token_endpoint_auth_method: clientTokenEndpointAuthMethod,
      scope: requestedScope || null,
      client_uri: (client_uri as string) || null,
      logo_uri: (logo_uri as string) || null,
      contacts: contacts && Array.isArray(contacts) ? contacts : null,
      tos_uri: (tos_uri as string) || null,
      policy_uri: (policy_uri as string) || null,
      software_id: (software_id as string) || null,
      software_version: (software_version as string) || null,
      created_at: new Date(),
    },
  };
}
