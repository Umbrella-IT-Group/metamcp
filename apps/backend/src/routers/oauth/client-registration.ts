import {
  OAuthClientCreateInput,
  OAuthGrantTypeEnum,
  OAuthResponseTypeEnum,
  OAuthTokenEndpointAuthMethodEnum,
} from "@repo/zod-types";

import {
  generateSecureClientId,
  generateSecureClientSecret,
  GRANTED_OAUTH_SCOPE,
  isAllowedRedirectUri,
} from "./utils";

/**
 * Shared OAuth 2.1 client-registration core.
 *
 * Lifted out of the RFC 7591 dynamic-registration express handler when the
 * admin UI gained a "create OAuth client" flow, so both mint paths run ONE
 * set of rules. Two entry points each carrying their own copy would drift,
 * and the drift would be silent in the dangerous direction: a UI-minted
 * client that skipped `isAllowedRedirectUri` is an open redirect, and one that
 * skipped the auth-method check could be stored with a method the token
 * endpoint refuses to honour.
 *
 * That sharing also means the redirect_uri host allowlist covers the admin UI's
 * create-client dialog, not just anonymous DCR. Deliberate: an admin who needs
 * a callback host outside `DCR_REDIRECT_URI_ALLOWED_HOSTS` changes that env
 * var, which leaves a deployment-visible record of the decision, rather than
 * quietly minting through the UI a client the anonymous path would refuse.
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

export type ClientRegistrationResult =
  | { ok: true; client: OAuthClientCreateInput }
  | { ok: false; error: string; error_description: string };

const VALID_GRANT_TYPES: readonly string[] = OAuthGrantTypeEnum.options;
const VALID_RESPONSE_TYPES: readonly string[] = OAuthResponseTypeEnum.options;
const VALID_AUTH_METHODS: readonly string[] =
  OAuthTokenEndpointAuthMethodEnum.options;

/**
 * Size caps on the untrusted registration body.
 *
 * WHY THESE EXIST AT ALL. `POST /oauth/register` takes no credential — that is
 * RFC 7591's design, not a gap — and every field below is written verbatim
 * into `oauth_clients`, a table with cascade children and, until the retention
 * sweep in ./index.ts, no prune path whatsoever. Nothing capped the input, so
 * one anonymous request could store a multi-megabyte `redirect_uris` array,
 * and 45 never-used client rows had already accumulated from junk
 * registrations. Validating the SHAPE of a redirect URI while leaving its
 * LENGTH unbounded is what turned an audit table into a disk-exhaustion
 * primitive.
 *
 * WHY THESE NUMBERS. They are the smallest values that no real client comes
 * near. A connector registers one or two callbacks (claude.ai's is under 50
 * characters); ten at 512 is an order of magnitude of headroom on both axes.
 * MAX_CLIENT_NAME_LENGTH is 255 to match the `.max(255)` the admin UI's
 * CreateOAuthClientRequestSchema already enforces in @repo/zod-types — the two
 * mint paths share this core precisely so a rule cannot differ between them.
 *
 * Over-cap input is refused with the RFC 7591 error pair this endpoint already
 * emits (`invalid_redirect_uri` for the callback list, `invalid_request` for
 * everything else). No new error code: a registered client would not recognise
 * one, and the caps are a size rule, not a new failure mode.
 */
export const MAX_REDIRECT_URIS = 10;
export const MAX_REDIRECT_URI_LENGTH = 512;
export const MAX_CLIENT_NAME_LENGTH = 255;
/** client_uri, logo_uri, tos_uri, policy_uri — all URLs, same budget. */
export const MAX_METADATA_URI_LENGTH = 512;
export const MAX_CONTACTS = 10;
export const MAX_CONTACT_LENGTH = 255;
export const MAX_SOFTWARE_ID_LENGTH = 255;
export const MAX_SOFTWARE_VERSION_LENGTH = 64;

type RegistrationRejection = Extract<ClientRegistrationResult, { ok: false }>;

/**
 * Cap one optional string field.
 *
 * Rejects a non-string outright rather than letting the `(x as string) || null`
 * cast below carry it into the insert: `client_name` is `text NOT NULL`, so an
 * object or array reaching the driver is either a stored `[object Object]` or a
 * 500 on an anonymous endpoint, and neither is an answer. `undefined`/`null`
 * mean "not supplied", which every one of these fields allows.
 */
function checkOptionalString(
  value: unknown,
  field: string,
  max: number,
): RegistrationRejection | null {
  if (value === undefined || value === null) return null;

  if (typeof value !== "string") {
    return {
      ok: false,
      error: "invalid_request",
      error_description: `${field} must be a string`,
    };
  }

  if (value.length > max) {
    return {
      ok: false,
      error: "invalid_request",
      error_description: `${field} exceeds the maximum length of ${max} characters`,
    };
  }

  return null;
}

/**
 * Validate a registration request and mint the client row for it.
 *
 * Validation order matches the original handler exactly (redirect URIs, then
 * grant types, response types, auth method) so error responses are unchanged
 * for existing DCR callers.
 *
 * Not pure — it generates the client id and, where the auth method calls for
 * one, the client secret. It performs no I/O, so tests drive it directly.
 */
export function buildClientRegistration(
  input: ClientRegistrationInput,
): ClientRegistrationResult {
  const {
    redirect_uris,
    response_types,
    grant_types,
    client_name,
    client_uri,
    logo_uri,
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

  // Size before shape. Both caps below run ahead of the per-URI parse loop so
  // that an oversized payload is refused on the cheapest possible work — the
  // point of a cap on an anonymous endpoint is to not do the expensive thing.
  if (redirect_uris.length > MAX_REDIRECT_URIS) {
    return {
      ok: false,
      error: "invalid_redirect_uri",
      error_description: `redirect_uris must contain at most ${MAX_REDIRECT_URIS} entries`,
    };
  }

  for (const uri of redirect_uris) {
    if (typeof uri === "string" && uri.length > MAX_REDIRECT_URI_LENGTH) {
      return {
        ok: false,
        error: "invalid_redirect_uri",
        error_description: `Invalid redirect URI: each entry must be at most ${MAX_REDIRECT_URI_LENGTH} characters`,
      };
    }
  }

  // OAuth 2.1 Security: Validate redirect URIs.
  //
  // `isAllowedRedirectUri` — scheme, userinfo, fragment, exact-match loopback,
  // and the non-loopback host allowlist. See its doc comment for why each rule
  // exists; the scheme-only check it replaced accepted attacker-controlled hosts.
  //
  // The 400 pair below is unchanged apart from a trailing parenthesised reason:
  // the allowlist is default-on, so a registration that used to succeed can now
  // fail, and an operator staring at "Must use secure scheme and valid format"
  // for `https://partner.example/cb` has no way to tell that the HOST is what
  // was refused. `error` and the leading sentence are byte-identical, so
  // anything matching on the RFC 7591 contract is unaffected.
  for (const uri of redirect_uris) {
    const check = isAllowedRedirectUri(uri);
    if (!check.ok) {
      return {
        ok: false,
        error: "invalid_redirect_uri",
        error_description: `Invalid redirect URI: ${uri}. Must use secure scheme and valid format. (${check.reason})`,
      };
    }
  }

  // Optional metadata caps. Placed AFTER the redirect-URI rules so the
  // documented "redirect URIs are validated before anything else" ordering
  // still holds, and BEFORE the value-set checks below so no oversized field
  // survives to the insert regardless of which other rule a payload also
  // breaks.
  const metadataRejection =
    checkOptionalString(client_name, "client_name", MAX_CLIENT_NAME_LENGTH) ??
    checkOptionalString(client_uri, "client_uri", MAX_METADATA_URI_LENGTH) ??
    checkOptionalString(logo_uri, "logo_uri", MAX_METADATA_URI_LENGTH) ??
    checkOptionalString(tos_uri, "tos_uri", MAX_METADATA_URI_LENGTH) ??
    checkOptionalString(policy_uri, "policy_uri", MAX_METADATA_URI_LENGTH) ??
    checkOptionalString(software_id, "software_id", MAX_SOFTWARE_ID_LENGTH) ??
    checkOptionalString(
      software_version,
      "software_version",
      MAX_SOFTWARE_VERSION_LENGTH,
    );

  if (metadataRejection) {
    return metadataRejection;
  }

  // `contacts` is the one array that is stored verbatim (the redirect list is
  // parsed URI by URI above), so it needs both bounds: how many, and how long
  // each. A non-string element is refused for the same reason as the scalar
  // fields — the column is `text[]`, and the driver is not the place to find
  // out what an object serialises to.
  if (contacts !== undefined && contacts !== null) {
    if (!Array.isArray(contacts)) {
      return {
        ok: false,
        error: "invalid_request",
        error_description: "contacts must be an array of strings",
      };
    }

    if (contacts.length > MAX_CONTACTS) {
      return {
        ok: false,
        error: "invalid_request",
        error_description: `contacts must contain at most ${MAX_CONTACTS} entries`,
      };
    }

    for (const contact of contacts) {
      // Not `checkOptionalString`: that helper treats null/undefined as "field
      // omitted", which is right for a scalar and wrong for an ELEMENT — a
      // null inside the array is a value being stored, not an absence.
      if (typeof contact !== "string") {
        return {
          ok: false,
          error: "invalid_request",
          error_description: "contacts must be an array of strings",
        };
      }

      if (contact.length > MAX_CONTACT_LENGTH) {
        return {
          ok: false,
          error: "invalid_request",
          error_description: `contacts entries must be at most ${MAX_CONTACT_LENGTH} characters`,
        };
      }
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
      // The caller's requested `scope` is deliberately NOT honoured — the
      // authorization server decides what it grants (RFC 7591 §3.2.1). See
      // GRANTED_OAUTH_SCOPE. `POST /oauth/register` is anonymous, so echoing
      // an attacker-chosen string here let a self-registered client be
      // recorded with, and told it held, "admin".
      scope: GRANTED_OAUTH_SCOPE,
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
