import type { OAuthClientRegistrationDraft } from "@repo/zod-types";

import { buildClientRegistration } from "./client-registration";
import {
  isAllowedRedirectUri,
  isLoopbackRedirectUri,
  validateRedirectUri,
} from "./utils";

/**
 * Validation of a client metadata document (CIMD) into a client row.
 *
 * Pure and I/O-free: it takes the text a fetch returned and the client id the
 * fetch was made for. The checks follow the mcp-use client metadata resolver
 * (`libraries/typescript/packages/server/src/oauth/proxy/clients.ts`, MIT,
 * Copyright (c) 2025 pietrozullo): the document's `client_id` must equal its
 * own URL, a document naming a client secret or a shared-secret method is
 * refused, and the client must be a public client. The redirect rules are this
 * gateway's own, applied through the same registration core the anonymous
 * registration endpoint and the admin dialog use, so the three doors cannot
 * drift apart.
 *
 * HOSTED CALLBACKS ONLY. A document whose `redirect_uris` include a loopback
 * address or a private-use scheme is refused outright. A loopback callback is
 * the shape a local process listens on, and the consent screen for one hands
 * the code to a person to copy (consent-success-page); with registration
 * through this door an allowlisted, publicly named client could otherwise reach
 * that page without the administrator approval an anonymous loopback
 * registration waits for. A local command-line client keeps using dynamic
 * registration. The cost is stated in README-oauth.md: advertising CIMD steers
 * every CIMD-capable client to a URL client id, so a local client that sends
 * one is refused rather than registered, which is why the flag is advertised
 * only while an allowlist is set.
 */

/** Why a document was refused. Fixed strings: they go to audit rows and logs. */
export type CimdDocumentRefusal =
  | "not_json"
  | "invalid_document"
  | "not_public_client"
  | "client_id_mismatch"
  | "invalid_redirect_uri"
  | "non_hosted_redirect_uri";

export type CimdDocumentResult =
  | { ok: true; client: OAuthClientRegistrationDraft }
  | {
      ok: false;
      reason: CimdDocumentRefusal;
      /**
       * A fixed machine-readable detail for the refusal (the redirect rule that
       * refused, for instance). Never text from the document.
       */
      detail?: string;
    };

/** The grant types a CIMD client may declare; the draft default is both. */
const CIMD_GRANT_TYPES: readonly string[] = [
  "authorization_code",
  "refresh_token",
];
const CIMD_RESPONSE_TYPES: readonly string[] = ["code"];
const SHARED_SECRET_METHODS: ReadonlySet<string> = new Set([
  "client_secret_post",
  "client_secret_basic",
  "client_secret_jwt",
]);

/** Controls, format characters (bidi overrides, zero-width marks) and line separators. */
const UNPRINTABLE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;

const refuse = (
  reason: CimdDocumentRefusal,
  detail?: string,
): CimdDocumentResult => ({
  ok: false,
  reason,
  ...(detail === undefined ? {} : { detail }),
});

/**
 * Decode a response body as UTF-8, or null for bytes that are not valid
 * UTF-8. Fatal decoding on purpose: a lossy decode would let a document
 * carry bytes the stored text no longer shows.
 */
export function decodeCimdBody(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

function isStringArray(value: unknown): value is string[] {
  return (
    Array.isArray(value) && value.every((item) => typeof item === "string")
  );
}

/**
 * A metadata URL is kept only as an https URL. The four are stored as text,
 * never fetched and never rendered as a link or an image; keeping a value that
 * is not an https URL would only hand a later page something it must not
 * trust.
 */
function httpsUrlOrUndefined(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  try {
    return new URL(value).protocol === "https:" ? value : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Check every callback is a hosted https one the shared validators accept.
 * Order matters for the reason reported: a loopback or private-use callback is
 * `non_hosted_redirect_uri` whatever else is wrong with the list.
 */
function checkRedirectUris(uris: unknown): CimdDocumentResult | null {
  if (!Array.isArray(uris) || uris.length === 0) {
    return refuse("invalid_redirect_uri", "missing");
  }
  for (const uri of uris) {
    if (typeof uri !== "string") {
      return refuse("invalid_redirect_uri", "not_a_string");
    }
    let parsed: URL;
    try {
      parsed = new URL(uri);
    } catch {
      return refuse("invalid_redirect_uri", "unparseable");
    }
    if (parsed.protocol !== "https:") {
      // Plain http (loopback or not), custom and private-use schemes,
      // javascript: and the rest.
      return refuse("non_hosted_redirect_uri", "scheme");
    }
    if (isLoopbackRedirectUri(uri)) {
      return refuse("non_hosted_redirect_uri", "loopback");
    }
  }
  for (const uri of uris as string[]) {
    // The shared host allowlist (DCR_REDIRECT_URI_ALLOWED_HOSTS), the same
    // rule anonymous registration and the admin dialog apply, and the
    // authorize endpoint applies again to the request.
    const allowed = isAllowedRedirectUri(uri);
    if (!allowed.ok) return refuse("invalid_redirect_uri", allowed.reason);
    if (!validateRedirectUri(uri)) {
      return refuse("invalid_redirect_uri", "validate_redirect_uri");
    }
  }
  return null;
}

/**
 * Turn the text of a fetched document into a client draft, or say why not.
 * The returned draft carries the URL as its `client_id`, no secret, the
 * `none` method (PKCE is always enforced) and the scope this server grants.
 */
export function parseCimdDocument(
  text: string,
  clientId: string,
): CimdDocumentResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return refuse("not_json");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return refuse("invalid_document", "not_an_object");
  }
  const doc = parsed as Record<string, unknown>;

  // Strict equality, no normalization: the document at a URL must name that
  // URL, or any published page could claim to be any client.
  if (doc.client_id !== clientId) return refuse("client_id_mismatch");

  // Public clients only. A document that names a secret (or a shared-secret
  // method) is describing a confidential client, which a world-readable
  // document cannot be: the secret would be public.
  if (
    doc.client_secret !== undefined ||
    doc.client_secret_expires_at !== undefined
  ) {
    return refuse("not_public_client", "client_secret");
  }
  const method = doc.token_endpoint_auth_method;
  const methods = doc.token_endpoint_auth_methods_supported;
  if (method !== undefined && typeof method !== "string") {
    return refuse("invalid_document", "token_endpoint_auth_method");
  }
  if (methods !== undefined && !isStringArray(methods)) {
    return refuse("invalid_document", "token_endpoint_auth_methods_supported");
  }
  if (
    (typeof method === "string" && SHARED_SECRET_METHODS.has(method)) ||
    (methods !== undefined && methods.some((m) => SHARED_SECRET_METHODS.has(m)))
  ) {
    return refuse("not_public_client", "shared_secret_method");
  }
  // When the document lists the methods it can use the list decides (a client
  // may prefer private_key_jwt and still offer none); otherwise the singular
  // value must be absent or none.
  const offersNone =
    methods !== undefined
      ? methods.includes("none")
      : method === undefined || method === "none";
  if (!offersNone) return refuse("not_public_client", "no_none_method");

  const uriRefusal = checkRedirectUris(doc.redirect_uris);
  if (uriRefusal) return uriRefusal;

  const grants =
    doc.grant_types === undefined ? CIMD_GRANT_TYPES : doc.grant_types;
  if (
    !isStringArray(grants) ||
    !grants.includes("authorization_code") ||
    !grants.every((grant) => CIMD_GRANT_TYPES.includes(grant))
  ) {
    return refuse("invalid_document", "grant_types");
  }
  const responses =
    doc.response_types === undefined ? CIMD_RESPONSE_TYPES : doc.response_types;
  if (
    !isStringArray(responses) ||
    responses.length === 0 ||
    !responses.every((type) => CIMD_RESPONSE_TYPES.includes(type))
  ) {
    return refuse("invalid_document", "response_types");
  }

  if (doc.client_name !== undefined && typeof doc.client_name !== "string") {
    return refuse("invalid_document", "client_name");
  }
  // The name is whatever the document says, shown on a consent screen. Without
  // controls and bidirectional marks it cannot reorder or hide the text around
  // it; clamped to the column budget the registration core enforces; the host
  // stands in for a missing one so the screen never reads "Unnamed".
  const cleanName =
    typeof doc.client_name === "string"
      ? doc.client_name.replace(UNPRINTABLE, "").trim().slice(0, 255)
      : "";
  const name = cleanName === "" ? new URL(clientId).host : cleanName;

  const built = buildClientRegistration({
    redirect_uris: doc.redirect_uris,
    grant_types: [...new Set(grants)],
    response_types: [...new Set(responses)],
    token_endpoint_auth_method: "none",
    client_name: name,
    client_uri: httpsUrlOrUndefined(doc.client_uri),
    logo_uri: httpsUrlOrUndefined(doc.logo_uri),
    tos_uri: httpsUrlOrUndefined(doc.tos_uri),
    policy_uri: httpsUrlOrUndefined(doc.policy_uri),
  });
  if (!built.ok) {
    return refuse(
      built.error === "invalid_redirect_uri"
        ? "invalid_redirect_uri"
        : "invalid_document",
      "registration_core",
    );
  }

  // The core generated a random client id and (for any method but none) a
  // secret; the URL is the id, and there is no secret.
  return {
    ok: true,
    client: { ...built.client, client_id: clientId, client_secret: null },
  };
}
