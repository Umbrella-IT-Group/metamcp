import express from "express";

import { ApiKeysRepository } from "../../db/repositories";

/**
 * The credential gate on `POST /oauth/introspect`.
 *
 * RFC 7662 §2.1 is unambiguous: an introspection endpoint MUST require
 * authorization, because it answers "is this credential live, and whose is
 * it?" to whoever asks. This one took no credential at all. Anyone who could
 * reach the gateway could hand it a token value and learn whether it was
 * active plus its `scope`, `client_id` and `sub` — a validation oracle for a
 * stolen or guessed credential, and a user-id disclosure on top.
 *
 * WHY GATING IT IS SAFE NOW, which it would not have been before c0e3cad. The
 * only realistic caller used to be this gateway itself: the OAuth bearer path
 * in `middleware/api-key-oauth.middleware.ts` self-fetched `/oauth/introspect`
 * once per MCP request. That call is gone — it reads the token row in-process
 * through `oauthRepository.getAccessToken` — and the middleware's own doc
 * comment records the move. Nothing else in this repository, backend or
 * frontend, posts to the endpoint. It stays MOUNTED and advertised in the
 * authorization-server metadata rather than removed, because introspection is
 * a real RFC 7662 surface a first-party resource server may legitimately want;
 * what changes is that it now requires the credential the RFC says it must.
 *
 * WHY AN API KEY IS THE RIGHT CREDENTIAL HERE. Introspection is a
 * machine-to-machine call, so a better-auth browser session is the wrong
 * shape, and the OAuth clients themselves are secretless public PKCE clients
 * with nothing to authenticate WITH — which is exactly the reasoning already
 * recorded on the failure-only limiter in ./token.ts. A MetaMCP API key is the
 * one first-party credential in this system that a server-side caller can
 * hold, and it is minted and revoked through the admin UI.
 *
 * NOT applied to `/oauth/revoke`, deliberately. Revocation requires the token
 * VALUE to do anything, destroying a credential is the safe direction to fail,
 * and the public PKCE clients that legitimately revoke have no secret to
 * present. Gating it would break revocation for the clients least able to
 * protect a token in the first place. It keeps its existing failure-only rate
 * limit; see the RFC 7009 note in ./token.ts.
 */

/**
 * Constructed on first use, not at module load.
 *
 * ./token imports this module, and ./token is imported by suites that mock the
 * repository barrel down to the two members they exercise. A module-scope
 * `new ApiKeysRepository()` would throw for all of them at import time, which
 * turns a missing mock member into "the whole file failed to load" — the least
 * legible failure available. Lazily, only a test that actually drives the gate
 * has to supply it.
 */
let apiKeysRepository: ApiKeysRepository | null = null;

function apiKeys(): ApiKeysRepository {
  if (!apiKeysRepository) {
    apiKeysRepository = new ApiKeysRepository();
  }
  return apiKeysRepository;
}

export type IntrospectionCredentialCheck =
  | { ok: true; userId: string | null }
  | { ok: false; reason: "missing_credential" | "invalid_credential" };

/**
 * Pull the presented API key off the request.
 *
 * Accepts `X-API-Key` and `Authorization: Bearer <key>`, the same two carriers
 * the MCP data plane accepts (see extractApiKey in
 * middleware/api-key-oauth.middleware.ts). Deliberately NOT the query-string
 * form that middleware also supports for opted-in endpoints: a credential in a
 * URL is a credential in an access log, and there is no legacy caller here to
 * accommodate.
 */
function extractPresentedKey(req: express.Request): string | null {
  const header = req.headers["x-api-key"];
  const fromHeader = Array.isArray(header) ? header[0] : header;
  if (typeof fromHeader === "string" && fromHeader.trim() !== "") {
    return fromHeader.trim();
  }

  const authorization = req.headers.authorization;
  if (typeof authorization === "string") {
    const match = /^Bearer\s+(.+)$/i.exec(authorization.trim());
    if (match && match[1].trim() !== "") {
      return match[1].trim();
    }
  }

  return null;
}

/**
 * Resolve the caller's first-party credential.
 *
 * Returns a discriminated result rather than writing the response itself so
 * the handler keeps ownership of the wire format (RFC 7662 §2.3 puts a failed
 * introspection authorization on the 401 path) and so this is testable without
 * a fake response object.
 */
export async function requireIntrospectionCredential(
  req: express.Request,
): Promise<IntrospectionCredentialCheck> {
  const presented = extractPresentedKey(req);
  if (!presented) {
    return { ok: false, reason: "missing_credential" };
  }

  const result = await apiKeys().validateApiKey(presented);
  if (!result.valid) {
    return { ok: false, reason: "invalid_credential" };
  }

  return { ok: true, userId: result.user_id ?? null };
}
