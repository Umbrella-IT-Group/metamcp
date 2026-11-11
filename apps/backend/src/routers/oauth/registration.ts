import express from "express";

import {
  auditRequestContext,
  clampAuditText,
  clampAuditTextList,
  emit,
} from "@/lib/audit/audit-emitter";
import logger from "@/utils/logger";

import { oauthRepository } from "../../db/repositories";
import { buildClientRegistration } from "./client-registration";
import {
  getOAuthDcrMode,
  type OAuthDcrMode,
  REGISTRATION_DISABLED_BODY,
} from "./dcr-mode";
import {
  getBaseUrl,
  GRANTED_OAUTH_SCOPE,
  isDcrLoopbackRedirectUri,
  rateLimitRegistration,
} from "./utils";

const registrationRouter = express.Router();

/**
 * The 400 a self-registration with any non-loopback callback receives.
 *
 * RFC 7591's `invalid_redirect_uri`, because that is what it is: the callback
 * is not one this door accepts. The shared validator may have accepted it
 * (claude.ai is on the hosted-host allowlist for administrator-created
 * clients), so the description says where hosted clients come from instead.
 */
export const NON_LOOPBACK_REGISTRATION_BODY = Object.freeze({
  error: "invalid_redirect_uri",
  error_description:
    "This gateway registers only local callback addresses automatically. Hosted clients use a client an administrator creates.",
});

/**
 * The host of each refused callback, for the denial audit row: hostname only
 * (no path or query, which can carry anything), de-duplicated and clamped. The
 * URIs reaching this have already parsed in the shared registration core.
 */
function refusedHosts(uris: readonly string[]): string[] {
  const hosts = new Set<string>();
  for (const uri of uris) {
    try {
      hosts.add(new URL(uri).hostname);
    } catch {
      hosts.add("(unparseable)");
    }
  }
  return clampAuditTextList([...hosts], 10, 255);
}

/**
 * Record a refused self-registration. `/oauth/register` is anonymous, so the
 * row carries only the source address the request context resolved and a
 * reason, plus bounded caller-derived fields where the reason needs them.
 */
function emitRegistrationDenied(
  req: express.Request,
  mode: OAuthDcrMode,
  httpStatus: number,
  detail: Record<string, unknown>,
): void {
  const audit = auditRequestContext(req);
  emit({
    actor_type: "anonymous",
    actor_id: null,
    actor_label: null,
    actor_ip: audit.actor_ip,
    actor_user_agent: audit.actor_user_agent,
    action: "oauth.dcr.register",
    target_type: "oauth_client",
    target_id: null,
    outcome: "denied",
    request_id: audit.request_id,
    http_status: httpStatus,
    detail: { dcr_mode: mode, ...detail },
  });
}

/**
 * OAuth 2.0 Dynamic Client Registration Endpoint
 * Allows clients to dynamically register with the authorization server
 * Implementation follows RFC 7591 with OAuth 2.1 security enhancements
 */
// `rateLimitRegistration`, NOT the token endpoint's limiter this route used to
// share: one bucket meant anonymous registration traffic could spend the budget
// a paired connector's token exchange needed. See rateLimitRegistration.
registrationRouter.post(
  "/oauth/register",
  rateLimitRegistration,
  async (req, res) => {
    try {
      // Check if body was parsed correctly
      if (!req.body || typeof req.body !== "object") {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "Request body is missing or malformed",
        });
      }

      // The registration switch (OAUTH_DCR_MODE, resolved and latched at
      // startup). `off` refuses here, before anything is minted or stored.
      // The body limit and the rate limiter have already run, so they still
      // bound refused traffic.
      const mode = getOAuthDcrMode();
      if (mode === "off") {
        emitRegistrationDenied(req, mode, 400, {
          reason: "registration_disabled",
        });
        return res.status(400).json(REGISTRATION_DISABLED_BODY);
      }

      // Validate + mint through the shared registration core, so this public
      // DCR endpoint and the admin UI's tRPC create path apply one identical
      // rule set (see ./client-registration.ts). The error pair it returns is
      // already the RFC 7591 shape this endpoint has always emitted.
      const registration = buildClientRegistration(req.body);

      if (!registration.ok) {
        return res.status(400).json({
          error: registration.error,
          error_description: registration.error_description,
        });
      }

      // Self-registration accepts loopback callbacks only, in every mode. The
      // shared core above has already applied every shared rule (scheme,
      // userinfo, fragment, the gateway's internal port, the hosted-host
      // allowlist); this door then narrows to plain-http loopback. The shared
      // allowlist is NOT emptied to get this effect: it also serves the admin
      // create dialog and existing hosted clients' authorize requests. A
      // single non-loopback entry refuses the whole registration.
      const nonLoopback = registration.client.redirect_uris.filter(
        (uri) => !isDcrLoopbackRedirectUri(uri),
      );
      if (nonLoopback.length > 0) {
        emitRegistrationDenied(req, mode, 400, {
          reason: "non_loopback_redirect_uri",
          refused_hosts: refusedHosts(nonLoopback),
          redirect_uri_count: registration.client.redirect_uris.length,
        });
        return res.status(400).json(NON_LOOPBACK_REGISTRATION_BODY);
      }

      // `registration_source: "dcr"` and the approval status are stamped HERE
      // rather than inside the shared core, because this is the door — the
      // core serves both and never reads either from its input, so a body that
      // asks for "approved" gets what this door decides. "dcr" is what makes
      // the row eligible for the retention sweep (./client-retention.ts);
      // "pending" is what keeps it from being authorized until an
      // administrator approves it. Only the local-development `open` mode
      // writes "approved", and then with the time but no approving person.
      const approvedNow = mode === "open";
      const clientRegistration = {
        ...registration.client,
        registration_source: "dcr" as const,
        approval_status: approvedNow
          ? ("approved" as const)
          : ("pending" as const),
        approved_at: approvedNow ? new Date() : null,
      };
      const clientSecret = clientRegistration.client_secret;

      // Store the client registration
      await oauthRepository.upsertClient(clientRegistration);

      // The highest-signal anonymous write this gateway accepts, and until now
      // it was invisible. RFC 7591 dynamic registration needs no credential, so
      // anyone who can reach /oauth/register can add a client that a signed-in
      // human may then be asked to approve — and `client_name` is whatever that
      // caller typed, which is how a consent screen ends up saying "Claude".
      // Emitted AFTER upsertClient, so a row here means a client that exists.
      //
      // actor_type is `anonymous`, honestly: there is no session, no key and no
      // prior client identity on this request. The IP is the only attribution
      // available, which is precisely why the CF-Connecting-IP middleware had
      // to land before this lane. `client_secret` is never recorded — it is
      // returned to the caller once, in the response below, and nowhere else.
      const audit = auditRequestContext(req);
      emit({
        actor_type: "anonymous",
        actor_id: null,
        actor_label: null,
        actor_ip: audit.actor_ip,
        actor_user_agent: audit.actor_user_agent,
        action: "oauth.dcr.register",
        target_type: "oauth_client",
        target_id: clientRegistration.client_id,
        outcome: "success",
        request_id: audit.request_id,
        http_status: 201,
        // EVERY caller-supplied field here is clamped, and on this endpoint
        // that is a hard requirement rather than tidiness: `/oauth/register`
        // takes no credential, and the target is a jsonb column in a table
        // with DELETE/TRUNCATE triggers, so every byte written is permanent.
        //
        // Three controls now stand in front of this clamp, and it is kept
        // anyway. The body limit is 256kb rather than the app-wide 50mb
        // (OAUTH_BODY_LIMIT), `buildClientRegistration` caps the redirect
        // array and every element and metadata field it stores, and the
        // registration rate limit is its own bucket keyed on the real caller
        // IP instead of one process-global `req.ip` budget. What survives all
        // three is a payload that is legal but still worth writing compactly
        // a thousand times over — and a clamp that only exists at the caller
        // is a clamp the next call site does not get.
        // `redirect_uri_count` preserves the fact that truncation happened.
        detail: {
          client_name: clientRegistration.client_name
            ? clampAuditText(clientRegistration.client_name, 100)
            : null,
          redirect_uris: clampAuditTextList(
            clientRegistration.redirect_uris,
            10,
            512,
          ),
          redirect_uri_count: Array.isArray(clientRegistration.redirect_uris)
            ? clientRegistration.redirect_uris.length
            : 0,
          grant_types: clampAuditTextList(
            clientRegistration.grant_types,
            10,
            64,
          ),
          token_endpoint_auth_method: clampAuditText(
            clientRegistration.token_endpoint_auth_method,
            64,
          ),
          has_client_secret: Boolean(clientSecret),
          approval_status: clientRegistration.approval_status,
          dcr_mode: mode,
        },
      });

      // Prepare response according to RFC 7591 with OAuth 2.1 guidance.
      // getBaseUrl, not `req.get("host")`: every request reaches this router
      // through the Next.js proxy, so the Host header is the container-internal
      // `localhost:12009`. Building the advertised endpoints from it both leaked
      // the internal listener to an anonymous caller and handed registering
      // clients token/authorize URLs they cannot reach. getBaseUrl prefers
      // APP_URL, then X-Forwarded-Host.
      const baseUrl = getBaseUrl(req);
      const response: any = {
        client_id: clientRegistration.client_id,
        client_name: clientRegistration.client_name,
        redirect_uris: clientRegistration.redirect_uris,
        grant_types: clientRegistration.grant_types,
        response_types: clientRegistration.response_types,
        token_endpoint_auth_method:
          clientRegistration.token_endpoint_auth_method,
        scope: clientRegistration.scope,

        // Not an RFC 7591 field; clients ignore unknown members. Present so a
        // person reading the response knows the client cannot be used until
        // an administrator approves it.
        approval_status: clientRegistration.approval_status,

        // OAuth 2.1 Security Information
        oauth_compliance: "OAuth 2.1",
        pkce_required: true,
        pkce_methods_supported: ["S256"],

        // Endpoint information for the client
        authorization_endpoint: `${baseUrl}/oauth/authorize`,
        token_endpoint: `${baseUrl}/oauth/token`,
        userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
        revocation_endpoint: `${baseUrl}/oauth/revoke`,
      };

      // Include client_secret only if one was generated
      if (clientSecret) {
        response.client_secret = clientSecret;
        response.security_note =
          "Store client_secret securely. For public clients, use PKCE instead.";
      } else {
        response.security_note =
          "This client uses PKCE for security. Ensure code_challenge and code_challenge_method are included in authorization requests.";
      }

      // Include optional metadata if provided
      if (clientRegistration.client_uri)
        response.client_uri = clientRegistration.client_uri;
      if (clientRegistration.logo_uri)
        response.logo_uri = clientRegistration.logo_uri;
      if (clientRegistration.contacts)
        response.contacts = clientRegistration.contacts;
      if (clientRegistration.tos_uri)
        response.tos_uri = clientRegistration.tos_uri;
      if (clientRegistration.policy_uri)
        response.policy_uri = clientRegistration.policy_uri;
      if (clientRegistration.software_id)
        response.software_id = clientRegistration.software_id;
      if (clientRegistration.software_version)
        response.software_version = clientRegistration.software_version;

      res.status(201).json(response);
    } catch (error) {
      logger.error("Error in OAuth registration endpoint:", error);
      res.status(500).json({
        error: "server_error",
        error_description: "Internal server error during client registration",
      });
    }
  },
);

/**
 * OAuth 2.0 Dynamic Client Registration Information Endpoint
 * Describes how registration works on this gateway in its current mode.
 */
registrationRouter.get("/oauth/register", async (req, res) => {
  try {
    // Same proxy caveat as the POST handler above — see the comment there.
    const baseUrl = getBaseUrl(req);
    const mode = getOAuthDcrMode();

    if (mode === "off") {
      return res.json({
        registration_mode: "off",
        registration_enabled: false,
        oauth_version: "OAuth 2.1",
        description:
          "Automatic client registration is turned off on this gateway. Clients are created by an administrator.",
        next_steps: [
          "Ask an administrator for a client_id (and client_secret, if your application needs one).",
          "Use PKCE in your authorization requests (code_challenge_method=S256).",
        ],
      });
    }

    res.json({
      registration_endpoint: `${baseUrl}/oauth/register`,
      registration_mode: mode,
      registration_enabled: true,
      oauth_version: "OAuth 2.1",
      description:
        "Dynamic Client Registration for MetaMCP OAuth Server. Only applications on the local machine (loopback callbacks) can register here; hosted applications use a client an administrator creates.",
      approval:
        mode === "open"
          ? "New registrations are approved automatically (local development only)."
          : "A new registration cannot be used until an administrator approves it. Quote the returned client_id to your administrator.",

      required_parameters: {
        redirect_uris:
          "Array of local callback URIs: http://localhost, http://127.0.0.1 or http://[::1], on any port. Any other callback is refused.",
      },

      optional_parameters: {
        client_name: "Human-readable name for your application",
        grant_types: "OAuth grant types (default: ['authorization_code'])",
        response_types: "OAuth response types (default: ['code'])",
        token_endpoint_auth_method:
          "Client authentication method (default: 'none' for PKCE)",
        // Kept listed because RFC 7591 allows clients to send it, but say
        // plainly that it is ignored — this doc previously told callers to
        // ask for 'admin', which the server now never grants.
        scope: `Ignored. This server always grants '${GRANTED_OAUTH_SCOPE}'.`,
        client_uri: "Homepage URL for your application",
        logo_uri: "Logo URL for your application",
        contacts: "Array of contact email addresses",
        tos_uri: "Terms of service URL",
        policy_uri: "Privacy policy URL",
      },

      security_recommendations: {
        use_pkce: "Always use PKCE (token_endpoint_auth_method: 'none')",
        local_callbacks_only:
          "Register a plain http loopback callback; this endpoint refuses every other callback",
        secure_storage:
          "Store client credentials securely if using client authentication",
        code_challenge_method: "Use 'S256' for code_challenge_method",
      },

      example_registration: {
        method: "POST",
        url: `${baseUrl}/oauth/register`,
        headers: {
          "Content-Type": "application/json",
        },
        body: {
          client_name: "My MCP Application",
          redirect_uris: ["http://127.0.0.1:33418/callback"],
          grant_types: ["authorization_code"],
          response_types: ["code"],
          token_endpoint_auth_method: "none",
        },
      },

      next_steps: [
        "Register your client using POST to this endpoint",
        "Save the returned client_id",
        ...(mode === "open"
          ? []
          : [
              "Ask an administrator to approve the client, quoting its client_id; until then the authorization page says it is waiting",
            ]),
        "Use PKCE in your authorization requests",
        "Include code_challenge and code_challenge_method=S256",
        "Exchange authorization codes for access tokens",
      ],
    });
  } catch (error) {
    logger.error("Error in OAuth registration info endpoint:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Internal server error",
    });
  }
});

export default registrationRouter;
