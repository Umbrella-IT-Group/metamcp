import express from "express";

import logger from "@/utils/logger";

import { oauthRepository } from "../../db/repositories";
import { buildClientRegistration } from "./client-registration";
import { getBaseUrl, GRANTED_OAUTH_SCOPE, rateLimitToken } from "./utils";

const registrationRouter = express.Router();

/**
 * OAuth 2.0 Dynamic Client Registration Endpoint
 * Allows clients to dynamically register with the authorization server
 * Implementation follows RFC 7591 with OAuth 2.1 security enhancements
 */
registrationRouter.post("/oauth/register", rateLimitToken, async (req, res) => {
  try {
    // Check if body was parsed correctly
    if (!req.body || typeof req.body !== "object") {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Request body is missing or malformed",
      });
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

    const clientRegistration = registration.client;
    const clientSecret = clientRegistration.client_secret;

    // Store the client registration
    await oauthRepository.upsertClient(clientRegistration);

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
      token_endpoint_auth_method: clientRegistration.token_endpoint_auth_method,
      scope: clientRegistration.scope,

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
});

/**
 * OAuth 2.0 Dynamic Client Registration Information Endpoint
 * Provides guidance on how to register OAuth clients
 */
registrationRouter.get("/oauth/register", async (req, res) => {
  try {
    // Same proxy caveat as the POST handler above — see the comment there.
    const baseUrl = getBaseUrl(req);

    res.json({
      registration_endpoint: `${baseUrl}/oauth/register`,
      oauth_version: "OAuth 2.1",
      description: "Dynamic Client Registration for MetaMCP OAuth Server",

      required_parameters: {
        redirect_uris:
          "Array of redirect URIs for your application (HTTPS required in production)",
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
        https_only: "Use HTTPS redirect URIs in production",
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
          redirect_uris: ["https://myapp.example.com/oauth/callback"],
          grant_types: ["authorization_code"],
          response_types: ["code"],
          token_endpoint_auth_method: "none",
        },
      },

      next_steps: [
        "Register your client using POST to this endpoint",
        "Save the returned client_id",
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
