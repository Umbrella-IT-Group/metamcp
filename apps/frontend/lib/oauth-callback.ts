import { auth } from "@modelcontextprotocol/sdk/client/auth.js";

import { getServerSpecificKey, SESSION_KEYS } from "./constants";
import { createAuthProvider } from "./oauth-provider";
import { vanillaTrpcClient } from "./trpc";

/**
 * The /fe-oauth/callback flow: exchange the authorization code, then persist
 * the OAuth session the Inspector started for an upstream MCP server.
 *
 * It lives here rather than in components/OAuthCallback so a test can drive
 * the real code. The callback page is outside the middleware matcher and so
 * outside the Content-Security-Policy, which makes this the one place where
 * `auth()` can reach an arbitrary authorization server from the browser: it is
 * where a stored client_secret would have been sent to a changed authorization
 * server (GHSA-6qxp-vccf-f47h), and the issuer binding has to hold here.
 *
 * Resolves to the path to navigate to. Throws when the exchange fails,
 * including when the stored client information is bound to a different
 * authorization server than the one the MCP server now advertises (the SDK
 * refuses to exchange the code rather than send it there); the caller logs
 * that and falls back to the server list.
 */
export async function completeOAuthCallback(search: string): Promise<string> {
  const params = new URLSearchParams(search);
  const code = params.get("code");
  const serverUrl = sessionStorage.getItem(SESSION_KEYS.SERVER_URL);
  const mcpServerUuid = sessionStorage.getItem(SESSION_KEYS.MCP_SERVER_UUID);

  if (!code || !serverUrl || !mcpServerUuid) {
    console.error("Missing required OAuth parameters");
    return "/mcp-servers";
  }

  // Create auth provider with existing server UUID and URL
  const authProvider = createAuthProvider(mcpServerUuid, serverUrl);

  // Complete the OAuth flow
  const result = await auth(authProvider, {
    serverUrl,
    authorizationCode: code,
  });

  if (result !== "AUTHORIZED") {
    throw new Error(
      `Expected to be authorized after providing auth code, got: ${result}`,
    );
  }

  // Transfer OAuth data from session storage to database
  const clientInformationKey = getServerSpecificKey(
    SESSION_KEYS.CLIENT_INFORMATION,
    serverUrl,
  );
  const tokensKey = getServerSpecificKey(SESSION_KEYS.TOKENS, serverUrl);
  const codeVerifierKey = getServerSpecificKey(
    SESSION_KEYS.CODE_VERIFIER,
    serverUrl,
  );

  const clientInformation = sessionStorage.getItem(clientInformationKey);
  const tokens = sessionStorage.getItem(tokensKey);
  const codeVerifier = sessionStorage.getItem(codeVerifierKey);

  // Save OAuth session in database using tRPC. The stored values are written
  // exactly as the SDK saved them, `issuer` stamp included; the upsert schema
  // keeps it (see @repo/zod-types oauth.zod).
  await vanillaTrpcClient.frontend.oauth.upsert.mutate({
    mcp_server_uuid: mcpServerUuid,
    client_information: clientInformation
      ? JSON.parse(clientInformation)
      : undefined,
    tokens: tokens ? JSON.parse(tokens) : undefined,
    code_verifier: codeVerifier || undefined,
  });

  // Clean up session storage
  sessionStorage.removeItem(clientInformationKey);
  sessionStorage.removeItem(tokensKey);
  sessionStorage.removeItem(codeVerifierKey);
  sessionStorage.removeItem(SESSION_KEYS.SERVER_URL);
  sessionStorage.removeItem(SESSION_KEYS.MCP_SERVER_UUID);

  // Redirect back to the MCP server detail page
  return `/mcp-servers/${mcpServerUuid}`;
}
