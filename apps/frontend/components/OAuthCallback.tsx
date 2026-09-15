"use client";

import { auth } from "@modelcontextprotocol/sdk/client/auth.js";
import { useEffect, useRef } from "react";

import { useTranslations } from "@/hooks/useTranslations";

import { getServerSpecificKey, SESSION_KEYS } from "../lib/constants";
import { createAuthProvider } from "../lib/oauth-provider";
import { vanillaTrpcClient } from "../lib/trpc";

// Drop every sessionStorage entry the SDK used during the pre-redirect
// half of the flow. Called from both the success and the error paths so a
// failed exchange leaves no stale state to confuse a retry. (ai-dev 3f8e88b.)
function clearOAuthSessionKeys(serverUrl: string | null): void {
  if (serverUrl) {
    sessionStorage.removeItem(
      getServerSpecificKey(SESSION_KEYS.CLIENT_INFORMATION, serverUrl),
    );
    sessionStorage.removeItem(
      getServerSpecificKey(SESSION_KEYS.TOKENS, serverUrl),
    );
    sessionStorage.removeItem(
      getServerSpecificKey(SESSION_KEYS.CODE_VERIFIER, serverUrl),
    );
  }
  sessionStorage.removeItem(SESSION_KEYS.SERVER_URL);
  sessionStorage.removeItem(SESSION_KEYS.MCP_SERVER_UUID);
}

const OAuthCallback = () => {
  const { t } = useTranslations();
  const hasProcessedRef = useRef(false);

  useEffect(() => {
    const handleCallback = async () => {
      // Skip if we've already processed this callback
      if (hasProcessedRef.current) {
        return;
      }
      hasProcessedRef.current = true;

      const params = new URLSearchParams(window.location.search);
      const code = params.get("code");
      const serverUrl = sessionStorage.getItem(SESSION_KEYS.SERVER_URL);
      const mcpServerUuid = sessionStorage.getItem(
        SESSION_KEYS.MCP_SERVER_UUID,
      );

      if (!code || !serverUrl || !mcpServerUuid) {
        console.error("Missing required OAuth parameters");
        clearOAuthSessionKeys(serverUrl);
        window.location.href = "/mcp-servers";
        return;
      }

      try {
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

        // Save OAuth session in database using tRPC
        await vanillaTrpcClient.frontend.oauth.upsert.mutate({
          mcp_server_uuid: mcpServerUuid,
          client_information: clientInformation
            ? JSON.parse(clientInformation)
            : undefined,
          tokens: tokens ? JSON.parse(tokens) : undefined,
          code_verifier: codeVerifier || undefined,
        });

        // Clean up session storage
        clearOAuthSessionKeys(serverUrl);

        // Redirect back to the MCP server detail page
        window.location.href = `/mcp-servers/${mcpServerUuid}`;
      } catch (error) {
        console.error("OAuth callback error:", error);
        clearOAuthSessionKeys(serverUrl);
        window.location.href = "/mcp-servers";
      }
    };

    void handleCallback();
  }, []);

  return (
    <div className="flex items-center justify-center h-screen">
      <p className="text-lg text-gray-500">
        {t("common:oauth.processingCallback")}
      </p>
    </div>
  );
};

export default OAuthCallback;
