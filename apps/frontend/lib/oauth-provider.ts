import { OAuthClientProvider } from "@modelcontextprotocol/sdk/client/auth.js";
import {
  OAuthClientInformation,
  OAuthClientInformationSchema,
  OAuthClientMetadata,
  OAuthTokens,
  OAuthTokensSchema,
} from "@modelcontextprotocol/sdk/shared/auth.js";

import { getServerSpecificKey, SESSION_KEYS } from "./constants";
import { getAppUrl } from "./env";
import { vanillaTrpcClient } from "./trpc";

/*
 * Issuer binding for the upstream credentials this provider stores
 * (GHSA-6qxp-vccf-f47h).
 *
 * The SDK's `auth()` discovers the authorization server from whatever the
 * upstream MCP server advertises, then sends the stored client_secret
 * (registration) and refresh token to that server's token endpoint. Since SDK
 * 1.31 it stamps `issuer` (the authorization server URL) on every value it
 * saves and, on read, treats a value stamped for a DIFFERENT server as absent.
 * That protection only works if the stamp survives storage, which is why the
 * `oauth.upsert` / `oauth.get` schemas in @repo/zod-types carry `issuer`.
 *
 * A value with NO stamp is the gap. The SDK presents it as-is to whichever
 * authorization server discovery returns and stamps it with that server once
 * it is accepted (trust on first use, `discardIfIssuerMismatch` in
 * sdk/client/auth.js). Every credential saved before 1.31 is unstamped, so on
 * an upstream server whose advertised authorization server has changed, the
 * first use would send the old client_secret or refresh token to the new
 * server and then bind it there. Nothing records which server issued those
 * values, so a safe rebind is impossible: they are refused here instead of
 * handed to the SDK.
 *
 * - Unstamped client information reads as absent. The SDK then registers a
 *   new client with the current authorization server (it re-registers the same
 *   way for a mismatched stamp), and a callback holding an authorization code
 *   with no stamped client information fails rather than exchanging it.
 * - Unstamped tokens keep their access token and lose only the refresh token.
 *   The access token goes to the MCP server, never to an authorization server,
 *   so it stays usable until it expires; after that the Inspector asks for a
 *   fresh authorization instead of refreshing silently.
 *
 * Each refusal is logged with the reason, so the extra authorization prompt
 * is explained rather than mysterious.
 */
function hasIssuerStamp(value: { issuer?: unknown }): boolean {
  return typeof value.issuer === "string";
}

function refuseUnboundClientInformation(
  clientInformation: OAuthClientInformation,
  mcpServerUuid: string,
): OAuthClientInformation | undefined {
  if (hasIssuerStamp(clientInformation)) {
    return clientInformation;
  }
  console.warn(
    `[oauth] The stored OAuth client registration for MCP server ${mcpServerUuid} ` +
      "was saved without the authorization server it belongs to (before issuer " +
      "binding), so it is not presented to any authorization server. A new client " +
      "will be registered with the server's current authorization server, and you " +
      "will be asked to authorize again.",
  );
  return undefined;
}

function withholdUnboundRefreshToken(
  tokens: OAuthTokens,
  mcpServerUuid: string,
): OAuthTokens {
  if (hasIssuerStamp(tokens) || tokens.refresh_token === undefined) {
    return tokens;
  }
  console.warn(
    `[oauth] The stored OAuth refresh token for MCP server ${mcpServerUuid} was ` +
      "saved without the authorization server it belongs to (before issuer " +
      "binding), so it is not presented to any authorization server. The stored " +
      "access token is still used until it expires; after that you will be asked " +
      "to authorize again.",
  );
  return { ...tokens, refresh_token: undefined };
}

// OAuth client provider that works with a specific MCP server
class DbOAuthClientProvider implements OAuthClientProvider {
  private mcpServerUuid: string;
  protected serverUrl: string;

  constructor(mcpServerUuid: string, serverUrl: string) {
    this.mcpServerUuid = mcpServerUuid;
    this.serverUrl = serverUrl;
    // useConnection() instantiates this provider at render time, and that
    // render includes the server render of every page that hosts an MCP
    // connection. sessionStorage is browser-only, so writing it unconditionally
    // throws "sessionStorage is not defined" during SSR and turns the whole
    // route into a 500 before the client can hydrate. The write only keeps the
    // server URL in sync for the client-side OAuth flow (SERVER_URL is read back
    // exclusively in the browser), so it is skipped when web storage is absent;
    // the client re-runs the constructor on hydration and performs it then.
    if (typeof window !== "undefined") {
      sessionStorage.setItem(SESSION_KEYS.SERVER_URL, serverUrl);
    }
  }

  get redirectUrl() {
    return getAppUrl() + "/fe-oauth/callback";
  }

  get clientMetadata(): OAuthClientMetadata {
    return {
      redirect_uris: [this.redirectUrl],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      client_name: "MetaMCP",
      client_uri: "https://github.com/metatool-ai/metamcp",
    };
  }

  // Check if the server exists in the database
  private async serverExists() {
    try {
      const result = await vanillaTrpcClient.frontend.mcpServers.get.query({
        uuid: this.mcpServerUuid,
      });
      return result.success && !!result.data;
    } catch (error) {
      console.error("Error checking server existence:", error);
      return false;
    }
  }

  // During OAuth flow, we use sessionStorage for temporary data
  // After successful authentication, we'll save to the database
  async clientInformation() {
    try {
      // Check if server exists in the database
      const exists = await this.serverExists();

      if (exists) {
        // Get from database if server exists
        const result = await vanillaTrpcClient.frontend.oauth.get.query({
          mcp_server_uuid: this.mcpServerUuid,
        });
        if (result.success && result.data?.client_information) {
          return refuseUnboundClientInformation(
            await OAuthClientInformationSchema.parseAsync(
              result.data.client_information,
            ),
            this.mcpServerUuid,
          );
        }
      } else {
        // Get from session storage during OAuth flow
        const key = getServerSpecificKey(
          SESSION_KEYS.CLIENT_INFORMATION,
          this.serverUrl,
        );
        const storedInfo = sessionStorage.getItem(key);
        if (storedInfo) {
          return refuseUnboundClientInformation(
            await OAuthClientInformationSchema.parseAsync(
              JSON.parse(storedInfo),
            ),
            this.mcpServerUuid,
          );
        }
      }

      return undefined;
    } catch (error) {
      console.error("Error retrieving client information:", error);
      return undefined;
    }
  }

  async saveClientInformation(clientInformation: OAuthClientInformation) {
    // Save to session storage during OAuth flow
    const key = getServerSpecificKey(
      SESSION_KEYS.CLIENT_INFORMATION,
      this.serverUrl,
    );
    sessionStorage.setItem(key, JSON.stringify(clientInformation));

    // If server exists, also save to database
    if (await this.serverExists()) {
      try {
        await vanillaTrpcClient.frontend.oauth.upsert.mutate({
          mcp_server_uuid: this.mcpServerUuid,
          client_information: clientInformation,
        });
      } catch (error) {
        console.error("Error saving client information to database:", error);
      }
    }
  }

  async tokens() {
    try {
      // Check if server exists in the database
      const exists = await this.serverExists();

      if (exists) {
        // Get from database if server exists
        const result = await vanillaTrpcClient.frontend.oauth.get.query({
          mcp_server_uuid: this.mcpServerUuid,
        });
        if (result.success && result.data?.tokens) {
          return withholdUnboundRefreshToken(
            await OAuthTokensSchema.parseAsync(result.data.tokens),
            this.mcpServerUuid,
          );
        }
      } else {
        // Get from session storage during OAuth flow
        const key = getServerSpecificKey(SESSION_KEYS.TOKENS, this.serverUrl);
        const storedTokens = sessionStorage.getItem(key);
        if (storedTokens) {
          return withholdUnboundRefreshToken(
            await OAuthTokensSchema.parseAsync(JSON.parse(storedTokens)),
            this.mcpServerUuid,
          );
        }
      }

      return undefined;
    } catch (error) {
      console.error("Error retrieving tokens:", error);
      return undefined;
    }
  }

  async saveTokens(tokens: OAuthTokens) {
    // Save to session storage during OAuth flow
    const key = getServerSpecificKey(SESSION_KEYS.TOKENS, this.serverUrl);
    sessionStorage.setItem(key, JSON.stringify(tokens));

    // If server exists, also save to database
    if (await this.serverExists()) {
      try {
        await vanillaTrpcClient.frontend.oauth.upsert.mutate({
          mcp_server_uuid: this.mcpServerUuid,
          tokens,
        });
      } catch (error) {
        console.error("Error saving tokens to database:", error);
      }
    }
  }

  redirectToAuthorization(authorizationUrl: URL) {
    window.location.href = authorizationUrl.href;
  }

  async saveCodeVerifier(codeVerifier: string) {
    // Save to session storage during OAuth flow
    const key = getServerSpecificKey(
      SESSION_KEYS.CODE_VERIFIER,
      this.serverUrl,
    );
    sessionStorage.setItem(key, codeVerifier);

    // If server exists, also save to database
    if (await this.serverExists()) {
      try {
        await vanillaTrpcClient.frontend.oauth.upsert.mutate({
          mcp_server_uuid: this.mcpServerUuid,
          code_verifier: codeVerifier,
        });
      } catch (error) {
        console.error("Error saving code verifier to database:", error);
      }
    }
  }

  async codeVerifier() {
    // Check if server exists in the database
    const exists = await this.serverExists();

    if (exists) {
      // Get from database if server exists
      try {
        const result = await vanillaTrpcClient.frontend.oauth.get.query({
          mcp_server_uuid: this.mcpServerUuid,
        });
        if (result.success && result.data?.code_verifier) {
          return result.data.code_verifier;
        }
      } catch (error) {
        console.error("Error retrieving code verifier from database:", error);
      }
    }

    // Get from session storage during OAuth flow
    const key = getServerSpecificKey(
      SESSION_KEYS.CODE_VERIFIER,
      this.serverUrl,
    );
    const codeVerifier = sessionStorage.getItem(key);
    if (!codeVerifier) {
      throw new Error("No code verifier saved for session");
    }

    return codeVerifier;
  }

  clear() {
    sessionStorage.removeItem(
      getServerSpecificKey(SESSION_KEYS.CLIENT_INFORMATION, this.serverUrl),
    );
    sessionStorage.removeItem(
      getServerSpecificKey(SESSION_KEYS.TOKENS, this.serverUrl),
    );
    sessionStorage.removeItem(
      getServerSpecificKey(SESSION_KEYS.CODE_VERIFIER, this.serverUrl),
    );
  }
}

// Factory function to create an OAuth provider for a specific MCP server
export function createAuthProvider(
  mcpServerUuid: string,
  serverUrl: string,
): DbOAuthClientProvider {
  return new DbOAuthClientProvider(mcpServerUuid, serverUrl);
}
