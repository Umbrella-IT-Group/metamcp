/**
 * Environment-derived configuration for the M365 delegated-token broker.
 *
 * All values come from the `metamcp-m365.env` SOPS-vaulted env file
 * (Umbrella-Cloud-Vault `secrets/mcp-host/metamcp-m365.env.enc`, mounted
 * via compose `env_file` with `required: false`). The broker must boot
 * CLEANLY when the file is absent — `isM365BrokerConfigured()` gates
 * every route and the injection path, returning typed `not_configured`
 * errors instead of crashing. This lets the fork image deploy before the
 * Entra app registration exists (the admin-consent morning gate).
 *
 * Design doc: Umbrella-MCP-Server `docs/M365_DELEGATED_MCP_DESIGN.md` §4.1.
 */

/**
 * Delegated scopes requested at enrollment AND on every refresh grant.
 * Entra refresh tokens bind user+client (not scopes), so the refresh
 * grant may request any admin-consented scope; pinning the same list on
 * both legs keeps minted access tokens predictable. Overridable via
 * `M365_SCOPES` (space-separated) for staged rollouts.
 */
export const DEFAULT_M365_SCOPES = [
  "openid",
  "profile",
  "email",
  "offline_access",
  "User.Read",
  "Mail.ReadWrite",
  "Mail.Send",
  "Calendars.ReadWrite",
  "Calendars.Read.Shared",
  "Tasks.ReadWrite",
  "Contacts.ReadWrite",
  "Files.ReadWrite.All",
  "Sites.Read.All",
  "Chat.ReadWrite",
  "Notes.ReadWrite.All",
  "People.Read",
].join(" ");

export interface M365BrokerConfig {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  /** Raw 32-byte KEK, decoded from base64 `M365_TOKEN_KEK`. */
  kek: Buffer;
  /** Identifier stamped on ciphertexts so KEK rotation can coexist. */
  kekId: string;
  scopes: string;
  /** Public gateway base URL (existing `APP_URL`), no trailing slash. */
  appUrl: string;
  /**
   * MCP server names whose backend requests get per-user Graph token
   * injection. Comma-separated via `M365_INJECTED_SERVER_NAMES`;
   * defaults to `m365` (the delegated destination server registration).
   */
  injectedServerNames: Set<string>;
}

/** Read env fresh each call — config.service-style caching is overkill
 * for a handful of process-lifetime-constant vars, and fresh reads make
 * unit tests trivial (vitest mutates process.env per case). */
function readEnv(): {
  tenantId?: string;
  clientId?: string;
  clientSecret?: string;
  kekB64?: string;
} {
  return {
    tenantId: process.env.M365_TENANT_ID || undefined,
    clientId: process.env.M365_CLIENT_ID || undefined,
    clientSecret: process.env.M365_CLIENT_SECRET || undefined,
    kekB64: process.env.M365_TOKEN_KEK || undefined,
  };
}

export function isM365BrokerConfigured(): boolean {
  const { tenantId, clientId, clientSecret, kekB64 } = readEnv();
  return Boolean(tenantId && clientId && clientSecret && kekB64);
}

/**
 * Server names eligible for injection. Readable even when the broker is
 * otherwise unconfigured so `client.ts` wiring stays deterministic.
 */
export function getInjectedServerNames(): Set<string> {
  const raw = process.env.M365_INJECTED_SERVER_NAMES || "m365";
  return new Set(
    raw
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  );
}

/**
 * Full config. Throws (with a plain Error — callers translate to the
 * typed `not_configured` broker error where user-facing) when required
 * env is missing or the KEK is malformed.
 */
export function getM365BrokerConfig(): M365BrokerConfig {
  const { tenantId, clientId, clientSecret, kekB64 } = readEnv();
  if (!tenantId || !clientId || !clientSecret || !kekB64) {
    throw new Error(
      "M365 broker is not configured: M365_TENANT_ID, M365_CLIENT_ID, M365_CLIENT_SECRET and M365_TOKEN_KEK are all required",
    );
  }
  const kek = Buffer.from(kekB64, "base64");
  if (kek.length !== 32) {
    throw new Error(
      `M365_TOKEN_KEK must be base64 for exactly 32 bytes (AES-256); got ${kek.length} bytes`,
    );
  }
  const appUrl = (process.env.APP_URL || "").replace(/\/+$/, "");
  if (!appUrl) {
    // APP_URL is already required at boot by auth.ts; this is defensive.
    throw new Error("APP_URL is required for M365 broker redirect URIs");
  }
  return {
    tenantId,
    clientId,
    clientSecret,
    kek,
    kekId: process.env.M365_KEK_ID || "k1",
    scopes: process.env.M365_SCOPES || DEFAULT_M365_SCOPES,
    appUrl,
    injectedServerNames: getInjectedServerNames(),
  };
}

/** Entra v2 endpoints for the configured tenant. */
export function entraAuthorizeUrl(tenantId: string): string {
  return `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`;
}
export function entraTokenUrl(tenantId: string): string {
  return `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;
}

/** Absolute enrollment URL surfaced in typed errors + elicitations. */
export function m365EnrollUrl(): string {
  const appUrl = (process.env.APP_URL || "").replace(/\/+$/, "");
  return `${appUrl}/m365/enroll`;
}
