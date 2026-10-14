import { ConfigKey, ConfigKeyEnum } from "@repo/zod-types";

import { configRepo } from "../db/repositories/config.repo";
import {
  type GlobalIpPolicy,
  type IpPolicyMode,
  parseStoredGlobalPolicy,
} from "./api-key-ip-policy";

export const configService = {
  async isSignupDisabled(): Promise<boolean> {
    const config = await configRepo.getConfig(
      ConfigKeyEnum.enum.DISABLE_SIGNUP,
    );
    return config?.value === "true";
  },

  async setSignupDisabled(disabled: boolean): Promise<void> {
    await configRepo.setConfig(
      ConfigKeyEnum.enum.DISABLE_SIGNUP,
      disabled.toString(),
      "Whether new user signup is disabled",
    );
  },

  async isSsoSignupDisabled(): Promise<boolean> {
    const config = await configRepo.getConfig(
      ConfigKeyEnum.enum.DISABLE_SSO_SIGNUP,
    );
    return config?.value === "true";
  },

  async setSsoSignupDisabled(disabled: boolean): Promise<void> {
    await configRepo.setConfig(
      ConfigKeyEnum.enum.DISABLE_SSO_SIGNUP,
      disabled.toString(),
      "Whether new user signup via SSO/OAuth is disabled",
    );
  },

  async isBasicAuthDisabled(): Promise<boolean> {
    const config = await configRepo.getConfig(
      ConfigKeyEnum.enum.DISABLE_BASIC_AUTH,
    );
    return config?.value === "true";
  },

  async setBasicAuthDisabled(disabled: boolean): Promise<void> {
    await configRepo.setConfig(
      ConfigKeyEnum.enum.DISABLE_BASIC_AUTH,
      disabled.toString(),
      "Whether basic email/password authentication is disabled",
    );
  },

  async getMcpResetTimeoutOnProgress(): Promise<boolean> {
    const config = await configRepo.getConfig(
      ConfigKeyEnum.enum.MCP_RESET_TIMEOUT_ON_PROGRESS,
    );
    return config?.value === "true" || true;
  },

  async setMcpResetTimeoutOnProgress(enabled: boolean): Promise<void> {
    await configRepo.setConfig(
      ConfigKeyEnum.enum.MCP_RESET_TIMEOUT_ON_PROGRESS,
      enabled.toString(),
      "Whether to reset timeout on progress for MCP requests",
    );
  },

  async getMcpTimeout(): Promise<number> {
    const config = await configRepo.getConfig(ConfigKeyEnum.enum.MCP_TIMEOUT);
    return config?.value ? parseInt(config.value, 10) : 60000;
  },

  async setMcpTimeout(timeout: number): Promise<void> {
    await configRepo.setConfig(
      ConfigKeyEnum.enum.MCP_TIMEOUT,
      timeout.toString(),
      "MCP request timeout in milliseconds",
    );
  },

  async getMcpMaxTotalTimeout(): Promise<number> {
    const config = await configRepo.getConfig(
      ConfigKeyEnum.enum.MCP_MAX_TOTAL_TIMEOUT,
    );
    return config?.value ? parseInt(config.value, 10) : 60000;
  },

  async setMcpMaxTotalTimeout(timeout: number): Promise<void> {
    await configRepo.setConfig(
      ConfigKeyEnum.enum.MCP_MAX_TOTAL_TIMEOUT,
      timeout.toString(),
      "MCP maximum total timeout in milliseconds",
    );
  },

  async getMcpMaxAttempts(): Promise<number> {
    const config = await configRepo.getConfig(
      ConfigKeyEnum.enum.MCP_MAX_ATTEMPTS,
    );
    return config?.value ? parseInt(config.value, 10) : 3;
  },

  async setMcpMaxAttempts(maxAttempts: number): Promise<void> {
    await configRepo.setConfig(
      ConfigKeyEnum.enum.MCP_MAX_ATTEMPTS,
      maxAttempts.toString(),
      "Maximum number of crash attempts before marking MCP server as ERROR",
    );
  },

  /**
   * Per-attempt hard cap (ms) for the bounded reconnect-window warmup
   * on the tools/call path (metamcp-proxy.ts / openapi/handlers.ts).
   * Default 5s: long enough to catch the common watchtower-bounce
   * reconnect, short enough that a genuinely dead upstream still fails
   * fast instead of hanging the caller on `client.ts`'s much longer
   * (up to 30s+ per hop) internal reconnect backoff.
   */
  async getMcpToolCallReconnectWarmupTimeout(): Promise<number> {
    const config = await configRepo.getConfig(
      ConfigKeyEnum.enum.MCP_TOOL_CALL_RECONNECT_WARMUP_TIMEOUT,
    );
    return config?.value ? parseInt(config.value, 10) : 5000;
  },

  async setMcpToolCallReconnectWarmupTimeout(timeout: number): Promise<void> {
    await configRepo.setConfig(
      ConfigKeyEnum.enum.MCP_TOOL_CALL_RECONNECT_WARMUP_TIMEOUT,
      timeout.toString(),
      "Per-attempt hard cap (ms) for the tools/call reconnect-window warmup",
    );
  },

  async getSessionLifetime(): Promise<number | null> {
    const config = await configRepo.getConfig(
      ConfigKeyEnum.enum.SESSION_LIFETIME,
    );
    if (!config?.value) {
      // Fallback to env var (milliseconds), then null (infinite sessions)
      const envLifetime = process.env.SESSION_LIFETIME;
      if (envLifetime) {
        const parsed = parseInt(envLifetime, 10);
        return isNaN(parsed) ? null : parsed;
      }
      return null;
    }
    const lifetime = parseInt(config.value, 10);
    return isNaN(lifetime) ? null : lifetime;
  },

  async setSessionLifetime(lifetime?: number | null): Promise<void> {
    if (lifetime === null || lifetime === undefined) {
      // Remove the config to indicate infinite session lifetime
      await configRepo.deleteConfig(ConfigKeyEnum.enum.SESSION_LIFETIME);
    } else {
      await configRepo.setConfig(
        ConfigKeyEnum.enum.SESSION_LIFETIME,
        lifetime.toString(),
        "Session lifetime in milliseconds before automatic cleanup",
      );
    }
  },

  /**
   * The GLOBAL API-key IP policy (migration 0041), read live on every key
   * validation that needs it, the way DISABLE_BASIC_AUTH is read per request:
   * one query for both rows, no cache, so a change made through the admin
   * plane applies to the very next request. `problems` lists stored values the
   * parser could not read; see parseStoredGlobalPolicy for how each is read
   * (always fail closed).
   */
  async getApiKeyIpPolicy(): Promise<GlobalIpPolicy & { problems: string[] }> {
    const rows = await configRepo.getConfigs([
      ConfigKeyEnum.enum.API_KEY_IP_POLICY_MODE,
      ConfigKeyEnum.enum.API_KEY_IP_ALLOWED_CIDRS,
    ]);
    const value = (id: string) => rows.find((row) => row.id === id)?.value;
    return parseStoredGlobalPolicy(
      value(ConfigKeyEnum.enum.API_KEY_IP_POLICY_MODE),
      value(ConfigKeyEnum.enum.API_KEY_IP_ALLOWED_CIDRS),
    );
  },

  /**
   * Write the global policy. The caller (apiKeys.setGlobalIpPolicy) has
   * already validated and canonicalised the list; both rows and the snapshots
   * used for the audit/readback share one serialized transaction.
   */
  async setApiKeyIpPolicy(policy: {
    mode: IpPolicyMode;
    cidrs: string[];
  }): Promise<{ before: GlobalIpPolicy; after: GlobalIpPolicy }> {
    const snapshots = await configRepo.setConfigs([
      {
        id: ConfigKeyEnum.enum.API_KEY_IP_POLICY_MODE,
        value: policy.mode,
        description:
          "Global API-key IP policy mode (off | audit | enforce) for keys with no allowed_cidrs of their own",
      },
      {
        id: ConfigKeyEnum.enum.API_KEY_IP_ALLOWED_CIDRS,
        value: JSON.stringify(policy.cidrs),
        description:
          "Global API-key IP allowlist (JSON array of CIDRs) for keys with no allowed_cidrs of their own",
      },
    ]);
    const parse = (rows: Array<{ id: string; value: string }>) =>
      parseStoredGlobalPolicy(
        rows.find((row) => row.id === ConfigKeyEnum.enum.API_KEY_IP_POLICY_MODE)
          ?.value,
        rows.find(
          (row) => row.id === ConfigKeyEnum.enum.API_KEY_IP_ALLOWED_CIDRS,
        )?.value,
      );
    return { before: parse(snapshots.before), after: parse(snapshots.after) };
  },

  async getConfig(key: ConfigKey): Promise<string | undefined> {
    const config = await configRepo.getConfig(key);
    return config?.value;
  },

  async setConfig(
    key: ConfigKey,
    value: string,
    description?: string,
  ): Promise<void> {
    await configRepo.setConfig(key, value, description);
  },

  async getAllConfigs(): Promise<
    Array<{ id: string; value: string; description?: string | null }>
  > {
    return await configRepo.getAllConfigs();
  },

  async getAuthProviders(): Promise<
    Array<{ id: string; name: string; enabled: boolean }>
  > {
    const providers = [];

    // Check if OIDC is configured
    const isOidcEnabled = !!(
      process.env.OIDC_CLIENT_ID &&
      process.env.OIDC_CLIENT_SECRET &&
      process.env.OIDC_DISCOVERY_URL
    );

    if (isOidcEnabled) {
      providers.push({
        id: "oidc",
        name: "OIDC",
        enabled: true,
      });
    }

    return providers;
  },
};
