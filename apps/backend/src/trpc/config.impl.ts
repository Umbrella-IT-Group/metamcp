import type { AuditActor } from "@repo/trpc";
import { SetConfigRequest } from "@repo/zod-types";

import { emitAdminEvent } from "../lib/audit/admin-event";
import { configService } from "../lib/config.service";

/**
 * Read a config value for the `old_value` half of an audit row, without ever
 * being able to fail the write it is about to describe.
 *
 * The toggle is the operation; the before-picture is commentary on it. A
 * transient database error while reading the current value must degrade the
 * row to `old_value: null`, not refuse the administrator's change — the same
 * ordering the emitter itself enforces one level down.
 */
async function previousValue<T>(read: () => Promise<T>): Promise<T | null> {
  try {
    return await read();
  } catch {
    return null;
  }
}

/**
 * Gateway configuration writes.
 *
 * AUDITING, and why it is not uniform across this file. Until Phase 1B every
 * setter here was completely silent: an administrator (or anyone holding an
 * admin session) could re-open self-registration, turn basic auth back on, or
 * stretch the session lifetime, and the only evidence afterwards was the
 * config row's `updated_at`. That is the 2026-08-13 incident's front door, so
 * the five AUTH-POSTURE writes — signup, SSO signup, basic auth, session
 * lifetime, and the generic `setConfig` escape hatch that can reach all of
 * them — emit an attributed `config.*.set` row carrying old AND new value.
 * The new value alone does not answer "did this change anything?", which is
 * the first question asked of a toggle during an incident.
 *
 * The four MCP tuning setters (`setMcpResetTimeoutOnProgress`,
 * `setMcpTimeout`, `setMcpMaxTotalTimeout`, `setMcpMaxAttempts`) deliberately
 * do NOT emit. They change upstream retry/timeout behaviour, not who may
 * reach this gateway, and they are the ones an operator touches routinely
 * while debugging a flaky backend. Adding them is a decision, not an
 * oversight to be quietly corrected — the reason to make it would be treating
 * `audit_log` as a general config-change ledger rather than a security one.
 */
export const configImplementations = {
  getSignupDisabled: async (): Promise<boolean> => {
    return await configService.isSignupDisabled();
  },

  setSignupDisabled: async (
    input: {
      disabled: boolean;
    },
    actor?: AuditActor,
  ): Promise<{ success: boolean }> => {
    const old_value = await previousValue(() =>
      configService.isSignupDisabled(),
    );
    await configService.setSignupDisabled(input.disabled);
    // After the write, never before: a row claiming signup was re-opened by a
    // call that then threw would be worse than no row at all.
    emitAdminEvent(actor, {
      action: "config.signup_disabled.set",
      target_type: "config_key",
      target_id: "DISABLE_SIGNUP",
      detail: { old_value, new_value: input.disabled },
    });
    return { success: true };
  },

  getSsoSignupDisabled: async (): Promise<boolean> => {
    return await configService.isSsoSignupDisabled();
  },

  setSsoSignupDisabled: async (
    input: {
      disabled: boolean;
    },
    actor?: AuditActor,
  ): Promise<{ success: boolean }> => {
    const old_value = await previousValue(() =>
      configService.isSsoSignupDisabled(),
    );
    await configService.setSsoSignupDisabled(input.disabled);
    emitAdminEvent(actor, {
      action: "config.sso_signup_disabled.set",
      target_type: "config_key",
      target_id: "DISABLE_SSO_SIGNUP",
      detail: { old_value, new_value: input.disabled },
    });
    return { success: true };
  },

  getBasicAuthDisabled: async (): Promise<boolean> => {
    return await configService.isBasicAuthDisabled();
  },

  setBasicAuthDisabled: async (
    input: {
      disabled: boolean;
    },
    actor?: AuditActor,
  ): Promise<{ success: boolean }> => {
    const old_value = await previousValue(() =>
      configService.isBasicAuthDisabled(),
    );
    await configService.setBasicAuthDisabled(input.disabled);
    emitAdminEvent(actor, {
      action: "config.basic_auth_disabled.set",
      target_type: "config_key",
      target_id: "DISABLE_BASIC_AUTH",
      detail: { old_value, new_value: input.disabled },
    });
    return { success: true };
  },

  getMcpResetTimeoutOnProgress: async (): Promise<boolean> => {
    return await configService.getMcpResetTimeoutOnProgress();
  },

  setMcpResetTimeoutOnProgress: async (input: {
    enabled: boolean;
  }): Promise<{ success: boolean }> => {
    await configService.setMcpResetTimeoutOnProgress(input.enabled);
    return { success: true };
  },

  getMcpTimeout: async (): Promise<number> => {
    return await configService.getMcpTimeout();
  },

  setMcpTimeout: async (input: {
    timeout: number;
  }): Promise<{ success: boolean }> => {
    await configService.setMcpTimeout(input.timeout);
    return { success: true };
  },

  getMcpMaxTotalTimeout: async (): Promise<number> => {
    return await configService.getMcpMaxTotalTimeout();
  },

  setMcpMaxTotalTimeout: async (input: {
    timeout: number;
  }): Promise<{ success: boolean }> => {
    await configService.setMcpMaxTotalTimeout(input.timeout);
    return { success: true };
  },

  getMcpMaxAttempts: async (): Promise<number> => {
    return await configService.getMcpMaxAttempts();
  },

  setMcpMaxAttempts: async (input: {
    maxAttempts: number;
  }): Promise<{ success: boolean }> => {
    await configService.setMcpMaxAttempts(input.maxAttempts);
    return { success: true };
  },

  getSessionLifetime: async (): Promise<number | null> => {
    return await configService.getSessionLifetime();
  },

  setSessionLifetime: async (
    input: {
      lifetime?: number | null;
    },
    actor?: AuditActor,
  ): Promise<{ success: boolean }> => {
    const old_value = await previousValue(() =>
      configService.getSessionLifetime(),
    );
    await configService.setSessionLifetime(input.lifetime);
    emitAdminEvent(actor, {
      action: "config.session_lifetime.set",
      target_type: "config_key",
      target_id: "SESSION_LIFETIME",
      // `null` is a real value here, not a missing one — it means unlimited
      // session lifetime (the row is deleted). Normalised so the two are the
      // same shape in the column rather than one being an absent key.
      detail: { old_value, new_value: input.lifetime ?? null },
    });
    return { success: true };
  },

  getAllConfigs: async (): Promise<
    Array<{ id: string; value: string; description?: string | null }>
  > => {
    return await configService.getAllConfigs();
  },

  setConfig: async (
    input: SetConfigRequest,
    actor?: AuditActor,
  ): Promise<{ success: boolean }> => {
    // The generic escape hatch: `key` is the full ConfigKey enum, so this one
    // procedure can set DISABLE_SIGNUP without going through the named setter
    // above. It therefore has to be audited even though the named setters are
    // — otherwise the front door has a second, unlogged handle.
    const old_value = await previousValue(() =>
      configService.getConfig(input.key),
    );
    await configService.setConfig(input.key, input.value, input.description);
    emitAdminEvent(actor, {
      action: "config.set",
      target_type: "config_key",
      target_id: input.key,
      // Values are safe to persist: ConfigKey is a closed enum of gateway
      // behaviour flags and timeouts, none of which is a credential.
      detail: { old_value: old_value ?? null, new_value: input.value },
    });
    return { success: true };
  },

  getAuthProviders: async (): Promise<
    Array<{ id: string; name: string; enabled: boolean }>
  > => {
    return await configService.getAuthProviders();
  },
};
