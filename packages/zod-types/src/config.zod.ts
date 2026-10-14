import { z } from "zod";

// Define config key enum
export const ConfigKeyEnum = z.enum([
  "DISABLE_SIGNUP",
  "DISABLE_SSO_SIGNUP",
  "DISABLE_BASIC_AUTH",
  "MCP_RESET_TIMEOUT_ON_PROGRESS",
  "MCP_TIMEOUT",
  "MCP_MAX_TOTAL_TIMEOUT",
  "MCP_MAX_ATTEMPTS",
  "SESSION_LIFETIME",
  // Hard cap (ms) per warmup attempt when a tools/call lands in the
  // reconnect window (invalidateServerConnection tears the pooled
  // client down before the replacement exists) and has to wait for the
  // owning server to reconnect before falling back to "Unknown tool".
  // See config.service.ts's getMcpToolCallReconnectWarmupTimeout.
  "MCP_TOOL_CALL_RECONNECT_WARMUP_TIMEOUT",
  // The GLOBAL API-key IP policy (migration 0040), applied to every key whose
  // own api_keys.allowed_cidrs is NULL. MODE is off | audit | enforce (unset
  // reads as off); ALLOWED_CIDRS is a JSON array of CIDR strings. Written ONLY
  // through apiKeys.setGlobalIpPolicy, which validates both and writes them in
  // one transaction; the generic config.setConfig refuses these two keys so an
  // unvalidated value cannot reach the evaluator. See
  // apps/backend/src/lib/api-key-ip-policy.ts.
  "API_KEY_IP_POLICY_MODE",
  "API_KEY_IP_ALLOWED_CIDRS",
]);

// Config schema
export const ConfigSchema = z.object({
  id: z.string(),
  value: z.string(),
  description: z.string().nullable(),
  created_at: z.string(),
  updated_at: z.string(),
});

// Request/Response schemas
export const SetConfigRequestSchema = z.object({
  key: ConfigKeyEnum,
  value: z.string(),
  description: z.string().optional(),
});

export const SetConfigResponseSchema = z.object({
  success: z.boolean(),
});

export const GetConfigRequestSchema = z.object({
  key: ConfigKeyEnum,
});

export const GetConfigResponseSchema = z.object({
  success: z.boolean(),
  data: z
    .object({
      value: z.string(),
    })
    .optional(),
  message: z.string().optional(),
});

export const GetAllConfigsResponseSchema = z.object({
  success: z.boolean(),
  data: z.array(ConfigSchema),
  message: z.string().optional(),
});

// Type exports
export type ConfigKey = z.infer<typeof ConfigKeyEnum>;
export type Config = z.infer<typeof ConfigSchema>;
export type SetConfigRequest = z.infer<typeof SetConfigRequestSchema>;
export type SetConfigResponse = z.infer<typeof SetConfigResponseSchema>;
export type GetConfigRequest = z.infer<typeof GetConfigRequestSchema>;
export type GetConfigResponse = z.infer<typeof GetConfigResponseSchema>;
export type GetAllConfigsResponse = z.infer<typeof GetAllConfigsResponseSchema>;

// Repository-specific schemas
export const ConfigCreateInputSchema = z.object({
  id: z.string(),
  value: z.string(),
  description: z.string().nullable().optional(),
});

export const ConfigUpdateInputSchema = z.object({
  id: z.string(),
  value: z.string(),
  description: z.string().nullable().optional(),
});

export type ConfigCreateInput = z.infer<typeof ConfigCreateInputSchema>;
export type ConfigUpdateInput = z.infer<typeof ConfigUpdateInputSchema>;

// Settings form schema for frontend
export const SettingsFormSchema = z.object({
  mcpTimeout: z.number().int(),
  mcpMaxTotalTimeout: z.number().int(),
  mcpMaxAttempts: z.number().int(),
  sessionLifetime: z.number().int().min(5).max(1440).nullable().optional(),
});

export type SettingsFormData = z.infer<typeof SettingsFormSchema>;

// Database-specific schemas (with Date objects)
export const DatabaseConfigSchema = z.object({
  id: z.string(),
  value: z.string(),
  description: z.string().nullable(),
  created_at: z.date(),
  updated_at: z.date(),
});

export type DatabaseConfig = z.infer<typeof DatabaseConfigSchema>;
