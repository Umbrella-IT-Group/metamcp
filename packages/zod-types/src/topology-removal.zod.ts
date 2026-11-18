import { z } from "zod";

/**
 * The leaf-only topology removals an operator-scope admin-plane key may make:
 * one endpoint, one namespace or one MCP server, each only once nothing else
 * depends on it, confirmed by its current name and by the fingerprint its
 * `removalImpact` read returned. The broad `endpoints.delete`,
 * `namespaces.delete` and `mcpServers.delete` stay a person's act in the UI.
 */

export const TopologyRemovalKindSchema = z.enum([
  "endpoint",
  "namespace",
  "mcp_server",
]);

/** Every rule that can stop a removal, in the order it is reported. */
export const TopologyRemovalRuleSchema = z.enum([
  "target_private",
  "endpoint_has_keys",
  "endpoint_has_groups",
  "namespace_has_endpoints",
  "server_mounted",
  "server_tools_mapped",
]);

/** `sha256:` and 64 lower-case hex digits. */
export const TopologyImpactFingerprintSchema = z
  .string()
  .regex(/^sha256:[0-9a-f]{64}$/);

/**
 * A row that stops the removal and that the caller may see: an API key, an
 * access group, an endpoint or a namespace. Names and identifiers only.
 */
export const TopologyRemovalDependentSchema = z.object({
  rule: TopologyRemovalRuleSchema,
  kind: z.enum(["api_key", "access_group", "endpoint", "namespace"]),
  uuid: z.string().uuid(),
  name: z.string(),
  // An API key's active flag; null for every other kind.
  is_active: z.boolean().nullable(),
});

/** Rows that stop the removal and that the caller may not see, counted. */
export const TopologyRemovalHiddenSchema = z.object({
  rule: TopologyRemovalRuleSchema,
  count: z.number().int().positive(),
});

/** What the removal takes with it, as the row's own content, counted. */
export const TopologyRemovalCascadeSchema = z.object({
  kind: z.enum([
    "endpoint_presentation",
    "namespace_server_mapping",
    "namespace_tool_mapping",
    "tool",
    "oauth_session",
  ]),
  count: z.number().int().nonnegative(),
});

/**
 * Identifying metadata of the target, picked field by field: never a
 * connection setting, a credential, a description or other free text.
 */
export const TopologyRemovalSnapshotSchema = z.record(
  z.string(),
  z.union([z.string(), z.number(), z.boolean(), z.null()]),
);

export const TopologyRemovalImpactRequestSchema = z.object({
  uuid: z.string().uuid(),
});

export const TopologyRemovalImpactResponseSchema = z.object({
  kind: TopologyRemovalKindSchema,
  uuid: z.string().uuid(),
  name: z.string(),
  removable: z.boolean(),
  blocked_by: z.array(TopologyRemovalRuleSchema),
  dependents: z.array(TopologyRemovalDependentSchema),
  hidden_dependents: z.array(TopologyRemovalHiddenSchema),
  cascades: z.array(TopologyRemovalCascadeSchema),
  // Persisted MCP session records naming the endpoint or namespace (null for
  // a server, whose sessions carry no server reference). Informational: not
  // a blocker, not in the fingerprint, not removed with the row.
  live_sessions: z.number().int().nonnegative().nullable(),
  impact_fingerprint: TopologyImpactFingerprintSchema,
  snapshot: TopologyRemovalSnapshotSchema,
});

export const RemoveTopologyRequestSchema = z.object({
  uuid: z.string().uuid(),
  confirm_name: z.string().min(1).max(100),
  impact_fingerprint: TopologyImpactFingerprintSchema,
});

export const RemoveTopologyResponseSchema = z.object({
  kind: TopologyRemovalKindSchema,
  uuid: z.string().uuid(),
  name: z.string(),
  removed: z.literal(true),
  snapshot: TopologyRemovalSnapshotSchema,
  // The in-memory cleanup after the commit (idle pools, caches, Inspector
  // sessions). "failed" never means the removal did not commit.
  cleanup: z.enum(["ok", "failed", "not_needed"]),
});

export type TopologyRemovalKind = z.infer<typeof TopologyRemovalKindSchema>;
export type TopologyRemovalRule = z.infer<typeof TopologyRemovalRuleSchema>;
export type TopologyRemovalDependent = z.infer<
  typeof TopologyRemovalDependentSchema
>;
export type TopologyRemovalHidden = z.infer<typeof TopologyRemovalHiddenSchema>;
export type TopologyRemovalCascade = z.infer<
  typeof TopologyRemovalCascadeSchema
>;
export type TopologyRemovalSnapshot = z.infer<
  typeof TopologyRemovalSnapshotSchema
>;
export type TopologyRemovalImpactRequest = z.infer<
  typeof TopologyRemovalImpactRequestSchema
>;
export type TopologyRemovalImpactResponse = z.infer<
  typeof TopologyRemovalImpactResponseSchema
>;
export type RemoveTopologyRequest = z.infer<typeof RemoveTopologyRequestSchema>;
export type RemoveTopologyResponse = z.infer<
  typeof RemoveTopologyResponseSchema
>;
