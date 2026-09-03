import { z } from "zod";

import { DatabaseNamespaceSchema, NamespaceSchema } from "./namespaces.zod";

// Endpoint schema definitions
export const createEndpointFormSchema = z.object({
  name: z
    .string()
    .min(1, "validation:endpointName.required")
    .regex(/^[a-zA-Z0-9_-]+$/, "validation:endpointName.urlCompatible"),
  description: z.string().optional(),
  namespaceUuid: z.string().uuid("Please select a valid namespace"),
  enableApiKeyAuth: z.boolean(),
  requireScopedApiKey: z.boolean(),
  // Access-group gate (OAuth callers). Exposed on create so an endpoint can be
  // stood up already confined instead of being created open and locked down in
  // a second step. When on, the server forces requireScopedApiKey on too (the
  // two only compose when both are set: a restricted endpoint that still
  // admits unscoped keys leaves the API-key path fully open), which is why the
  // create dialog binds the two toggles together.
  restricted: z.boolean(),
  enableClientMaxRate: z.boolean(),
  enableMaxRate: z.boolean(),
  maxRateSeconds: z.number().min(1, "validation:maxRateSeconds").optional(),
  maxRate: z.number().min(1, "validation:maxRate").optional(),
  clientMaxRate: z.number().min(1, "validation:clientMaxRate").optional(),
  clientMaxRateSeconds: z
    .number()
    .min(1, "validation:clientMaxRateSeconds")
    .optional(),
  clientMaxRateStrategy: z.string().optional(),
  clientMaxRateStrategyKey: z.string().optional(),
  enableOauth: z.boolean(),
  useQueryParamAuth: z.boolean(),
  createMcpServer: z.boolean(),
  user_id: z.string().nullable().optional(),
});

export const editEndpointFormSchema = z.object({
  name: z
    .string()
    .min(1, "validation:endpointName.required")
    .regex(/^[a-zA-Z0-9_-]+$/, "validation:endpointName.urlCompatible"),
  description: z.string().optional(),
  namespaceUuid: z.string().uuid("Please select a valid namespace"),
  enableApiKeyAuth: z.boolean().optional(),
  requireScopedApiKey: z.boolean().optional(),
  enableClientMaxRate: z.boolean(),
  enableMaxRate: z.boolean(),
  maxRateSeconds: z.number().min(1, "validation:maxRateSeconds").optional(),
  maxRate: z.number().min(1, "validation:maxRate").optional(),
  clientMaxRate: z.number().min(1, "validation:clientMaxRate").optional(),
  clientMaxRateSeconds: z
    .number()
    .min(1, "validation:clientMaxRateSeconds")
    .optional(),
  clientMaxRateStrategy: z.string().optional(),
  clientMaxRateStrategyKey: z.string().optional(),
  enableOauth: z.boolean().optional(),
  useQueryParamAuth: z.boolean().optional(),
  user_id: z.string().nullable().optional(),
});

export const CreateEndpointRequestSchema = z.object({
  name: z
    .string()
    .min(1, "validation:endpointName.required")
    .regex(/^[a-zA-Z0-9_-]+$/, "validation:endpointName.urlCompatible"),
  description: z.string().optional(),
  namespaceUuid: z.string().uuid(),
  enableApiKeyAuth: z.boolean().default(true),
  // API-KEY-ONLY gate. When true, checkApiKeyAccess refuses unscoped
  // (grandfathered gateway-wide) API keys on this endpoint. It does NOT
  // affect OAuth consumers — an authenticated OAuth user is gated by
  // endpoint ownership, not by key scope, so there is no "unscoped OAuth
  // token" for this flag to reject (see checkOAuthAccess). Pair it with
  // scoping the consumer's key before flipping enable_api_key_auth on a
  // sensitive endpoint.
  requireScopedApiKey: z.boolean().default(false),
  // Access-group gate for OAuth callers, settable at create time. The
  // implementation forces `requireScopedApiKey` true whenever this is true, so
  // a restricted endpoint never ships with the API-key path left open (the two
  // controls only confine an endpoint when both are set). Default false keeps
  // an unspecified create as today's behaviour.
  restricted: z.boolean().default(false),
  enableClientMaxRate: z.boolean(),
  // Default ON: a new endpoint gets a per-credential tool-call ceiling out of
  // the box (the token-bucket data-plane limiter), rather than being unbounded
  // until an operator remembers to enable it per endpoint. The impl supplies a
  // conservative default budget when the numbers are omitted.
  enableMaxRate: z.boolean().default(true),
  maxRateSeconds: z.number().min(1, "validation:maxRateSeconds").optional(),
  maxRate: z.number().min(1, "validation:maxRate").optional(),
  clientMaxRate: z.number().min(1, "validation:clientMaxRate").optional(),
  clientMaxRateSeconds: z
    .number()
    .min(1, "validation:clientMaxRateSeconds")
    .optional(),
  clientMaxRateStrategy: z.string().optional(),
  clientMaxRateStrategyKey: z.string().optional(),
  enableOauth: z.boolean().default(true),
  useQueryParamAuth: z.boolean().default(false),
  createMcpServer: z.boolean().default(true),
  // Ownership / visibility. `undefined` (the default when the caller says
  // nothing) means PRIVATE to the creating admin; the impl fills user_id with
  // the creator. An explicit `null` is the deliberate publish-to-everyone
  // opt-in (public endpoint). A user id assigns ownership to that user.
  user_id: z.string().nullable().optional(),
});

// DELIBERATELY WITHOUT `restricted` (migration 0033). This is the wire shape
// for `endpoints.list` / `endpoints.get`, which are protectedProcedure and
// therefore MEMBER-visible. Which endpoints are gated, and which are not, is
// the authorization policy itself: the whole reason every procedure on the
// access-groups router is adminProcedure is that a member has no business
// reading that map, and shipping the same bit here through a member-visible
// endpoint would hand it back one row at a time.
//
// The middleware does not read this schema. It reads `DatabaseEndpointSchema`
// below, off the row the lookup middleware stamps on the request, which still
// carries `restricted` as a REQUIRED field. Enforcement is unaffected.
//
// The admin surface reads it through `accessGroups.getEndpointAccess`.
export const EndpointSchema = z.object({
  uuid: z.string(),
  name: z.string(),
  description: z.string().nullable(),
  namespace_uuid: z.string(),
  enable_api_key_auth: z.boolean(),
  require_scoped_api_key: z.boolean(),
  enableClientMaxRate: z.boolean(),
  enableMaxRate: z.boolean(),
  maxRateSeconds: z.number().min(1, "validation:maxRateSeconds").optional(),
  maxRate: z.number().min(1, "validation:maxRate").optional(),
  clientMaxRate: z.number().min(1, "validation:clientMaxRate").optional(),
  clientMaxRateSeconds: z
    .number()
    .min(1, "validation:clientMaxRateSeconds")
    .optional(),
  clientMaxRateStrategy: z.string().optional(),
  clientMaxRateStrategyKey: z.string().optional(),
  enable_oauth: z.boolean(),
  use_query_param_auth: z.boolean(),
  created_at: z.string(),
  updated_at: z.string(),
  user_id: z.string().nullable(),
});

// Extended endpoint schema with namespace details
export const EndpointWithNamespaceSchema = EndpointSchema.extend({
  namespace: NamespaceSchema,
});

export const CreateEndpointResponseSchema = z.object({
  success: z.boolean(),
  data: EndpointSchema.optional(),
  message: z.string().optional(),
  // PARTIAL success: the endpoint exists, but an optional companion step did
  // not complete (today: the auto-generated MCP server, whose bearer key
  // could not be minted). It is not a `success: false` — the endpoint really
  // was created, and reporting failure would send the caller into a retry
  // that hits "Endpoint name already exists". It is not folded into
  // `message` either, because `message` is populated on the happy path too
  // and callers would have to string-match to tell the two apart.
  warning: z.string().optional(),
});

export const ListEndpointsResponseSchema = z.object({
  success: z.boolean(),
  data: z.array(EndpointWithNamespaceSchema),
  message: z.string().optional(),
});

export const GetEndpointResponseSchema = z.object({
  success: z.boolean(),
  data: EndpointWithNamespaceSchema.optional(),
  message: z.string().optional(),
});

export const UpdateEndpointRequestSchema = z.object({
  uuid: z.string(),
  name: z
    .string()
    .min(1, "validation:endpointName.required")
    .regex(/^[a-zA-Z0-9_-]+$/, "validation:endpointName.urlCompatible"),
  description: z.string().optional(),
  namespaceUuid: z.string().uuid(),
  enableApiKeyAuth: z.boolean().optional(),
  requireScopedApiKey: z.boolean().optional(),
  enableClientMaxRate: z.boolean(),
  enableMaxRate: z.boolean(),
  maxRateSeconds: z.number().min(1, "validation:maxRateSeconds").optional(),
  maxRate: z.number().min(1, "validation:maxRate").optional(),
  clientMaxRate: z.number().min(1, "validation:clientMaxRate").optional(),
  clientMaxRateSeconds: z
    .number()
    .min(1, "validation:clientMaxRateSeconds")
    .optional(),
  clientMaxRateStrategy: z.string().optional(),
  clientMaxRateStrategyKey: z.string().optional(),
  enableOauth: z.boolean().optional(),
  useQueryParamAuth: z.boolean().optional(),
  user_id: z.string().nullable().optional(),
});

export const UpdateEndpointResponseSchema = z.object({
  success: z.boolean(),
  data: EndpointSchema.optional(),
  message: z.string().optional(),
});

export const DeleteEndpointRequestSchema = z.object({
  uuid: z.string(),
});

export const DeleteEndpointResponseSchema = z.object({
  success: z.boolean(),
  message: z.string().optional(),
});

// Type exports
export type CreateEndpointFormData = z.infer<typeof createEndpointFormSchema>;
export type EditEndpointFormData = z.infer<typeof editEndpointFormSchema>;
export type CreateEndpointRequest = z.infer<typeof CreateEndpointRequestSchema>;
export type Endpoint = z.infer<typeof EndpointSchema>;
export type EndpointWithNamespace = z.infer<typeof EndpointWithNamespaceSchema>;
export type CreateEndpointResponse = z.infer<
  typeof CreateEndpointResponseSchema
>;
export type ListEndpointsResponse = z.infer<typeof ListEndpointsResponseSchema>;
export type GetEndpointResponse = z.infer<typeof GetEndpointResponseSchema>;
export type UpdateEndpointRequest = z.infer<typeof UpdateEndpointRequestSchema>;
export type UpdateEndpointResponse = z.infer<
  typeof UpdateEndpointResponseSchema
>;
export type DeleteEndpointRequest = z.infer<typeof DeleteEndpointRequestSchema>;
export type DeleteEndpointResponse = z.infer<
  typeof DeleteEndpointResponseSchema
>;

// Repository-specific schemas
export const EndpointCreateInputSchema = z.object({
  name: z.string(),
  description: z.string().nullable().optional(),
  namespace_uuid: z.string(),
  enable_api_key_auth: z.boolean().optional().default(true),
  require_scoped_api_key: z.boolean().optional().default(false),
  // Access-group gate persisted at create time. Default false matches the
  // column default; the create handler is what enforces the restricted =>
  // require_scoped_api_key pairing before this reaches the row.
  restricted: z.boolean().optional().default(false),
  enable_max_rate: z.boolean(),
  enable_client_max_rate: z.boolean(),
  max_rate_seconds: z.number().nullable().optional(),
  max_rate: z.number().nullable().optional(),
  client_max_rate: z.number().nullable().optional(),
  client_max_rate_seconds: z.number().nullable().optional(),
  client_max_rate_strategy: z.string().nullable().optional(),
  client_max_rate_strategy_key: z.string().nullable().optional(),
  enable_oauth: z.boolean().optional().default(true),
  use_query_param_auth: z.boolean().optional().default(false),
  user_id: z.string().nullable().optional(),
});

export const EndpointUpdateInputSchema = z.object({
  uuid: z.string(),
  name: z.string(),
  description: z.string().nullable().optional(),
  namespace_uuid: z.string(),
  enable_api_key_auth: z.boolean().optional(),
  require_scoped_api_key: z.boolean().optional(),
  enable_max_rate: z.boolean(),
  enable_client_max_rate: z.boolean(),
  max_rate_seconds: z.number().nullable().optional(),
  max_rate: z.number().nullable().optional(),
  client_max_rate: z.number().nullable().optional(),
  client_max_rate_seconds: z.number().nullable().optional(),
  client_max_rate_strategy: z.string().nullable().optional(),
  client_max_rate_strategy_key: z.string().nullable().optional(),
  enable_oauth: z.boolean().optional(),
  use_query_param_auth: z.boolean().optional(),
  user_id: z.string().nullable().optional(),
});

export type EndpointCreateInput = z.infer<typeof EndpointCreateInputSchema>;
export type EndpointUpdateInput = z.infer<typeof EndpointUpdateInputSchema>;

// Database-specific schemas (raw database results with Date objects)
export const DatabaseEndpointSchema = z.object({
  uuid: z.string(),
  name: z.string(),
  description: z.string().nullable(),
  namespace_uuid: z.string(),
  enable_api_key_auth: z.boolean(),
  require_scoped_api_key: z.boolean(),
  enable_max_rate: z.boolean(),
  enable_client_max_rate: z.boolean(),
  max_rate_seconds: z.number().nullable().optional(),
  max_rate: z.number().nullable().optional(),
  client_max_rate: z.number().nullable().optional(),
  client_max_rate_seconds: z.number().nullable().optional(),
  client_max_rate_strategy: z.string().nullable().optional(),
  client_max_rate_strategy_key: z.string().nullable().optional(),
  enable_oauth: z.boolean(),
  use_query_param_auth: z.boolean(),
  // REQUIRED, not optional, and that is the point. `middleware/api-key-oauth`
  // reads this off the endpoint row the lookup middleware stamped on the
  // request, and every repository read projects columns explicitly — so an
  // optional field here would let a projection that forgot `restricted` compile
  // and then fail OPEN at runtime, admitting an OAuth caller to an endpoint an
  // operator had switched on. Required makes that a type error at the read site.
  restricted: z.boolean(),
  created_at: z.date(),
  updated_at: z.date(),
  user_id: z.string().nullable(),
});

export const DatabaseEndpointWithNamespaceSchema =
  DatabaseEndpointSchema.extend({
    namespace: DatabaseNamespaceSchema,
  });

export type DatabaseEndpoint = z.infer<typeof DatabaseEndpointSchema>;
export type DatabaseEndpointWithNamespace = z.infer<
  typeof DatabaseEndpointWithNamespaceSchema
>;
