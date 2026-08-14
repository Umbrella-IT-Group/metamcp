import { z } from "zod";

// OAuth Client Information schema (matching MCP SDK)
export const OAuthClientInformationSchema = z.object({
  client_id: z.string(),
  client_secret: z.string().optional(),
  client_id_issued_at: z.number().optional(),
  client_secret_expires_at: z.number().optional(),
});

// OAuth Tokens schema (matching MCP SDK)
export const OAuthTokensSchema = z.object({
  access_token: z.string(),
  token_type: z.string(),
  expires_in: z.number().optional(),
  scope: z.string().optional(),
  refresh_token: z.string().optional(),
});

// OAuth Client schema for registered clients
export const OAuthClientSchema = z.object({
  client_id: z.string(),
  client_secret: z.string().nullable(),
  client_name: z.string(),
  redirect_uris: z.array(z.string()),
  grant_types: z.array(z.string()),
  response_types: z.array(z.string()),
  token_endpoint_auth_method: z.string(),
  scope: z.string().nullable(),
  client_uri: z.string().nullable(),
  logo_uri: z.string().nullable(),
  contacts: z.array(z.string()).nullable(),
  tos_uri: z.string().nullable(),
  policy_uri: z.string().nullable(),
  software_id: z.string().nullable(),
  software_version: z.string().nullable(),
  created_at: z.date(),
  updated_at: z.date().optional(),
});

// OAuth Authorization Code schema
export const OAuthAuthorizationCodeSchema = z.object({
  code: z.string(),
  client_id: z.string(),
  redirect_uri: z.string(),
  scope: z.string(),
  user_id: z.string(),
  code_challenge: z.string().nullable(),
  code_challenge_method: z.string().nullable(),
  expires_at: z.date(),
  created_at: z.date(),
});

// OAuth Access Token schema
export const OAuthAccessTokenSchema = z.object({
  access_token: z.string(),
  client_id: z.string(),
  user_id: z.string(),
  scope: z.string(),
  expires_at: z.date(),
  refresh_token: z.string().nullable(),
  refresh_token_expires_at: z.date().nullable(),
  created_at: z.date(),
});

// Input schemas for repositories
export const OAuthClientCreateInputSchema = z.object({
  client_id: z.string(),
  client_secret: z.string().nullable(),
  client_name: z.string(),
  redirect_uris: z.array(z.string()),
  grant_types: z.array(z.string()),
  response_types: z.array(z.string()),
  token_endpoint_auth_method: z.string(),
  scope: z.string().nullable(),
  client_uri: z.string().nullable().optional(),
  logo_uri: z.string().nullable().optional(),
  contacts: z.array(z.string()).nullable().optional(),
  tos_uri: z.string().nullable().optional(),
  policy_uri: z.string().nullable().optional(),
  software_id: z.string().nullable().optional(),
  software_version: z.string().nullable().optional(),
  created_at: z.date(),
  updated_at: z.date().optional(),
});

export const OAuthAuthorizationCodeCreateInputSchema = z.object({
  client_id: z.string(),
  redirect_uri: z.string(),
  scope: z.string(),
  user_id: z.string(),
  code_challenge: z.string().nullable().optional(),
  code_challenge_method: z.string().nullable().optional(),
  expires_at: z.number(), // timestamp
});

export const OAuthAccessTokenCreateInputSchema = z.object({
  client_id: z.string(),
  user_id: z.string(),
  scope: z.string(),
  expires_at: z.number(), // timestamp
});

// Base OAuth Session schema - client_information can be nullable since DB has default {}
export const OAuthSessionSchema = z.object({
  uuid: z.string().uuid(),
  mcp_server_uuid: z.string().uuid(),
  client_information: OAuthClientInformationSchema.nullable(),
  tokens: OAuthTokensSchema.nullable(),
  code_verifier: z.string().nullable(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime(),
});

// Get OAuth Session Request
export const GetOAuthSessionRequestSchema = z.object({
  mcp_server_uuid: z.string().uuid(),
});

// Get OAuth Session Response
export const GetOAuthSessionResponseSchema = z.union([
  z.object({
    success: z.literal(true),
    data: OAuthSessionSchema,
    message: z.string(),
  }),
  z.object({
    success: z.literal(false),
    message: z.string(),
  }),
]);

// Upsert OAuth Session Request - all fields optional for updates
export const UpsertOAuthSessionRequestSchema = z.object({
  mcp_server_uuid: z.string().uuid(),
  client_information: OAuthClientInformationSchema.optional(),
  tokens: OAuthTokensSchema.nullable().optional(),
  code_verifier: z.string().nullable().optional(),
});

// Upsert OAuth Session Response
export const UpsertOAuthSessionResponseSchema = z.union([
  z.object({
    success: z.literal(true),
    data: OAuthSessionSchema,
    message: z.string(),
  }),
  z.object({
    success: z.literal(false),
    error: z.string(),
  }),
]);

// Repository-specific schemas
export const OAuthSessionCreateInputSchema = z.object({
  mcp_server_uuid: z.string(),
  client_information: OAuthClientInformationSchema.optional(),
  tokens: OAuthTokensSchema.nullable().optional(),
  code_verifier: z.string().nullable().optional(),
});

export const OAuthSessionUpdateInputSchema = z.object({
  mcp_server_uuid: z.string(),
  client_information: OAuthClientInformationSchema.optional(),
  tokens: OAuthTokensSchema.nullable().optional(),
  code_verifier: z.string().nullable().optional(),
});

// Export repository types
export type OAuthSessionCreateInput = z.infer<
  typeof OAuthSessionCreateInputSchema
>;
export type OAuthSessionUpdateInput = z.infer<
  typeof OAuthSessionUpdateInputSchema
>;

// Database-specific schemas (raw database results with Date objects)
export const DatabaseOAuthSessionSchema = z.object({
  uuid: z.string(),
  mcp_server_uuid: z.string(),
  client_information: OAuthClientInformationSchema.nullable(),
  tokens: OAuthTokensSchema.nullable(),
  code_verifier: z.string().nullable(),
  created_at: z.date(),
  updated_at: z.date(),
});

export type DatabaseOAuthSession = z.infer<typeof DatabaseOAuthSessionSchema>;

// Export OAuth types
export type OAuthClient = z.infer<typeof OAuthClientSchema>;
export type OAuthClientCreateInput = z.infer<
  typeof OAuthClientCreateInputSchema
>;
export type OAuthAuthorizationCode = z.infer<
  typeof OAuthAuthorizationCodeSchema
>;
export type OAuthAuthorizationCodeCreateInput = z.infer<
  typeof OAuthAuthorizationCodeCreateInputSchema
>;
export type OAuthAccessToken = z.infer<typeof OAuthAccessTokenSchema>;
export type OAuthAccessTokenCreateInput = z.infer<
  typeof OAuthAccessTokenCreateInputSchema
>;

// ===== Registered-client administration (admin UI) =====

// The value sets RFC 7591 registration accepts. Declared in the shared
// contract package — not inline in the express DCR handler where they used to
// live — because there are now TWO ways to mint a client (the public DCR
// endpoint and the admin UI) and a second copy of these lists would let the
// UI offer an option the server rejects. The backend registration core and
// the tRPC contract both validate against these.
export const OAuthGrantTypeEnum = z.enum([
  "authorization_code",
  "refresh_token",
  "client_credentials",
]);
export const OAuthResponseTypeEnum = z.enum(["code"]);
export const OAuthTokenEndpointAuthMethodEnum = z.enum([
  "none",
  "client_secret_post",
  "client_secret_basic",
]);

// Defaults mirror the OAuth 2.1 posture the DCR handler already applied:
// PKCE-only public client ("none" — no secret is minted at all), the single
// authorization_code grant, and the `code` response type.
export const CreateOAuthClientRequestSchema = z.object({
  client_name: z.string().min(1, "Name is required").max(255),
  redirect_uris: z
    .array(z.string().min(1))
    .min(1, "At least one redirect URI is required"),
  token_endpoint_auth_method: OAuthTokenEndpointAuthMethodEnum.default("none"),
  grant_types: z
    .array(OAuthGrantTypeEnum)
    .min(1)
    .default(["authorization_code"]),
  response_types: z.array(OAuthResponseTypeEnum).min(1).default(["code"]),
  scope: z.string().min(1).default("admin"),
});

// The ONE response that ever carries `client_secret`. It is returned straight
// from the mint and never read back out of the database by any other route —
// the list schema below deliberately has no field for it — so the UI's
// "you will not see this secret again" promise is enforced by the contract,
// not just by the dialog. `client_secret` is null for a PKCE public client
// ("none"), where no secret is generated in the first place.
export const CreateOAuthClientResponseSchema = z.object({
  client_id: z.string(),
  client_secret: z.string().nullable(),
  client_name: z.string(),
  redirect_uris: z.array(z.string()),
  grant_types: z.array(z.string()),
  response_types: z.array(z.string()),
  token_endpoint_auth_method: z.string(),
  scope: z.string().nullable(),
  created_at: z.date(),
});

// Admin listing. Mirrors the api-key admin view's rule (AdminApiKeyItemSchema)
// — the stored secret is NEVER echoed back, only whether one exists, so the
// list route cannot become a credential-exfiltration surface.
export const OAuthClientListItemSchema = z.object({
  client_id: z.string(),
  client_name: z.string(),
  redirect_uris: z.array(z.string()),
  grant_types: z.array(z.string()),
  response_types: z.array(z.string()),
  token_endpoint_auth_method: z.string(),
  scope: z.string().nullable(),
  has_client_secret: z.boolean(),
  created_at: z.date(),
  updated_at: z.date().nullable(),
});

export const ListOAuthClientsResponseSchema = z.object({
  clients: z.array(OAuthClientListItemSchema),
});

export const DeleteOAuthClientRequestSchema = z.object({
  client_id: z.string().min(1),
});

export const DeleteOAuthClientResponseSchema = z.object({
  success: z.boolean(),
  message: z.string(),
});

// Form-side schema for the create dialog. redirect_uris is a newline-separated
// STRING here, not an array: the frontend has no useFieldArray anywhere and
// renders every multi-value input as a Textarea split at submit time (the same
// convention mcp-servers uses for `env`). The page parses this into the
// string[] CreateOAuthClientRequestSchema expects.
export const CreateOAuthClientFormSchema = z.object({
  client_name: z.string().min(1, "Name is required").max(255),
  redirect_uris: z.string().min(1, "At least one redirect URI is required"),
  token_endpoint_auth_method: OAuthTokenEndpointAuthMethodEnum,
  scope: z.string().min(1, "Scope is required"),
});

export type OAuthGrantType = z.infer<typeof OAuthGrantTypeEnum>;
export type OAuthResponseType = z.infer<typeof OAuthResponseTypeEnum>;
export type OAuthTokenEndpointAuthMethod = z.infer<
  typeof OAuthTokenEndpointAuthMethodEnum
>;
export type CreateOAuthClientRequest = z.infer<
  typeof CreateOAuthClientRequestSchema
>;
export type CreateOAuthClientResponse = z.infer<
  typeof CreateOAuthClientResponseSchema
>;
export type CreateOAuthClientForm = z.infer<typeof CreateOAuthClientFormSchema>;
export type OAuthClientListItem = z.infer<typeof OAuthClientListItemSchema>;
export type ListOAuthClientsResponse = z.infer<
  typeof ListOAuthClientsResponseSchema
>;
export type DeleteOAuthClientRequest = z.infer<
  typeof DeleteOAuthClientRequestSchema
>;
export type DeleteOAuthClientResponse = z.infer<
  typeof DeleteOAuthClientResponseSchema
>;

// ===== Active access-token administration (Access dashboard) =====
//
// "Who is connected via OAuth right now" had no answer in the GUI: tokens
// were only visible in psql. This is the metadata view of
// `oauth_access_tokens`, joined to the owning user and the registered client.
//
// The token value itself (and the refresh token) is STRUCTURALLY absent from
// this schema, not masked — `access_token` is the table's primary key and a
// bearer credential for the whole gateway. Same rule as
// OAuthClientListItemSchema and AdminApiKeyItemSchema: presence only, via
// `has_refresh_token`.
export const ActiveOAuthTokenItemSchema = z.object({
  user_id: z.string(),
  // LEFT JOINed: nullable so a token whose user row vanished mid-cascade
  // still appears in the listing instead of dropping out of it. An orphaned
  // live token is exactly the thing an administrator must be able to see.
  user_email: z.string().nullable(),
  client_id: z.string(),
  client_name: z.string().nullable(),
  scope: z.string(),
  created_at: z.date(),
  expires_at: z.date(),
  has_refresh_token: z.boolean(),
  refresh_token_expires_at: z.date().nullable(),
});

export const ListActiveOAuthTokensResponseSchema = z.object({
  tokens: z.array(ActiveOAuthTokenItemSchema),
});

export type ActiveOAuthTokenItem = z.infer<typeof ActiveOAuthTokenItemSchema>;
export type ListActiveOAuthTokensResponse = z.infer<
  typeof ListActiveOAuthTokensResponseSchema
>;
