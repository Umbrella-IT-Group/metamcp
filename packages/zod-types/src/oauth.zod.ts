import { z } from "zod";

// The authorization server a stored upstream credential belongs to. MCP SDK
// 1.31 `auth()` stamps it on everything it hands to `saveClientInformation` /
// `saveTokens`, and on read refuses to present a value stamped for a different
// authorization server (GHSA-6qxp-vccf-f47h). It is not part of the OAuth wire
// format, so it has to be carried here explicitly: `z.object` strips unknown
// keys, and while these two schemas lacked the field the stamp was dropped on
// the way into `oauth_sessions` and every stored client_secret and refresh
// token read back unbound, i.e. sendable to whatever authorization server the
// upstream MCP server advertised next. Optional because rows written before
// 1.31 have none; the Inspector's provider (apps/frontend/lib/oauth-provider)
// refuses to present those to any authorization server.
const OAuthIssuerSchema = z.string().optional();

// OAuth Client Information schema (matching MCP SDK)
export const OAuthClientInformationSchema = z.object({
  client_id: z.string(),
  client_secret: z.string().optional(),
  client_id_issued_at: z.number().optional(),
  client_secret_expires_at: z.number().optional(),
  issuer: OAuthIssuerSchema,
});

// OAuth Tokens schema (matching MCP SDK)
export const OAuthTokensSchema = z.object({
  access_token: z.string(),
  token_type: z.string(),
  expires_in: z.number().optional(),
  scope: z.string().optional(),
  refresh_token: z.string().optional(),
  issuer: OAuthIssuerSchema,
});

/**
 * Which mint path wrote an `oauth_clients` row.
 *
 * "dcr"   — the anonymous RFC 7591 `POST /oauth/register` endpoint.
 * "admin" — an authenticated administrator through the OAuth Clients UI.
 * "cimd"  - a client metadata document the gateway fetched for an allowlisted
 *           https client id (migration 0046). The row is a cache of that
 *           document, not a registration: it is rewritten from the document,
 *           never approved or rejected by an administrator, and swept by its
 *           own rule (never by the DCR one).
 *
 * This exists ONLY so the retention sweep can tell the paths apart, and it has
 * to exist because nothing else can. The first two call the same
 * `buildClientRegistration` core and therefore the same
 * `generateSecureClientId()`, so every client_id from either door reads
 * `mcp_client_<random>` — the prefix is not a discriminator. An admin who
 * pre-provisions a partner client days before the partner pairs it owns a row
 * that is legitimately unused, and deleting it is a support incident, so the
 * sweep must never guess.
 */
export const OAuthClientRegistrationSourceEnum = z.enum([
  "dcr",
  "admin",
  "cimd",
]);

/**
 * Whether an `oauth_clients` row may be used to authorize anyone (migration
 * 0042).
 *
 * "approved" — the only value that lets the authorize, consent, decision and
 *              token endpoints proceed. Admin-created clients are written
 *              approved; a self-registered client becomes approved only when
 *              an administrator approves it (or, in local development only,
 *              when OAUTH_DCR_MODE=open).
 * "pending"  — a self-registered client waiting for an administrator. The
 *              column default, so an insert that forgets the field can never
 *              produce a usable client.
 * "rejected" — an administrator refused it; it cannot be used and is swept a
 *              day after rejection.
 *
 * Any other value (there should be none: a database CHECK enforces the set)
 * refuses access exactly as pending does.
 */
export const OAuthClientApprovalStatusEnum = z.enum([
  "approved",
  "pending",
  "rejected",
]);

// OAuth Client schema for registered clients
export const OAuthClientSchema = z.object({
  client_id: z.string(),
  // Salted-hash at rest (migration 0036): client_secret holds the sha256 of
  // secret||salt, not the secret. Nullable for a PKCE/public client that has
  // no secret. Never leaves the server, the list view exposes presence only.
  client_secret: z.string().nullable(),
  // The salt for client_secret above (migration 0036). NULL when there is no
  // secret. Read by verifyClientSecret at the token endpoint.
  client_secret_salt: z.string().nullable().optional(),
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
  // Nullable on READ and never on write: every row minted since migration 0029
  // carries its provenance, but rows that predate the column cannot have one
  // invented for them. NULL therefore means "unknown", which the sweep treats
  // as not-DCR and leaves alone.
  registration_source: OAuthClientRegistrationSourceEnum.nullable().optional(),
  // Migration 0042. Read as a plain string, not the enum, so a value outside
  // the set (written by hand despite the CHECK) still reads back and is then
  // refused by isOAuthClientApproved instead of failing the whole read.
  approval_status: z.string(),
  // Who approved the client and when. NULL for every row approved by the
  // migration's grandfathering, for admin-created rows (creation is the
  // approval, and the create audit row names the administrator), and for
  // rows approved by OAUTH_DCR_MODE=open.
  approved_by: z.string().nullable().optional(),
  approved_at: z.date().nullable().optional(),
  // When an administrator rejected the client. The retention sweep counts the
  // rejected row's age from here, not from registration.
  rejected_at: z.date().nullable().optional(),
  created_at: z.date(),
  updated_at: z.date().optional(),
});

/**
 * The one approval test every authorization and token path uses.
 *
 * Exact equality with "approved" and nothing else: a missing row, a null, an
 * unexpected spelling or any future status all refuse. Kept beside the schema
 * so the backend gates and the admin UI agree on what "approved" means.
 */
export function isOAuthClientApproved(
  client: { approval_status?: unknown } | null | undefined,
): boolean {
  return client?.approval_status === "approved";
}

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
  // Hash at rest (migration 0036): the sha256 of the token, not the token.
  access_token: z.string(),
  // Last 4 characters of the token, kept for the admin view (migration 0036).
  access_token_last4: z.string(),
  client_id: z.string(),
  user_id: z.string(),
  scope: z.string(),
  expires_at: z.date(),
  refresh_token: z.string().nullable(),
  refresh_token_expires_at: z.date().nullable(),
  // Refresh-token family (migration 0037): every pair in one refresh chain
  // shares this id, so reuse of a rotated-out token can revoke the whole
  // lineage. A uuid rendered as a string.
  family_id: z.string(),
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
  // REQUIRED on write, unlike the nullable read field above, so the compiler
  // refuses any new persist path that does not say which door the client came
  // through. A row minted without provenance is a row the retention sweep has
  // to guess about, and the whole point of this column is that it never
  // guesses.
  registration_source: OAuthClientRegistrationSourceEnum,
  // REQUIRED on write for the same reason as registration_source: each door
  // states the status it writes (the DCR endpoint "pending", or "approved"
  // only in local-development open mode; the admin create path "approved").
  // The column default is "pending" as a backstop, so a write path that
  // somehow omits it still cannot produce a usable client.
  approval_status: OAuthClientApprovalStatusEnum,
  // Set only for a row written already approved outside an administrator's
  // decision (OAUTH_DCR_MODE=open). Never taken from a request body.
  approved_at: z.date().nullable().optional(),
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
export type OAuthClientRegistrationSource = z.infer<
  typeof OAuthClientRegistrationSourceEnum
>;
export type OAuthClientApprovalStatus = z.infer<
  typeof OAuthClientApprovalStatusEnum
>;
/**
 * A minted client row that does not yet know which door it came through.
 *
 * `buildClientRegistration` returns this rather than a full
 * `OAuthClientCreateInput` because it is shared by both mint paths and so is
 * the one place that genuinely cannot know the answer. Each caller stamps its
 * own `registration_source` and `approval_status` (and, in open mode only,
 * `approved_at`) on the way to `upsertClient`, and because the first two are
 * required on the create input, a caller that forgets does not compile. The
 * core never reads either from its untrusted input.
 */
export type OAuthClientRegistrationDraft = Omit<
  OAuthClientCreateInput,
  "registration_source" | "approval_status" | "approved_at"
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
  // Always "approved": an administrator creating a client is the approval.
  approval_status: OAuthClientApprovalStatusEnum,
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
  // Approval state (migration 0042). A string rather than the enum so an
  // out-of-set value is shown as-is instead of failing the whole listing; the
  // gates treat anything but "approved" as refused.
  approval_status: z.string(),
  // Which door created the row: "dcr", "admin", "cimd" (a fetched client
  // metadata document), or null for rows that predate migration 0029.
  registration_source: OAuthClientRegistrationSourceEnum.nullable(),
  approved_by: z.string().nullable(),
  approved_at: z.date().nullable(),
  rejected_at: z.date().nullable(),
  // The source address of the successful self-registration, read from its
  // `oauth.dcr.register` audit row. An observed network address, not an
  // authenticated person and not evidence the client is safe. Null for admin
  // and legacy rows, and when the audit write did not land.
  registered_from_ip: z.string().nullable(),
  created_at: z.date(),
  updated_at: z.date().nullable(),
});

// Approve or reject one self-registered client. Only the client id is taken
// from the caller: the deciding administrator and the time come from the
// authenticated session on the server.
export const DecideOAuthClientRequestSchema = z.object({
  client_id: z.string().min(1),
});

export const DecideOAuthClientResponseSchema = z.object({
  client_id: z.string(),
  approval_status: OAuthClientApprovalStatusEnum,
  approved_by: z.string().nullable(),
  approved_at: z.date().nullable(),
  rejected_at: z.date().nullable(),
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
export type DecideOAuthClientRequest = z.infer<
  typeof DecideOAuthClientRequestSchema
>;
export type DecideOAuthClientResponse = z.infer<
  typeof DecideOAuthClientResponseSchema
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
// `has_refresh_token`. The one readable fragment is `access_token_last4`, the
// four-character tail the table now stores (migration 0036) and the audit log
// already records, safe to show, and enough to correlate a listed token with
// an audit row.
export const ActiveOAuthTokenItemSchema = z.object({
  user_id: z.string(),
  access_token_last4: z.string(),
  // LEFT JOINed: nullable so a token whose user row vanished mid-cascade
  // still appears in the listing instead of dropping out of it. An orphaned
  // live token is exactly the thing an administrator must be able to see.
  user_email: z.string().nullable(),
  client_id: z.string(),
  client_name: z.string().nullable(),
  // The issuing client's approval state (migration 0042), LEFT JOINed like
  // client_name, so the Access view never presents a token from a client that
  // is not approved as ordinary approved access. Null when the client row is
  // gone.
  client_approval_status: z.string().nullable(),
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
