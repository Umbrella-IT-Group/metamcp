import { OAuthClientInformation } from "@modelcontextprotocol/sdk/shared/auth.js";
import { OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import {
  MCP_SERVER_ERROR_STATUSES,
  MCP_SERVER_STATUSES,
  MCP_SERVER_TYPES,
  McpServerErrorStatusEnum,
  McpServerStatusEnum,
  McpServerTypeEnum,
  type OAuthClientRegistrationSource,
} from "@repo/zod-types";
import { sql } from "drizzle-orm";
import {
  type AnyPgColumn,
  boolean,
  check,
  index,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  text,
  timestamp,
  unique,
  uuid,
} from "drizzle-orm/pg-core";

// Build the drizzle enums from the shared literal tuples (not
// `SomeEnum.options`, which zod 4 widens to string[] and breaks pgEnum's
// literal-union inference — see MCP_SERVER_TYPES in @repo/zod-types).
export const mcpServerTypeEnum = pgEnum("mcp_server_type", MCP_SERVER_TYPES);
export const mcpServerStatusEnum = pgEnum(
  "mcp_server_status",
  MCP_SERVER_STATUSES,
);
export const mcpServerErrorStatusEnum = pgEnum(
  "mcp_server_error_status",
  MCP_SERVER_ERROR_STATUSES,
);

export const mcpServersTable = pgTable(
  "mcp_servers",
  {
    uuid: uuid("uuid").primaryKey().defaultRandom(),
    name: text("name").notNull(),
    description: text("description"),
    type: mcpServerTypeEnum("type")
      .notNull()
      .default(McpServerTypeEnum.enum.STDIO),
    command: text("command"),
    args: text("args")
      .array()
      .notNull()
      .default(sql`'{}'::text[]`),
    env: jsonb("env")
      .$type<{ [key: string]: string }>()
      .notNull()
      .default(sql`'{}'::jsonb`),
    url: text("url"),
    error_status: mcpServerErrorStatusEnum("error_status")
      .notNull()
      .default(McpServerErrorStatusEnum.enum.NONE),
    created_at: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    bearerToken: text("bearer_token"),
    headers: jsonb("headers")
      .$type<{ [key: string]: string }>()
      .notNull()
      .default(sql`'{}'::jsonb`),
    user_id: text("user_id").references(() => usersTable.id, {
      onDelete: "cascade",
    }),
  },
  (table) => [
    index("mcp_servers_type_idx").on(table.type),
    index("mcp_servers_user_id_idx").on(table.user_id),
    index("mcp_servers_error_status_idx").on(table.error_status),
    // Allow same name for different users, but unique within user scope (including public)
    unique("mcp_servers_name_user_unique_idx").on(table.name, table.user_id),
    sql`CONSTRAINT mcp_servers_name_regex_check CHECK (
        name ~ '^[a-zA-Z0-9_-]+$'
      )`,
    sql`CONSTRAINT mcp_servers_url_check CHECK (
        (type = 'SSE' AND url IS NOT NULL AND command IS NULL AND url ~ '^https?://[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*(:[0-9]+)?(/[a-zA-Z0-9-._~:/?#\[\]@!$&''()*+,;=]*)?$') OR
        (type = 'STDIO' AND url IS NULL AND command IS NOT NULL) OR
        (type = 'STREAMABLE_HTTP' AND url IS NOT NULL AND command IS NULL AND url ~ '^https?://[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*(:[0-9]+)?(/[a-zA-Z0-9-._~:/?#\[\]@!$&''()*+,;=]*)?$')
      )`,
  ],
);

export const oauthSessionsTable = pgTable(
  "oauth_sessions",
  {
    uuid: uuid("uuid").primaryKey().defaultRandom(),
    mcp_server_uuid: uuid("mcp_server_uuid")
      .notNull()
      .references(() => mcpServersTable.uuid, { onDelete: "cascade" }),
    client_information: jsonb("client_information")
      .$type<OAuthClientInformation>()
      .notNull()
      .default(sql`'{}'::jsonb`),
    tokens: jsonb("tokens").$type<OAuthTokens>(),
    code_verifier: text("code_verifier"),
    created_at: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updated_at: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index("oauth_sessions_mcp_server_uuid_idx").on(table.mcp_server_uuid),
    unique("oauth_sessions_unique_per_server_idx").on(table.mcp_server_uuid),
  ],
);

export const toolsTable = pgTable(
  "tools",
  {
    uuid: uuid("uuid").primaryKey().defaultRandom(),
    name: text("name").notNull(),
    description: text("description"),
    toolSchema: jsonb("tool_schema")
      .$type<{
        type: "object";
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        properties?: Record<string, any>;
        required?: string[];
      }>()
      .notNull(),
    created_at: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updated_at: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    mcp_server_uuid: uuid("mcp_server_uuid")
      .notNull()
      .references(() => mcpServersTable.uuid, { onDelete: "cascade" }),
  },
  (table) => [
    index("tools_mcp_server_uuid_idx").on(table.mcp_server_uuid),
    unique("tools_unique_tool_name_per_server_idx").on(
      table.mcp_server_uuid,
      table.name,
    ),
  ],
);

// Better-auth tables
export const usersTable = pgTable("users", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
  emailVerified: boolean("email_verified").notNull().default(false),
  image: text("image"),
  // RBAC role: 'admin' | 'member'. Gates administrative tRPC mutations
  // (MCP-server / namespace / endpoint create-update-delete + all API-key
  // administration) through `adminProcedure`. NOT NULL default 'member' so
  // every pre-existing and future account is least-privilege until it is
  // explicitly promoted — migration 0020 seeds the bootstrap operator account
  // to 'admin'. Surfaced into the better-auth session via `user.additionalFields`
  // in auth.ts with `input: false`, so a user cannot self-escalate by
  // sending a role on sign-up / update.
  role: text("role").notNull().default("member"),
  // Account lock (migration 0027). TRUE means this account may not hold a
  // session: `session.create.before` in auth.ts refuses to mint a new one,
  // and the tRPC context treats any session it already holds as
  // unauthenticated rather than waiting out the 30-day expiry. Both halves
  // are required — either alone leaves a real path in.
  //
  // The containment middle tier: revoking access lets the account sign
  // straight back in, and deleting it destroys the evidence AND cascades into
  // other users' endpoints and API keys. Disabling locks the account while
  // preserving it whole.
  //
  // Deliberately absent from better-auth `additionalFields`: unlike `role`
  // (which is surfaced read-only for the session), nothing a client sends may
  // reach this column, and the enforcement paths re-read it from the database
  // per request rather than trusting a serialized session.
  disabled: boolean("disabled").notNull().default(false),
  disabled_at: timestamp("disabled_at", { withTimezone: true }),
  // Who locked the account. ON DELETE SET NULL, not CASCADE: deleting the
  // administrator who disabled an account must never quietly re-enable it or
  // erase the record of the action.
  disabled_by: text("disabled_by").references(
    (): AnyPgColumn => usersTable.id,
    {
      onDelete: "set null",
    },
  ),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export const sessionsTable = pgTable("sessions", {
  id: text("id").primaryKey(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  token: text("token").notNull().unique(),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  userId: text("user_id")
    .notNull()
    .references(() => usersTable.id, { onDelete: "cascade" }),
});

export const accountsTable = pgTable("accounts", {
  id: text("id").primaryKey(),
  accountId: text("account_id").notNull(),
  providerId: text("provider_id").notNull(),
  userId: text("user_id")
    .notNull()
    .references(() => usersTable.id, { onDelete: "cascade" }),
  accessToken: text("access_token"),
  refreshToken: text("refresh_token"),
  idToken: text("id_token"),
  accessTokenExpiresAt: timestamp("access_token_expires_at", {
    withTimezone: true,
  }),
  refreshTokenExpiresAt: timestamp("refresh_token_expires_at", {
    withTimezone: true,
  }),
  scope: text("scope"),
  password: text("password"),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export const verificationsTable = pgTable("verifications", {
  id: text("id").primaryKey(),
  identifier: text("identifier").notNull(),
  value: text("value").notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

// Namespaces table
export const namespacesTable = pgTable(
  "namespaces",
  {
    uuid: uuid("uuid").primaryKey().defaultRandom(),
    name: text("name").notNull(),
    description: text("description"),
    created_at: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updated_at: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    user_id: text("user_id").references(() => usersTable.id, {
      onDelete: "cascade",
    }),
  },
  (table) => [
    index("namespaces_user_id_idx").on(table.user_id),
    // Allow same name for different users, but unique within user scope (including public)
    unique("namespaces_name_user_unique_idx").on(table.name, table.user_id),
    sql`CONSTRAINT namespaces_name_regex_check CHECK (
        name ~ '^[a-zA-Z0-9_-]+$'
      )`,
  ],
);

// Endpoints table - public routing endpoints that map to namespaces
export const endpointsTable = pgTable(
  "endpoints",
  {
    uuid: uuid("uuid").primaryKey().defaultRandom(),
    name: text("name").notNull(),
    description: text("description"),
    namespace_uuid: uuid("namespace_uuid")
      .notNull()
      .references(() => namespacesTable.uuid, { onDelete: "cascade" }),
    enable_api_key_auth: boolean("enable_api_key_auth").notNull().default(true),
    enable_oauth: boolean("enable_oauth").notNull().default(false),
    enable_max_rate: boolean("enable_max_rate").notNull().default(false),
    enable_client_max_rate: boolean("enable_client_max_rate")
      .notNull()
      .default(false),
    max_rate: integer("max_rate"),
    max_rate_seconds: integer("max_rate_seconds"),
    client_max_rate: integer("client_max_rate"),
    client_max_rate_seconds: integer("client_max_rate_seconds"),
    client_max_rate_strategy: text("client_max_rate_strategy"),
    client_max_rate_strategy_key: text("client_max_rate_strategy_key"),
    use_query_param_auth: boolean("use_query_param_auth")
      .notNull()
      .default(false),
    // When true, this endpoint rejects unscoped (endpoint_uuid IS NULL)
    // API keys: only keys explicitly scoped to THIS endpoint authenticate.
    // The opt-out from grandfathered gateway-wide keys for sensitive
    // endpoints. Default false = legacy behavior for existing endpoints.
    require_scoped_api_key: boolean("require_scoped_api_key")
      .notNull()
      .default(false),
    created_at: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updated_at: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    user_id: text("user_id").references(() => usersTable.id, {
      onDelete: "cascade",
    }),
  },
  (table) => [
    index("endpoints_namespace_uuid_idx").on(table.namespace_uuid),
    index("endpoints_user_id_idx").on(table.user_id),
    // Endpoints must be globally unique because they're used in URLs like /metamcp/[name]/sse
    unique("endpoints_name_unique").on(table.name),
    sql`CONSTRAINT endpoints_name_url_compatible_check CHECK (
        name ~ '^[a-zA-Z0-9_-]+$'
      )`,
  ],
);

// Many-to-many relationship table between namespaces and mcp servers
export const namespaceServerMappingsTable = pgTable(
  "namespace_server_mappings",
  {
    uuid: uuid("uuid").primaryKey().defaultRandom(),
    namespace_uuid: uuid("namespace_uuid")
      .notNull()
      .references(() => namespacesTable.uuid, { onDelete: "cascade" }),
    mcp_server_uuid: uuid("mcp_server_uuid")
      .notNull()
      .references(() => mcpServersTable.uuid, { onDelete: "cascade" }),
    status: mcpServerStatusEnum("status")
      .notNull()
      .default(McpServerStatusEnum.enum.ACTIVE),
    created_at: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index("namespace_server_mappings_namespace_uuid_idx").on(
      table.namespace_uuid,
    ),
    index("namespace_server_mappings_mcp_server_uuid_idx").on(
      table.mcp_server_uuid,
    ),
    index("namespace_server_mappings_status_idx").on(table.status),
    unique("namespace_server_mappings_unique_idx").on(
      table.namespace_uuid,
      table.mcp_server_uuid,
    ),
  ],
);

// Many-to-many relationship table between namespaces and tools for status control and overrides
export const namespaceToolMappingsTable = pgTable(
  "namespace_tool_mappings",
  {
    uuid: uuid("uuid").primaryKey().defaultRandom(),
    namespace_uuid: uuid("namespace_uuid")
      .notNull()
      .references(() => namespacesTable.uuid, { onDelete: "cascade" }),
    tool_uuid: uuid("tool_uuid")
      .notNull()
      .references(() => toolsTable.uuid, { onDelete: "cascade" }),
    mcp_server_uuid: uuid("mcp_server_uuid")
      .notNull()
      .references(() => mcpServersTable.uuid, { onDelete: "cascade" }),
    status: mcpServerStatusEnum("status")
      .notNull()
      .default(McpServerStatusEnum.enum.ACTIVE),
    override_name: text("override_name"),
    override_title: text("override_title"),
    override_description: text("override_description"),
    override_annotations: jsonb("override_annotations")
      .$type<Record<string, unknown> | null>()
      .default(sql`NULL`),
    created_at: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index("namespace_tool_mappings_namespace_uuid_idx").on(
      table.namespace_uuid,
    ),
    index("namespace_tool_mappings_tool_uuid_idx").on(table.tool_uuid),
    index("namespace_tool_mappings_mcp_server_uuid_idx").on(
      table.mcp_server_uuid,
    ),
    index("namespace_tool_mappings_status_idx").on(table.status),
    unique("namespace_tool_mappings_unique_idx").on(
      table.namespace_uuid,
      table.tool_uuid,
    ),
  ],
);

// API Keys table
export const apiKeysTable = pgTable(
  "api_keys",
  {
    uuid: uuid("uuid").primaryKey().defaultRandom(),
    name: text("name").notNull(),
    key: text("key").notNull().unique(),
    user_id: text("user_id").references(() => usersTable.id, {
      onDelete: "cascade",
    }),
    // Endpoint scope. Non-NULL binds this key to exactly ONE endpoint —
    // checkApiKeyAccess denies it everywhere else. NULL = legacy/unscoped
    // (grandfathered): reaches every enable_api_key_auth endpoint, as all
    // keys did before migration 0023. New keys must name an endpoint or pass
    // the explicit all_endpoints escape hatch (enforced in the tRPC create
    // path); NULL can no longer be reached silently through the app. ON
    // DELETE CASCADE: a key bound to a deleted endpoint is revoked with it.
    endpoint_uuid: uuid("endpoint_uuid").references(() => endpointsTable.uuid, {
      onDelete: "cascade",
    }),
    // Acts-as identity binding (migration 0024). Non-NULL names the ONE
    // better-auth user whose delegated m365 identity requests authenticated
    // by this key exercise (the streamable-http m365 context gate injects
    // this id; see routers/public-metamcp/streamable-http.ts). NULL = no
    // identity — the injected fetch fail-closes for this key exactly as it
    // did before the migration. The binding is admin-set at CREATION only
    // and immutable through the app (absent from every update schema/path),
    // and the create path requires it to be paired with a non-null
    // endpoint_uuid: an identity-bound key must be endpoint-scoped, never
    // gateway-wide. ON DELETE CASCADE: a key bound to a deleted user dies
    // with the identity it exercises.
    acts_as_user_id: text("acts_as_user_id").references(() => usersTable.id, {
      onDelete: "cascade",
    }),
    created_at: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    is_active: boolean("is_active").notNull().default(true),
    // Last time this key authenticated a public-endpoint request. Written
    // fire-and-forget and throttled (only when NULL or >=15 min stale) by
    // `validateApiKey` so the hot auth path never pays a write per request
    // and a failed timestamp write can never fail the request. Nullable: a
    // key that has never authenticated reads NULL. Surfaced only in the
    // admin cross-user key view — the owner-scoped list does not expose it.
    last_used_at: timestamp("last_used_at", { withTimezone: true }),
  },
  (table) => [
    index("api_keys_user_id_idx").on(table.user_id),
    index("api_keys_key_idx").on(table.key),
    index("api_keys_is_active_idx").on(table.is_active),
    index("api_keys_endpoint_uuid_idx").on(table.endpoint_uuid),
    index("api_keys_acts_as_user_id_idx").on(table.acts_as_user_id),
    unique("api_keys_name_per_user_idx").on(table.user_id, table.name),
    // Structural pairing invariant (migration 0024): an identity binding
    // REQUIRES a single-endpoint scope. App-layer enforcement (zod + impl +
    // the middleware's runtime stamp gate) cannot reach rows written outside
    // the app, so the pairing is also a CHECK — an unscoped-but-bound row
    // cannot exist.
    check(
      "api_keys_acts_as_requires_scope",
      sql`${table.acts_as_user_id} IS NULL OR ${table.endpoint_uuid} IS NOT NULL`,
    ),
  ],
);

// Configuration table for app-wide settings
export const configTable = pgTable("config", {
  id: text("id").primaryKey(),
  value: text("value").notNull(),
  description: text("description"),
  created_at: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
  updated_at: timestamp("updated_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

// OAuth Registered Clients table
export const oauthClientsTable = pgTable(
  "oauth_clients",
  {
    client_id: text("client_id").primaryKey(),
    client_secret: text("client_secret"),
    client_name: text("client_name").notNull(),
    redirect_uris: text("redirect_uris")
      .array()
      .notNull()
      .default(sql`'{}'::text[]`),
    grant_types: text("grant_types")
      .array()
      .notNull()
      .default(sql`'{"authorization_code","refresh_token"}'::text[]`),
    response_types: text("response_types")
      .array()
      .notNull()
      .default(sql`'{"code"}'::text[]`),
    token_endpoint_auth_method: text("token_endpoint_auth_method")
      .notNull()
      .default("none"),
    // Matches GRANTED_OAUTH_SCOPE ("mcp"), the one scope this server ever
    // issues. The default used to be "admin", so a row written without an
    // explicit scope — and every legacy row — recorded an administrative-
    // sounding grant for a caller who was never an administrator. Scope carries
    // no privilege here (checkOAuthAccess authorizes on user id + endpoint
    // ownership and never reads it), so this is honest labelling rather than an
    // access change — but handleRefreshTokenGrant copies the stored scope
    // forward on every refresh, so a wrong default persists indefinitely.
    // Migration 0026 flips the column default and rewrites the legacy rows.
    // (Numbered 0026, not 0025: an earlier renumber left 0025 unused — the
    // journal jumps idx 24 -> 26 — and this comment named the pre-renumber
    // file until 2026-08-14.)
    scope: text("scope").default("mcp"),
    client_uri: text("client_uri"),
    logo_uri: text("logo_uri"),
    contacts: text("contacts").array(),
    tos_uri: text("tos_uri"),
    policy_uri: text("policy_uri"),
    software_id: text("software_id"),
    software_version: text("software_version"),
    // Which mint path wrote this row. Read by exactly one query: the retention
    // sweep in db/repositories/oauth.repo.ts, which deletes only 'dcr'.
    //
    // NULLABLE WITH NO DEFAULT, both on purpose. No default because a
    // forgotten insert path must land as "unknown" (never swept) rather than
    // inherit "dcr" (swept) — the column exists to protect rows, so its
    // failure mode has to point at keeping them. Nullable because rows written
    // before migration 0029 have a provenance nobody recorded, and inventing
    // one for them would be the same guess the column was added to eliminate.
    //
    // `$type` narrows the TS type from `string`; the CHECK below is what makes
    // that narrowing true of the DATA rather than just of the code, since psql
    // is a routine ops path here and could otherwise write a third value the
    // sweep would silently never match.
    registration_source: text(
      "registration_source",
    ).$type<OAuthClientRegistrationSource>(),
    created_at: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updated_at: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    // Migration 0029. NULL stays legal — it is the honest value for every row
    // that predates the column.
    check(
      "oauth_clients_registration_source_valid",
      sql`${table.registration_source} IS NULL OR ${table.registration_source} IN ('dcr', 'admin')`,
    ),
  ],
);

// OAuth Authorization Codes table
export const oauthAuthorizationCodesTable = pgTable(
  "oauth_authorization_codes",
  {
    code: text("code").primaryKey(),
    client_id: text("client_id")
      .notNull()
      .references(() => oauthClientsTable.client_id, { onDelete: "cascade" }),
    redirect_uri: text("redirect_uri").notNull(),
    // "mcp", not "admin" — see oauthClientsTable.scope above.
    scope: text("scope").notNull().default("mcp"),
    user_id: text("user_id")
      .notNull()
      .references(() => usersTable.id, { onDelete: "cascade" }),
    code_challenge: text("code_challenge"),
    code_challenge_method: text("code_challenge_method"),
    expires_at: timestamp("expires_at", { withTimezone: true }).notNull(),
    created_at: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index("oauth_authorization_codes_client_id_idx").on(table.client_id),
    index("oauth_authorization_codes_user_id_idx").on(table.user_id),
    index("oauth_authorization_codes_expires_at_idx").on(table.expires_at),
  ],
);

// OAuth Access Tokens table
export const oauthAccessTokensTable = pgTable(
  "oauth_access_tokens",
  {
    access_token: text("access_token").primaryKey(),
    client_id: text("client_id")
      .notNull()
      .references(() => oauthClientsTable.client_id, { onDelete: "cascade" }),
    user_id: text("user_id")
      .notNull()
      .references(() => usersTable.id, { onDelete: "cascade" }),
    // "mcp", not "admin" — see oauthClientsTable.scope above.
    scope: text("scope").notNull().default("mcp"),
    expires_at: timestamp("expires_at", { withTimezone: true }).notNull(),
    refresh_token: text("refresh_token"),
    refresh_token_expires_at: timestamp("refresh_token_expires_at", {
      withTimezone: true,
    }),
    created_at: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index("oauth_access_tokens_client_id_idx").on(table.client_id),
    index("oauth_access_tokens_user_id_idx").on(table.user_id),
    index("oauth_access_tokens_expires_at_idx").on(table.expires_at),
    index("oauth_access_tokens_refresh_token_idx").on(table.refresh_token),
  ],
);

// MCP Sessions table — persists Streamable HTTP session metadata so that
// metamcp restarts don't force every consumer to re-initialize. When a
// request arrives with an unknown `Mcp-Session-Id` (in-memory transport
// map empty after restart), the router queries this table and lazily
// recreates the transport from the stored namespace + auth principal +
// init params. See `apps/backend/src/routers/public-metamcp/streamable-http.ts`
// for the recovery path and `mcp-sessions.repo.ts` for the access layer.
//
// auth_principal is a constant-time-compared SHA-256 of the original
// bearer token (or API key). Raw tokens are never stored. If the client
// rotates / revokes its token, the lazy-recovery path refuses and the
// client must initialize a fresh session.
export const mcpSessionsTable = pgTable(
  "mcp_sessions",
  {
    session_id: text("session_id").primaryKey(),
    namespace_uuid: uuid("namespace_uuid").notNull(),
    endpoint_name: text("endpoint_name").notNull(),
    auth_principal: text("auth_principal").notNull(),
    auth_method: text("auth_method").notNull(),
    init_params: jsonb("init_params")
      .$type<Record<string, unknown>>()
      .notNull()
      .default(sql`'{}'::jsonb`),
    created_at: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    last_seen_at: timestamp("last_seen_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    // PR #22: gateway process UUID stamped at session init. Nullable
    // for backwards-compat with rows persisted before this column
    // existed; the lazy-recovery path treats null as "allow" (pre-PR
    // row, no metadata to compare) and treats mismatch as "refuse"
    // (cross-restart row whose negotiated capability set may now be
    // stale). See `lib/metamcp/gateway-boot-id.ts`.
    gateway_boot_id: uuid("gateway_boot_id"),
    // PR #23: SHA-256 of the upstream-advertised capability set at
    // session init. Used alongside `gateway_boot_id` so lazy-recovery
    // refuses only when capabilities actually changed across a
    // restart (different boot_id AND different hash), not on every
    // capability-neutral restart (different boot_id, same hash —
    // safe to recover). Nullable for backwards-compat with rows
    // persisted before this column existed. See
    // `lib/metamcp/gateway-boot-id.ts#shouldRefuseRecovery`.
    capability_hash: text("capability_hash"),
  },
  (table) => [
    index("mcp_sessions_last_seen_at_idx").on(table.last_seen_at),
    index("mcp_sessions_namespace_uuid_idx").on(table.namespace_uuid),
  ],
);

// M365 delegated-token broker: per-user Entra refresh-token custody.
//
// One row per enrolled gateway user. `rt_ciphertext` is an
// AES-256-GCM envelope (`lib/m365/crypto.ts`) — plaintext refresh
// tokens are NEVER stored (deliberately separate from better-auth's
// `accounts` table, which persists provider tokens unencrypted).
// `kek_id` mirrors the envelope header for SQL-side visibility during
// KEK rotation. Row deletion cascades with the user (FK) and is the
// primary revocation surface (`/m365/disconnect`); Entra-side disable /
// revokeSignInSessions is the org kill switch. `status` values:
// `active`, `reauth_required` (refresh grant rejected — row kept for
// audit, mint path treats it as missing).
export const m365UserTokensTable = pgTable(
  "m365_user_tokens",
  {
    uuid: uuid("uuid")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    user_id: text("user_id")
      .notNull()
      .unique()
      .references(() => usersTable.id, { onDelete: "cascade" }),
    // Entra object id + tenant of the enrolled account — audit surface
    // only (not enforced): a re-enrollment overwrites them, and the
    // callback route logs an m365_enroll_account_switch event when the
    // oid changes rather than blocking the legitimate account switch.
    entra_oid: text("entra_oid").notNull(),
    tenant_id: text("tenant_id").notNull(),
    entra_upn: text("entra_upn"),
    rt_ciphertext: text("rt_ciphertext").notNull(),
    kek_id: text("kek_id").notNull(),
    scopes_granted: text("scopes_granted").notNull(),
    status: text("status").notNull().default("active"),
    created_at: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    rotated_at: timestamp("rotated_at", { withTimezone: true }),
    last_used_at: timestamp("last_used_at", { withTimezone: true }),
  },
  (table) => [index("m365_user_tokens_status_idx").on(table.status)],
);

// Tool-call audit log (fork feature — Umbrella TASKLIST "Tool-call audit
// logging" SPEC): one row per proxied tools/call so "who called what when"
// is SQL-queryable instead of a Loki grep. Raw params are NEVER stored —
// `params_hash` is a sha256 of the JSON-serialized arguments. Written
// fire-and-forget by the auditing middleware (an audit-write failure must
// never fail the tool call); pruned after TOOL_AUDIT_RETENTION_DAYS
// (default 90) by the oauth cleanup interval. `client_name` is the resolved
// consumer identity (api-key name / OAuth user email) rather than the
// SPEC's raw user_id — api-key consumers have no user row.
export const toolCallAuditTable = pgTable(
  "tool_call_audit",
  {
    uuid: uuid("uuid")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    called_at: timestamp("called_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    client_name: text("client_name"),
    namespace_uuid: text("namespace_uuid"),
    session_id: text("session_id"),
    server_name: text("server_name").notNull(),
    tool_name: text("tool_name").notNull(),
    params_hash: text("params_hash"),
    success: boolean("success").notNull(),
    error_code: text("error_code"),
    latency_ms: integer("latency_ms"),
  },
  (table) => [
    index("tool_call_audit_called_at_idx").on(table.called_at),
    index("tool_call_audit_tool_name_idx").on(table.tool_name),
    index("tool_call_audit_client_name_idx").on(table.client_name),
  ],
);

// Control-plane security audit log (migration 0028). Companion to
// `tool_call_audit` above, deliberately a SECOND table rather than more
// columns on that one: different write rate, different query shape, and
// `tool_call_audit` already has consumers whose indexes should not churn.
//
// The two differ in one more way that matters: `tool_call_audit` is pruned
// (`pruneOlderThan`, hard DELETE, 90d). This table has NO prune, NO update
// and NO delete anywhere in the application — the repository exposes
// `record()` and nothing else, and migration 0028 adds BEFORE
// UPDATE/DELETE/TRUNCATE triggers that RAISE. That asymmetry is the point:
// an audit archive an admin can empty is not an audit archive.
//
// Raw secrets are NEVER written. `detail` carries a sha256 + last-4
// fingerprint of a presented credential, never the credential.
export const auditLogTable = pgTable(
  "audit_log",
  {
    uuid: uuid("uuid")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    occurred_at: timestamp("occurred_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    // user | api_key | oauth_client | anonymous | system. Kept as text
    // rather than a pgEnum: a new actor class must never be able to make an
    // audit INSERT fail, and a failed audit INSERT is a silently missing
    // security record.
    actor_type: text("actor_type").notNull(),
    actor_id: text("actor_id"),
    actor_label: text("actor_label"),
    // Resolved from CF-Connecting-IP by the audit-context middleware, not
    // from req.ip (which is container-local for every caller — see
    // middleware/audit-context.middleware.ts).
    actor_ip: text("actor_ip"),
    actor_user_agent: text("actor_user_agent"),
    action: text("action").notNull(),
    target_type: text("target_type"),
    target_id: text("target_id"),
    // success | failure | denied — same reasoning as actor_type for staying
    // text.
    outcome: text("outcome").notNull(),
    request_id: text("request_id"),
    http_status: integer("http_status"),
    detail: jsonb("detail")
      .notNull()
      .default(sql`'{}'::jsonb`),
  },
  (table) => [
    index("audit_log_occurred_at_idx").on(table.occurred_at),
    index("audit_log_action_idx").on(table.action),
    index("audit_log_actor_id_idx").on(table.actor_id),
    index("audit_log_outcome_idx").on(table.outcome),
  ],
);

// Gateway activity history (migration 0031). The durable half of the Live
// Logs page: the in-memory ring buffer in `lib/metamcp/log-store.ts` keeps the
// last 2000 entries for the live tail, and every one of them that is not a
// tool call is also written here so the history survives a restart.
//
// `tool_call` is deliberately NOT one of the categories. Those rows already
// exist in `tool_call_audit` above, with more detail (params hash, latency,
// namespace) than this envelope carries — writing them twice would double the
// busiest write path in the gateway to store a poorer copy. The writer in
// `lib/gateway-events/sink.ts` filters the category out.
//
// Retention differs from BOTH neighbours, which is the reason it is a third
// table. `tool_call_audit` is prunable at any age; `audit_log` is never
// prunable at all. This one is immutable for 30 days and prunable after —
// migration 0031 installs an age-gated DELETE trigger plus unconditional
// UPDATE/TRUNCATE blocks, and `lib/gateway-events/retention.ts` floor-clamps
// the retention env to the same 30 days so the sweeper can never ask for a
// deletion the database refuses.
export const gatewayEventsTable = pgTable(
  "gateway_events",
  {
    uuid: uuid("uuid")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    // Millisecond precision, matching migration 0031. The keyset cursor is a
    // JavaScript Date, which cannot carry microseconds, so a finer column would
    // hand back a cursor slightly earlier than the row it came from and skip
    // every row sharing that millisecond.
    occurred_at: timestamp("occurred_at", { withTimezone: true, precision: 3 })
      .notNull()
      .defaultNow(),
    // connection | client | server | system. Text rather than a pgEnum for the
    // same reason `audit_log.actor_type` is text: a new event class must never
    // be able to make this INSERT fail.
    category: text("category").notNull(),
    // info | warn | error. Nullable because the column describes severity, and
    // an event that arrives without one is still worth keeping.
    level: text("level"),
    server_uuid: uuid("server_uuid"),
    server_name: text("server_name"),
    client_name: text("client_name"),
    session_id: text("session_id"),
    message: text("message").notNull(),
    // Small, clamped extras (tool name, duration, normalized error text).
    // Nullable rather than defaulting to `{}` so "nothing to add" and "an empty
    // object was supplied" stay distinguishable.
    metadata: jsonb("metadata"),
  },
  (table) => [
    // Mirrors the DESC indexes migration 0031 creates — the history view reads
    // newest-first and pages with a keyset on (occurred_at, uuid).
    index("gateway_events_occurred_at_idx").on(table.occurred_at.desc()),
    index("gateway_events_category_occurred_at_idx").on(
      table.category,
      table.occurred_at.desc(),
    ),
  ],
);
