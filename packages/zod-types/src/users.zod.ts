import { z } from "zod";

// ===== User administration (Access dashboard) =====
//
// Self-registration abuse: member accounts were INVISIBLE. The
// gateway had no users page and no list-users procedure at all, so the only
// way to learn an account existed was to open a psql shell. These schemas are
// the wire contract for the admin surface that closes that gap.
//
// The `users` table itself stores no credential material (better-auth keeps
// password hashes in `accounts`), but the allow-list below is written as an
// allow-list anyway, and the router's `.output()` strips anything else — so a
// future column added to the table cannot leak by simply existing.
export const UserListItemSchema = z.object({
  id: z.string(),
  email: z.string(),
  name: z.string(),
  // 'admin' | 'member'. Not an enum: the column is a free-text NOT NULL
  // default 'member', and a row written outside the app could hold anything.
  // A z.enum here would make the whole listing throw on the one row an
  // administrator most needs to see.
  role: z.string(),
  emailVerified: z.boolean(),
  // Account lock (migration 0027). A disabled account cannot mint a session
  // and its existing sessions are rejected on the next request.
  disabled: z.boolean(),
  disabled_at: z.date().nullable(),
  disabled_by: z.string().nullable(),
  created_at: z.date(),
  updated_at: z.date(),
  // Most recent `sessions.updated_at` for this user.
  //
  // Named for what it MEASURES, not for what a reader might wish it meant.
  // better-auth only touches that column on its sliding refresh — `updateAge`
  // defaults to 7 days in this fork — so this is the last time the session
  // cookie was renewed, NOT the last request. An account active minutes ago
  // can legitimately read as six days stale, which is exactly the kind of
  // number that gets misread during a live response. `active_session_count`
  // and the API-key `last_used_at` on the keys tab are the finer-grained
  // signals.
  //
  // NULL when the user has never held a session, or when every session they
  // had has been deleted (including by revokeAccess).
  last_session_refresh_at: z.date().nullable(),
  // Live (non-expired) session count. The response question "is this account
  // signed in right now" reads straight off this.
  active_session_count: z.number().int(),
  // Live (non-expired) OAuth access tokens. An account can hold zero sessions
  // and still be reaching MCP through a token minted weeks ago, so the two
  // counts are shown side by side rather than collapsed into one "active".
  active_oauth_token_count: z.number().int(),
  // Active API keys that can act as this identity — keys the user OWNS plus
  // keys anyone owns that carry `acts_as_user_id = this user` (migration
  // 0024). Both are live paths to this identity; counting only ownership
  // under-reported it.
  active_api_key_count: z.number().int(),
});

export const ListUsersResponseSchema = z.object({
  users: z.array(UserListItemSchema),
  // True total in the table, which may exceed `users.length` — the listing is
  // capped so a signup flood cannot make the page unusable at the exact
  // moment it matters. The UI says "showing N of TOTAL" rather than silently
  // truncating, because a missing row on this screen is the failure.
  total: z.number().int(),
});

export const DeleteUserRequestSchema = z.object({
  user_id: z.string().min(1),
});

export const DeleteUserResponseSchema = z.object({
  success: z.boolean(),
  message: z.string(),
});

// What a delete would destroy, shown BEFORE the irreversible confirmation.
//
// Split own/other because the "other" numbers are the ones that must stop an
// operator mid-click: the FK cascade reaches endpoints owned by other users
// (they live in this user's namespaces) and API keys owned by other users
// (they act as this identity, or are scoped to a doomed endpoint). Verified
// against a real postgres — deleting a CI/sync identity revoked another
// administrator's production key and killed a live endpoint.
export const DeleteUserImpactSchema = z.object({
  own_namespaces: z.number().int(),
  own_endpoints: z.number().int(),
  own_mcp_servers: z.number().int(),
  own_api_keys: z.number().int(),
  other_users_endpoints: z.number().int(),
  other_users_api_keys: z.number().int(),
  sessions: z.number().int(),
  oauth_tokens: z.number().int(),
  m365_tokens: z.number().int(),
});

export const PreviewDeleteUserRequestSchema = z.object({
  user_id: z.string().min(1),
});

export const PreviewDeleteUserResponseSchema = z.object({
  found: z.boolean(),
  email: z.string().nullable(),
  impact: DeleteUserImpactSchema,
});

export const SetUserDisabledRequestSchema = z.object({
  user_id: z.string().min(1),
  disabled: z.boolean(),
});

export const SetUserDisabledResponseSchema = z.object({
  success: z.boolean(),
  message: z.string(),
  disabled: z.boolean(),
});

export const RevokeUserAccessRequestSchema = z.object({
  user_id: z.string().min(1),
});

// Revocation reports WHAT it severed rather than a bare success flag. An
// operator acting on a live intrusion needs to see that every access path was
// actually cut, and a silent zero is itself a finding (wrong account).
export const RevokeUserAccessResponseSchema = z.object({
  success: z.boolean(),
  message: z.string(),
  sessions_deleted: z.number().int(),
  oauth_tokens_deleted: z.number().int(),
  authorization_codes_deleted: z.number().int(),
  // Keys the user owns PLUS keys that act as this identity.
  api_keys_deactivated: z.number().int(),
  // M365 delegations forced back to `reauth_required` — without this a
  // revoked identity could still be exercised against Microsoft 365.
  m365_tokens_revoked: z.number().int(),
});

export type UserListItem = z.infer<typeof UserListItemSchema>;
export type ListUsersResponse = z.infer<typeof ListUsersResponseSchema>;
export type DeleteUserRequest = z.infer<typeof DeleteUserRequestSchema>;
export type DeleteUserResponse = z.infer<typeof DeleteUserResponseSchema>;
export type DeleteUserImpact = z.infer<typeof DeleteUserImpactSchema>;
export type PreviewDeleteUserRequest = z.infer<
  typeof PreviewDeleteUserRequestSchema
>;
export type PreviewDeleteUserResponse = z.infer<
  typeof PreviewDeleteUserResponseSchema
>;
export type SetUserDisabledRequest = z.infer<
  typeof SetUserDisabledRequestSchema
>;
export type SetUserDisabledResponse = z.infer<
  typeof SetUserDisabledResponseSchema
>;
export type RevokeUserAccessRequest = z.infer<
  typeof RevokeUserAccessRequestSchema
>;
export type RevokeUserAccessResponse = z.infer<
  typeof RevokeUserAccessResponseSchema
>;
