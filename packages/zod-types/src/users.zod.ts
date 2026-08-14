import { z } from "zod";

// ===== User administration (Access dashboard) =====
//
// Incident 2026-08-13: self-registered member accounts were INVISIBLE. The
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
  created_at: z.date(),
  updated_at: z.date(),
  // Most recent `sessions.updated_at` for this user — better-auth touches it
  // on the sliding refresh, so it is the cheapest available "last active"
  // signal. NULL when the user has never held a session, or when every
  // session they had has been deleted (including by revokeAccess below).
  last_active_at: z.date().nullable(),
  // Live (non-expired) session count. The incident question "is this account
  // signed in right now" reads straight off this.
  active_session_count: z.number().int(),
  // Live (non-expired) OAuth access tokens. An account can hold zero sessions
  // and still be reaching MCP through a token minted weeks ago, so the two
  // counts are shown side by side rather than collapsed into one "active".
  active_oauth_token_count: z.number().int(),
  // Active API keys owned by this user. Third independent access path.
  active_api_key_count: z.number().int(),
});

export const ListUsersResponseSchema = z.object({
  users: z.array(UserListItemSchema),
});

export const DeleteUserRequestSchema = z.object({
  user_id: z.string().min(1),
});

export const DeleteUserResponseSchema = z.object({
  success: z.boolean(),
  message: z.string(),
});

export const RevokeUserAccessRequestSchema = z.object({
  user_id: z.string().min(1),
});

// Revocation reports WHAT it severed rather than a bare success flag. An
// operator acting on a live intrusion needs to see that the four access paths
// were actually cut, and a silent zero is itself a finding (wrong account).
export const RevokeUserAccessResponseSchema = z.object({
  success: z.boolean(),
  message: z.string(),
  sessions_deleted: z.number().int(),
  oauth_tokens_deleted: z.number().int(),
  authorization_codes_deleted: z.number().int(),
  api_keys_deactivated: z.number().int(),
});

export type UserListItem = z.infer<typeof UserListItemSchema>;
export type ListUsersResponse = z.infer<typeof ListUsersResponseSchema>;
export type DeleteUserRequest = z.infer<typeof DeleteUserRequestSchema>;
export type DeleteUserResponse = z.infer<typeof DeleteUserResponseSchema>;
export type RevokeUserAccessRequest = z.infer<
  typeof RevokeUserAccessRequestSchema
>;
export type RevokeUserAccessResponse = z.infer<
  typeof RevokeUserAccessResponseSchema
>;
