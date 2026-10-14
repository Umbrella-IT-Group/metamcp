import { z } from "zod";

// Scope selection at mint time: a key names the ONE endpoint it may reach
// (endpoint_uuid), or the caller deliberately passes all_endpoints: true —
// the explicit escape hatch that stores NULL (legacy gateway-wide key).
// Exactly one of the two must be chosen; a request that picks neither, or
// both, is rejected so a global key can never be minted silently. Shared by
// the form + request schemas below (kept inline in each .superRefine so zod
// v4 infers the ctx type).
const scopeShape = {
  endpoint_uuid: z.string().uuid().optional(),
  all_endpoints: z.boolean().optional(),
};

// Acts-as identity binding (migration 0024): the better-auth user id whose
// delegated m365 identity requests authenticated by this key exercise.
// Admin-only, creation-only, and REQUIRES a single-endpoint scope — an
// identity-bound key must never be gateway-wide, so pairing it with
// all_endpoints (or no scope at all) is rejected in the superRefines below
// and re-checked in the impl for schema-bypassing callers. Plain string, not
// uuid: better-auth ids are text.
const actsAsShape = {
  acts_as_user_id: z.string().min(1).optional(),
};

// Plane flag (migration 0038): true mints a CONTROL-plane (admin-plane / CI)
// key that authenticates on /trpc as its owner, false/absent a DATA-plane key.
// Admin-only, creation-only, and MUTUALLY EXCLUSIVE with every data-plane input
// (endpoint scope + acts-as), a control-plane key has no endpoint to reach and
// carries no delegated identity. The superRefines below reject that combination
// and relax the mandatory-scope rule for admin-plane keys (they have no endpoint
// to name); the admin-only and owner-must-be-admin policy lives in the impl,
// the only layer that sees the caller's and the owner's role.
const adminPlaneShape = {
  admin_plane: z.boolean().optional(),
};

export const CreateApiKeyFormSchema = z
  .object({
    name: z
      .string()
      .min(1, "validation:apiKeyName.required")
      .max(100, "Name must be less than 100 characters")
      .regex(
        /^[a-zA-Z0-9_\s-]+$/,
        "Name can only contain letters, numbers, spaces, underscores, and hyphens",
      ),
    user_id: z.string().nullable().optional(),
    ...scopeShape,
    ...actsAsShape,
    ...adminPlaneShape,
  })
  .superRefine((val, ctx) => {
    // Admin-plane (control-plane / CI) key: a separate population with NO
    // data-plane scope. It authenticates a user on /trpc, never reaches an
    // endpoint, and carries no acts-as identity, so the three data-plane inputs
    // must be absent and the mandatory-scope rule below is skipped for it (it
    // has no endpoint to name). Admin-only and owner-must-be-admin are enforced
    // in the impl, the only layer that sees the caller's and owner's role.
    if (val.admin_plane === true) {
      if (val.endpoint_uuid !== undefined || val.all_endpoints !== undefined) {
        ctx.addIssue({
          code: "custom",
          path: ["admin_plane"],
          message: "validation:apiKeyAdminPlane.noScope",
        });
      }
      if (val.acts_as_user_id !== undefined) {
        ctx.addIssue({
          code: "custom",
          path: ["admin_plane"],
          message: "validation:apiKeyAdminPlane.noActsAs",
        });
      }
      return;
    }
    if (val.endpoint_uuid && val.all_endpoints === true) {
      ctx.addIssue({
        code: "custom",
        path: ["endpoint_uuid"],
        message: "validation:apiKeyScope.exclusive",
      });
    }
    if (!val.endpoint_uuid && val.all_endpoints !== true) {
      ctx.addIssue({
        code: "custom",
        path: ["endpoint_uuid"],
        message: "validation:apiKeyScope.required",
      });
    }
    // Identity requires scope: an acts-as binding is only valid on a key
    // scoped to exactly ONE endpoint. Covers both the all_endpoints escape
    // hatch and a missing scope (endpoint_uuid unset in either case).
    if (val.acts_as_user_id && !val.endpoint_uuid) {
      ctx.addIssue({
        code: "custom",
        path: ["acts_as_user_id"],
        message: "validation:apiKeyActsAs.requiresEndpoint",
      });
    }
    // Ownership invariant: an identity-bound key must be OWNED by the
    // identity it exercises. `user_id: null` is the public ('everyone')
    // selection — a public key exists to be handed to every consumer, so a
    // public identity-bound key would be a fleet-distributed delegated
    // credential; an explicit foreign owner is the same hazard one hop
    // removed. `user_id: undefined` (default: the caller) can only be
    // checked where the caller is known — the impl enforces that half.
    if (
      val.acts_as_user_id !== undefined &&
      val.user_id !== undefined &&
      val.user_id !== val.acts_as_user_id
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["acts_as_user_id"],
        message: "validation:apiKeyActsAs.ownerMismatch",
      });
    }
  });

export const CreateApiKeyRequestSchema = z
  .object({
    name: z
      .string()
      .min(1, "validation:apiKeyName.required")
      .max(100, "Name must be less than 100 characters")
      .regex(
        /^[a-zA-Z0-9_\s-]+$/,
        "Name can only contain letters, numbers, spaces, underscores, and hyphens",
      ),
    user_id: z.string().nullable().optional(),
    ...scopeShape,
    ...actsAsShape,
    ...adminPlaneShape,
  })
  .superRefine((val, ctx) => {
    // Admin-plane (control-plane / CI) key: a separate population with NO
    // data-plane scope. It authenticates a user on /trpc, never reaches an
    // endpoint, and carries no acts-as identity, so the three data-plane inputs
    // must be absent and the mandatory-scope rule below is skipped for it (it
    // has no endpoint to name). Admin-only and owner-must-be-admin are enforced
    // in the impl, the only layer that sees the caller's and owner's role.
    if (val.admin_plane === true) {
      if (val.endpoint_uuid !== undefined || val.all_endpoints !== undefined) {
        ctx.addIssue({
          code: "custom",
          path: ["admin_plane"],
          message: "validation:apiKeyAdminPlane.noScope",
        });
      }
      if (val.acts_as_user_id !== undefined) {
        ctx.addIssue({
          code: "custom",
          path: ["admin_plane"],
          message: "validation:apiKeyAdminPlane.noActsAs",
        });
      }
      return;
    }
    if (val.endpoint_uuid && val.all_endpoints === true) {
      ctx.addIssue({
        code: "custom",
        path: ["endpoint_uuid"],
        message: "validation:apiKeyScope.exclusive",
      });
    }
    if (!val.endpoint_uuid && val.all_endpoints !== true) {
      ctx.addIssue({
        code: "custom",
        path: ["endpoint_uuid"],
        message: "validation:apiKeyScope.required",
      });
    }
    // Identity requires scope: an acts-as binding is only valid on a key
    // scoped to exactly ONE endpoint. Covers both the all_endpoints escape
    // hatch and a missing scope (endpoint_uuid unset in either case).
    if (val.acts_as_user_id && !val.endpoint_uuid) {
      ctx.addIssue({
        code: "custom",
        path: ["acts_as_user_id"],
        message: "validation:apiKeyActsAs.requiresEndpoint",
      });
    }
    // Ownership invariant (mirrors the form schema above, same reasoning): an
    // identity-bound key must be OWNED by the identity it exercises — public
    // (`user_id: null`) and explicit-foreign-owner bindings are rejected
    // here; the `user_id: undefined` (owner = caller) half is enforced in the
    // impl, where the caller is known.
    if (
      val.acts_as_user_id !== undefined &&
      val.user_id !== undefined &&
      val.user_id !== val.acts_as_user_id
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["acts_as_user_id"],
        message: "validation:apiKeyActsAs.ownerMismatch",
      });
    }
  });

export const CreateApiKeyResponseSchema = z.object({
  uuid: z.string().uuid(),
  name: z.string(),
  key: z.string(),
  created_at: z.date(),
});

export const UpdateApiKeyRequestSchema = z.object({
  uuid: z.string().uuid(),
  name: z
    .string()
    .min(1, "validation:apiKeyName.required")
    .max(100, "Name must be less than 100 characters")
    .regex(
      /^[a-zA-Z0-9_\s-]+$/,
      "Name can only contain letters, numbers, spaces, underscores, and hyphens",
    )
    .optional(),
  is_active: z.boolean().optional(),
});

// Update readback (rename / activate / revoke). Deliberately omits the full
// `key` secret and carries only the non-reversible prefix, exactly like the
// list surfaces below.
//
// Security review finding: this schema used to type `key` as the full string
// and the serializer returned it raw, so the response to a plain rename
// re-disclosed a usable credential to any member holding the key's uuid. The
// raw key is shown exactly once, at mint time
// (CreateApiKeyResponseSchema above). Because this is the tRPC `.output()`
// schema, keeping key out of it is also the second half of the defense: a
// serializer that regressed and re-added `key` would have it stripped here
// before the response leaves the server.
export const UpdateApiKeyResponseSchema = z.object({
  uuid: z.string().uuid(),
  name: z.string(),
  key_prefix: z.string(),
  created_at: z.date(),
  is_active: z.boolean(),
});

export const DeleteApiKeyRequestSchema = z.object({
  uuid: z.string().uuid(),
});

export const DeleteApiKeyResponseSchema = z.object({
  success: z.boolean(),
  message: z.string(),
});

// Member-facing key list: the caller's own keys plus every public
// ('everyone') key. Deliberately omits the full `key` secret and carries only
// a non-reversible prefix, exactly like the admin view below.
//
// Security review finding: this schema used to type `key` as the full
// string and the serializer returned it raw, so any self-registered member
// could read every public key — gateway-wide production credentials — in
// plaintext. Because this is the tRPC `.output()` schema, keeping key out of
// it is also the second half of the defense: even a serializer that
// regressed and re-added `key` would have it stripped here before the
// response leaves the server.
export const ListApiKeysResponseSchema = z.object({
  apiKeys: z.array(
    z.object({
      uuid: z.string().uuid(),
      name: z.string(),
      key_prefix: z.string(),
      created_at: z.date(),
      is_active: z.boolean(),
      user_id: z.string().nullable(),
      endpoint_uuid: z.string().uuid().nullable(),
      acts_as_user_id: z.string().nullable(),
    }),
  ),
});

// Admin-only cross-user key view. Deliberately omits the full `key` secret —
// listing every user's raw key would be an exfiltration surface — and returns
// only a non-reversible prefix for identification. owner_email is null for a
// public ('everyone') key; last_used_at is null for a key never used.
export const AdminApiKeyItemSchema = z.object({
  uuid: z.string().uuid(),
  name: z.string(),
  key_prefix: z.string(),
  user_id: z.string().nullable(),
  owner_email: z.string().nullable(),
  endpoint_uuid: z.string().uuid().nullable(),
  // Acts-as identity binding (migration 0024): the bound better-auth user id
  // plus their email (NULL when the key has no identity binding). Surfaced
  // so the admin view labels identity-bound keys loudly.
  acts_as_user_id: z.string().nullable(),
  acts_as_email: z.string().nullable(),
  // Plane flag (migration 0038): true labels a control-plane (admin-plane / CI)
  // key loudly in the admin view, the way acts-as is labelled. A boolean, not
  // credential material, so it is safe in a list.
  admin_plane: z.boolean(),
  created_at: z.date(),
  last_used_at: z.date().nullable(),
  is_active: z.boolean(),
  // IP allowlist (migration 0040). allowed_cidrs NULL = the key follows the
  // global policy; non-NULL = its own list, governed by its own
  // ip_policy_mode. last_used_ip is the CF-Connecting-IP of the key's last
  // authenticated request (throttled like last_used_at). None of the three is
  // credential material.
  allowed_cidrs: z.array(z.string()).nullable(),
  ip_policy_mode: z.enum(["off", "audit", "enforce"]),
  last_used_ip: z.string().nullable(),
});

export const ListAllApiKeysResponseSchema = z.object({
  apiKeys: z.array(AdminApiKeyItemSchema),
});

// ---- API-key IP allowlists (migration 0040) ----
//
// off: nothing is evaluated. audit: the request is served and a throttled
// would-deny audit row is written. enforce: the request is refused with 403.
export const IpPolicyModeSchema = z.enum(["off", "audit", "enforce"]);

// Shape only. CIDR syntax (IPv4 or IPv6, prefix in range, no host bits set) is
// checked on the server with node:net, which is also what evaluates the list,
// so the rule that accepts an entry and the rule that matches it are the same
// code. 64 characters covers the longest legitimate IPv6 CIDR (49), and 100
// entries per list is far above any real allowlist.
export const IpCidrListSchema = z
  .array(z.string().trim().min(1).max(64))
  .max(100);

// Set ONE key's policy. allowed_cidrs null returns the key to the global
// policy (ip_policy_mode must then be "off", since a per-key mode without a
// per-key list is never read). The any-IP exemption is
// ["0.0.0.0/0", "::/0"].
export const SetApiKeyIpPolicyRequestSchema = z.object({
  uuid: z.string().uuid(),
  allowed_cidrs: IpCidrListSchema.nullable(),
  ip_policy_mode: IpPolicyModeSchema,
});

// Readback of the written row: the policy as stored (canonicalised CIDRs), so
// a caller can confirm the write without a second query. No credential
// material, same as the list surfaces.
export const SetApiKeyIpPolicyResponseSchema = z.object({
  uuid: z.string().uuid(),
  name: z.string(),
  key_prefix: z.string(),
  is_active: z.boolean(),
  allowed_cidrs: z.array(z.string()).nullable(),
  ip_policy_mode: IpPolicyModeSchema,
  last_used_ip: z.string().nullable(),
});

// The global policy, applied to every key whose allowed_cidrs is NULL.
export const SetGlobalIpPolicyRequestSchema = z.object({
  mode: IpPolicyModeSchema,
  allowed_cidrs: IpCidrListSchema,
});

export const SetGlobalIpPolicyResponseSchema = z.object({
  mode: IpPolicyModeSchema,
  allowed_cidrs: z.array(z.string()),
});

// `problems` names stored values the evaluator could not read (a value
// written outside the app); each is handled fail-closed and is listed here so
// an administrator sees it. `kill_switch_active` reports
// API_KEY_IP_POLICY_DISABLED=true, under which nothing is evaluated at all.
export const GetGlobalIpPolicyResponseSchema = z.object({
  mode: IpPolicyModeSchema,
  allowed_cidrs: z.array(z.string()),
  problems: z.array(z.string()),
  kill_switch_active: z.boolean(),
});

export const ValidateApiKeyRequestSchema = z.object({
  key: z.string(),
});

// NOTE: intentionally does NOT expose the key's endpoint scope. `validate`
// is callable by any member with an arbitrary key string; echoing
// endpoint_uuid would widen the key oracle (probe which endpoint a guessed
// key is bound to). Scope is enforced server-side in checkApiKeyAccess and
// never disclosed through this response.
export const ValidateApiKeyResponseSchema = z.object({
  valid: z.boolean(),
  user_id: z.string().optional(),
  key_uuid: z.string().uuid().optional(),
});

// Repository schemas
export const ApiKeyCreateInputSchema = z.object({
  name: z.string(),
  user_id: z.string().nullable().optional(),
  // NULL/omitted = unscoped (legacy gateway-wide). The tRPC create path is
  // responsible for making NULL an explicit choice (all_endpoints: true);
  // at the repository layer the column is just nullable.
  endpoint_uuid: z.string().uuid().nullable().optional(),
  // NULL/omitted = no acts-as identity (m365 injection fail-closes). The
  // tRPC create path enforces admin-only + requires-endpoint-scope; at the
  // repository layer the column is just nullable.
  acts_as_user_id: z.string().nullable().optional(),
  // Plane flag (migration 0038). Optional (not defaulted) so it stays absent
  // from the inferred input type and existing data-plane callers need not pass
  // it; the repository persists `admin_plane ?? false`. The tRPC create path
  // owns the admin-only + owner-must-be-admin + plane-exclusivity policy.
  admin_plane: z.boolean().optional(),
  is_active: z.boolean().optional().default(true),
});

export const ApiKeyUpdateInputSchema = z.object({
  name: z.string().optional(),
  is_active: z.boolean().optional(),
});

// Type exports
export type CreateApiKeyForm = z.infer<typeof CreateApiKeyFormSchema>;
export type CreateApiKeyRequest = z.infer<typeof CreateApiKeyRequestSchema>;
export type CreateApiKeyResponse = z.infer<typeof CreateApiKeyResponseSchema>;
export type UpdateApiKeyRequest = z.infer<typeof UpdateApiKeyRequestSchema>;
export type UpdateApiKeyResponse = z.infer<typeof UpdateApiKeyResponseSchema>;
export type DeleteApiKeyRequest = z.infer<typeof DeleteApiKeyRequestSchema>;
export type DeleteApiKeyResponse = z.infer<typeof DeleteApiKeyResponseSchema>;
export type ListApiKeysResponse = z.infer<typeof ListApiKeysResponseSchema>;
export type AdminApiKeyItem = z.infer<typeof AdminApiKeyItemSchema>;
export type ListAllApiKeysResponse = z.infer<
  typeof ListAllApiKeysResponseSchema
>;
export type ValidateApiKeyRequest = z.infer<typeof ValidateApiKeyRequestSchema>;
export type ValidateApiKeyResponse = z.infer<
  typeof ValidateApiKeyResponseSchema
>;
export type ApiKeyCreateInput = z.infer<typeof ApiKeyCreateInputSchema>;
export type ApiKeyUpdateInput = z.infer<typeof ApiKeyUpdateInputSchema>;
export type IpPolicyMode = z.infer<typeof IpPolicyModeSchema>;
export type SetApiKeyIpPolicyRequest = z.infer<
  typeof SetApiKeyIpPolicyRequestSchema
>;
export type SetApiKeyIpPolicyResponse = z.infer<
  typeof SetApiKeyIpPolicyResponseSchema
>;
export type SetGlobalIpPolicyRequest = z.infer<
  typeof SetGlobalIpPolicyRequestSchema
>;
export type SetGlobalIpPolicyResponse = z.infer<
  typeof SetGlobalIpPolicyResponseSchema
>;
export type GetGlobalIpPolicyResponse = z.infer<
  typeof GetGlobalIpPolicyResponseSchema
>;
