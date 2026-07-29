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

// Base API Key schemas
export const ApiKeySchema = z.object({
  uuid: z.string().uuid(),
  name: z.string(),
  key: z.string(),
  user_id: z.string().nullable(),
  endpoint_uuid: z.string().uuid().nullable(),
  acts_as_user_id: z.string().nullable(),
  created_at: z.date(),
  is_active: z.boolean(),
});

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
  })
  .superRefine((val, ctx) => {
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
  })
  .superRefine((val, ctx) => {
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

export const UpdateApiKeyResponseSchema = z.object({
  uuid: z.string().uuid(),
  name: z.string(),
  key: z.string(),
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

export const ListApiKeysResponseSchema = z.object({
  apiKeys: z.array(
    z.object({
      uuid: z.string().uuid(),
      name: z.string(),
      key: z.string(),
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
  created_at: z.date(),
  last_used_at: z.date().nullable(),
  is_active: z.boolean(),
});

export const ListAllApiKeysResponseSchema = z.object({
  apiKeys: z.array(AdminApiKeyItemSchema),
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
  is_active: z.boolean().optional().default(true),
});

export const ApiKeyUpdateInputSchema = z.object({
  name: z.string().optional(),
  is_active: z.boolean().optional(),
});

// Type exports
export type ApiKey = z.infer<typeof ApiKeySchema>;
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
