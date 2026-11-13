import { z } from "zod";

/**
 * Named access groups (migration 0033): which people may reach which
 * endpoints.
 *
 * SCOPE, stated here because it is the first thing a reader of this contract
 * needs: these grants govern OAuth sign-ins and API keys. A key is judged by
 * its OWNER, whether it is scoped to one endpoint or gateway-wide, and a key
 * with no owner is refused on a restricted endpoint — see
 * `lib/endpoint-access-control` and the README's Access groups section.
 */

/**
 * Group names are FREE TEXT, unlike namespace and endpoint names.
 *
 * Those two carry a `^[a-zA-Z0-9_-]+$` constraint because they appear in URLs
 * (`/metamcp/<endpoint>/sse`). A group name never leaves the admin UI and the
 * audit `detail`, so the same constraint would buy nothing and would cost the
 * one thing that makes a group list readable at a glance — "Helpdesk Tier 1"
 * rather than "helpdesk-tier-1".
 *
 * Bounded at 100 characters because the name is copied into `audit_log.detail`
 * on every group mutation, and that table has no prune path.
 */
export const ACCESS_GROUP_NAME_MAX = 100;
export const ACCESS_GROUP_DESCRIPTION_MAX = 500;

const accessGroupName = z
  .string()
  .trim()
  .min(1, "validation:accessGroupName.required")
  .max(ACCESS_GROUP_NAME_MAX, "validation:accessGroupName.tooLong");

const accessGroupDescription = z
  .string()
  .trim()
  .max(
    ACCESS_GROUP_DESCRIPTION_MAX,
    "validation:accessGroupDescription.tooLong",
  )
  .optional();

export const AccessGroupSchema = z.object({
  uuid: z.string(),
  name: z.string(),
  description: z.string().nullable(),
  created_at: z.string(),
  // Counts rather than the full member/endpoint arrays: the list screen shows
  // "4 members, 2 endpoints" and a group with 500 members would otherwise ship
  // 500 rows per group on every page load.
  member_count: z.number(),
  endpoint_count: z.number(),
});

export const AccessGroupMemberSchema = z.object({
  user_id: z.string(),
  name: z.string(),
  email: z.string(),
  role: z.string(),
});

export const AccessGroupEndpointSchema = z.object({
  endpoint_uuid: z.string(),
  name: z.string(),
  // Whether the mapped endpoint actually enforces this group today. A mapping
  // on an unrestricted endpoint is legal and inert, and the UI has to be able
  // to say so — otherwise an operator reads a grant list as protection that is
  // not switched on.
  restricted: z.boolean(),
  // `restricted` alone is not enough to answer that question. The gate applies
  // to OAuth sign-ins and to API keys by their owner, so it is inert only on an
  // endpoint with both `enable_oauth` and `enable_api_key_auth` off. The badge
  // needs both to be honest.
  enable_oauth: z.boolean(),
  enable_api_key_auth: z.boolean(),
  // Whether gateway-wide keys are refused on this endpoint. Independent of
  // `restricted`: restricting an endpoint does not turn it on, and a restricted
  // endpoint with it off still admits a key whose owner may reach the
  // endpoint. Carried so the panel can report both switches without a guess.
  require_scoped_api_key: z.boolean(),
});

export const AccessGroupDetailSchema = AccessGroupSchema.extend({
  members: z.array(AccessGroupMemberSchema),
  endpoints: z.array(AccessGroupEndpointSchema),
});

export const CreateAccessGroupRequestSchema = z.object({
  name: accessGroupName,
  description: accessGroupDescription,
});

export const UpdateAccessGroupRequestSchema = z.object({
  uuid: z.string().uuid(),
  name: accessGroupName,
  description: accessGroupDescription,
});

export const DeleteAccessGroupRequestSchema = z.object({
  uuid: z.string().uuid(),
});

export const GetAccessGroupRequestSchema = z.object({
  uuid: z.string().uuid(),
});

export const AccessGroupMemberRequestSchema = z.object({
  group_uuid: z.string().uuid(),
  // `users.id` is better-auth's text id, not a uuid — do not tighten this to
  // `.uuid()`; it would refuse every real account.
  user_id: z.string().min(1),
});

export const AccessGroupEndpointRequestSchema = z.object({
  group_uuid: z.string().uuid(),
  endpoint_uuid: z.string().uuid(),
});

export const SetEndpointRestrictedRequestSchema = z.object({
  endpoint_uuid: z.string().uuid(),
  restricted: z.boolean(),
});

export const GetEndpointAccessRequestSchema = z.object({
  endpoint_uuid: z.string().uuid(),
});

/**
 * The endpoint-detail Access panel: the toggle's state plus who it admits.
 *
 * `enable_oauth` and `enable_api_key_auth` ride along because the gate's REAL
 * effect depends on them and the switch alone cannot express it. The gate
 * applies to OAuth sign-ins and to API keys by their owner, so it is inert
 * only on an endpoint that accepts neither, whatever `restricted` says. Without
 * these two fields the UI can only say "restricted", which an operator
 * reasonably reads as "locked down" even when no caller can arrive through the
 * gate.
 */
export const EndpointAccessSchema = z.object({
  endpoint_uuid: z.string(),
  restricted: z.boolean(),
  enable_oauth: z.boolean(),
  enable_api_key_auth: z.boolean(),
  // Carried so the panel can say whether gateway-wide keys are refused here
  // outright, on top of the owner rule. Independent of `restricted`.
  require_scoped_api_key: z.boolean(),
  groups: z.array(
    z.object({
      uuid: z.string(),
      name: z.string(),
      member_count: z.number(),
    }),
  ),
});

/**
 * One response envelope for every mutation on this surface.
 *
 * `success: false` with a message rather than a thrown TRPCError for the
 * expected misses (unknown group, duplicate name), matching the endpoints and
 * namespaces routers — the dialog renders the message inline. Genuine faults
 * still throw.
 */
export const AccessGroupMutationResponseSchema = z.object({
  success: z.boolean(),
  message: z.string().optional(),
});

export const CreateAccessGroupResponseSchema = z.object({
  success: z.boolean(),
  data: AccessGroupSchema.optional(),
  message: z.string().optional(),
});

export const ListAccessGroupsResponseSchema = z.object({
  success: z.boolean(),
  data: z.array(AccessGroupSchema),
  message: z.string().optional(),
});

export const GetAccessGroupResponseSchema = z.object({
  success: z.boolean(),
  data: AccessGroupDetailSchema.optional(),
  message: z.string().optional(),
});

export const GetEndpointAccessResponseSchema = z.object({
  success: z.boolean(),
  data: EndpointAccessSchema.optional(),
  message: z.string().optional(),
});

/**
 * Every endpoint on the gateway, reduced to what the mapping picker needs.
 *
 * Three columns rather than the endpoint row, because the endpoint row also
 * carries the namespace binding, the rate-limit configuration and the whole
 * auth posture, and a picker needs none of it. Narrower query, narrower
 * disclosure — and this one is admin-only for exactly that reason.
 */
export const ListEndpointOptionsResponseSchema = z.object({
  success: z.boolean(),
  data: z.array(
    z.object({
      uuid: z.string(),
      name: z.string(),
      restricted: z.boolean(),
    }),
  ),
  message: z.string().optional(),
});

export type AccessGroup = z.infer<typeof AccessGroupSchema>;
export type AccessGroupMember = z.infer<typeof AccessGroupMemberSchema>;
export type AccessGroupEndpoint = z.infer<typeof AccessGroupEndpointSchema>;
export type AccessGroupDetail = z.infer<typeof AccessGroupDetailSchema>;
export type EndpointAccess = z.infer<typeof EndpointAccessSchema>;
export type CreateAccessGroupRequest = z.infer<
  typeof CreateAccessGroupRequestSchema
>;
export type UpdateAccessGroupRequest = z.infer<
  typeof UpdateAccessGroupRequestSchema
>;
export type DeleteAccessGroupRequest = z.infer<
  typeof DeleteAccessGroupRequestSchema
>;
export type AccessGroupMemberRequest = z.infer<
  typeof AccessGroupMemberRequestSchema
>;
export type AccessGroupEndpointRequest = z.infer<
  typeof AccessGroupEndpointRequestSchema
>;
export type SetEndpointRestrictedRequest = z.infer<
  typeof SetEndpointRestrictedRequestSchema
>;
export type AccessGroupMutationResponse = z.infer<
  typeof AccessGroupMutationResponseSchema
>;
