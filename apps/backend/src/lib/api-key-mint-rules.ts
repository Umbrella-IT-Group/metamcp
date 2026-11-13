import { ADMIN_PLANE_FORBIDDEN_MESSAGE } from "@repo/trpc";

import {
  agentCidrTooWide,
  apiKeyIpPolicyDisabled,
  normalizeCidrList,
  parseCidr,
} from "./api-key-ip-policy";

/**
 * The rules for a data-plane API key created by an admin-plane key (an
 * `operator`-scope key calling `apiKeys.create`).
 *
 * This is the whole rule, written once so the implementation, the repository
 * transaction and the tests share it:
 *
 *  1. The key is a data-plane key. No `admin_plane`, no `admin_plane_scope`:
 *     an admin-plane key of either scope is a human click in the admin UI.
 *  2. No acts-as identity (`acts_as_user_id`), null and empty included.
 *  3. `user_id` names an existing user whose account is not disabled. Never
 *     null (the public, everyone key) and never omitted (which would default
 *     to the calling key's owner).
 *  4. Exactly one of `endpoint_uuid` (an existing PUBLIC endpoint) or
 *     `all_endpoints: true`, and what each may reach follows the owner, not the
 *     request:
 *       - An endpoint-scoped key may name a restricted endpoint only when the
 *         owner is an explicit member of a group mapped to it. An
 *         administrator's role alone does not count at mint time, though it
 *         does at request time: otherwise an operator key could mint an
 *         admin-owned key for any restricted endpoint.
 *       - A gateway-wide key is refused for an administrator-role owner,
 *         because it would inherit the administrator's bypass on every
 *         restricted endpoint. For any other owner it is allowed, since the
 *         access-group rule decides each request by the owner's membership
 *         (lib/endpoint-access-control), whichever endpoint the key is aimed
 *         at.
 *     Together with rule 3 this keeps a key from reaching more than its owner
 *     can reach through OAuth. A human administrator's mint in the admin UI is
 *     not held to this rule.
 *  5. An IP policy in the same request: `enforce`, one to eight entries, each
 *     IPv4 /24 or narrower and IPv6 /48 or narrower, IPv4-mapped IPv6 counted
 *     at its IPv4 width; refused while the global IP-policy kill switch is on.
 *  6. A name of the usual shape that no key of the same owner already uses,
 *     inactive keys included.
 *
 * Every refusal is one fixed sentence with no echo of the request beyond a
 * field name, so a refusal tells a probing caller nothing about other users,
 * endpoints or keys.
 *
 * Pure: no database and no logger. The checks that need the database (the
 * owner, the endpoint, the name) run in the repository's transaction against
 * the locked rows and throw the same typed refusals.
 */

export type MintRule =
  | "request_invalid"
  | "caller_not_operator"
  | "admin_plane_field"
  | "acts_as_field"
  | "owner_required"
  | "scope_choice"
  | "endpoint_missing"
  | "endpoint_not_eligible"
  | "gateway_wide_admin_owner"
  | "ip_policy_shape"
  | "ip_policy_entries"
  | "ip_policy_too_wide"
  | "ip_policy_disabled"
  | "ip_policy_change_shape"
  | "ip_policy_change_too_wide"
  | "name_invalid"
  | "name_taken";

export const MINT_REFUSALS: Readonly<
  Record<MintRule, { code: "FORBIDDEN" | "BAD_REQUEST"; message: string }>
> = {
  // The request failed the input schema for a reason none of the rules below
  // names (a malformed body, a type the schema refuses that the rules do not
  // look at). One sentence, no echo of the request.
  request_invalid: {
    code: "BAD_REQUEST",
    message: "The request is not a valid API key request.",
  },
  // A legacy gateway, a sync-scope key and a missing or unknown scope all get
  // the sentence every other admin-plane refusal carries.
  caller_not_operator: {
    code: "FORBIDDEN",
    message: ADMIN_PLANE_FORBIDDEN_MESSAGE,
  },
  admin_plane_field: {
    code: "FORBIDDEN",
    message:
      "An admin-plane API key cannot create admin-plane API keys (admin_plane, admin_plane_scope).",
  },
  acts_as_field: {
    code: "FORBIDDEN",
    message:
      "An admin-plane API key cannot create an API key that acts as a user (acts_as_user_id).",
  },
  owner_required: {
    code: "BAD_REQUEST",
    message: "user_id must name an existing, enabled user.",
  },
  scope_choice: {
    code: "BAD_REQUEST",
    message:
      "Pass exactly one of endpoint_uuid or all_endpoints: true (endpoint_uuid must be a uuid).",
  },
  endpoint_missing: {
    code: "BAD_REQUEST",
    message: "endpoint_uuid must name an existing endpoint.",
  },
  endpoint_not_eligible: {
    code: "FORBIDDEN",
    message:
      "endpoint_uuid must name a public endpoint, and a restricted one only when the key's owner is a member of a group mapped to it. A key for any other endpoint is created in the admin UI.",
  },
  gateway_wide_admin_owner: {
    code: "FORBIDDEN",
    message:
      "A gateway-wide key cannot be created for an administrator, because it would reach every restricted endpoint. Scope the key to one endpoint, or create it in the admin UI.",
  },
  ip_policy_shape: {
    code: "BAD_REQUEST",
    message:
      'ip_policy must be { mode: "enforce", allowed_cidrs: [...] } with 1 to 8 entries.',
  },
  ip_policy_entries: {
    code: "BAD_REQUEST",
    message:
      "ip_policy.allowed_cidrs holds an entry that is not a valid CIDR with its host bits clear.",
  },
  ip_policy_too_wide: {
    code: "BAD_REQUEST",
    message:
      "ip_policy.allowed_cidrs holds an entry wider than IPv4 /24 or IPv6 /48 (IPv4-mapped IPv6 is counted at its IPv4 width).",
  },
  ip_policy_disabled: {
    code: "FORBIDDEN",
    message:
      "API key IP policies are switched off on this gateway, so a key cannot be created locked to a network list.",
  },
  // The two rules below apply when an admin-plane key CHANGES the policy of a
  // data-plane key, so a key created locked cannot be unlocked or widened by a
  // second call. A human administrator's change is not held to them.
  ip_policy_change_shape: {
    code: "BAD_REQUEST",
    message:
      "An admin-plane API key can set a data-plane key's IP policy only to mode enforce with 1 to 8 entries in allowed_cidrs. Turning a policy off, to audit, to the global policy or to an empty list is done in the admin UI.",
  },
  ip_policy_change_too_wide: {
    code: "BAD_REQUEST",
    message:
      "allowed_cidrs holds an entry wider than IPv4 /24 or IPv6 /48 (IPv4-mapped IPv6 is counted at its IPv4 width). A data-plane key's list is widened in the admin UI.",
  },
  name_invalid: {
    code: "BAD_REQUEST",
    message:
      "name must be 1 to 100 characters: letters, numbers, spaces, underscores and hyphens.",
  },
  name_taken: {
    code: "BAD_REQUEST",
    message:
      "name is already used by a key of this owner (inactive keys count). Use a new name.",
  },
};

/** A refusal of one rule, carrying its fixed code and sentence. */
export class ApiKeyMintRefusal extends Error {
  readonly rule: MintRule;
  readonly code: "FORBIDDEN" | "BAD_REQUEST";

  constructor(rule: MintRule) {
    super(MINT_REFUSALS[rule].message);
    this.name = "ApiKeyMintRefusal";
    this.rule = rule;
    this.code = MINT_REFUSALS[rule].code;
  }
}

/** Largest number of entries a created key's policy may carry. */
export const MINT_MAX_CIDRS = 8;

const NAME_PATTERN = /^[a-zA-Z0-9_\s-]+$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** What survives validation: everything the repository transaction needs. */
export interface ValidatedMintRequest {
  name: string;
  ownerUserId: string;
  /** The one endpoint the key is scoped to; null for a gateway-wide key. */
  endpointUuid: string | null;
  allEndpoints: boolean;
  /** Canonical, deduplicated, in the order submitted. */
  allowedCidrs: string[];
}

/**
 * Validate the request fields of an agent-created key, without touching the
 * database. Accepts `unknown` fields on purpose: this is the guard for a
 * caller that bypassed the tRPC input schema, so it checks every type itself
 * and treats anything it does not expect as a refusal, never as absent.
 *
 * Throws `ApiKeyMintRefusal`; nothing is written and no key value exists yet.
 */
export function validateAgentMintRequest(
  input: Record<string, unknown>,
): ValidatedMintRequest {
  // Rule 1. `false` is the data-plane value; anything else, a malformed type
  // included, is refused.
  if (input.admin_plane !== undefined && input.admin_plane !== false) {
    throw new ApiKeyMintRefusal("admin_plane_field");
  }
  if (input.admin_plane_scope !== undefined) {
    throw new ApiKeyMintRefusal("admin_plane_field");
  }

  // Rule 2. null and "" are refused as well as a real id.
  if (input.acts_as_user_id !== undefined) {
    throw new ApiKeyMintRefusal("acts_as_field");
  }

  // Rule 3, the part that needs no database. Null (the everyone key) and
  // undefined (which would mean "the caller") are both refused.
  const owner = input.user_id;
  if (typeof owner !== "string" || owner.trim().length === 0) {
    throw new ApiKeyMintRefusal("owner_required");
  }

  // Rule 4, the shape. `all_endpoints: false` is not a choice.
  const endpoint = input.endpoint_uuid;
  const allEndpoints = input.all_endpoints;
  if (endpoint !== undefined && typeof endpoint !== "string") {
    throw new ApiKeyMintRefusal("scope_choice");
  }
  if (allEndpoints !== undefined && allEndpoints !== true) {
    throw new ApiKeyMintRefusal("scope_choice");
  }
  const hasEndpoint = endpoint !== undefined;
  const hasAll = allEndpoints === true;
  if (hasEndpoint === hasAll) {
    throw new ApiKeyMintRefusal("scope_choice");
  }
  if (hasEndpoint && !UUID_PATTERN.test(endpoint as string)) {
    throw new ApiKeyMintRefusal("scope_choice");
  }

  // Rule 6, the shape.
  const name = input.name;
  if (
    typeof name !== "string" ||
    name.length < 1 ||
    name.length > 100 ||
    !NAME_PATTERN.test(name)
  ) {
    throw new ApiKeyMintRefusal("name_invalid");
  }

  // Rule 5.
  const allowedCidrs = validateAgentIpPolicy(input.ip_policy);

  return {
    name,
    ownerUserId: owner,
    endpointUuid: hasEndpoint ? (endpoint as string) : null,
    allEndpoints: hasAll,
    allowedCidrs,
  };
}

/**
 * Rule 5 on its own: returns the canonical list or throws. The kill switch is
 * checked first, so with it on nothing else about the policy matters and no
 * later step runs.
 */
export function validateAgentIpPolicy(policy: unknown): string[] {
  if (apiKeyIpPolicyDisabled()) {
    throw new ApiKeyMintRefusal("ip_policy_disabled");
  }
  if (typeof policy !== "object" || policy === null || Array.isArray(policy)) {
    throw new ApiKeyMintRefusal("ip_policy_shape");
  }
  const { mode, allowed_cidrs: cidrs } = policy as Record<string, unknown>;
  if (
    mode !== "enforce" ||
    !Array.isArray(cidrs) ||
    cidrs.length < 1 ||
    cidrs.length > MINT_MAX_CIDRS ||
    !cidrs.every((entry) => typeof entry === "string")
  ) {
    throw new ApiKeyMintRefusal("ip_policy_shape");
  }
  const normalized = normalizeCidrList(cidrs as string[]);
  if (!normalized.ok) {
    throw new ApiKeyMintRefusal("ip_policy_entries");
  }
  const verdict = widthVerdict(normalized.cidrs);
  if (verdict === "invalid") throw new ApiKeyMintRefusal("ip_policy_entries");
  if (verdict === "too_wide") throw new ApiKeyMintRefusal("ip_policy_too_wide");
  return normalized.cidrs;
}

/** Is every canonical entry parseable and no wider than an agent may carry? */
function widthVerdict(cidrs: readonly string[]): "ok" | "invalid" | "too_wide" {
  for (const cidr of cidrs) {
    const parsed = parseCidr(cidr);
    if (!parsed.ok) return "invalid";
    if (agentCidrTooWide(parsed.value)) return "too_wide";
  }
  return "ok";
}

/**
 * The policy an admin-plane key may leave on a DATA-plane key it changes (the
 * second half of rule 5: a key is created locked and narrow, and a later call
 * must not undo that). `enforce`, a list of its own with 1 to `MINT_MAX_CIDRS`
 * entries, none wider than an agent may carry. `cidrs` is the canonical list
 * the caller already validated and normalised, or null for "follow the global
 * policy".
 *
 * Unlike `validateAgentIpPolicy` this does not look at the kill switch: a
 * narrower list on an existing key is never made worse by it. Throws
 * `ApiKeyMintRefusal`; nothing has been written.
 */
export function assertAgentSettableIpPolicy(policy: {
  mode: string;
  cidrs: readonly string[] | null;
}): void {
  if (
    policy.mode !== "enforce" ||
    policy.cidrs === null ||
    policy.cidrs.length < 1 ||
    policy.cidrs.length > MINT_MAX_CIDRS
  ) {
    throw new ApiKeyMintRefusal("ip_policy_change_shape");
  }
  const verdict = widthVerdict(policy.cidrs);
  if (verdict === "invalid") {
    throw new ApiKeyMintRefusal("ip_policy_change_shape");
  }
  if (verdict === "too_wide") {
    throw new ApiKeyMintRefusal("ip_policy_change_too_wide");
  }
}

/**
 * Rule 4 for an endpoint-scoped key, against an endpoint row read under lock in
 * the transaction: the endpoint must be PUBLIC (no owner), and when it is
 * restricted the key's owner must be an explicit member of a group mapped to it
 * (`ownerIsMappedMember`, read in the same transaction; the owner's role does
 * not stand in for it). One sentence for every reason, so a refusal does not
 * say which.
 */
export function assertEndpointEligible(
  endpoint: {
    user_id: string | null;
    restricted: boolean;
  },
  ownerIsMappedMember: boolean,
): void {
  if (endpoint.user_id !== null) {
    throw new ApiKeyMintRefusal("endpoint_not_eligible");
  }
  if (endpoint.restricted !== false && !ownerIsMappedMember) {
    throw new ApiKeyMintRefusal("endpoint_not_eligible");
  }
}

/**
 * Rule 4 for a gateway-wide key, against the owner row read under lock in the
 * transaction: an administrator-role owner is refused. The check is on the
 * role exactly as the request-time gate reads it (`"admin"`), so the two cannot
 * drift into a role this refuses and that passes.
 */
export function assertGatewayWideOwnerAllowed(owner: {
  role: string | null;
}): void {
  if (owner.role === "admin") {
    throw new ApiKeyMintRefusal("gateway_wide_admin_owner");
  }
}
