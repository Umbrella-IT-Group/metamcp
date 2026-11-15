/**
 * The endpoint namespace gate: one rule for every writer that can add a route
 * to a namespace or open an endpoint, judged in one transaction under the
 * namespace's lock (db/repositories/endpoint-gate.repo).
 *
 * THE RULE. Access groups are enforced per endpoint (lib/endpoint-access-
 * control): a restricted endpoint admits administrators and members of a
 * mapped group, an unrestricted one admits every caller its auth mode accepts.
 * So a namespace that one restricted endpoint guards is open to everyone as
 * soon as a second, unrestricted endpoint serves it. The gate refuses every
 * write that would ADD such an unrestricted route while another endpoint over
 * the namespace stays restricted:
 *
 *  - create: a new unrestricted endpoint (public or private, an owner's
 *    private endpoint is also a route) over a namespace with a restricted
 *    endpoint;
 *  - move: any endpoint, restricted or not, onto such a namespace. A
 *    restricted endpoint's access-group mappings travel with it by endpoint
 *    id, so moving it would grant the namespace to the groups mapped to it;
 *  - un-restrict: opening an endpoint while another endpoint over its
 *    namespace stays restricted.
 *
 * It applies to every writer: a human administrator's session, an admin-plane
 * key and the bootstrap. It is one-sided on purpose: restricting is always
 * allowed (refusing it would deadlock two open endpoints over one namespace),
 * and an unrestricted endpoint that already existed is not repaired by it.
 * Mappings are never copied: a new restricted endpoint starts with none and
 * admits administrators only until a group is mapped to it.
 *
 * TWO RULES FOR ADMIN-PLANE KEYS ONLY, kept beside it:
 *  - publish: an admin-plane key may not create or move a public unrestricted
 *    endpoint over a namespace that a restricted OR private endpoint serves
 *    (a key it could then create for that endpoint would reach what the gated
 *    one keeps from its owner);
 *  - un-restrict provenance: an admin-plane key may open an endpoint only to
 *    roll back a restriction it made itself in the last 24 hours, while that is
 *    still the endpoint's current restriction (endpoints.restricted_by_api_key_
 *    uuid, migration 0047). Every other un-restrict is a human's decision.
 *
 * Every refusal is a fixed sentence naming no endpoint or namespace, answered
 * as a coded error (CONFLICT, or FORBIDDEN for the provenance rule), never as
 * `success: false`. Pure: no database, no logger.
 */

export type EndpointGateRule =
  | "namespace_restricted_create_open"
  | "namespace_restricted_move"
  | "namespace_restricted_unrestrict"
  | "admin_plane_publish"
  | "admin_plane_unrestrict"
  | "endpoint_changed";

export const ENDPOINT_GATE_REFUSALS: Readonly<
  Record<EndpointGateRule, { code: "CONFLICT" | "FORBIDDEN"; message: string }>
> = {
  namespace_restricted_create_open: {
    code: "CONFLICT",
    message:
      "Another endpoint over this namespace is restricted, so a new endpoint over it must be restricted too. Create it with restricted on, then map its access groups.",
  },
  namespace_restricted_move: {
    code: "CONFLICT",
    message:
      "Another endpoint over the target namespace is restricted, so no endpoint can be moved onto it: the moved endpoint's access-group mappings would move with it. Create a new restricted endpoint over that namespace and map its groups instead.",
  },
  namespace_restricted_unrestrict: {
    code: "CONFLICT",
    message:
      "Another endpoint over this namespace is restricted, so this endpoint cannot be opened while that one stays restricted. Open or delete the other endpoint first.",
  },
  admin_plane_publish: {
    code: "CONFLICT",
    message:
      "An admin-plane API key cannot make a namespace public that a restricted or private endpoint already serves. Do this in the admin UI.",
  },
  admin_plane_unrestrict: {
    code: "FORBIDDEN",
    message:
      "An admin-plane API key can open an endpoint only to roll back a restriction it made itself in the last 24 hours. Do this in the admin UI.",
  },
  endpoint_changed: {
    code: "CONFLICT",
    message:
      "The endpoint changed while this request was applied. Read it again and retry.",
  },
};

/** What a create is judged on, read under the namespace lock. */
export interface CreateFacts {
  restricted: boolean;
  isPublic: boolean;
  adminPlane: boolean;
  /** Another endpoint over the namespace is restricted. */
  restrictedSibling: boolean;
  /** Another endpoint over the namespace is restricted or private. */
  gatedSibling: boolean;
}

/** What a move is judged on, read under both namespace locks. */
export interface MoveFacts {
  /** The endpoint as locked: its own restriction and owner. */
  restricted: boolean;
  isPublic: boolean;
  adminPlane: boolean;
  /** Another endpoint over the TARGET namespace is restricted. */
  restrictedSibling: boolean;
  /** Another endpoint over the target namespace is restricted or private. */
  gatedSibling: boolean;
}

/** What opening an endpoint is judged on, read under its namespace lock. */
export interface UnrestrictFacts {
  adminPlane: boolean;
  /** Another endpoint over the namespace is restricted. */
  restrictedSibling: boolean;
  /**
   * The endpoint's current restriction was made by the acting admin-plane key
   * less than 24 hours ago (always false for a human, who does not need it).
   */
  rollbackEligible: boolean;
}

export function judgeEndpointCreate(
  facts: CreateFacts,
): EndpointGateRule | null {
  if (!facts.restricted && facts.restrictedSibling) {
    return "namespace_restricted_create_open";
  }
  if (
    facts.adminPlane &&
    facts.isPublic &&
    !facts.restricted &&
    facts.gatedSibling
  ) {
    return "admin_plane_publish";
  }
  return null;
}

export function judgeEndpointMove(facts: MoveFacts): EndpointGateRule | null {
  if (facts.restrictedSibling) return "namespace_restricted_move";
  if (
    facts.adminPlane &&
    facts.isPublic &&
    !facts.restricted &&
    facts.gatedSibling
  ) {
    return "admin_plane_publish";
  }
  return null;
}

export function judgeEndpointUnrestrict(
  facts: UnrestrictFacts,
): EndpointGateRule | null {
  if (facts.restrictedSibling) return "namespace_restricted_unrestrict";
  if (facts.adminPlane && !facts.rollbackEligible) {
    return "admin_plane_unrestrict";
  }
  return null;
}

/** How long an admin-plane key may roll back its own restriction. */
export const UNRESTRICT_ROLLBACK_WINDOW_HOURS = 24;
