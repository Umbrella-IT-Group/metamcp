/**
 * Who a repository write is made for, decided by the tRPC layer from the
 * verified request context and passed down as a required argument (a write
 * that depends on it has no default, so a new call site must state it).
 *
 *  - `person`: a signed-in person, in the admin UI or through a session. The
 *    writes behave as they always have.
 *  - `admin_plane`: a request authenticated by an admin-plane API key of either
 *    scope. A write that could put a tool in front of callers it was withheld
 *    from keeps what a person curated instead of resetting it.
 *
 * Imports nothing, so naming it loads no database module.
 */
export type WriteCaller = "person" | "admin_plane";

/**
 * The caller kind of a write, from the actor bundle `auditActor(ctx)` built
 * from the verified request context: an actor carrying `admin_plane` (set only
 * from an admin-plane key row the backend verified) is `admin_plane`, any
 * other is a person. An actor missing altogether (a direct call that did not
 * come through a router) carries no admin-plane provenance and is a person.
 */
export function writeCallerOf(
  actor: { admin_plane?: unknown } | undefined | null,
): WriteCaller {
  return actor?.admin_plane ? "admin_plane" : "person";
}
