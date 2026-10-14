/**
 * Which ownership choices the namespace create and edit forms may offer.
 *
 * The backend stores a namespace created without an owner as PUBLIC: the
 * create path maps a missing `user_id` to null. The create form nevertheless
 * offered "For myself", which sent no owner, so choosing it silently produced
 * a public namespace. This gateway does not keep namespaces private to one
 * user (operator ruling 2026-10-07: administrators must see and manage every
 * namespace), so the forms now offer only what the backend actually does:
 *
 *  - a NEW namespace is public; there is nothing to choose;
 *  - an existing PUBLIC namespace stays public. "For myself" there sent
 *    `undefined`, which the update path reads as "keep the current owner",
 *    so it never did anything;
 *  - an existing OWNED namespace (one created through the API, or before this
 *    change) keeps both choices. Only its owner can open the edit dialog for
 *    it, so "For myself" truthfully means "leave it as it is", and "Everyone"
 *    publishes it.
 *
 * Decide from the namespace's STORED owner, never from the form value: after
 * an owner picks "Everyone" the form holds null, and deciding from that would
 * collapse the control before they can change their mind.
 */
export type NamespaceOwnershipChoice = "forMyself" | "everyone";

export function namespaceOwnershipChoices(
  storedOwner: string | null | undefined,
): NamespaceOwnershipChoice[] {
  return typeof storedOwner === "string" && storedOwner !== ""
    ? ["forMyself", "everyone"]
    : ["everyone"];
}
