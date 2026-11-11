/**
 * Whether the API Keys page offers the active-state toggle for a key.
 *
 * Deactivating an active key is open to every viewer who can see it (a
 * member's own keys, every key for an administrator). Re-activating an
 * inactive key is an administrator's decision: the backend refuses a member's
 * `is_active: true` with FORBIDDEN, so that an administrator's deactivation
 * cannot be undone by the key's owner. The page hides the re-activate action
 * from anyone else rather than offer a button that can only fail.
 *
 * `isAdmin` must be the RESOLVED role: the page holds it false until the
 * session says otherwise, so a viewer whose role is still loading sees no
 * re-activate action. The backend enforces the rule regardless of the UI.
 */
export function canToggleApiKeyActive({
  isActive,
  isAdmin,
}: {
  isActive: boolean;
  isAdmin: boolean;
}): boolean {
  return isActive || isAdmin;
}
