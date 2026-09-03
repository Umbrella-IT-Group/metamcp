/**
 * The credential-shaped values `example.env` ships as obvious non-working
 * placeholders, and the rule for when a placeholder that survived to a running
 * gateway is a warning versus a hard boot refusal.
 *
 * WHY A SEPARATE MODULE. Two modules need the same answer and must not drift:
 * `auth.ts` refuses to boot on a placeholder signing key, and
 * `bootstrap.service.ts` warns (dev) or refuses (production) on a placeholder
 * bootstrap password. `auth.ts` cannot import `bootstrap.service.ts` because
 * `bootstrap.service.ts` already imports `auth.ts`, so a shared constant has to
 * live below both of them. This is that leaf: it imports nothing from the app,
 * so either side can depend on it without a cycle, and the published strings
 * are stated once rather than copied into each guard where one rotation would
 * silently disarm the other.
 */

/**
 * Passwords `example.env` has, at some point, shipped for the BOOTSTRAP
 * ADMINISTRATOR account.
 *
 * `changeme` was the shipped default for the whole life of the file, so it is
 * the first password anyone who has read this repository would try against a
 * MetaMCP deployment, and a deployment that copied `example.env` and edited
 * only the lines it noticed would still be running it. The replacement
 * placeholder is listed for exactly the same reason: it is public, so it is
 * guessable, and the point of a placeholder is that it must never survive to a
 * running install.
 */
export const SHIPPED_PLACEHOLDER_PASSWORDS: ReadonlySet<string> = new Set([
  "changeme",
  "REPLACE_ME__generate_a_strong_password",
]);

/**
 * The signing key `example.env` ships. Deliberately its own constant rather
 * than a member of the set above: this value signs session cookies and OAuth
 * consent requests, so `example.env` gives it a distinct placeholder to stop
 * one find-and-replace setting the database password and the session signing
 * key to the same string. Someone who knows it does not need to guess a
 * password at all, so a placeholder here is a total authentication bypass, not
 * a weak-password problem.
 */
export const SHIPPED_PLACEHOLDER_AUTH_SECRET =
  "REPLACE_ME__generate_a_signing_key";

/**
 * The floor a bootstrap administrator password must clear. Raised from 8 to 14
 * as an interim credential-hardening step: while a caller can still reach the
 * gateway with the bootstrap administrator's password, the bootstrap floor is
 * where a real length can be required. Production REFUSES below it (not merely
 * warns) via `shouldRefuseBootstrapPasswordInProduction`; outside production it
 * stays warn-only so a throwaway local stack still boots.
 */
export const MIN_BOOTSTRAP_PASSWORD_LENGTH = 14;

/**
 * Whether a bootstrap password is one this repository publishes or is too
 * short to be a real secret. An undefined password is NOT this function's
 * concern: a missing password is a distinct configuration case that
 * `validateConfig` warns on separately and that Better Auth rejects on its
 * own, so it is left out rather than folded into the sub-length test (where an
 * empty string would otherwise read as "too short").
 */
export function isPlaceholderOrShortBootstrapPassword(
  password: string | undefined,
): boolean {
  if (password === undefined) return false;
  return (
    SHIPPED_PLACEHOLDER_PASSWORDS.has(password) ||
    password.length < MIN_BOOTSTRAP_PASSWORD_LENGTH
  );
}

/**
 * The environment where a placeholder must be fatal rather than a warning.
 *
 * Only the exact string `production` counts, matching how the rest of the
 * backend reads `NODE_ENV` (see `middleware/error-handler.middleware` and
 * `routers/oauth/utils`). Outside production a placeholder stays warn-only so a
 * throwaway local stack still boots.
 */
function isProduction(nodeEnv: string | undefined): boolean {
  return nodeEnv === "production";
}

/**
 * Refuse to boot on the shipped placeholder signing key in production.
 *
 * A running gateway signing sessions with the published key lets anyone who
 * read the repository mint a valid cookie for any account, so this is a
 * refusal, not a warning. Kept as a predicate the caller throws on so the
 * decision is testable in every mode without booting the auth graph.
 */
export function shouldRefuseAuthSecretInProduction(
  secret: string | undefined,
  nodeEnv: string | undefined,
): boolean {
  return isProduction(nodeEnv) && secret === SHIPPED_PLACEHOLDER_AUTH_SECRET;
}

/**
 * Refuse to create a bootstrap administrator with a placeholder or sub-length
 * password in production. Same predicate-not-throw shape and same reason as the
 * signing-key guard above.
 */
export function shouldRefuseBootstrapPasswordInProduction(
  password: string | undefined,
  nodeEnv: string | undefined,
): boolean {
  return (
    isProduction(nodeEnv) && isPlaceholderOrShortBootstrapPassword(password)
  );
}
