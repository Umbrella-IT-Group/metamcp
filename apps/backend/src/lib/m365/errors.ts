/**
 * Typed error surface for the M365 delegated-token broker.
 *
 * Every failure the broker can hit on the per-call path maps to one of
 * these codes so the proxy layer can translate it into an actionable
 * tool result (and, when the consumer supports SEP-1036, a URL-mode
 * elicitation carrying the enrollment link) instead of an opaque 500.
 *
 * Design doc: internal M365 delegated-MCP design, §4.3 (enrollment +
 * re-auth, lazy + elicitation-driven) and §5.5.
 */

export type M365BrokerErrorCode =
  /** No stored grant for this user — enrollment has never happened. */
  | "credential_missing"
  /** Refresh grant rejected (expired / password-reset-with-revocation). */
  | "credential_expired"
  /** Grant explicitly revoked (admin disable, revokeSignInSessions). */
  | "credential_revoked"
  /** Conditional Access / MFA claims challenge — user must re-auth interactively. */
  | "mfa_required"
  /** Broker env (tenant/client/KEK) not configured on this deployment. */
  | "not_configured"
  /** Mint failed for an operational reason (network, 5xx, persist failure). */
  | "mint_failed";

/** Codes that a fresh interactive enrollment round-trip resolves. */
const REAUTH_RESOLVABLE: ReadonlySet<M365BrokerErrorCode> = new Set([
  "credential_missing",
  "credential_expired",
  "credential_revoked",
  "mfa_required",
]);

export class M365BrokerError extends Error {
  readonly code: M365BrokerErrorCode;
  /** Absolute enrollment URL when a re-auth round-trip resolves this error. */
  readonly enrollUrl?: string;

  constructor(code: M365BrokerErrorCode, message: string, enrollUrl?: string) {
    super(message);
    this.name = "M365BrokerError";
    this.code = code;
    this.enrollUrl = REAUTH_RESOLVABLE.has(code) ? enrollUrl : undefined;
  }
}

export function isM365BrokerError(error: unknown): error is M365BrokerError {
  // instanceof plus name-check so errors that crossed a bundling/module
  // boundary (vitest + tsup can dual-instantiate a module) still match.
  return (
    error instanceof M365BrokerError ||
    (error instanceof Error && error.name === "M365BrokerError")
  );
}

/**
 * A broker error that is the connecting user's own enrollment state
 * (no grant, expired, revoked, MFA challenge), as opposed to an
 * operator-actionable fault (`not_configured`, `mint_failed`). A fresh
 * enrollment round-trip by that user resolves it; nothing is wrong with
 * the backend or the gateway, so it must never be read as a backend fault.
 *
 * A plain boolean, not a type predicate: a predicate's false branch would
 * tell the compiler that `not_configured` is not an `M365BrokerError`.
 */
export function isPerUserBrokerError(error: unknown): boolean {
  return isM365BrokerError(error) && REAUTH_RESOLVABLE.has(error.code);
}
