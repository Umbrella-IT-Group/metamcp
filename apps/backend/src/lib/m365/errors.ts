/**
 * Typed error surface for the M365 delegated-token broker.
 *
 * Every failure the broker can hit on the per-call path maps to one of
 * these codes so the proxy layer can translate it into an actionable
 * tool result (and, when the consumer supports SEP-1036, a URL-mode
 * elicitation carrying the enrollment link) instead of an opaque 500.
 *
 * Design doc: Umbrella-MCP-Server `docs/M365_DELEGATED_MCP_DESIGN.md`
 * §4.3 (enrollment + re-auth, lazy + elicitation-driven) and §5.5.
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
