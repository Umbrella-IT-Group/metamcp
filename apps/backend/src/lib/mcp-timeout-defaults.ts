/**
 * The cap on a backend call that keeps reporting progress (10 minutes). The
 * SDK checks it only when a progress notification resets the per-request
 * timer, not as an independent deadline: a call that reports progress can run
 * until this cap plus at most one per-request timeout, and a call that never
 * reports progress times out at the per-request timeout alone. It used to
 * equal the per-request default (60 s), which made progress reporting
 * pointless. An explicitly stored MCP_MAX_TOTAL_TIMEOUT row still wins.
 *
 * Lives in this leaf module, free of the database, so the call chain's
 * middleware can arm a deadline from it without importing the config service
 * (which `config.service.ts` re-exports it from, so existing importers and the
 * tests that mock that service are unaffected).
 */
export const DEFAULT_MCP_MAX_TOTAL_TIMEOUT_MS = 600_000;
