import type { AuditActor } from "@repo/trpc";

import { type AuditOutcome, emit } from "./audit-emitter";

/**
 * Maps an admin/control-plane mutation onto an `audit_log` row.
 *
 * The success-path twin of `trpc-denial-sink.ts`: that one records the
 * attempts the RBAC gate REFUSED, this one records the ones it let through.
 * Until Phase 1B the second half was entirely missing — the config toggles
 * that decide whether anyone can register an account, the API-key mints, the
 * OAuth-client registrations and the account disable/enable switches all
 * happened without leaving a single durable row. The 2026-08-13 incident was
 * read from `app.log` and inference for exactly that reason.
 *
 * A pure mapping function, deliberately: it exists so ~25 call sites cannot
 * drift on `actor_type`, on which actor field goes in which column, or on
 * remembering that `emit` must not be awaited. It adds no infrastructure —
 * the pool, the sink and the swallow all belong to `audit-emitter.ts`.
 *
 * SAFETY. `emit` swallows every failure of its own, but it is handed a
 * finished object, so anything that throws while BUILDING that object throws
 * at the call site — inside the mutation, after the write, which would turn a
 * completed admin action into a 500. The row is therefore built inside a
 * try/catch here (optional chaining does NOT stop a throwing getter). Call
 * sites still owe the same care for the values they pass IN: a local or a
 * field off the row they just wrote, never an expression that can throw,
 * because that expression is evaluated before this function is entered.
 *
 * SECRETS. `detail` is persisted verbatim. Never put a credential in it — not
 * an API key, not a client secret, not a bearer token, not an MCP server's
 * vendor credentials. Ids, names, counts and old/new toggle values only; use
 * `credentialFingerprint()` from `audit-emitter.ts` when a credential has to
 * be correlatable across rows.
 */
export function emitAdminEvent(
  actor: AuditActor | undefined | null,
  event: {
    /** Verb from the controlled list (e.g. `config.signup_disabled.set`). */
    action: string;
    target_type: string;
    target_id?: string | null;
    /** Defaults to `success` — these fire on the outcome path after a write. */
    outcome?: AuditOutcome;
    detail?: Record<string, unknown>;
  },
): void {
  try {
    emitEvent(actor, event);
  } catch {
    // `emit` swallows its own failures but is handed a FINISHED object, so
    // anything that throws while BUILDING that object throws at the call
    // site — inside a mutation, after its write, where the impl's own catch
    // would turn it into `success: false` or a 500. Optional chaining does
    // not stop a throwing getter, so the reads below are not self-guarding.
    // This is the throw-proof boundary all 26 admin call sites depend on;
    // same guard as `emitHookEvent` in auth-hook-audit.ts.
  }
}

function emitEvent(
  actor: AuditActor | undefined | null,
  event: {
    action: string;
    target_type: string;
    target_id?: string | null;
    outcome?: AuditOutcome;
    detail?: Record<string, unknown>;
  },
): void {
  emit({
    // A MISSING actor bundle means there was no tRPC request behind this call
    // at all, which is a different claim from "a user whose id we could not
    // read" — and it is reachable: `lib/metamcp/metamcp-proxy.ts` calls
    // `toolsImplementations.sync` directly during a proxied MCP `tools/list`,
    // with no session and no request context. Labelling that row `user` with
    // five null columns would put a phantom administrator in the table for
    // something a background refresh did. An actor bundle that EXISTS but
    // holds nulls stays `user`, because a request really was made by someone
    // whose identity could not be read — see `auditActor()`.
    actor_type: actor ? "user" : "system",
    actor_id: actor?.actor_id ?? null,
    actor_label: actor?.actor_label ?? null,
    actor_ip: actor?.actor_ip ?? null,
    actor_user_agent: actor?.actor_user_agent ?? null,
    action: event.action,
    target_type: event.target_type,
    target_id: event.target_id ?? null,
    outcome: event.outcome ?? "success",
    request_id: actor?.request_id ?? null,
    detail: event.detail ?? {},
  });
}
