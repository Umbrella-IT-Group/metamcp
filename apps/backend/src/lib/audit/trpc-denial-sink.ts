import type { TrpcDenialEvent } from "@repo/trpc";

import { emit } from "./audit-emitter";

/**
 * Maps a tRPC denial from @repo/trpc onto an `audit_log` row.
 *
 * Lives on the backend side of the seam because @repo/trpc is also consumed by
 * the frontend and must stay free of any database import — it owns the choke
 * points, this owns the writing. Registered once via `setTrpcAuditSink` in
 * `routers/trpc.ts`.
 *
 * Extracted as a named function rather than an inline lambda at the
 * registration site so the mapping is directly testable: `path` landing in the
 * wrong column is the difference between "someone was denied" and "someone was
 * denied reaching for `config.setSignupDisabled`", and that is the whole value
 * of the row.
 *
 * Never throws — `emit` swallows everything and is never awaited.
 */
export function trpcDenialSink(event: TrpcDenialEvent): void {
  emit({
    actor_type: event.actor_type,
    actor_id: event.actor_id,
    actor_label: event.actor_label,
    actor_ip: event.audit?.actor_ip ?? null,
    actor_user_agent: event.audit?.actor_user_agent ?? null,
    action: event.action,
    // The procedure the caller reached for. `rbac.denied` on
    // `config.setSignupDisabled` and `rbac.denied` on `logs.get` are very
    // different events, and the path is the only field that separates them.
    target_type: "trpc_procedure",
    target_id: event.path,
    outcome: "denied",
    request_id: event.audit?.request_id ?? null,
    http_status: event.http_status,
    detail: { trpc_type: event.type },
  });
}
