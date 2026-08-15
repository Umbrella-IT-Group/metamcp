import { auditContextFromHook, emit } from "./audit-emitter";

/**
 * The four control-plane events better-auth's `databaseHooks` can see, mapped
 * onto `audit_log` rows.
 *
 * WHY HOOKS AND NOT ONLY THE RELAY WRAP. `lib/audit/auth-relay-audit.ts`
 * reads HTTP status codes off the `/api/auth` relay, which is enough for
 * email sign-in and sign-out and nothing else. These four sit one layer down,
 * at the database writes themselves, so they fire for every path that reaches
 * them — email, the OIDC callback, account linking — without this fork having
 * to enumerate better-auth's endpoints and re-enumerate them on every upgrade.
 *
 * WHY THEY LIVE HERE AND NOT INLINE IN `auth.ts`. Importing `auth.ts` boots
 * better-auth, its drizzle adapter and a pg pool, none of which exist in a
 * unit test — so an emitter defined inside that module could only ever be
 * tested by testing the whole auth stack. Extracted, the mapping is directly
 * testable, which matters because these rows are the record of who got an
 * account and who got a session. Same reasoning as `trpc-denial-sink.ts`.
 *
 * NEVER THROWS. better-auth AWAITS its `after` hooks inside `withHooks`, so a
 * throw here does not lose a row — it propagates into the sign-up, sign-in or
 * sign-out request that was being recorded. Every read is guarded and every
 * failure is swallowed; `emit` itself is fire-and-forget and is never awaited.
 *
 * SECRETS. A session row carries `token`, the bearer credential in the user's
 * cookie. Only `id` and `userId` are ever read off it. A user row carries no
 * secret (the password hash lives on `account`), but only `id` and `email`
 * are read regardless.
 */

/** Read a string field off a better-auth row without throwing. */
function hookField(row: unknown, key: string): string | null {
  try {
    const value = (row as Record<string, unknown> | null | undefined)?.[key];
    return typeof value === "string" && value !== "" ? value : null;
  } catch {
    return null;
  }
}

function emitHookEvent(
  context: unknown,
  event: {
    action: string;
    actor_id: string | null;
    actor_label: string | null;
    target_type: string;
    target_id: string | null;
    outcome: "success" | "denied";
    detail?: Record<string, unknown>;
  },
): void {
  try {
    // `context` is better-auth's GenericEndpointContext. The two audit
    // headers `index.ts` stamps on the relayed Request are the only reason it
    // can name a request id or a caller IP at all — see AUDIT_*_HEADER.
    const audit = auditContextFromHook(context);
    emit({
      actor_type: "user",
      actor_id: event.actor_id,
      actor_label: event.actor_label,
      actor_ip: audit.actor_ip,
      actor_user_agent: audit.actor_user_agent,
      action: event.action,
      target_type: event.target_type,
      target_id: event.target_id,
      outcome: event.outcome,
      request_id: audit.request_id,
      detail: event.detail ?? {},
    });
  } catch {
    // Swallowed by design — see the file header.
  }
}

/**
 * A registration this gateway refused because signup is disabled.
 *
 * When self-registration was open on 2026-08-13 the accounts that walked
 * through it left no trace beyond their own `users` rows; when it is CLOSED,
 * the attempts that bounce off it leave nothing at all — and a burst of them
 * is the clearest signal that someone is still trying the door.
 *
 * `actor_id` is null on purpose: no user row was created, so there is no id.
 * The attempted email is the identifier that matters — it separates one
 * determined party retrying from a spray across many addresses.
 */
export function emitSignupDenied(
  user: unknown,
  context: unknown,
  method: "basic" | "sso",
): void {
  emitHookEvent(context, {
    action: "auth.signup.denied",
    actor_id: null,
    actor_label: hookField(user, "email"),
    target_type: "user",
    target_id: null,
    outcome: "denied",
    detail: { method },
  });
}

/**
 * A new account now exists.
 *
 * Only reachable from `user.create.after`, i.e. only for registrations the
 * `before` hook allowed. Answers "when did this account appear, and from
 * where", which the 2026-08-13 review had to reconstruct from
 * `users.created_at` plus inference.
 */
export function emitSignupCreated(user: unknown, context: unknown): void {
  emitHookEvent(context, {
    action: "auth.signup",
    actor_id: hookField(user, "id"),
    actor_label: hookField(user, "email"),
    target_type: "user",
    target_id: hookField(user, "id"),
    outcome: "success",
  });
}

/**
 * A credential that grants access to this gateway came into existence.
 *
 * The direct replacement for the forensic record lost at containment on
 * 2026-08-13, when the attacker's sessions were DELETEd and took their
 * `ip_address` and `user_agent` with them.
 */
export function emitSessionCreated(session: unknown, context: unknown): void {
  emitHookEvent(context, {
    action: "session.create",
    actor_id: hookField(session, "userId"),
    actor_label: null,
    target_type: "session",
    // The session ID, never the session TOKEN.
    target_id: hookField(session, "id"),
    outcome: "success",
  });
}

/**
 * A session row was deleted — sign-out, expiry cleanup, or a bulk revoke.
 *
 * COVERAGE: this only sees deletions that go THROUGH better-auth. The admin
 * `users.revokeAccess` and `users.delete` paths tear down session rows with
 * drizzle directly and never reach this hook — they emit their own
 * `user.access.revoked` / `user.delete` rows from `users.impl.ts` instead, so
 * an administrator severing or destroying an account is recorded there rather
 * than here. A future teardown path that bypasses BOTH would be silent, which
 * is the thing to check when one is added.
 */
export function emitSessionRevoked(session: unknown, context: unknown): void {
  emitHookEvent(context, {
    action: "session.revoke",
    actor_id: hookField(session, "userId"),
    actor_label: null,
    target_type: "session",
    target_id: hookField(session, "id"),
    outcome: "success",
    // One verb covers sign-out, expiry sweeping and a deliberate bulk
    // revocation, and during an investigation "which sessions were killed on
    // purpose" is the question actually being asked. `already_expired`
    // separates them: a session whose `expiresAt` had already passed was
    // swept, one still in date was ended by somebody. Carried in `detail`
    // rather than split into two verbs because better-auth gives the hook no
    // reason code — this is an inference from the row, and labelling it as
    // one keeps it from being read as an assertion.
    detail: { already_expired: sessionAlreadyExpired(session) },
  });
}

/** Whether a deleted session had already lapsed — see `emitSessionRevoked`. */
function sessionAlreadyExpired(session: unknown): boolean | null {
  try {
    const raw = (session as Record<string, unknown> | null | undefined)?.[
      "expiresAt"
    ];
    if (raw === null || raw === undefined) return null;
    const expiry = new Date(raw as string | number | Date).getTime();
    return Number.isFinite(expiry) ? expiry <= Date.now() : null;
  } catch {
    return null;
  }
}
