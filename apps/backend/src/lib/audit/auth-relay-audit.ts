import {
  type AuditRequestContext,
  clampAuditText,
  emit,
} from "./audit-emitter";

/**
 * Turns one `/api/auth` relay round-trip into an `audit_log` row.
 *
 * WHY THIS EXISTS. better-auth is mounted in `index.ts` as a hand-rolled
 * Express → web-`Request` relay, and it emits nothing durable of its own. So
 * until Phase 1B a failed password attempt against this gateway left no
 * record anywhere — no row, no counter, nothing to alert on and nothing to
 * count after the fact. Sign-in failure is the credential-stuffing and
 * account-enumeration signal, and it is the one event in this file with no
 * database-hook equivalent: a refused sign-in creates no session, so
 * `databaseHooks.session.create.after` never fires for it.
 *
 * Extracted from `index.ts` rather than inlined so the mapping is directly
 * testable — importing `index.ts` boots the whole server graph. Same reason
 * `trpc-denial-sink.ts` is its own module.
 *
 * WHY ONLY `sign-in/email`, and not every `sign-in/*`. A 200 from
 * `sign-in/social` or `sign-in/oauth2` means "here is the URL to redirect the
 * browser to", NOT "these credentials were accepted" — treating its status as
 * a login outcome would write a successful-login row for a flow that has not
 * authenticated anybody yet. `sign-in/email` is the only sub-path where the
 * HTTP status genuinely IS the credential verdict. SSO logins are still
 * recorded: they mint a session, so `session.create` in `auth.ts` catches
 * them, which is exactly why that hook is wired as well as this wrap.
 *
 * SECRETS. The response body of a successful sign-in contains the SESSION
 * TOKEN. Only `user.id` and `user.email` are ever read out of it, never the
 * body itself, and the request body — which holds the submitted password — is
 * read only for `email`. An attempted email address is an identifier, not a
 * credential, and it is the entire value of a failure row: "someone tried
 * this account 400 times" is unanswerable without it.
 *
 * SIZE. That attempted address is attacker-controlled body text on a route
 * whose JSON limit is 50mb, so it is clamped to RFC 5321's 320-character
 * maximum address length before it reaches a column in a table with no
 * prune path. The row SIZE is bounded here; the row COUNT is bounded by
 * `middleware/auth-signin-rate-limit.middleware`, and both are needed. It is
 * NOT bounded by better-auth's own limiter — `auth.ts` pins that off, because
 * its address resolution puts every caller in one shared bucket behind this
 * deployment's proxy chain.
 */

/** RFC 5321 §4.5.3.1.3: the longest legal email address. */
const MAX_EMAIL_LENGTH = 320;

const AUTH_PREFIX = "/api/auth";

/**
 * Exported because the sign-in rate limiter needs the same answer to "which
 * path is the one where the HTTP status IS the credential verdict", and that
 * distinction — drawn in WHY ONLY `sign-in/email` above — should be drawn once
 * rather than restated where it can drift.
 */
export const SIGN_IN_EMAIL_PATH = `${AUTH_PREFIX}/sign-in/email`;
const SIGN_OUT_PATH = `${AUTH_PREFIX}/sign-out`;

/** Pull a string property off an unknown object without ever throwing. */
function readString(source: unknown, key: string): string | null {
  try {
    const value = (source as Record<string, unknown> | null | undefined)?.[key];
    return typeof value === "string" && value !== "" ? value : null;
  } catch {
    return null;
  }
}

/** The address a failed sign-in claimed, clamped — see SIZE in the header. */
function attemptedEmail(requestBody: unknown): string | null {
  const email = readString(requestBody, "email");
  return email === null ? null : clampAuditText(email, MAX_EMAIL_LENGTH);
}

/** `{ id, email }` of the signed-in user, out of a sign-in response body. */
function signedInUser(responseBody: string): {
  id: string | null;
  email: string | null;
} {
  try {
    const parsed = JSON.parse(responseBody) as { user?: unknown };
    return {
      id: readString(parsed?.user, "id"),
      email: readString(parsed?.user, "email"),
    };
  } catch {
    // A non-JSON body is not a reason to lose the event — the row still
    // records that a sign-in succeeded, from this IP, at this time.
    return { id: null, email: null };
  }
}

export function emitAuthRelayEvent(params: {
  /** `req.path`, i.e. including the `/api/auth` prefix. */
  path: string;
  status: number;
  /** `req.body` — read for the attempted email only. */
  requestBody: unknown;
  /** The raw response text the relay is about to send. */
  responseBody: string;
  audit: AuditRequestContext;
}): void {
  const ok = params.status >= 200 && params.status < 300;

  if (params.path === SIGN_IN_EMAIL_PATH) {
    if (ok) {
      const user = signedInUser(params.responseBody);
      emit({
        actor_type: "user",
        actor_id: user.id,
        actor_label: user.email,
        actor_ip: params.audit.actor_ip,
        actor_user_agent: params.audit.actor_user_agent,
        action: "auth.login.success",
        target_type: "user",
        target_id: user.id,
        outcome: "success",
        request_id: params.audit.request_id,
        http_status: params.status,
        detail: { method: "email" },
      });
      return;
    }

    // Anonymous, not `user`: the whole point of a failure row is that the
    // claimed identity was NOT proven. The attempted address goes in
    // `actor_label` where an operator reads it, and `actor_id` stays null
    // because no user was authenticated.
    emit({
      actor_type: "anonymous",
      actor_id: null,
      actor_label: attemptedEmail(params.requestBody),
      actor_ip: params.audit.actor_ip,
      actor_user_agent: params.audit.actor_user_agent,
      action: "auth.login.failure",
      target_type: "user",
      target_id: null,
      outcome: "failure",
      request_id: params.audit.request_id,
      http_status: params.status,
      detail: { method: "email" },
    });
    return;
  }

  if (params.path === SIGN_OUT_PATH && ok) {
    // Actor is deliberately absent here rather than guessed: the sign-out
    // response carries no user, and re-resolving the session to name one
    // would add a database round-trip to a request that is already over.
    // `session.revoke` (auth.ts, `databaseHooks.session.delete.after`) fires
    // in the same request with the real user id, and both rows carry the same
    // `request_id` — that join is what the relay header threading is for.
    emit({
      actor_type: "user",
      actor_id: null,
      actor_label: null,
      actor_ip: params.audit.actor_ip,
      actor_user_agent: params.audit.actor_user_agent,
      action: "auth.logout",
      target_type: "session",
      target_id: null,
      outcome: "success",
      request_id: params.audit.request_id,
      http_status: params.status,
    });
  }
}
