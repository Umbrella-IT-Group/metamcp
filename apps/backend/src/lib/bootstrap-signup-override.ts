/**
 * The one exemption to this fork's fail-closed registration default:
 * bootstrap's own account creation.
 *
 * WHY IT EXISTS. `BOOTSTRAP_DISABLE_REGISTRATION_UI` defaults to `true` here,
 * and bootstrap writes that decision into the `config` table on every run, so
 * from the SECOND boot onward `DISABLE_SIGNUP` is already stored `true` before
 * bootstrap starts. Bootstrap creates its accounts by POSTing to Better Auth's
 * own `/api/auth/sign-up/email` (`ensureUser` in `bootstrap.service.ts`), which
 * runs the `databaseHooks.user.create.before` hook in `auth.ts`, and that hook
 * refuses the request while the stored flag is `true`. The refusal is not a
 * harmless no-op: with `BOOTSTRAP_RECREATE_USER=true` (what `example.env`
 * ships) `ensureUser` DELETES the existing administrator, and its user-scoped
 * API keys with it, BEFORE the re-signup. A refused re-signup therefore brings
 * the deploy up with no administrator, registration closed, and the connector
 * keys unrecoverable, on an ordinary container restart.
 *
 * WHY ORDERING WAS NOT ENOUGH. Writing the lock after the users are created
 * only helps the FIRST boot, the one where no `config` row exists yet. On every
 * boot after it the STORED row is what refuses, and no reordering inside a
 * single boot can change what a previous boot persisted. The exemption has to
 * be about WHO is signing up, not about when the flag is written.
 *
 * WHY IT OPENS NO WINDOW. The flag is process-global, defaults to `false`, and
 * `initializeEnvironmentConfiguration` is its only writer: it sets the flag
 * immediately before the bootstrap user pass and clears it in a `finally`
 * immediately after, so a throw inside that pass cannot leave it on. That whole
 * pass runs inside `initializeOnStartup()`, which `index.ts` awaits BEFORE
 * `app.listen()`, so the HTTP server is not accepting connections for any part
 * of the window and no request can reach the sign-up route while it is open.
 *
 * WHAT IT DOES NOT EXEMPT. The audit trail. `user.create.after` still emits
 * `emitSignupCreated` for the account, so a bootstrap-created administrator is
 * exactly as visible in the audit log as any other account.
 */
let bootstrapSignupAllowed = false;

/**
 * Open (`true`) or close (`false`) the bootstrap exemption. Call sites outside
 * `initializeEnvironmentConfiguration` are a bug: this is the one switch that
 * makes runtime signup possible while the stored flag says it is closed.
 */
export function setBootstrapSignupAllowed(allowed: boolean): void {
  bootstrapSignupAllowed = allowed;
}

export function isBootstrapSignupAllowed(): boolean {
  return bootstrapSignupAllowed;
}
