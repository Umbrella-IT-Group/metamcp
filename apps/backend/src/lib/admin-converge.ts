/**
 * Boot-time admin converge: promote the accounts named in METAMCP_ADMIN_EMAIL
 * to `admin`, then warn loudly if the gateway still has no administrator.
 *
 * WHY THIS EXISTS. Migration 0020 added `users.role` with a `member` default,
 * which backfilled every existing account as a member, and the only promotions
 * anywhere were two seed migrations (0020, 0022) naming this fork's own
 * operator addresses by literal. Every other install upgraded to zero admins,
 * and since the admin gate (`adminProcedure`) covers the settings that could
 * fix it, there was no path out except SQL (fork issue #196). A fresh install
 * had the same hole: `BOOTSTRAP_USER_EMAIL` creates an account and never gives
 * it a role. This module is the configuration path the README already
 * promised: the deployment names its administrators, and every boot converges
 * the database toward that list.
 *
 * WHAT IT WILL AND WILL NOT DO.
 *   - Promotes only accounts whose email is NAMED. There is no "the only user"
 *     or "the first user" rule: the operator who can set an opt-in flag for
 *     such a rule can set this variable to their own address instead, and a
 *     rule that picks an account by position is one that can pick the wrong
 *     account on a multi-user install.
 *   - Never demotes. Removing an address from the list leaves that account an
 *     administrator; the only write here sets `admin` (see
 *     `buildPromoteToAdminQuery`). Demotion stays a deliberate act.
 *   - Never creates an account. An address with no account is a WARN and a
 *     no-op; the account is promoted on the first boot after it exists (for
 *     example, after `BOOTSTRAP_USERS` creates it earlier in the same boot).
 *   - Refuses an address that matches more than one account case-
 *     insensitively, rather than promoting both rows or guessing between them.
 *   - Writes one `user.role.set` audit row per promotion it actually makes, and
 *     none on a restart that changes nothing.
 *
 * UNSET IS A NO-OP. With the variable unset or empty, nothing is written: the
 * only database access is the read that counts administrators for the boot
 * log and the zero-admin warning.
 *
 * SEQUENCE. Runs after migrations and after environment bootstrap (so an
 * account `BOOTSTRAP_USERS` creates on this boot can be promoted on this
 * boot), and before the HTTP server listens. Never fatal: every failure is
 * logged and the gateway starts with the roles it already had, which is
 * exactly the pre-change behaviour.
 */
import logger from "@/utils/logger";

import { usersRepository } from "../db/repositories";
import { emitAdminEvent } from "./audit/admin-event";
import { clampAuditText } from "./audit/audit-emitter";

export const ADMIN_EMAIL_ENV = "METAMCP_ADMIN_EMAIL";

/**
 * RFC 5321 §4.5.3.1.3: the longest legal email address. Same clamp the other
 * audit rows that carry an email use, because `audit_log` has no prune path.
 */
const MAX_EMAIL_LENGTH = 320;

// One address per entry: a local part, exactly one "@", a domain, and no
// whitespace or separators. Deliberately loose about everything else (the
// match against existing accounts is the real test), but strict enough that a
// list written with the wrong separator ("a@x.io; b@y.io", "a@x.io b@y.io")
// is reported as unparseable instead of quietly matching nothing.
const SINGLE_ADDRESS = /^[^\s@,;]+@[^\s@,;]+$/;

export interface ParsedAdminEmails {
  /** Distinct addresses, trimmed and lowercased, in configured order. */
  emails: string[];
  /** Entries that are not a single address, as written (trimmed). */
  rejected: string[];
}

/**
 * Parse METAMCP_ADMIN_EMAIL: a comma-separated list of addresses.
 *
 * Each entry is trimmed and lowercased, empty entries (a trailing comma, a
 * doubled comma) are skipped, and duplicates collapse. Lowercasing matches how
 * better-auth stores an address at sign-up, and the lookup compares against
 * `lower(email)`, so case in the variable never decides whether a match
 * happens.
 */
export function parseAdminEmails(raw: string | undefined): ParsedAdminEmails {
  const emails: string[] = [];
  const rejected: string[] = [];
  if (raw === undefined) return { emails, rejected };

  for (const entry of raw.split(",")) {
    const trimmed = entry.trim();
    if (trimmed === "") continue;
    if (!SINGLE_ADDRESS.test(trimmed)) {
      rejected.push(trimmed);
      continue;
    }
    const normalized = trimmed.toLowerCase();
    if (!emails.includes(normalized)) emails.push(normalized);
  }
  return { emails, rejected };
}

export interface AdminConvergeResult {
  /** Distinct addresses the variable names. */
  configured: number;
  /** Ids of the accounts this run promoted. */
  promoted: string[];
  /** Named accounts that were already administrators. */
  alreadyAdmin: number;
  /** Named addresses with no account. */
  unmatched: string[];
  /** Named addresses matching more than one account ignoring case. */
  ambiguous: string[];
  /** Entries that are not a single address. */
  rejected: string[];
  /** Administrators after the run; null when the count itself failed. */
  admins: number | null;
}

/**
 * The SQL an operator can run when the gateway has no administrator. Kept in
 * one place so the warning and its test cannot drift apart.
 */
export const MANUAL_PROMOTION_SQL =
  "UPDATE users SET role = 'admin' WHERE email = '<address>';";

export async function convergeConfiguredAdmins(
  env: NodeJS.ProcessEnv = process.env,
): Promise<AdminConvergeResult> {
  const { emails, rejected } = parseAdminEmails(env[ADMIN_EMAIL_ENV]);
  const result: AdminConvergeResult = {
    configured: emails.length,
    promoted: [],
    alreadyAdmin: 0,
    unmatched: [],
    ambiguous: [],
    rejected,
    admins: null,
  };

  if (rejected.length > 0) {
    logger.warn(
      `Admin converge: ignoring ${rejected.length} ${ADMIN_EMAIL_ENV} ` +
        `entr${rejected.length === 1 ? "y" : "ies"} that are not a single ` +
        `address: [${rejected.join(", ")}]. Separate addresses with commas.`,
    );
  }

  if (emails.length > 0) {
    await promoteNamedAccounts(emails, result);
  }

  try {
    const { admins, users } = await usersRepository.countAdmins();
    result.admins = admins;
    const headcount = `${admins} administrator(s) among ${users} account(s).`;
    if (emails.length > 0) {
      logger.info(
        `Admin converge: ${ADMIN_EMAIL_ENV} names ${emails.length} ` +
          `address(es): promoted ${result.promoted.length}, already admin ` +
          `${result.alreadyAdmin}, no account ${result.unmatched.length}, ` +
          `ambiguous ${result.ambiguous.length}. ${headcount}`,
      );
    } else if (rejected.length > 0) {
      logger.info(
        `Admin converge: ${ADMIN_EMAIL_ENV} names no usable address; no ` +
          `promotions. ${headcount}`,
      );
    } else {
      logger.info(
        `Admin converge: ${ADMIN_EMAIL_ENV} is not set; no promotions. ${headcount}`,
      );
    }

    if (admins === 0) {
      // WARN, not INFO: production's LOG_LEVEL=info and the errors-only
      // default both put WARN on the console, which is where an operator
      // looking at a gateway that refuses every admin setting will look.
      logger.warn(
        `NO ADMINISTRATOR: this gateway has ${users} account(s) and none has ` +
          `role 'admin', so every admin-gated setting and mutation is refused ` +
          `and no one can promote anyone from the UI. Set ${ADMIN_EMAIL_ENV} ` +
          `to the address of an existing account (comma-separate several) and ` +
          `restart, or run this against the database: ${MANUAL_PROMOTION_SQL}`,
      );
    }
  } catch (err) {
    logger.error("Admin converge: could not count administrators:", err);
  }

  return result;
}

async function promoteNamedAccounts(
  emails: string[],
  result: AdminConvergeResult,
): Promise<void> {
  let rows: Array<{ id: string; email: string; role: string }>;
  try {
    rows = await usersRepository.findByEmailsIgnoringCase(emails);
  } catch (err) {
    logger.error(
      `Admin converge: could not look up the accounts ${ADMIN_EMAIL_ENV} names; no promotions this boot:`,
      err,
    );
    return;
  }

  const byAddress = new Map<string, typeof rows>();
  for (const row of rows) {
    const key = row.email.toLowerCase();
    byAddress.set(key, [...(byAddress.get(key) ?? []), row]);
  }

  for (const email of emails) {
    const matches = byAddress.get(email) ?? [];

    if (matches.length === 0) {
      result.unmatched.push(email);
      logger.warn(
        `Admin converge: ${ADMIN_EMAIL_ENV} names ${email}, but no account ` +
          `has that address; nothing promoted for it. Accounts are never ` +
          `created here: it is promoted on the first boot after it exists.`,
      );
      continue;
    }

    if (matches.length > 1) {
      // Two rows that differ only in case. Promoting both would elevate an
      // account the operator may not have meant; picking one would be a guess.
      result.ambiguous.push(email);
      logger.warn(
        `Admin converge: ${ADMIN_EMAIL_ENV} names ${email}, which matches ` +
          `${matches.length} accounts that differ only in letter case; ` +
          `promoting none of them. Resolve the duplicate accounts, or promote ` +
          `the intended one by its exact address.`,
      );
      continue;
    }

    const [account] = matches;
    if (account.role === "admin") {
      result.alreadyAdmin += 1;
      continue;
    }

    try {
      const promoted = await usersRepository.promoteToAdmin(account.id, email);
      if (!promoted) {
        // Became an administrator between the read and the write, or was
        // deleted or renamed. This run changed nothing, so it records nothing.
        continue;
      }
      result.promoted.push(promoted.id);
      logger.info(
        `Admin converge: promoted ${promoted.email} (user ${promoted.id}) ` +
          `from '${account.role}' to 'admin' via ${ADMIN_EMAIL_ENV}.`,
      );
      // After the write, never before: a row claiming a promotion that then
      // failed would be worse than no row. No actor: nothing in a request made
      // this change, so the row is `actor_type: "system"`, and `source` says
      // which configuration did.
      emitAdminEvent(undefined, {
        action: "user.role.set",
        target_type: "user",
        target_id: promoted.id,
        detail: {
          target_email: clampAuditText(promoted.email, MAX_EMAIL_LENGTH),
          old_role: account.role,
          new_role: "admin",
          source: "admin_email_env",
        },
      });
    } catch (err) {
      // One failed write must not stop the remaining promotions.
      logger.error(
        `Admin converge: failed to promote user ${account.id}:`,
        err,
      );
    }
  }
}
