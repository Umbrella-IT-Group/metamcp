/**
 * Boot-time admin converge (fork issue #196).
 *
 * The repository is replaced by an in-memory users table whose `promoteToAdmin`
 * honours the same `role <> 'admin'` predicate the real UPDATE carries (pinned
 * as SQL in `users.repo.admin-converge.test.ts`), so these cases can assert on
 * the RESULTING roles and on a second boot, not only on which calls were made.
 * The audit sink is the real `emitAdminEvent` path with a capturing sink, so the
 * row asserted is the row `audit_log` would receive.
 *
 * The properties that matter most, because each one failing is either a
 * lockout or an elevation:
 *   - unset or empty variable: no lookup, no write, no audit row (production
 *     runs with it unset, so this is what proves the change is inert there);
 *   - only NAMED accounts are promoted, never one picked by position;
 *   - nothing is ever demoted;
 *   - an address matching two accounts by case alone promotes neither;
 *   - zero administrators produces exactly one loud WARN naming the variable
 *     and the SQL.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const loggerMock = vi.hoisted(() => ({
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

type UserRow = { id: string; email: string; role: string };

// Only the three methods the converge may use. Anything else it reached for
// would be undefined here and fail the test, which is how "it never demotes"
// is enforced structurally: there is no other write to call.
const usersRepositoryMock = vi.hoisted(() => ({
  findByEmailsIgnoringCase: vi.fn(),
  promoteToAdmin: vi.fn(),
  countAdmins: vi.fn(),
}));

vi.mock("../db/repositories", () => ({
  usersRepository: usersRepositoryMock,
}));

import {
  ADMIN_EMAIL_ENV,
  convergeConfiguredAdmins,
  MANUAL_PROMOTION_SQL,
  parseAdminEmails,
} from "./admin-converge";
import { setAuditSinkForTesting } from "./audit/audit-emitter";

type AuditRow = {
  action: string;
  actor_type: string;
  actor_id?: string | null;
  outcome: string;
  target_type?: string | null;
  target_id?: string | null;
  detail?: Record<string, unknown>;
};

let users: UserRow[];
let auditRows: AuditRow[];

/** Flush the detached promise chain `emit()` schedules. */
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

const roleOf = (id: string) => users.find((u) => u.id === id)?.role;

const warnings = () => loggerMock.warn.mock.calls.map((c) => String(c[0]));
const noAdminWarnings = () =>
  warnings().filter((w) => w.includes("NO ADMINISTRATOR"));

beforeEach(() => {
  vi.clearAllMocks();
  auditRows = [];
  setAuditSinkForTesting(async (event) => {
    auditRows.push(event as AuditRow);
  });

  users = [
    { id: "u-admin", email: "alex@example.com", role: "admin" },
    { id: "u-member", email: "pat@example.com", role: "member" },
    { id: "u-other", email: "sam@example.com", role: "member" },
  ];

  usersRepositoryMock.findByEmailsIgnoringCase.mockImplementation(
    async (emails: string[]) =>
      users
        .filter((u) => emails.includes(u.email.toLowerCase()))
        .map((u) => ({ ...u })),
  );
  usersRepositoryMock.promoteToAdmin.mockImplementation(async (id: string) => {
    // Same predicate as the real UPDATE: matches only a non-admin row.
    const row = users.find((u) => u.id === id && u.role !== "admin");
    if (!row) return undefined;
    row.role = "admin";
    return { id: row.id, email: row.email };
  });
  usersRepositoryMock.countAdmins.mockImplementation(async () => ({
    admins: users.filter((u) => u.role === "admin").length,
    users: users.length,
  }));
});

afterEach(() => {
  setAuditSinkForTesting(undefined);
});

describe("parseAdminEmails", () => {
  it("returns nothing for an unset variable", () => {
    expect(parseAdminEmails(undefined)).toEqual({ emails: [], rejected: [] });
  });

  it("splits on commas, trims, lowercases, skips blanks and collapses duplicates", () => {
    expect(
      parseAdminEmails(" Pat@Example.com ,, sam@example.com,PAT@example.COM, "),
    ).toEqual({
      emails: ["pat@example.com", "sam@example.com"],
      rejected: [],
    });
  });

  it("rejects an entry that is not exactly one address instead of guessing", () => {
    // A list written with the wrong separator must surface, not quietly match
    // nothing (or, worse, be read as one odd address).
    expect(
      parseAdminEmails(
        "a@x.io; b@y.io, c@z.io d@w.io, not-an-address, ok@v.io",
      ),
    ).toEqual({
      emails: ["ok@v.io"],
      rejected: ["a@x.io; b@y.io", "c@z.io d@w.io", "not-an-address"],
    });
  });
});

describe("convergeConfiguredAdmins: unset is a no-op", () => {
  it.each([
    ["unset", {}],
    ["empty", { [ADMIN_EMAIL_ENV]: "" }],
    ["whitespace and commas only", { [ADMIN_EMAIL_ENV]: " , ,, " }],
  ])("%s: no lookup, no write, no audit row", async (_label, env) => {
    const before = JSON.stringify(users);

    const result = await convergeConfiguredAdmins(env);
    await flush();

    expect(usersRepositoryMock.findByEmailsIgnoringCase).not.toHaveBeenCalled();
    expect(usersRepositoryMock.promoteToAdmin).not.toHaveBeenCalled();
    expect(auditRows).toEqual([]);
    expect(JSON.stringify(users)).toBe(before);
    expect(result).toMatchObject({ configured: 0, promoted: [], admins: 1 });
    // An admin exists, so nothing is loud: the one line is the INFO posture.
    expect(loggerMock.warn).not.toHaveBeenCalled();
    expect(loggerMock.info).toHaveBeenCalledWith(
      expect.stringContaining(`${ADMIN_EMAIL_ENV} is not set; no promotions`),
    );
  });
});

describe("convergeConfiguredAdmins: promotion", () => {
  it("promotes a named member and writes one user.role.set audit row", async () => {
    const result = await convergeConfiguredAdmins({
      [ADMIN_EMAIL_ENV]: "pat@example.com",
    });
    await flush();

    expect(roleOf("u-member")).toBe("admin");
    expect(result.promoted).toEqual(["u-member"]);
    expect(auditRows).toEqual([
      expect.objectContaining({
        action: "user.role.set",
        // No request made this change: a system row, not a phantom admin.
        actor_type: "system",
        actor_id: null,
        outcome: "success",
        target_type: "user",
        target_id: "u-member",
        detail: {
          target_email: "pat@example.com",
          old_role: "member",
          new_role: "admin",
          source: "admin_email_env",
        },
      }),
    ]);
  });

  it("leaves an already-admin account untouched: no write, no audit row", async () => {
    const result = await convergeConfiguredAdmins({
      [ADMIN_EMAIL_ENV]: "alex@example.com",
    });
    await flush();

    expect(usersRepositoryMock.promoteToAdmin).not.toHaveBeenCalled();
    expect(auditRows).toEqual([]);
    expect(result).toMatchObject({ alreadyAdmin: 1, promoted: [] });
    expect(roleOf("u-admin")).toBe("admin");
  });

  it("is idempotent: a second boot with the same list changes and records nothing", async () => {
    const env = { [ADMIN_EMAIL_ENV]: "pat@example.com" };
    await convergeConfiguredAdmins(env);
    await flush();
    expect(auditRows).toHaveLength(1);

    auditRows = [];
    const second = await convergeConfiguredAdmins(env);
    await flush();

    expect(second).toMatchObject({ promoted: [], alreadyAdmin: 1 });
    expect(auditRows).toEqual([]);
  });

  it("promotes only the named account, never another member", async () => {
    await convergeConfiguredAdmins({ [ADMIN_EMAIL_ENV]: "pat@example.com" });

    expect(roleOf("u-other")).toBe("member");
    expect(usersRepositoryMock.promoteToAdmin).toHaveBeenCalledTimes(1);
    expect(usersRepositoryMock.promoteToAdmin).toHaveBeenCalledWith("u-member");
  });

  it("never demotes an administrator the list does not name", async () => {
    // alex@ is admin and absent from the list; the list names only sam@.
    await convergeConfiguredAdmins({ [ADMIN_EMAIL_ENV]: "sam@example.com" });
    await flush();

    expect(roleOf("u-admin")).toBe("admin");
    expect(roleOf("u-other")).toBe("admin");
    expect(usersRepositoryMock.promoteToAdmin).not.toHaveBeenCalledWith(
      "u-admin",
    );
    expect(auditRows.map((r) => r.target_id)).toEqual(["u-other"]);
  });

  it("matches case-insensitively on both sides", async () => {
    users.push({ id: "u-mixed", email: "Robin@Example.com", role: "member" });

    const result = await convergeConfiguredAdmins({
      [ADMIN_EMAIL_ENV]: "  PAT@EXAMPLE.COM , robin@example.com ",
    });
    await flush();

    expect(usersRepositoryMock.findByEmailsIgnoringCase).toHaveBeenCalledWith([
      "pat@example.com",
      "robin@example.com",
    ]);
    expect(roleOf("u-member")).toBe("admin");
    expect(roleOf("u-mixed")).toBe("admin");
    expect(result.promoted.sort()).toEqual(["u-member", "u-mixed"]);
    // The audit row carries the address as stored, not as configured.
    expect(
      auditRows.find((r) => r.target_id === "u-mixed")?.detail?.target_email,
    ).toBe("Robin@Example.com");
  });

  it("promotes neither account when an address matches two rows by case alone", async () => {
    users.push(
      { id: "u-carol-1", email: "carol@example.com", role: "member" },
      { id: "u-carol-2", email: "Carol@example.com", role: "member" },
    );

    const result = await convergeConfiguredAdmins({
      [ADMIN_EMAIL_ENV]: "carol@example.com",
    });
    await flush();

    expect(roleOf("u-carol-1")).toBe("member");
    expect(roleOf("u-carol-2")).toBe("member");
    expect(usersRepositoryMock.promoteToAdmin).not.toHaveBeenCalled();
    expect(auditRows).toEqual([]);
    expect(result.ambiguous).toEqual(["carol@example.com"]);
    expect(warnings()).toEqual(
      expect.arrayContaining([
        expect.stringContaining(
          "matches 2 accounts that differ only in letter case",
        ),
      ]),
    );
  });

  it("processes the valid entries of a list that also holds rejected ones", async () => {
    const result = await convergeConfiguredAdmins({
      [ADMIN_EMAIL_ENV]: "pat@example.com, nope, sam@example.com",
    });
    await flush();

    expect(result.rejected).toEqual(["nope"]);
    expect(roleOf("u-member")).toBe("admin");
    expect(roleOf("u-other")).toBe("admin");
    expect(warnings()).toEqual(
      expect.arrayContaining([expect.stringContaining("[nope]")]),
    );
  });
});

describe("convergeConfiguredAdmins: an address with no account", () => {
  it("is a no-op with a warning naming the address, and creates no account", async () => {
    const before = users.length;

    const result = await convergeConfiguredAdmins({
      [ADMIN_EMAIL_ENV]: "nobody@example.com",
    });
    await flush();

    expect(result.unmatched).toEqual(["nobody@example.com"]);
    expect(usersRepositoryMock.promoteToAdmin).not.toHaveBeenCalled();
    expect(auditRows).toEqual([]);
    expect(users).toHaveLength(before);
    expect(warnings()).toEqual(
      expect.arrayContaining([
        expect.stringContaining(
          `${ADMIN_EMAIL_ENV} names nobody@example.com, but no account has that address`,
        ),
      ]),
    );
  });
});

describe("convergeConfiguredAdmins: zero administrators", () => {
  beforeEach(() => {
    users = [
      { id: "u-1", email: "one@example.com", role: "member" },
      { id: "u-2", email: "two@example.com", role: "member" },
    ];
  });

  it("logs exactly one loud warning naming the variable and the SQL", async () => {
    const result = await convergeConfiguredAdmins({});

    expect(result.admins).toBe(0);
    const loud = noAdminWarnings();
    expect(loud).toHaveLength(1);
    expect(loud[0]).toContain(ADMIN_EMAIL_ENV);
    expect(loud[0]).toContain(MANUAL_PROMOTION_SQL);
    expect(loud[0]).toContain("2 account(s)");
    // The warning is advice. It must not act on it: no unnamed account is
    // promoted to fill the gap, not even when there is exactly one.
    expect(usersRepositoryMock.promoteToAdmin).not.toHaveBeenCalled();
  });

  it("does not promote a sole account that nobody named", async () => {
    users = [{ id: "u-solo", email: "solo@example.com", role: "member" }];

    await convergeConfiguredAdmins({});

    expect(roleOf("u-solo")).toBe("member");
    expect(noAdminWarnings()).toHaveLength(1);
  });

  it("still warns when the list names only addresses with no account", async () => {
    await convergeConfiguredAdmins({ [ADMIN_EMAIL_ENV]: "ghost@example.com" });

    expect(noAdminWarnings()).toHaveLength(1);
  });

  it("stays quiet once the converge itself produced an administrator", async () => {
    await convergeConfiguredAdmins({ [ADMIN_EMAIL_ENV]: "one@example.com" });

    expect(roleOf("u-1")).toBe("admin");
    expect(noAdminWarnings()).toEqual([]);
  });
});

describe("convergeConfiguredAdmins: failures never stop the boot", () => {
  it("keeps promoting the rest when one write fails, and records only real promotions", async () => {
    usersRepositoryMock.promoteToAdmin.mockImplementationOnce(async () => {
      throw new Error("connection reset");
    });

    const result = await convergeConfiguredAdmins({
      [ADMIN_EMAIL_ENV]: "pat@example.com, sam@example.com",
    });
    await flush();

    expect(result.promoted).toEqual(["u-other"]);
    expect(auditRows.map((r) => r.target_id)).toEqual(["u-other"]);
    expect(loggerMock.error).toHaveBeenCalledWith(
      expect.stringContaining("failed to promote user u-member"),
      expect.any(Error),
    );
  });

  it("records nothing when the row stopped matching between read and write", async () => {
    usersRepositoryMock.promoteToAdmin.mockResolvedValueOnce(undefined);

    const result = await convergeConfiguredAdmins({
      [ADMIN_EMAIL_ENV]: "pat@example.com",
    });
    await flush();

    expect(result.promoted).toEqual([]);
    expect(auditRows).toEqual([]);
  });

  it("resolves (does not throw) when the lookup fails, and still counts admins", async () => {
    usersRepositoryMock.findByEmailsIgnoringCase.mockRejectedValueOnce(
      new Error("db down"),
    );

    const result = await convergeConfiguredAdmins({
      [ADMIN_EMAIL_ENV]: "pat@example.com",
    });

    expect(result.promoted).toEqual([]);
    expect(result.admins).toBe(1);
    expect(loggerMock.error).toHaveBeenCalled();
  });

  it("resolves (does not throw) when the admin count fails", async () => {
    usersRepositoryMock.countAdmins.mockRejectedValueOnce(new Error("db down"));

    const result = await convergeConfiguredAdmins({});

    expect(result.admins).toBeNull();
    expect(loggerMock.error).toHaveBeenCalledWith(
      expect.stringContaining("could not count administrators"),
      expect.any(Error),
    );
  });
});

/**
 * The converge is worth nothing if the boot never calls it, and every case
 * above calls it directly. `index.ts` opens pools and starts the server at
 * import, so the wiring is pinned against its source (same technique as
 * `audit-storage/tripwire-wiring.test.ts`).
 */
describe("boot wiring", () => {
  const INDEX = readFileSync(
    path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../index.ts"),
    "utf8",
  );

  it("runs after environment bootstrap and before the server listens", () => {
    const bootstrap = INDEX.indexOf("await initializeOnStartup();");
    const converge = INDEX.indexOf("await convergeConfiguredAdmins();");
    // The call itself, not the comments above it that mention `app.listen()`.
    const listen = INDEX.indexOf("app.listen(12009");

    expect(bootstrap).toBeGreaterThan(-1);
    expect(converge).toBeGreaterThan(bootstrap);
    expect(listen).toBeGreaterThan(converge);
  });
});
