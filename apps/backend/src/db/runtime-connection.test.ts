/**
 * The runtime/migration credential split, at the two places it can go wrong.
 *
 * First: the resolver. The property that has to hold above every other is that
 * an UNCONFIGURED deployment gets byte-identical behaviour — the moment this
 * indirection changes what a stock stack dials, it has broken every existing
 * install to buy a feature nobody asked for yet.
 *
 * Second: `scripts/ensure-runtime-role.sh`. It runs against a real server, so
 * most of it needs a database (see ./ensure-runtime-role.integration.test.ts).
 * What can be asserted without one is the part that rots silently: the list of
 * audit tables whose mutation grants get revoked. `ALTER DEFAULT PRIVILEGES`
 * in that script hands full DML on every FUTURE table to the runtime role, so
 * an audit table added by a later migration is UPDATE-able unless someone
 * remembers to add it. The last case here removes "remembers" from that
 * sentence.
 */

import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

import { Client } from "pg";
import { describe, expect, it } from "vitest";

import {
  DEFAULT_RUNTIME_DB_ROLE,
  resolveRuntimeConnection,
} from "./runtime-connection";

const OWNER_URL = "postgresql://metamcp_user:m3t4mcp@postgres:5432/metamcp_db";

describe("resolveRuntimeConnection — unconfigured", () => {
  it("returns DATABASE_URL untouched when neither variable is set", () => {
    const resolved = resolveRuntimeConnection({ DATABASE_URL: OWNER_URL });

    expect(resolved.connectionString).toBe(OWNER_URL);
    expect(resolved.mode).toBe("unsplit");
    expect(resolved.expectedRole).toBeNull();
  });

  it("treats a blank runtime password as unset rather than as a password", () => {
    // Blanking a value in `.env` is how operators turn a feature off. Reading
    // "" as a real password would derive a connection string that cannot
    // authenticate, i.e. turn a disable into an outage.
    const resolved = resolveRuntimeConnection({
      DATABASE_URL: OWNER_URL,
      METAMCP_RUNTIME_DB_PASSWORD: "   ",
      RUNTIME_DATABASE_URL: "",
    });

    expect(resolved.connectionString).toBe(OWNER_URL);
    expect(resolved.mode).toBe("unsplit");
  });

  it("still throws the original error when DATABASE_URL is missing", () => {
    expect(() => resolveRuntimeConnection({})).toThrow(
      "DATABASE_URL is not set",
    );
  });
});

describe("resolveRuntimeConnection — derived", () => {
  it("swaps only the credentials, preserving host, port, database and options", () => {
    const resolved = resolveRuntimeConnection({
      DATABASE_URL:
        "postgresql://metamcp_user:m3t4mcp@db.internal:6432/metamcp_db?sslmode=require&application_name=gw",
      METAMCP_RUNTIME_DB_PASSWORD: "runtime-secret",
    });

    const url = new URL(resolved.connectionString);
    expect(url.username).toBe(DEFAULT_RUNTIME_DB_ROLE);
    expect(decodeURIComponent(url.password)).toBe("runtime-secret");
    expect(url.hostname).toBe("db.internal");
    expect(url.port).toBe("6432");
    expect(url.pathname).toBe("/metamcp_db");
    expect(url.searchParams.get("sslmode")).toBe("require");
    expect(url.searchParams.get("application_name")).toBe("gw");
    expect(resolved.mode).toBe("derived");
    expect(resolved.expectedRole).toBe(DEFAULT_RUNTIME_DB_ROLE);
  });

  it("does NOT trim the password it was given", () => {
    // The entrypoint script hands psql the raw environment value, so a
    // password with surrounding whitespace is set on the role WITH that
    // whitespace. Trimming here would derive a credential the entrypoint never
    // created, and the only symptom would be an authentication failure with
    // nothing in either log pointing at the cause.
    const password = "  padded-secret  ";
    const resolved = resolveRuntimeConnection({
      DATABASE_URL: OWNER_URL,
      METAMCP_RUNTIME_DB_PASSWORD: password,
    });

    expect(
      decodeURIComponent(new URL(resolved.connectionString).password),
    ).toBe(password);
  });

  it("honours an explicit role name", () => {
    const resolved = resolveRuntimeConnection({
      DATABASE_URL: OWNER_URL,
      METAMCP_RUNTIME_DB_ROLE: "gateway_rt",
      METAMCP_RUNTIME_DB_PASSWORD: "pw",
    });

    expect(new URL(resolved.connectionString).username).toBe("gateway_rt");
    expect(resolved.expectedRole).toBe("gateway_rt");
  });

  /**
   * The failure this prevents is silent, not loud: a password containing `@`
   * or `%` spliced in unencoded either moves the host or decodes to a
   * different password, and the operator sees an authentication failure with
   * no hint that the string was mangled on the way in. Round-tripped through
   * pg's own parser rather than through a hand-written expectation, because pg
   * is what will actually read this string.
   */
  it.each([
    "plain",
    "a@b",
    "a%41b",
    "a%b",
    "p:/@?#&=",
    "éà",
    "S3cr3t!#$%^&*()",
  ])(
    "round-trips the password %j through pg's connection parser",
    (password) => {
      const resolved = resolveRuntimeConnection({
        DATABASE_URL: OWNER_URL,
        METAMCP_RUNTIME_DB_PASSWORD: password,
      });

      // `connectionParameters` is what pg resolved the string TO — the values it
      // would actually send on the wire. It is not in @types/pg, hence the cast;
      // asserting against a hand-rolled decoder instead would just be testing
      // this test.
      const parsed = (
        new Client({
          connectionString: resolved.connectionString,
        }) as unknown as {
          connectionParameters: {
            user: string;
            password: string;
            host: string;
            port: number;
            database: string;
          };
        }
      ).connectionParameters;

      expect(parsed.user).toBe(DEFAULT_RUNTIME_DB_ROLE);
      expect(parsed.password).toBe(password);
      expect(parsed.host).toBe("postgres");
      expect(String(parsed.port)).toBe("5432");
      expect(parsed.database).toBe("metamcp_db");
    },
  );

  it("refuses to fall back to the owner credential when DATABASE_URL cannot be parsed", () => {
    // Falling back silently would leave an operator who set the variable
    // running as the superuser while believing the split was on — the one
    // outcome worse than not having the feature.
    expect(() =>
      resolveRuntimeConnection({
        DATABASE_URL: "host=postgres user=metamcp_user",
        METAMCP_RUNTIME_DB_PASSWORD: "pw",
      }),
    ).toThrow(/not a parseable URL/);
  });
});

describe("resolveRuntimeConnection — explicit", () => {
  it("uses RUNTIME_DATABASE_URL verbatim and in preference to the derived form", () => {
    const explicit = "postgresql://rt:rtpw@pooler:6432/metamcp_db";
    const resolved = resolveRuntimeConnection({
      DATABASE_URL: OWNER_URL,
      RUNTIME_DATABASE_URL: explicit,
      METAMCP_RUNTIME_DB_PASSWORD: "ignored",
    });

    expect(resolved.connectionString).toBe(explicit);
    expect(resolved.mode).toBe("explicit");
    // No expectation is asserted about the role: the string may legitimately
    // name anything, and a warning about a mismatch that is not one is worse
    // than no warning.
    expect(resolved.expectedRole).toBeNull();
  });
});

describe("scripts/ensure-runtime-role.sh — the audit-table revoke list", () => {
  const SCRIPT_PATH = path.resolve(
    __dirname,
    "../../../../scripts/ensure-runtime-role.sh",
  );
  const script = readFileSync(SCRIPT_PATH, "utf8");

  it("agrees with the resolver on the default role name", () => {
    // A disagreement means the entrypoint grants one role and the app dials
    // another, and the only symptom is an authentication failure at boot.
    expect(script).toContain(
      `METAMCP_RUNTIME_DB_ROLE:-${DEFAULT_RUNTIME_DB_ROLE}`,
    );
  });

  it("keeps audit_log append-only and leaves the pruners able to prune", () => {
    expect(script).toMatch(
      /\('public\.audit_log',\s+'UPDATE, DELETE, TRUNCATE'\)/,
    );
    // DELETE deliberately survives on the pruned tables: their in-app pruners
    // remove aged rows. In-window immutability there is the triggers' job,
    // and a NOSUPERUSER role can no longer bypass those.
    expect(script).toMatch(
      /\('public\.tool_call_audit',\s+'UPDATE, TRUNCATE'\)/,
    );
    expect(script).toMatch(
      /\('public\.gateway_events',\s+'UPDATE, TRUNCATE'\)/,
    );
  });

  it("names every table that a migration protects with an immutability trigger", () => {
    // The rule this enforces: if a migration installs a BEFORE
    // UPDATE/DELETE/TRUNCATE trigger on a table, that table is an audit table,
    // and the runtime role must not be left holding the grants the trigger is
    // there to refuse. Without this, `ALTER DEFAULT PRIVILEGES` hands full DML
    // on the next such table to the runtime role and nothing says so.
    const migrationDir = path.resolve(__dirname, "../../drizzle");
    const protectedTables = new Set<string>();

    for (const file of readdirSync(migrationDir).filter((f) =>
      f.endsWith(".sql"),
    )) {
      const sql = readFileSync(path.join(migrationDir, file), "utf8");
      for (const match of sql.matchAll(
        /CREATE TRIGGER\s+\w+\s+BEFORE\s+(?:UPDATE|DELETE|TRUNCATE)\s+ON\s+"?(\w+)"?/gi,
      )) {
        protectedTables.add(match[1]);
      }
    }

    // Guards the guard: a regex that stopped matching would make this test
    // vacuously green.
    expect(protectedTables.size).toBeGreaterThan(0);

    for (const table of protectedTables) {
      expect(
        script,
        `${table} has an immutability trigger but no REVOKE entry in ensure-runtime-role.sh`,
      ).toContain(`'public.${table}'`);
    }
  });
});
