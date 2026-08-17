/**
 * Which connection string the RUNNING gateway dials, as opposed to the one
 * `drizzle-kit migrate` dials.
 *
 * WHY THE TWO ARE DIFFERENT AT ALL. On the stock compose stack they are the
 * same string, and it belongs to the `postgres:16-alpine` bootstrap role — a
 * SUPERUSER. Superusers bypass GRANTs, and can turn a trigger off for their
 * own session or drop it outright, so the append-only triggers migration 0028
 * installs on `audit_log` are bypassable by the credential the app holds every
 * second it is running. Migrations genuinely need that privilege (they create
 * and alter tables). The request path does not. Splitting them is what makes
 * the word "immutable" true rather than aspirational.
 *
 * OPT-IN, AND BYTE-IDENTICAL WHEN OFF. With neither variable set this returns
 * DATABASE_URL and the mode `"unsplit"`, which is exactly what both pools read
 * before this module existed. No deployment changes behaviour on upgrade.
 *
 * NO SILENT FALLBACK. When the split IS configured and the configuration is
 * unusable (an unparseable DATABASE_URL, an empty role name) this THROWS.
 * Quietly falling back to the superuser string would leave an operator who
 * believes the split is on running with it off — the one outcome worse than
 * not shipping the feature.
 */

/**
 * Role name the derived mode uses when METAMCP_RUNTIME_DB_ROLE is unset. Also
 * the name `scripts/ensure-runtime-role.sh` defaults to; the two have to agree
 * or the app dials a role the entrypoint never created.
 */
export const DEFAULT_RUNTIME_DB_ROLE = "metamcp_runtime";

export type RuntimeConnectionMode =
  | /** No runtime role configured: the app dials DATABASE_URL, as it always did. */
  "unsplit"
  /** RUNTIME_DATABASE_URL supplied verbatim by the operator. */
  | "explicit"
  /** Derived from DATABASE_URL by swapping in the runtime role's credentials. */
  | "derived";

export interface RuntimeConnection {
  connectionString: string;
  mode: RuntimeConnectionMode;
  /**
   * The role the connection is EXPECTED to authenticate as, when that is
   * knowable. `null` in `explicit` mode — the operator's string may name any
   * role, and inventing an expectation we cannot check would produce a boot
   * warning about a mismatch that is not one.
   */
  expectedRole: string | null;
}

/**
 * Empty and whitespace-only read as unset, matching the empty-means-unset rule
 * docker-entrypoint.sh already applies to the branding aliases. An operator
 * who blanks a variable in `.env` to turn a feature off should get it off, not
 * a connection string of `""`.
 *
 * The value itself is returned RAW, not trimmed. `scripts/ensure-runtime-role.sh`
 * hands the password to psql exactly as the environment holds it, so trimming
 * here would make the app derive a credential the entrypoint never set — an
 * authentication failure whose cause is invisible in both logs.
 */
function readOptional(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  return value.trim() === "" ? undefined : value;
}

export function resolveRuntimeConnection(
  env: NodeJS.ProcessEnv = process.env,
): RuntimeConnection {
  const databaseUrl = readOptional(env.DATABASE_URL);

  // Same message the two pool modules threw before this indirection existed;
  // it appears in deployment notes and in operators' muscle memory.
  if (!databaseUrl) {
    throw new Error("DATABASE_URL is not set");
  }

  const explicit = readOptional(env.RUNTIME_DATABASE_URL);
  if (explicit) {
    // Wins over the derived form deliberately: it is the escape hatch for a
    // topology the derivation cannot express (a separate host, a pooler in
    // front of the runtime role, a managed instance where the role is
    // provisioned outside this repo).
    return { connectionString: explicit, mode: "explicit", expectedRole: null };
  }

  const password = readOptional(env.METAMCP_RUNTIME_DB_PASSWORD);
  if (!password) {
    return {
      connectionString: databaseUrl,
      mode: "unsplit",
      expectedRole: null,
    };
  }

  const role =
    readOptional(env.METAMCP_RUNTIME_DB_ROLE) ?? DEFAULT_RUNTIME_DB_ROLE;

  // Rewritten through WHATWG `URL` rather than assembled from POSTGRES_* parts
  // or spliced with a regex: host, port, database and every query parameter
  // (`sslmode`, `application_name`, …) carry over untouched.
  //
  // `encodeURIComponent` before assignment, not instead of it. The `username`
  // and `password` setters percent-encode the userinfo-unsafe characters but
  // pass an existing `%` through untouched — so assigning a raw `a%41b` yields
  // `a%41b`, which pg decodes back to `aAb`. Encoding first turns that into
  // `a%2541b`, and the setter leaves it alone. Verified round-trip through
  // pg's own parser for `@`, `%`, `:`, `/` and non-ASCII in the test beside
  // this file.
  let url: URL;
  try {
    url = new URL(databaseUrl);
  } catch {
    throw new Error(
      "METAMCP_RUNTIME_DB_PASSWORD is set but DATABASE_URL is not a parseable URL; " +
        "set RUNTIME_DATABASE_URL explicitly instead",
    );
  }

  url.username = encodeURIComponent(role);
  url.password = encodeURIComponent(password);

  return {
    connectionString: url.toString(),
    mode: "derived",
    expectedRole: role,
  };
}
