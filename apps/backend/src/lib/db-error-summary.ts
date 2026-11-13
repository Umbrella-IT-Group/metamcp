/**
 * A log-safe description of a failed database write.
 *
 * Drizzle wraps a failed query in a DrizzleQueryError whose message is
 * "Failed query: <sql>\nparams: <bound values>" and which keeps the bound
 * values on `.params`; the node-postgres error under it can quote values in
 * its message and always does in `detail` ("Failing row contains (...)").
 * Logging any of those copies the row that failed to write into the log, and
 * the rows written through this gateway hold audit detail and
 * administrator-authored text.
 *
 * What survives is what an operator needs to diagnose the failure: the error
 * class and, from the error and its causes, the stable identifiers the
 * database and the network stack attach (SQLSTATE or errno code, constraint,
 * table and column names). The message of a query-bearing error (a Drizzle
 * query error, or a server error from Postgres) never appears, nor does any
 * detail, hint, query text or params. Other messages survive only when they
 * exactly match a fixed node-postgres diagnostic. Missing query metadata is
 * not evidence that a message is safe: JSON encoding can fail before the
 * query exists, and wrappers can copy a query error into their own message.
 * Network failures remain diagnosable by their errno code.
 */

const IDENTIFIER = /^[A-Za-z0-9_.$-]{1,64}$/;
const SQLSTATE = /^[0-9A-Z]{5}$/;
// Exact literals from pg and pg-pool. Code-less timeouts still need a useful
// diagnosis, but prefixes, truncation and control stripping do not redact row
// data. Never admit an arbitrary message based on the absence of DB fields.
const DRIVER_MESSAGES = new Set([
  "Connection terminated",
  "Connection terminated unexpectedly",
  "Connection terminated due to connection timeout",
  "timeout expired",
  "timeout exceeded when trying to connect",
  "Query read timeout",
  "Client has encountered a connection error and is not queryable",
  "Client was closed and is not queryable",
]);

function safeIdentifier(value: unknown): string | undefined {
  return typeof value === "string" && IDENTIFIER.test(value)
    ? value
    : undefined;
}

/**
 * A Drizzle query error carries `query` and `params`; a Postgres server error
 * carries a five-character SQLSTATE and usually `severity`, `routine` or
 * `detail`. Either can hold the row's values in its message.
 */
function isQueryBearing(record: Record<string, unknown>): boolean {
  return (
    "params" in record ||
    "query" in record ||
    "detail" in record ||
    "severity" in record ||
    "routine" in record ||
    (typeof record.code === "string" && SQLSTATE.test(record.code))
  );
}

function knownDriverMessage(value: unknown): string | undefined {
  return typeof value === "string" && DRIVER_MESSAGES.has(value)
    ? value
    : undefined;
}

function describeOne(error: unknown): string {
  if (!error || typeof error !== "object") return typeof error;
  const record = error as Record<string, unknown>;
  const ctor = safeIdentifier(
    (error as { constructor?: { name?: unknown } }).constructor?.name,
  );
  // DrizzleQueryError leaves `name` as the inherited "Error"; its class name
  // is what tells a responder that a query failed.
  const name =
    (ctor && ctor !== "Object" && ctor !== "Error" ? ctor : undefined) ??
    safeIdentifier(record.name) ??
    "Error";
  const fields: string[] = [];
  for (const key of ["code", "constraint", "table", "column"] as const) {
    const value = safeIdentifier(record[key]);
    if (value) fields.push(`${key}=${value}`);
  }
  const message = isQueryBearing(record)
    ? undefined
    : knownDriverMessage(record.message);
  let text = fields.length ? `${name} (${fields.join(" ")})` : name;
  if (message) text += `: ${message}`;
  return text;
}

/** At most this many links of a `cause` chain are described. */
const MAX_CAUSE_DEPTH = 4;

export function describeDbError(error: unknown): string {
  try {
    const parts: string[] = [];
    let current: unknown = error;
    for (let depth = 0; depth < MAX_CAUSE_DEPTH && current; depth += 1) {
      parts.push(describeOne(current));
      current =
        current && typeof current === "object"
          ? (current as { cause?: unknown }).cause
          : undefined;
    }
    return parts.join(" <- ");
  } catch {
    // A thrown value can have getters or be a proxy. Failure reporting must
    // not itself reject the audit's detached catch or the presentation save.
    // Do not inspect this second error: it can hold the same private data.
    return "Error (summary unavailable)";
  }
}
