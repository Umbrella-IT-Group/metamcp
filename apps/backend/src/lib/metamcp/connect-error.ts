/**
 * Connect/transport error diagnostics for the MCP backend client.
 *
 * undici (Node's fetch) wraps the real network failure several layers
 * deep: the SDK transport surfaces a generic `TypeError: fetch failed`
 * or `SSE stream disconnected: TypeError: terminated`, and the
 * actionable signal — `ECONNREFUSED` vs `ECONNRESET` vs `EAI_AGAIN`
 * plus the target address — is buried in `error.cause` (and, for
 * happy-eyeballs dual-stack dials, inside an `AggregateError.errors`
 * list). Logging the top-level wrapper tells an operator nothing about
 * WHY the connect failed; logging the unwrapped leaf turns
 * "Connect attempt 1/3 failed — fetch failed" into
 * "Connect attempt 1/3 failed — connect ECONNREFUSED 172.18.0.13:3000".
 *
 * Kept as a small pure module so the connect loop and the transport
 * onerror/onclose log sites in `client.ts` share one implementation and
 * it can be unit-tested without a live transport.
 */

/** Max `.cause` / `AggregateError` hops before we give up unwrapping. */
const MAX_UNWRAP_DEPTH = 10;

/** Shape of a Node system error after unwrapping (fields are optional). */
type NodeSystemError = Error & {
  code?: string;
  syscall?: string;
  address?: string;
  port?: number;
};

/**
 * Recursively unwrap undici's nested `error.cause` and the first
 * meaningful member of an `AggregateError.errors` list down to the
 * deepest underlying error. Returns the original value unchanged for a
 * non-Error throw (string, number, plain object) or when no cause chain
 * exists. Cycle-safe via a depth cap and an identity-seen set.
 */
export function unwrapErrorCause(error: unknown): unknown {
  let current: unknown = error;
  const seen = new Set<unknown>();

  for (let depth = 0; depth < MAX_UNWRAP_DEPTH; depth++) {
    if (current === null || current === undefined) {
      return current;
    }
    if (seen.has(current)) {
      return current;
    }
    seen.add(current);

    // AggregateError (e.g. dual-stack happy-eyeballs connect): prefer the
    // first member carrying a Node syscall code, else the first member —
    // it holds the real ECONNREFUSED/EAI_AGAIN we want to surface.
    if (
      current instanceof AggregateError &&
      Array.isArray(current.errors) &&
      current.errors.length > 0
    ) {
      const withCode = current.errors.find(
        (candidate) => (candidate as NodeSystemError | undefined)?.code,
      );
      current = withCode ?? current.errors[0];
      continue;
    }

    // undici nests the transport-level failure in `.cause`.
    if (
      current instanceof Error &&
      "cause" in current &&
      current.cause != null &&
      current.cause !== current
    ) {
      current = current.cause;
      continue;
    }

    return current;
  }

  return current;
}

/**
 * Render an actionable one-line description of a connect/transport
 * error: the unwrapped leaf's `syscall`, `code` and target address when
 * present (`connect ECONNREFUSED 172.18.0.13:3000`), else the leaf
 * error message, else `String(error)`. Never throws.
 */
export function describeConnectError(error: unknown): string {
  const leaf = unwrapErrorCause(error);

  if (leaf instanceof Error) {
    const sys = leaf as NodeSystemError;
    if (sys.code) {
      const call = [sys.syscall, sys.code].filter(Boolean).join(" ");
      const target =
        sys.address != null
          ? sys.port != null
            ? `${sys.address}:${sys.port}`
            : `${sys.address}`
          : "";
      return target ? `${call} ${target}` : call;
    }
    // No syscall code (e.g. an application-level Error) — the message is
    // the best signal we have.
    return leaf.message || leaf.name;
  }

  return String(leaf);
}

/**
 * Describe how long a connection had been established, for transport
 * drop logs — an established-then-dropped socket ("established 2h ago")
 * reads as a container replace / watchtower bounce, whereas a
 * never-established transport is a connect-time failure surfaced by the
 * connect-attempt log instead. `undefined` means the transport never
 * completed its handshake.
 */
export function formatConnectionAge(
  connectedAtMs: number | undefined,
  nowMs: number = Date.now(),
): string {
  if (connectedAtMs === undefined) {
    return "never-connected";
  }
  const ageMs = Math.max(0, nowMs - connectedAtMs);
  const seconds = Math.floor(ageMs / 1000);
  if (seconds < 60) {
    return `established ${seconds}s ago`;
  }
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return `established ${minutes}m ago`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `established ${hours}h ago`;
  }
  const days = Math.floor(hours / 24);
  return `established ${days}d ago`;
}
