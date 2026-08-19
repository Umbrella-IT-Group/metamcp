import type express from "express";

import logger from "@/utils/logger";

import { apiKeyLast4, hashApiKey } from "../api-key-hash";

/**
 * Fire-and-forget writer for the control-plane security audit log
 * (`audit_log`, migration 0028).
 *
 * THE SAFETY PROPERTY, and it outranks everything else in this file: an audit
 * write must NEVER block, delay, or fail the request it describes. The two
 * emitters wired in Phase 1A sit on the RBAC choke point (every admin-gated
 * tRPC mutation) and the MCP bearer path (every proxied MCP call). A throw
 * escaping `emit()` would not lose a log line — it would take the gateway
 * down. So `emit()` returns `void`, never a promise the caller can await into
 * the request path, and swallows every failure at every layer:
 *
 *   1. building the row is inside the try — a malformed `detail` must not
 *      throw at the call site;
 *   2. resolving the repository is lazy and failure-tolerant (no DATABASE_URL
 *      in unit tests / tooling disables the sink for the process lifetime
 *      rather than re-attempting the import per event);
 *   3. the write itself is a detached promise with a `.catch`.
 *
 * Failures are RATE-LIMITED WARNs, and both halves of that are load-bearing.
 *
 * WARN, because silent loss is indistinguishable from no attack. `audit_log`
 * carries BEFORE UPDATE / DELETE / TRUNCATE triggers and no prune path
 * (migration 0028), so a row that was never written can never be recovered,
 * and the audit pool is deliberately `max: 2` with a 1s checkout timeout
 * (`db/audit-db`) — dropping rows under flood is DESIGNED behaviour rather
 * than a fault. Dropping them INVISIBLY is the fault: production runs
 * `LOG_LEVEL=info`, whose console floor in `utils/logger` is INFO, so a debug
 * line reaches `app.log` but never the console an operator actually watches. A
 * responder reading the container log mid-incident would see a clean log while
 * the table quietly lost the rows they came to read.
 *
 * RATE-LIMITED, because the original debug was not simply a mistake. These
 * emitters sit on the hottest denial paths in the gateway and a database
 * outage fails EVERY one of them, so a line per failure is a flood that buries
 * its own cause. At most one line a minute, each carrying a running count of
 * rows lost since startup, says the same thing and stays readable. See
 * `reportAuditWriteFailure` for why the count is a total and not a delta.
 *
 * Same discipline (and the same lazy-import trick) as
 * `lib/metamcp/metamcp-middleware/auditing.functional.ts`, which has carried
 * the data-plane tool-call writes since PR #57.
 *
 * SECRETS: never pass a raw credential, token, password or request body into
 * an event. Use `credentialFingerprint()` — sha256 plus last-4, which is
 * enough to correlate repeated use of one stolen key across rows and enough
 * for an operator to match a row against a key list, and useless to anyone
 * who steals the audit table.
 */

export type AuditActorType =
  | "user"
  | "api_key"
  | "oauth_client"
  | "anonymous"
  | "system";

export type AuditOutcome = "success" | "failure" | "denied";

export interface AuditEvent {
  actor_type: AuditActorType;
  actor_id?: string | null;
  actor_label?: string | null;
  actor_ip?: string | null;
  actor_user_agent?: string | null;
  /** Verb from the controlled list (e.g. `rbac.denied`, `mcp.auth.denied`). */
  action: string;
  target_type?: string | null;
  target_id?: string | null;
  outcome: AuditOutcome;
  request_id?: string | null;
  http_status?: number | null;
  detail?: Record<string, unknown>;
}

type AuditSink = (event: AuditEvent) => Promise<void>;

let auditSink: AuditSink | null | undefined;

async function resolveSink(): Promise<AuditSink | null> {
  if (auditSink !== undefined) return auditSink;
  try {
    const { auditLogRepository } = await import(
      "../../db/repositories/audit-log.repo"
    );
    auditSink = (event) =>
      auditLogRepository.record({
        actor_type: event.actor_type,
        actor_id: event.actor_id ?? null,
        actor_label: event.actor_label ?? null,
        actor_ip: event.actor_ip ?? null,
        actor_user_agent: event.actor_user_agent ?? null,
        action: event.action,
        target_type: event.target_type ?? null,
        target_id: event.target_id ?? null,
        outcome: event.outcome,
        request_id: event.request_id ?? null,
        http_status: event.http_status ?? null,
        detail: event.detail ?? {},
      });
  } catch {
    // No database in this process (unit tests, tooling) — disable for the
    // process lifetime rather than re-attempting the import per event.
    auditSink = null;
  }
  return auditSink;
}

/** Test seam: override or disable the persistence sink (undefined = re-resolve). */
export function setAuditSinkForTesting(
  sink: AuditSink | null | undefined,
): void {
  auditSink = sink;
}

/** How long one reported failure suppresses the next report. */
const AUDIT_FAILURE_REPORT_INTERVAL_MS = 60 * 1000;

let auditFailuresTotal = 0;
let lastAuditFailureReportAt = 0;

/** Test seam: forget the counter and the throttle window. */
export function resetAuditFailureReportingForTesting(): void {
  auditFailuresTotal = 0;
  lastAuditFailureReportAt = 0;
}

/**
 * Make a dropped audit row DETECTABLE without making an outage unreadable.
 *
 * The count is what turns the line into a signal: "1 row lost" is a connection
 * that got recycled, "18,400 rows lost" is the sink being down during
 * something. The first failure reports IMMEDIATELY — detection must not wait
 * out a window — so that first line necessarily says 1, and the throttle then
 * holds the next report back.
 *
 * A RUNNING TOTAL since startup, not a per-window delta, and that is the
 * non-obvious part. A delta is stranded whenever the burst that produced it
 * stops before the next report fires: the line saying "49 more" never prints,
 * and silent loss is the exact thing this function exists to end. A total
 * cannot be stranded the same way — whenever the next line prints, it still
 * accounts for every failure that came before it. The cost is that two lines
 * must be subtracted to get a rate, which is the normal shape of a counter.
 *
 * Deliberately WARN and not ERROR. A lost audit row is a degraded record, not
 * a failed request — the caller was still authenticated, still authorised or
 * refused, still answered. Routing it to `error.log` would put it in front of
 * whatever pages on ERROR, and an audit sink that pages on a database blip is
 * an audit sink someone eventually turns off.
 */
function reportAuditWriteFailure(
  stage: "write" | "emit",
  error: unknown,
): void {
  auditFailuresTotal += 1;
  const now = Date.now();
  // The `!== 0` half matters under a mocked clock: a suite that pins Date to
  // the epoch would otherwise have its very first failure silently swallowed.
  if (
    lastAuditFailureReportAt !== 0 &&
    now - lastAuditFailureReportAt < AUDIT_FAILURE_REPORT_INTERVAL_MS
  ) {
    return;
  }
  lastAuditFailureReportAt = now;
  logger.warn(
    `[audit] ${stage} failed, ${auditFailuresTotal} audit row(s) lost since startup (request unaffected):`,
    error,
  );
}

/**
 * Record a security event. Returns immediately; the write happens detached.
 *
 * Every failure mode ends here — callers do not need (and must not add) a
 * try/catch of their own, and must not `await` this.
 */
export function emit(event: AuditEvent): void {
  try {
    void resolveSink()
      .then((sink) => sink?.(event))
      .catch((error) => {
        reportAuditWriteFailure("write", error);
      });
  } catch (error) {
    // Defence in depth: `resolveSink()` is async and should never throw
    // synchronously, but a future refactor that makes it sync must not be
    // able to turn a logging failure into a 500 on the auth path.
    reportAuditWriteFailure("emit", error);
  }
}

/**
 * Per-request attribution fields, stamped on `req` by the audit-context
 * middleware. Named rather than declaration-merged onto express's `Request`
 * so the property cannot collide with an upstream or dependency field —
 * matching the `ApiKeyAuthenticatedRequest` idiom in
 * `middleware/api-key-oauth.middleware.ts`.
 */
export interface AuditRequestFields {
  auditRequestId?: string;
  auditClientIp?: string;
}

export type AuditAttributedRequest = express.Request & AuditRequestFields;

export interface AuditRequestContext {
  actor_ip: string | null;
  actor_user_agent: string | null;
  request_id: string | null;
}

/**
 * Clamp budgets for the two envelope fields a CALLER controls.
 *
 * `actor_user_agent` and `actor_ip` are the only columns outside `detail` that
 * arrive verbatim from a request header, and both are written on paths that
 * need no credential at all: every no-credential 401 on `/metamcp/*` emits,
 * and so does every anonymous `protectedProcedure` miss on `/trpc`. Node caps
 * a header block at `http.maxHeaderSize` (16KB by default), so these were
 * never truly unbounded — but 16KB per row is not a bound worth writing to an
 * append-only table. Migration 0028 gives `audit_log` BEFORE UPDATE / DELETE /
 * TRUNCATE triggers and no prune path, so a row's SIZE is exactly as permanent
 * as its contents, and `clampAuditText` below already applies that reasoning
 * to `detail`. These two columns were simply never routed through it.
 *
 * 512 for the User-Agent: real agent strings — browsers, `claude-mcp/*`,
 * curl — run well under 200 characters, so 512 leaves a padded one still
 * identifiable while capping what one request can cost the archive.
 *
 * 64 for the IP: the longest legitimate value this column can hold is an IPv6
 * address, whose maximum textual form (the IPv4-mapped shape,
 * `0:0:0:0:0:ffff:255.255.255.255` written out in full) is 45 characters, plus
 * room for a zone id. Anything past that is not an address, so truncating it
 * costs no evidence: the row still records that a malformed value was
 * presented, which is the part a responder reads.
 */
export const AUDIT_USER_AGENT_MAX = 512;
export const AUDIT_IP_MAX = 64;

/**
 * Build the request half of the envelope.
 *
 * `actor_ip` comes from the middleware's CF-Connecting-IP read, NOT from
 * `req.ip`: the backend is reached through the frontend's in-container
 * rewrite, so `req.ip` is the same loopback address for every caller on
 * earth. Nullable rather than "unknown" — a column that says `127.0.0.1`
 * for everyone is worse than one that admits it does not know.
 */
export function auditRequestContext(
  req: express.Request | undefined | null,
): AuditRequestContext {
  const attributed = req as AuditAttributedRequest | undefined | null;
  const ua = attributed?.headers?.["user-agent"];
  return {
    // `auditClientIp` is already clamped where it is stamped, in
    // middleware/audit-context.middleware — clamping again here would only
    // hide a regression there.
    actor_ip: attributed?.auditClientIp ?? null,
    actor_user_agent:
      typeof ua === "string" ? clampAuditText(ua, AUDIT_USER_AGENT_MAX) : null,
    request_id: attributed?.auditRequestId ?? null,
  };
}

/**
 * Header names the `/api/auth` relay in `index.ts` writes onto the internal
 * `Request` it hands to `auth.handler()`, purely so better-auth's
 * `databaseHooks` can see the same attribution as the Express layer.
 *
 * WHY A HEADER AND NOT A PARAMETER. The signup / session-lifecycle events are
 * emitted from `databaseHooks` in `auth.ts`, which better-auth calls with a
 * `GenericEndpointContext` — the web `Request` it was given, and nothing from
 * Express. Without this, every hook-emitted row would carry a null
 * `request_id` and a null `actor_ip`, and could not be joined to the
 * `auth.login.*` row the same HTTP request produced. The relay is the one
 * place that holds both objects.
 *
 * NOT CLIENT-CONTROLLED. The relay copies the caller's headers into that
 * Request first, so a caller CAN put its own value under these names — which
 * is why the relay then unconditionally `set`s them when it has a value and
 * `delete`s them when it does not. Overwriting alone would not be enough: the
 * case with no `CF-Connecting-IP` is exactly the case where a forged
 * `x-audit-client-ip` would otherwise survive. These names are internal to
 * that one hop and are never emitted on any outbound request.
 */
export const AUDIT_REQUEST_ID_HEADER = "x-audit-request-id";
export const AUDIT_CLIENT_IP_HEADER = "x-audit-client-ip";

/**
 * Write this request's attribution onto the internal `Request` the `/api/auth`
 * relay hands to better-auth, replacing anything the caller sent under the
 * same names.
 *
 * EVERY branch writes, and the `delete` half is the security part rather than
 * tidiness: the relay copies the caller's headers into that bag first, so a
 * client that sends `x-audit-client-ip` has already put its own value there.
 * Setting only when we have a value would leave the forged one standing in
 * exactly the case that matters — a request with no `CF-Connecting-IP`, i.e.
 * one that did not come through the Cloudflare tunnel and whose IP claims are
 * therefore worthless. Deleting on absence makes "unknown" mean unknown.
 *
 * Lives here rather than inline in `index.ts` so the property is testable:
 * importing `index.ts` boots the entire server.
 */
export function stampAuditHeaders(
  headers: Headers,
  context: AuditRequestContext,
): void {
  if (context.request_id) {
    headers.set(AUDIT_REQUEST_ID_HEADER, context.request_id);
  } else {
    headers.delete(AUDIT_REQUEST_ID_HEADER);
  }
  if (context.actor_ip) {
    headers.set(AUDIT_CLIENT_IP_HEADER, context.actor_ip);
  } else {
    headers.delete(AUDIT_CLIENT_IP_HEADER);
  }
}

/** Anything header-shaped enough to read a value out of. */
interface HeaderReader {
  get(name: string): string | null;
}

/**
 * Read one header from the first of several candidate bags that can answer.
 *
 * Plural because better-auth types the hook context's `headers` as the loose
 * `HeadersInit`, which is satisfied by a plain object or an array of pairs as
 * well as by a real `Headers`. Reading only `context.headers` and giving up
 * when it has no `.get` would silently produce an unattributed row even
 * though `context.request.headers` — a genuine `Headers` — was sitting right
 * there. Falling through per lookup rather than picking one bag up front is
 * what makes that impossible.
 */
function readHeader(sources: unknown[], name: string): string | null {
  for (const source of sources) {
    const candidate = source as HeaderReader | null | undefined;
    if (typeof candidate?.get !== "function") continue;
    const value = candidate.get(name);
    if (typeof value === "string" && value !== "") return value;
  }
  return null;
}

/**
 * Rebuild the request half of the envelope inside a better-auth database
 * hook, from the two relay headers above plus the caller's User-Agent.
 *
 * Takes `unknown` deliberately: better-auth types the hook's context as
 * `GenericEndpointContext | null`, whose `headers` is the loose `HeadersInit`
 * and whose `request` may be absent, and this runs on the sign-up and
 * sign-in paths where a type assumption that turns out wrong at runtime would
 * throw inside an awaited hook — i.e. break authentication to record it.
 * Every read is guarded and every miss degrades to null.
 */
export function auditContextFromHook(context: unknown): AuditRequestContext {
  try {
    const candidate = context as
      | { headers?: unknown; request?: { headers?: unknown } }
      | null
      | undefined;
    const bags = [candidate?.headers, candidate?.request?.headers];
    // Clamped here too, and not only in `auditRequestContext`. This path reads
    // the User-Agent straight off the caller's headers rather than from the
    // relay, and `readHeader` falls through to `request.headers` — the bag the
    // caller filled — when the relay's own bag cannot answer. It runs on
    // sign-up and sign-in, which are reachable without a session, so leaving
    // it unclamped would leave the hole open on the one path an anonymous
    // caller can drive.
    const ip = readHeader(bags, AUDIT_CLIENT_IP_HEADER);
    const ua = readHeader(bags, "user-agent");
    return {
      actor_ip: ip === null ? null : clampAuditText(ip, AUDIT_IP_MAX),
      actor_user_agent:
        ua === null ? null : clampAuditText(ua, AUDIT_USER_AGENT_MAX),
      request_id: readHeader(bags, AUDIT_REQUEST_ID_HEADER),
    };
  } catch {
    return { actor_ip: null, actor_user_agent: null, request_id: null };
  }
}

/**
 * Bound a caller-supplied string before it goes into `detail`.
 *
 * `audit_log` has UPDATE/DELETE/TRUNCATE triggers and deliberately no prune
 * path, so a row's SIZE is as permanent as its contents. Anything that
 * reaches an emitter from a request body is therefore a write-amplification
 * primitive unless it is clamped at the emitter: the JSON body limit is 50mb
 * and `/oauth/register` is unauthenticated, so one anonymous request could
 * otherwise push megabytes into a jsonb column nobody can delete from. The
 * point of the table is to survive an attack, not to be the vector for the
 * next one.
 *
 * Clamping is lossy on purpose. A redirect URI truncated at 512 characters
 * still identifies where a grant was aimed; the untruncated value is not
 * worth an unbounded column.
 */
export function clampAuditText(value: unknown, maxLength: number): string {
  return String(value ?? "").slice(0, maxLength);
}

/**
 * Bound a caller-supplied ARRAY of strings the same way — both how many
 * entries are kept and how long each one may be.
 *
 * Array length matters as much as element length: `redirect_uris` arrives
 * verbatim from anonymous dynamic client registration, and nothing upstream
 * of the emitter caps how many entries a caller may send. Callers that keep
 * a count alongside the clamped list can still see when truncation happened.
 */
export function clampAuditTextList(
  values: unknown,
  maxItems: number,
  maxLength: number,
): string[] {
  if (!Array.isArray(values)) return [];
  return values.slice(0, maxItems).map((v) => clampAuditText(v, maxLength));
}

export interface CredentialFingerprint {
  /** sha256 of the presented credential — correlates reuse without storing it. */
  sha256: string | null;
  /** Last 4 characters, so an operator can match a row against a key list. */
  last4: string | null;
}

/**
 * Fingerprint a presented credential for storage in `detail`.
 *
 * NEVER store the credential itself. sha256 is one-way, and 4 trailing
 * characters of a high-entropy token identify a key to a human who already
 * holds the key list without being usable by anyone who does not.
 *
 * Delegates to `hashApiKey`/`apiKeyLast4` rather than re-implementing the
 * digest, because `api_keys.key_hash` stores that same encoding and the
 * whole point of the match is the JOIN: an operator answers "which key was
 * this denied request presenting" by comparing `detail.credential.sha256`
 * against a stored `key_hash`. A second local implementation is a second
 * thing to keep in step, and the failure mode of drift is silent — the join
 * simply returns nothing, which is indistinguishable from "that key does not
 * exist". One implementation makes drift impossible instead of tested-for.
 */
export function credentialFingerprint(
  credential: string | undefined | null,
): CredentialFingerprint {
  if (!credential) return { sha256: null, last4: null };
  try {
    return {
      sha256: hashApiKey(credential),
      last4: apiKeyLast4(credential),
    };
  } catch {
    // Unhashable input is not a reason to lose the event — the row still
    // records that a credential was presented and refused.
    return { sha256: null, last4: null };
  }
}
