import logger from "@/utils/logger";

import { normalizeOrigin, resolveTrustedOrigin } from "./cors-policy";

/**
 * Origin policy for the public MCP routes (`/metamcp/*`): which requests that
 * carry an `Origin` header are acceptable, how a refusal is worded, and how
 * much of it may be written down.
 *
 * WHY. The MCP Streamable HTTP transport spec (2025-11-25, "Security Warning")
 * says: "Servers MUST validate the Origin header on all incoming connections
 * to prevent DNS rebinding attacks. If the Origin header is present and
 * invalid, servers MUST respond with HTTP 403 Forbidden." Before this module
 * nothing on these routes read `Origin` at all: the CORS middleware only
 * decided whether to ADD a grant, never whether to answer. The SDK has an
 * option for this (`enableDnsRebindingProtection`), and it is off by default
 * and the wrong tool: it compares raw strings, echoes the header into its
 * error text, and runs after session admission.
 *
 * WHAT IT DOES NOT CLOSE, stated here so nobody reads more into it. A browser
 * sends `Origin` on every cross-origin request and on same-origin requests
 * that are not GET or HEAD, and omits it on a same-origin GET or HEAD. A page
 * on a rebound name is same-origin with that name, so its POSTs carry the
 * attacker's own `Origin` (refused here) while its GETs carry none (passed).
 * An absent `Origin` always passes, because every non-browser client (Node
 * `fetch`, httpx, curl, n8n) sends none. A `Host` allowlist would catch the GET
 * half; it is not here because which `Host` reaches the backend behind the
 * frontend's rewrite is not verified, and a wrong list would refuse real
 * traffic.
 *
 * MODES, `MCP_ORIGIN_POLICY`, the vocabulary `ip_policy_mode` already uses:
 *   audit    (default) every request is served as before; a request whose
 *            Origin would have been refused is recorded, with the status it
 *            was answered with, so a decision to enforce rests on evidence.
 *   enforce  such a request is answered 403 before any endpoint lookup,
 *            credential check or session admission.
 *   off      the guard does nothing.
 * Values are strict (no trimming, no case folding). An unrecognised or empty
 * value resolves to `audit`, never to `off` and never to a refusal, with an
 * ERROR line at boot: the default must not change what a legitimate caller
 * sees, and a typo must not silently switch the guard off.
 *
 * WHICH ORIGINS PASS. `APP_URL`, `EXTRA_TRUSTED_ORIGINS` and loopback when
 * `APP_URL` is loopback (the same resolver the CORS grants use), plus the
 * additive `MCP_ALLOWED_ORIGINS`. That last list passes the guard and grants no
 * CORS: `EXTRA_TRUSTED_ORIGINS` also hands the listed origin credentialed
 * reads of the session relay, which is the wrong trade for a server-side
 * caller that merely sends an `Origin`.
 *
 * Kept free of database and express imports so the policy is unit-testable on
 * its own. Everything here that touches a caller-supplied value returns a
 * bounded, single-line description, never the caller's bytes.
 */

export const ORIGIN_POLICY_ENV = "MCP_ORIGIN_POLICY";
export const ALLOWED_ORIGINS_ENV = "MCP_ALLOWED_ORIGINS";

export const ORIGIN_POLICY_MODES = ["off", "audit", "enforce"] as const;
export type OriginPolicyMode = (typeof ORIGIN_POLICY_MODES)[number];

/** What a request with no usable value gets. See the header for why not `off`. */
export const DEFAULT_ORIGIN_POLICY_MODE: OriginPolicyMode = "audit";

export interface OriginPolicyResolution {
  mode: OriginPolicyMode;
  /** Set when the value was present but not one of the three modes. */
  warning: string | null;
}

/** Pure resolution from an environment, for the request path, boot and tests. */
export function resolveOriginPolicyMode(
  env: NodeJS.ProcessEnv = process.env,
): OriginPolicyResolution {
  const raw = env[ORIGIN_POLICY_ENV];

  if (raw === undefined) {
    return { mode: DEFAULT_ORIGIN_POLICY_MODE, warning: null };
  }
  if (raw === "off" || raw === "audit" || raw === "enforce") {
    return { mode: raw, warning: null };
  }
  return {
    mode: DEFAULT_ORIGIN_POLICY_MODE,
    warning:
      `[origin-policy] ${ORIGIN_POLICY_ENV}=${JSON.stringify(raw.slice(0, 40))} is not off, audit or enforce; ` +
      `running as ${DEFAULT_ORIGIN_POLICY_MODE} (requests are served and untrusted origins recorded) until it is corrected.`,
  };
}

// One report per process for a bad value, from whichever of boot and the
// request path sees it first. The environment of a running container does not
// change, so a repeat would only be noise on the hot path.
let invalidModeReported = false;

function reportInvalidMode(warning: string): void {
  if (invalidModeReported) return;
  invalidModeReported = true;
  logger.error(warning);
}

/**
 * The mode a request is judged under. Read per request, like the CORS
 * allowlist, so the value the process is configured with now is the one used
 * (and a test can set it without controlling import order).
 */
export function currentOriginPolicyMode(): OriginPolicyMode {
  const { mode, warning } = resolveOriginPolicyMode();
  if (warning) reportInvalidMode(warning);
  return mode;
}

// ---------------------------------------------------------------------------
// Judging an Origin
// ---------------------------------------------------------------------------

/**
 * The `MCP_ALLOWED_ORIGINS` entries that are usable, in normalised form, and
 * how many were not. Each entry goes through the same `normalizeOrigin` the
 * CORS allowlist uses, which accepts http(s) only: WHATWG gives every other
 * scheme the same opaque origin (the string "null"), so one `moz-extension://`
 * entry would otherwise trust every sandboxed iframe and extension at once.
 */
function allowedOriginEntries(): { origins: Set<string>; ignored: number } {
  const origins = new Set<string>();
  let ignored = 0;
  for (const entry of (process.env[ALLOWED_ORIGINS_ENV] ?? "").split(",")) {
    if (entry.trim() === "") continue;
    const normalised = normalizeOrigin(entry);
    if (normalised === null) {
      ignored += 1;
    } else {
      origins.add(normalised);
    }
  }
  return { origins, ignored };
}

/** What a value that is not a URL at all is recorded as. */
export const UNPARSEABLE_ORIGIN = "(unparseable)";

export type OriginEvaluation =
  | { kind: "absent" }
  | { kind: "allowed" }
  | { kind: "refused"; described: string };

/**
 * Judge one `Origin` header value.
 *
 * Total: any throw is a refusal, so a hostile value can never turn the guard
 * into an error or a pass. The value is parsed with WHATWG `URL` and compared
 * as an origin, never as a string, so case, a default port and a trailing path
 * do not matter and `https://trusted.example.evil.example`,
 * `https://trusted.example@evil.example` and a different port or scheme do not
 * match. The literal `null` (sandboxed iframes, `file:`, privacy redirects),
 * non-http(s) schemes and a multi-value header (Node joins duplicates with
 * ", ", which no URL parser accepts) are refused.
 *
 * Empty or whitespace-only counts as absent: a browser never sends an empty
 * Origin, so only a hand-built client does, and it is no more a rebinding page
 * than a client that sent nothing.
 */
export function evaluateOrigin(header: unknown): OriginEvaluation {
  try {
    if (header === undefined) return { kind: "absent" };
    if (typeof header !== "string") {
      return { kind: "refused", described: UNPARSEABLE_ORIGIN };
    }
    if (header.trim() === "") return { kind: "absent" };

    if (resolveTrustedOrigin(header) !== null) return { kind: "allowed" };

    const candidate = normalizeOrigin(header);
    if (candidate !== null && allowedOriginEntries().origins.has(candidate)) {
      return { kind: "allowed" };
    }
    return { kind: "refused", described: describeOrigin(header) };
  } catch {
    return { kind: "refused", described: UNPARSEABLE_ORIGIN };
  }
}

// ---------------------------------------------------------------------------
// Describing caller-supplied values for a record
// ---------------------------------------------------------------------------

/**
 * The two caller-chosen values in an event message are capped so that, even
 * when every character has to be escaped by the quoting below (at most two
 * output characters per input character), the whole message still fits the
 * history sink's 1024-character cap with room for the fixed text and both
 * counts: 2 x 200 + 2 x 128 plus about 300 of fixed text is under 1000. A
 * test pins the worst case, so a longer cap or a longer message template
 * cannot silently push the user agent past the cut.
 */
export const ORIGIN_DESCRIPTION_MAX = 200;
export const USER_AGENT_MAX = 128;
const SCHEME_DESCRIPTION_MAX = 32;

/**
 * The form of an Origin that is allowed into a record. Raw attacker bytes never
 * are: a valid http(s) origin is recorded as `URL.origin` (a value this process
 * constructed, at most 200 characters), the literal `null` as `null`, a
 * parseable non-http scheme as `(scheme moz-extension)` (the scheme grammar is
 * letters, digits, `+`, `-` and `.`), and anything else as the constant
 * `(unparseable)`. The result never contains CR or LF.
 */
export function describeOrigin(raw: unknown): string {
  if (typeof raw !== "string") return UNPARSEABLE_ORIGIN;
  const text = raw.trim();
  if (text === "null") return "null";
  try {
    const url = new URL(text);
    if (url.protocol === "http:" || url.protocol === "https:") {
      return url.origin.slice(0, ORIGIN_DESCRIPTION_MAX);
    }
    return `(scheme ${url.protocol.slice(0, -1).slice(0, SCHEME_DESCRIPTION_MAX)})`;
  } catch {
    return UNPARSEABLE_ORIGIN;
  }
}

/**
 * A caller-supplied header value as it appears inside an event message: cut to
 * `max` characters, anything outside printable ASCII replaced by `?`, then
 * JSON-quoted. Quoting is what makes the value unmistakably one token in a log
 * line (a `"` or a backslash cannot end it early, and the replacement removes
 * every control character a line-oriented viewer could act on), and the cut is
 * what bounds a row whose message the sink only clamps at its far end.
 */
export function quoteBoundedHeader(value: unknown, max: number): string {
  const text = typeof value === "string" ? value.slice(0, max) : "";
  return JSON.stringify(text.replace(/[^\x20-\x7e]/g, "?"));
}

export type SecFetchSiteDescription =
  | "same-origin"
  | "same-site"
  | "cross-site"
  | "none"
  | "other"
  | "absent";

/**
 * `Sec-Fetch-Site`, clamped to its four defined values. Browsers set it and
 * scripts cannot, so it helps an operator tell a browser from a server-side
 * client sending an `Origin`. Anything else is `other`, never echoed.
 */
export function describeSecFetchSite(value: unknown): SecFetchSiteDescription {
  if (value === undefined) return "absent";
  if (
    value === "same-origin" ||
    value === "same-site" ||
    value === "cross-site" ||
    value === "none"
  ) {
    return value;
  }
  return "other";
}

// ---------------------------------------------------------------------------
// The request, classified
// ---------------------------------------------------------------------------

export type RouteFamily = "mcp" | "sse" | "message" | "api" | "admin" | "other";

function pathSegments(path: string): string[] {
  return path.split("/").filter((segment) => segment !== "");
}

/**
 * Which kind of route a path under the `/metamcp` mount is. The first segment
 * is the endpoint name (caller-supplied text, never recorded in an event
 * message); the second selects the family. Express matches routes
 * case-insensitively, so this does too.
 */
export function classifyRoute(path: string): RouteFamily {
  const family = pathSegments(path)[1]?.toLowerCase();
  switch (family) {
    case "mcp":
    case "sse":
    case "message":
    case "api":
    case "admin":
      return family;
    default:
      return "other";
  }
}

const ENDPOINT_NAME_MAX = 128;

/** The first path segment, clamped, for the one record that stores it. */
export function endpointNameFromPath(path: string): string | null {
  const first = pathSegments(path)[0];
  return first === undefined ? null : first.slice(0, ENDPOINT_NAME_MAX);
}

const LIVENESS_PATHS: ReadonlySet<string> = new Set([
  "/",
  "/health",
  "/health/sessions",
]);

/**
 * Whether a request is a liveness probe: GET or HEAD on exactly `/`, `/health`
 * or `/health/sessions` under the mount. Exact paths, never a `/health` prefix:
 * `/:endpoint_name/mcp` is a valid route for an endpoint NAMED `health`, so
 * `/health/mcp` is a real data-plane request and is not exempt.
 */
export function isLivenessRequest(method: string, path: string): boolean {
  return (method === "GET" || method === "HEAD") && LIVENESS_PATHS.has(path);
}

const KNOWN_METHODS: ReadonlySet<string> = new Set([
  "GET",
  "POST",
  "DELETE",
  "OPTIONS",
  "HEAD",
  "PUT",
  "PATCH",
]);

/** The request method, clamped to the standard set so a record cannot carry free text. */
export function clampMethod(method: string): string {
  return KNOWN_METHODS.has(method) ? method : "OTHER";
}

/**
 * What the request was answered with. `refused` is the guard's own 403 in
 * `enforce`; the rest classify the status an `audit`-mode request was served.
 */
export type OriginEventClass = "served" | "denied" | "error" | "refused";

export function statusClass(
  status: number,
): Exclude<OriginEventClass, "refused"> {
  if (status >= 500) return "error";
  if (status >= 400) return "denied";
  return "served";
}

// ---------------------------------------------------------------------------
// The refusal itself
// ---------------------------------------------------------------------------

/**
 * The 403 body. The SDK's own error shape (`createJsonErrorResponse(403,
 * -32000, ...)`), which the transport spec allows ("MAY comprise a JSON-RPC
 * error response that has no id"). The refused value is never echoed: the SDK's
 * check puts the header into its error text, which hands a reflected string
 * back to whoever sent it.
 */
export const ORIGIN_REFUSAL_BODY = Object.freeze({
  jsonrpc: "2.0",
  error: Object.freeze({ code: -32000, message: "Origin not allowed" }),
  id: null,
});

// ---------------------------------------------------------------------------
// Volume bounds
// ---------------------------------------------------------------------------

/**
 * A refused Origin is a value any caller on the internet controls the rate and
 * the variety of, and the cheapest way to send one needs no credential at all.
 * Every record this module asks for is therefore bounded three ways, the same
 * discipline `session-binding-denial` applies to the other refusal a caller
 * drives:
 *
 *  - PER KEY. Refusals with the same key (mode, origin, route family, method,
 *    status class, credential present) collapse to one record per 60 s. The
 *    suppressed attempts are COUNTED and the count rides on the next record for
 *    that key, so "once" and "40,000 times in a minute" stay distinguishable.
 *  - PER HOUR, PER BUCKET. At most 60 event records per fixed hour. Events go
 *    into one of two buckets so a flood cannot hide the one that matters: the
 *    `served` bucket holds only events for requests that were answered below
 *    400 (those are the evidence that a legitimate caller would be refused),
 *    and the `other` bucket holds everything else. A flood without a valid
 *    credential is answered 401, so it can only fill `other`.
 *  - AUDIT ROWS. `audit_log` is append-only with no prune path, so its rows get
 *    a much lower ceiling (20 an hour) and their own key map and counts.
 *
 * Nothing is dropped silently: a record dropped by an hourly ceiling is
 * counted, the count rides on the next record of that bucket, and the first
 * drop in a window writes one WARN line (stdout only, not the 30-day table).
 * The enforce-mode 403 itself is never throttled, only its recording, and the
 * growth tripwire for the audit tables remains the backstop for a sustained
 * flood. This is a per-process, in-memory bound: it resets on restart, which is
 * the same trade the sibling throttles make.
 */
export const ORIGIN_REPORT_INTERVAL_MS = 60 * 1000;
export const ORIGIN_REPORT_MAX_KEYS = 1_000;
export const ORIGIN_WINDOW_MS = 60 * 60 * 1000;
export const ORIGIN_EVENT_CEILING_PER_WINDOW = 60;
export const ORIGIN_AUDIT_CEILING_PER_WINDOW = 20;

/**
 * Separator for the composite key. NUL cannot appear in a described origin, a
 * route family, a method or a class, so the parts cannot run together into a
 * key two different tuples both produce. Written as the ESCAPE, never as a
 * literal NUL in source (a raw NUL makes git treat the file as binary and drops
 * it out of review).
 */
export const ORIGIN_KEY_SEPARATOR = "\u0000";

export type OriginEventBucket = "served" | "other";

export interface OriginReportDecision {
  report: boolean;
  /**
   * Requests with this key swallowed since its last record. Consumed (and
   * reset) only when `report` is true; when false it is the running count.
   */
  suppressed: number;
  /**
   * Records of this bucket dropped by the hourly ceiling since the last record
   * of the bucket. Consumed only when `report` is true; 0 otherwise.
   */
  droppedByCeiling: number;
}

interface KeyEntry {
  windowStartedAt: number;
  suppressed: number;
}

interface BucketState {
  windowStartedAt: number;
  reported: number;
  dropped: number;
  warned: boolean;
}

class VolumeLimiter {
  private readonly keys = new Map<string, KeyEntry>();
  private readonly buckets = new Map<string, BucketState>();

  constructor(
    private readonly ceiling: number,
    private readonly label: string,
  ) {}

  decide(key: string, bucketName: string, now: number): OriginReportDecision {
    const entry = this.keys.get(key);

    if (entry && now - entry.windowStartedAt < ORIGIN_REPORT_INTERVAL_MS) {
      entry.suppressed += 1;
      return {
        report: false,
        suppressed: entry.suppressed,
        droppedByCeiling: 0,
      };
    }

    const carried = entry?.suppressed ?? 0;
    // Cleared on overflow, like the sibling throttles: a flood of distinct
    // origins cannot grow this without bound, and the hourly ceiling below
    // still caps what any of it reports. The counts carried by the cleared
    // keys are lost with them, a deliberate bounded-memory trade.
    if (!entry && this.keys.size >= ORIGIN_REPORT_MAX_KEYS) {
      this.keys.clear();
    }

    let bucket = this.buckets.get(bucketName);
    if (!bucket) {
      bucket = { windowStartedAt: now, reported: 0, dropped: 0, warned: false };
      this.buckets.set(bucketName, bucket);
    } else if (now - bucket.windowStartedAt >= ORIGIN_WINDOW_MS) {
      // The window is fixed, not sliding. The drop count survives it: it is
      // owed to the next record this bucket writes.
      bucket.windowStartedAt = now;
      bucket.reported = 0;
      bucket.warned = false;
    }

    if (bucket.reported >= this.ceiling) {
      bucket.dropped += 1;
      if (!bucket.warned) {
        bucket.warned = true;
        logger.warn(
          `[origin-policy] hourly ceiling of ${this.ceiling} ${this.label} reached (bucket ${bucketName}); ` +
            `further ones are counted and carried on the next one written, not recorded individually.`,
        );
      }
      // The key still opens a new window, so the same refused origin does not
      // retry the ceiling on every request, and keeps what it had swallowed.
      this.keys.set(key, { windowStartedAt: now, suppressed: carried });
      return { report: false, suppressed: carried, droppedByCeiling: 0 };
    }

    bucket.reported += 1;
    const droppedByCeiling = bucket.dropped;
    bucket.dropped = 0;
    this.keys.set(key, { windowStartedAt: now, suppressed: 0 });
    return { report: true, suppressed: carried, droppedByCeiling };
  }

  reset(): void {
    this.keys.clear();
    this.buckets.clear();
  }
}

const eventLimiter = new VolumeLimiter(
  ORIGIN_EVENT_CEILING_PER_WINDOW,
  "origin-policy events",
);
const auditLimiter = new VolumeLimiter(
  ORIGIN_AUDIT_CEILING_PER_WINDOW,
  "origin-policy audit rows",
);

/** Should this refusal be written to the activity history, and with what counts? */
export function decideOriginReport(
  key: string,
  bucket: OriginEventBucket,
  now: number = Date.now(),
): OriginReportDecision {
  return eventLimiter.decide(key, bucket, now);
}

/** Should this refusal also be written to `audit_log` (enforce only)? */
export function decideAuditRow(
  key: string,
  now: number = Date.now(),
): OriginReportDecision {
  return auditLimiter.decide(key, "audit", now);
}

export function originReportKey(parts: {
  mode: OriginPolicyMode;
  described: string;
  route: RouteFamily;
  method: string;
  eventClass: OriginEventClass;
  credentialPresent: boolean;
}): string {
  return [
    parts.mode,
    parts.described,
    parts.route,
    parts.method,
    parts.eventClass,
    parts.credentialPresent ? "credential" : "no-credential",
  ].join(ORIGIN_KEY_SEPARATOR);
}

// ---------------------------------------------------------------------------
// The record
// ---------------------------------------------------------------------------

export interface OriginEventFields {
  mode: "audit" | "enforce";
  /** Output of `describeOrigin`. */
  origin: string;
  route: RouteFamily;
  method: string;
  eventClass: OriginEventClass;
  status: number;
  credentialPresent: boolean;
  secFetchSite: SecFetchSiteDescription;
  /** The raw header; quoted and bounded here. */
  userAgent: unknown;
  suppressed: number;
  droppedByCeiling: number;
}

/**
 * The one-line event message. The origin and the User-Agent, the two values a
 * caller chooses, are JSON-quoted and bounded (see `quoteBoundedHeader`); the
 * endpoint name is left out entirely because it is caller text read before any
 * lookup. The User-Agent comes last so that, in the worst case where quoting
 * stretches a value, the sink's own length cap cuts the least useful part.
 */
export function formatOriginEventMessage(fields: OriginEventFields): string {
  const credential = fields.credentialPresent
    ? "credential present"
    : "credential absent";
  const head =
    fields.mode === "enforce"
      ? `origin-policy enforce: refused Origin ${quoteBoundedHeader(fields.origin, ORIGIN_DESCRIPTION_MAX)}, ` +
        `${fields.method} ${fields.route}, ${fields.status}, ${credential}, sec-fetch-site ${fields.secFetchSite}`
      : `origin-policy audit: Origin ${quoteBoundedHeader(fields.origin, ORIGIN_DESCRIPTION_MAX)}, ` +
        `${fields.method} ${fields.route}, ${fields.eventClass} (${fields.status}), ${credential}, ` +
        `sec-fetch-site ${fields.secFetchSite}; would be refused under ${ORIGIN_POLICY_ENV}=enforce`;

  const parts = [head];
  if (fields.suppressed > 0) {
    parts.push(
      `${fields.suppressed} similar request(s) suppressed since the last event`,
    );
  }
  if (fields.droppedByCeiling > 0) {
    parts.push(`${fields.droppedByCeiling} dropped by the hourly ceiling`);
  }
  parts.push(
    typeof fields.userAgent === "string"
      ? `ua ${quoteBoundedHeader(fields.userAgent, USER_AGENT_MAX)}`
      : "ua absent",
  );
  return parts.join("; ");
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

let bootLogged = false;

/**
 * One boot line saying which mode is in effect and what it does, so the
 * posture is legible from the boot log rather than something to prove by hand.
 * An invalid value is an ERROR (see the header); `off` is a WARN, like the
 * other switches that disable a guard. `enforce` with `APP_URL` unset or
 * unusable warns, because nothing would be trusted: the Swagger try-it-out
 * page, whose Origin is the app's own, would be refused.
 *
 * Latched, so "one line at boot" holds if the boot path calls it twice.
 */
export function logOriginPolicyBootState(): void {
  if (bootLogged) return;
  bootLogged = true;

  const { mode, warning } = resolveOriginPolicyMode();
  if (warning) reportInvalidMode(warning);

  const { origins, ignored } = allowedOriginEntries();
  const allowed =
    `${ALLOWED_ORIGINS_ENV}: ${origins.size} origin(s)` +
    (ignored > 0 ? `, ${ignored} ignored (not http(s) origins)` : "");

  switch (mode) {
    case "off":
      logger.warn(
        `[origin-policy] ${ORIGIN_POLICY_ENV}=off: the Origin header on /metamcp requests is not checked.`,
      );
      break;
    case "audit":
      logger.info(
        `[origin-policy] ${ORIGIN_POLICY_ENV}=audit: requests with an Origin other than APP_URL, ` +
          `EXTRA_TRUSTED_ORIGINS or ${ALLOWED_ORIGINS_ENV} are served and recorded as would-be refusals (${allowed}).`,
      );
      break;
    case "enforce":
      logger.info(
        `[origin-policy] ${ORIGIN_POLICY_ENV}=enforce: requests with an Origin other than APP_URL, ` +
          `EXTRA_TRUSTED_ORIGINS or ${ALLOWED_ORIGINS_ENV} are refused with 403 (${allowed}).`,
      );
      if (normalizeOrigin(process.env.APP_URL) === null) {
        logger.warn(
          `[origin-policy] ${ORIGIN_POLICY_ENV}=enforce but APP_URL is unset or not an http(s) origin: ` +
            `the app's own origin is not trusted, so same-origin browser requests (the Swagger try-it-out page) will be refused.`,
        );
      }
      break;
  }
}

/** Test seam: forget the boot latch, the invalid-value latch and every throttle. */
export function __resetOriginPolicyStateForTesting(): void {
  bootLogged = false;
  invalidModeReported = false;
  eventLimiter.reset();
  auditLimiter.reset();
}
