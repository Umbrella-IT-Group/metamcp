import { createHash } from "node:crypto";

import type { FetchLike } from "@modelcontextprotocol/sdk/shared/transport.js";

import logger from "@/utils/logger";

import { getInjectedServerNames } from "../m365/config";
import type { CallerContext } from "./caller-context-store";
import { getCallerContext } from "./caller-context-store";

/**
 * `X-Umbrella-User-Id` on the POOLED data plane: the caller's identity as THIS
 * GATEWAY verified it, for the backends that are allowed to act on it.
 *
 * WHAT IT IS. A backend named in `VERIFIED_CALLER_SERVER_NAMES` receives the
 * better-auth `users.id` of the person whose credential authenticated the
 * inbound request, on every request that can execute backend code. The first
 * consumer is a team server whose tools act for "the person asking" (one
 * teammate's agent asks, another's answers), so the backend must know who is
 * calling, and must never learn it from the caller. A wrong value here lets
 * one employee's agent act as another's.
 *
 * WHERE THE VALUE COMES FROM, AND NOWHERE ELSE. `actsAsUserId ?? userId` from
 * the request-scoped caller binding (`caller-context-store`), which every
 * public transport builds per request from the fields `authenticateApiKey`
 * stamps (`apiKeyUserId`, `apiKeyActsAsUserId`, `oauthUserId`), and which the
 * admin Inspector's namespace surface builds from the signed-in session user.
 * An api-key caller is the key owner unless an admin bound the key to act as
 * someone (`api_keys.acts_as_user_id`, migration 0024); an OAuth caller is the
 * OAuth subject. Disabled accounts never get this far: the auth middleware
 * refuses them before stamping anything. Nothing the caller sends is read.
 * In particular `X-MCP-Actor` (`asserted-actor.ts`) is caller-ASSERTED and is
 * never consulted here.
 *
 * STRIP, ALWAYS; SET, ONLY WHEN PROVEN. For a named backend, any
 * `x-umbrella-user-id` already on the outgoing request is deleted first,
 * whatever request it is: a value stored on the server row, or one some future
 * code path copied from the inbound request, must never arrive. The verified
 * id is then set only when the request can execute backend code AND the
 * binding resolved an identity. No identity means no header, and the backend
 * refuses; it never falls back to the key owner when an acts-as binding is
 * present but blank.
 *
 * WHY "CAN EXECUTE BACKEND CODE" IS DECIDED POSITIVELY. One pooled backend
 * connection serves many callers, and its control traffic does not belong to
 * any one of them: a cold connect runs inside whichever request triggered it,
 * and SDK reconnect timers and the standing GET stream keep that opening
 * scope (see `asserted-actor.ts`, CONNECTION CONTROL TRAFFIC). So the header
 * is set only on a POST whose body parses to a JSON-RPC request that is not
 * the handshake, a listing or a notification. Everything else carries NO
 * identity: a response to a server-initiated request (sent from the opening
 * scope, and completing a request the backend already holds rather than
 * invoking a tool), an unparseable or non-string body, PUT and the rest. The
 * m365 token gate (`requestNeedsUserToken`) answers the same question. It
 * also sends nothing on a strictly shaped response, but mints when it cannot
 * classify a message, because there a missing token only fails the call;
 * here an unsure answer could name the wrong person. The two agree on every
 * request and every strictly shaped response, and differ only on malformed
 * messages; `verified-caller.test.ts` pins both the agreement and the named
 * divergences.
 *
 * WHY NOT THE M365 INJECTION. `lib/m365/injected-fetch.ts` sets the same
 * header name, but it also mints a Graph token, reads its own user context
 * (OAuth and acts-as only, never a plain key owner), and owns the backends in
 * `M365_INJECTED_SERVER_NAMES`. A server in both lists would get two writers
 * for one header, so the gateway refuses to start with an overlap
 * (`assertVerifiedCallerConfig`) and refuses to build that transport.
 *
 * INTERNAL DESTINATIONS ONLY. The pool's guarded fetch drops this header on
 * any hop whose destination is not internal (`internalOnlyHeaders` in
 * `client.ts`), so a user id never reaches a third-party server, and the
 * gateway trust header (`X-Gateway-Auth`, `url-guard.ts`) rides the same
 * internal hops. A backend must check that trust header before it believes
 * this one: the identity is only as good as the proof that the gateway sent
 * it.
 *
 * NO INJECTION BY DEFAULT. With `VERIFIED_CALLER_SERVER_NAMES` unset or empty
 * no backend is named and `getVerifiedCallerFetchForServer` returns the base
 * fetch itself. The Inspector still reserves this custom header, and the
 * pool still strips it on non-internal hops, even with an empty list.
 *
 * NEVER FROM A SERVER ROW, ON ANY SERVER. Both headers are gateway-set only.
 * The pool drops a stored copy of either from every remote row before its
 * transport is built, whatever the row's name (`storedHeadersForPool` in
 * `client.ts`), the admin Inspector drops them from every row it matches
 * (`storedHeadersFor` in `routers/mcp-proxy/server.ts`), and server create,
 * update and bulk import refuse either name as a stored header key
 * (`mcp-servers.impl.ts`).
 *
 * `X-Umbrella-Caller`: WHICH CREDENTIAL, AS WELL AS WHO. The user id names a
 * person, but one person may hold several credentials (a key per machine, an
 * OAuth client per app), and a backend that hands out a session or a grant to
 * "the caller" needs to know which of them asked, so that another of that
 * person's credentials, or another person's, cannot pick it up. A named
 * backend therefore also receives `X-Umbrella-Caller`, under exactly the
 * rules above: deleted in every casing on every request, set only on a
 * request that can execute backend code, read only from the request-scoped
 * binding, internal hops only, dropped on a method-rewriting redirect,
 * reserved in the Inspector. Its value is `v1.` followed by unpadded base64url
 * of one UTF-8 JSON object whose keys are always, in this order:
 *
 *   v      1, the format version.
 *   uid    the same user id `X-Umbrella-User-Id` carries.
 *   cred   the credential that authenticated the request:
 *          `api_key:<api_keys.uuid>`, `oauth:<oauth client id>`, or
 *          `session` for the Inspector's signed-in admin. For an OAuth client
 *          whose id is an https URL (a client metadata document client, whose
 *          id cannot fit this grammar) the client id is replaced by
 *          `cimd.<32 hex>.<16 hex>`: the first 32 hex characters of the
 *          SHA-256 of the URL's UTF-8 bytes, then the first 16 hex characters
 *          of the access token's family id (its uuid without hyphens). The
 *          family id is per grant, so two installs of one product stay two
 *          credentials, the way two dynamically registered clients are. The
 *          value is a binding key, not a label: a backend cannot recover the
 *          URL from it.
 *   email  the account email of `uid`, or null when it could not be read.
 *   label  the gateway's display label for the credential, or null.
 *   rid    the gateway's audit request id for this request, or null.
 *
 * Only `uid` and `cred` say who is calling; `email`, `label` and `rid` are
 * descriptive and never part of what a backend should bind to. The header is
 * set only when BOTH `uid` and `cred` resolve to values a strict reader
 * accepts, so a backend never receives half an identity in it; the user id
 * header keeps its own rule and is still sent without a credential (a
 * backend that reads only the user id sees no change). Both headers are
 * built from one binding in one step, so when both are present they always
 * name the same user. `verified-caller-v1-vectors.json` beside this file pins
 * the exact bytes for a set of inputs, so a reader in another language can
 * test against the same values.
 */
export const VERIFIED_CALLER_HEADER = "x-umbrella-user-id";

/** The structured caller header. See the module comment for its format. */
export const VERIFIED_CALLER_IDENTITY_HEADER = "x-umbrella-caller";

/** The prefix of every `X-Umbrella-Caller` value in this format version. */
export const VERIFIED_CALLER_IDENTITY_PREFIX = "v1.";

/**
 * The grammar a strict reader applies to the two identifying fields. The
 * encoder checks its own output against the same patterns and sends no header
 * when either fails, rather than a value the reader would refuse.
 */
const UID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const API_KEY_UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const OAUTH_CLIENT_ID_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;

/**
 * The URL-shaped client ids that get an alias in place of themselves.
 *
 * `URL_CLIENT_ID_MAX_LENGTH` is the longest client metadata URL the OAuth
 * server stores (`CIMD_CLIENT_ID_MAX_LENGTH` in `routers/oauth/cimd-config`;
 * this module may not import the router, so the number is repeated here and a
 * test pins the two equal). Every id the registration side admits has to be
 * covered by the alias, or a valid client would silently lose its
 * `X-Umbrella-Caller` header: a narrower pattern here once stopped at 508
 * characters while the id check allowed 512.
 */
export const URL_CLIENT_ID_MAX_LENGTH = 512;
const URL_CLIENT_ID_PATTERN = /^https:\/\/\S+$/;
/** Hex characters kept from the SHA-256 of the client id URL. */
export const URL_CLIENT_ID_HASH_LENGTH = 32;
/** Hex characters kept from the token family id (a uuid without hyphens). */
export const URL_CLIENT_FAMILY_LENGTH = 16;

/**
 * Length limits for the descriptive fields, in Unicode code points (what a
 * Python `len` counts, not UTF-16 units), and for the whole encoded value.
 * The field limits keep the worst case well under the encoded limit.
 */
export const VERIFIED_CALLER_IDENTITY_LIMITS = Object.freeze({
  email: 254,
  label: 200,
  rid: 64,
  encoded: 4096,
});

/**
 * Characters a descriptive field may not contain: controls (Cc), format
 * characters such as bidirectional overrides and zero-width marks (Cf), line
 * and paragraph separators (Zl, Zp), and lone UTF-16 surrogates (Cs), which
 * have no UTF-8 encoding. A value containing any of them is sent as null,
 * never cleaned up, because a cleaned value would read as something the
 * account never said.
 */
const FORBIDDEN_DISPLAY_CHARACTERS = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u;

/** Marks a label the gateway shortened, so a reader can see it was cut. */
const SHORTENED_MARK = "…";

/** The label for the Inspector's credential. See `verifiedCallerLabel`. */
const INSPECTOR_LABEL = "Inspector";

export const VERIFIED_CALLER_SERVER_NAMES_ENV = "VERIFIED_CALLER_SERVER_NAMES";

/**
 * The backends that receive the verified caller, by server name.
 *
 * Comma-separated, each name trimmed, empty entries dropped, duplicates
 * collapsed, matched exactly (the same parsing as `M365_INJECTED_SERVER_NAMES`
 * in `lib/m365/config.ts`). Read fresh on each call, as that list is, so tests
 * stay deterministic; the value is constant for the life of the process.
 */
export function getVerifiedCallerServerNames(): Set<string> {
  const raw = process.env[VERIFIED_CALLER_SERVER_NAMES_ENV] ?? "";
  return new Set(
    raw
      .split(",")
      .map((name) => name.trim())
      .filter(Boolean),
  );
}

function overlapError(names: readonly string[]): Error {
  return new Error(
    `${VERIFIED_CALLER_SERVER_NAMES_ENV} and M365_INJECTED_SERVER_NAMES (default "m365") ` +
      `both name: ${names.join(", ")}. Each backend may receive X-Umbrella-User-Id from ` +
      `one source only; remove the server from one of the two lists.`,
  );
}

/**
 * Boot check. Throws when a server is named in both
 * `VERIFIED_CALLER_SERVER_NAMES` and `M365_INJECTED_SERVER_NAMES`, and logs
 * which servers receive the verified caller, so the posture is in the boot
 * log. `index.ts` calls it at module scope, before any route is registered,
 * so a bad configuration stops the gateway instead of serving with two
 * writers for one identity header.
 */
export function assertVerifiedCallerConfig(): void {
  const names = getVerifiedCallerServerNames();
  const m365 = getInjectedServerNames();
  const overlap = [...names].filter((name) => m365.has(name)).sort();
  if (overlap.length > 0) throw overlapError(overlap);
  if (names.size > 0) {
    logger.info(
      `Verified caller identity: X-Umbrella-User-Id and X-Umbrella-Caller are set from the authenticated caller for: ${[...names].sort().join(", ")}`,
    );
  }
}

/**
 * JSON-RPC methods that never execute a tool or read a user's data: the
 * handshake and the registry listings, the same list as the m365 token gate
 * (`lib/m365/injected-fetch.ts`). `notifications/*` is matched by prefix.
 */
const NON_EXECUTING_RPC_METHODS: ReadonlySet<string> = new Set([
  "initialize",
  "ping",
  "tools/list",
  "prompts/list",
  "resources/list",
  "resources/templates/list",
]);
const NOTIFICATION_METHOD_PREFIX = "notifications/";

function isExecutingRpcRequest(message: unknown): boolean {
  if (typeof message !== "object" || message === null) return false;
  const method = (message as { method?: unknown }).method;
  return (
    typeof method === "string" &&
    !NON_EXECUTING_RPC_METHODS.has(method) &&
    !method.startsWith(NOTIFICATION_METHOD_PREFIX)
  );
}

/**
 * Whether this outgoing request can execute backend code and so carries the
 * verified caller. POSITIVE: true only for a POST whose string body parses to
 * a JSON-RPC message, or a batch, containing at least one request that is not
 * the handshake, a listing or a notification. Every other request is false.
 *
 * No body-size shortcut, as in the m365 gate: here an unparsed body would
 * mean "no identity", which would refuse a legitimate long tool call. The
 * body is already in memory as a string, and only named backends pay for the
 * parse.
 */
export function requestExecutesBackendCode(init?: RequestInit): boolean {
  if ((init?.method ?? "GET").toUpperCase() !== "POST") return false;
  const body = init?.body;
  if (typeof body !== "string") return false;
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return false;
  }
  const messages: unknown[] = Array.isArray(parsed) ? parsed : [parsed];
  return messages.some(isExecutingRpcRequest);
}

/**
 * The verified user id for a caller binding: `actsAsUserId ?? userId`, or
 * undefined. Literally that expression: a blank acts-as binding yields no
 * identity rather than falling back to the key owner, because a broken
 * binding must not quietly act as the admin who issued the key.
 */
export function verifiedCallerUserId(
  caller: CallerContext | undefined,
): string | undefined {
  const id = caller?.actsAsUserId ?? caller?.userId;
  return typeof id === "string" && id !== "" ? id : undefined;
}

/**
 * The credential id for an OAuth client whose id is an https URL:
 * `cimd.<sha256(url) prefix>.<token family id prefix>`, 54 characters, inside
 * the 128-character grammar a reader accepts, or undefined.
 *
 * Undefined when the id is not URL-shaped, is over `URL_CLIENT_ID_MAX_LENGTH`,
 * or no family id came with it: the caller then carries no credential, as for
 * any other malformed id. A real access token always has a family id (the
 * column is NOT NULL), so for a valid client this never takes that branch.
 *
 * Both halves are one-way and stable. The URL half is the client's identity;
 * the family half is the grant, constant across refreshes of one connection
 * and different for every new connection, so a backend that binds a session
 * to `cred` keeps two installs of the same product apart. A DCR or admin id
 * cannot contain `:` or `/`, so a URL id cannot collide with one of them.
 */
function urlClientCredentialId(
  clientId: string,
  familyId: unknown,
): string | undefined {
  if (
    clientId.length > URL_CLIENT_ID_MAX_LENGTH ||
    !URL_CLIENT_ID_PATTERN.test(clientId) ||
    typeof familyId !== "string" ||
    !API_KEY_UUID_PATTERN.test(familyId)
  ) {
    return undefined;
  }
  const urlHash = createHash("sha256")
    .update(clientId, "utf8")
    .digest("hex")
    .slice(0, URL_CLIENT_ID_HASH_LENGTH);
  const family = familyId
    .replaceAll("-", "")
    .slice(0, URL_CLIENT_FAMILY_LENGTH);
  return `cimd.${urlHash}.${family}`;
}

/**
 * The credential a caller binding authenticated with, as `X-Umbrella-Caller`
 * names it, or undefined.
 *
 * Chosen by the binding's auth method, never by which fields happen to be
 * present: `api_key:<uuid>` needs the key's uuid in its canonical lowercase
 * form, `oauth:<client id>` needs the OAuth client the access token was
 * issued to, and the Inspector's `session` stands for its signed-in admin.
 * Any other method, or a missing or malformed id, is no credential.
 */
export function verifiedCallerCredential(
  caller: CallerContext | undefined,
): string | undefined {
  switch (caller?.authMethod) {
    case "api_key": {
      const uuid = caller.apiKeyUuid;
      return typeof uuid === "string" && API_KEY_UUID_PATTERN.test(uuid)
        ? `api_key:${uuid}`
        : undefined;
    }
    case "oauth": {
      const clientId = caller.oauthClientId;
      if (typeof clientId !== "string") return undefined;
      if (OAUTH_CLIENT_ID_PATTERN.test(clientId)) return `oauth:${clientId}`;
      const alias = urlClientCredentialId(clientId, caller.oauthTokenFamilyId);
      return alias === undefined ? undefined : `oauth:${alias}`;
    }
    case "session":
      return "session";
    default:
      return undefined;
  }
}

/**
 * A descriptive field as it is sent: trimmed, then null when it is not a
 * string, is empty, or contains a forbidden character. Over its limit, a
 * label is shortened visibly (the last kept code point is replaced by an
 * ellipsis); an email or a request id is sent as null instead, because a
 * shortened email names someone else and a shortened request id joins
 * nothing.
 */
function descriptiveField(
  value: unknown,
  limit: number,
  overLimit: "shorten" | "null",
): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (trimmed === "" || FORBIDDEN_DISPLAY_CHARACTERS.test(trimmed)) {
    return null;
  }
  const codePoints = Array.from(trimmed);
  if (codePoints.length <= limit) return trimmed;
  if (overLimit === "null") return null;
  return codePoints.slice(0, limit - 1).join("") + SHORTENED_MARK;
}

/**
 * The display label for a credential: the label the router resolved for an
 * API key or OAuth caller (`clientName`), and "Inspector" for the
 * Inspector's session. The Inspector's caller binding deliberately carries no
 * `clientName`, because that field becomes the audit row's consumer column
 * and the Inspector is not a consumer (`routers/mcp-proxy/metamcp.ts`); the
 * header names the credential instead.
 */
function verifiedCallerLabel(
  caller: CallerContext | undefined,
  credential: string,
): unknown {
  return credential === "session" ? INSPECTOR_LABEL : caller?.clientName;
}

/**
 * The `X-Umbrella-Caller` value for a caller binding, or undefined when
 * either the user id or the credential does not resolve.
 *
 * The JSON object is built as a literal in the fixed key order (v, uid, cred,
 * email, label, rid); `JSON.stringify` keeps insertion order for these
 * non-numeric keys, so the bytes for one input are always the same.
 */
export function encodeVerifiedCaller(
  caller: CallerContext | undefined,
): string | undefined {
  const uid = verifiedCallerUserId(caller);
  const cred = verifiedCallerCredential(caller);
  if (uid === undefined || !UID_PATTERN.test(uid) || cred === undefined) {
    return undefined;
  }
  const limits = VERIFIED_CALLER_IDENTITY_LIMITS;
  const json = JSON.stringify({
    v: 1,
    uid,
    cred,
    email: descriptiveField(caller?.email, limits.email, "null"),
    label: descriptiveField(
      verifiedCallerLabel(caller, cred),
      limits.label,
      "shorten",
    ),
    rid: descriptiveField(caller?.requestId, limits.rid, "null"),
  });
  const value =
    VERIFIED_CALLER_IDENTITY_PREFIX +
    Buffer.from(json, "utf8").toString("base64url");
  // Unreachable with the field limits above (the test suite pins the worst
  // case); kept so a later field cannot push a value past what a reader
  // accepts.
  return value.length <= limits.encoded ? value : undefined;
}

/**
 * Wrap a pooled transport's fetch so each outgoing request carries the
 * verified caller of the inbound request it serves, and no other value.
 * See the module comment for the strip and set rules.
 *
 * Both headers are deleted first, on every request. The user id is then set
 * under its own rule even when no credential resolves, and the structured
 * header only when both its identifying fields do.
 */
export function withVerifiedCaller(baseFetch: FetchLike): FetchLike {
  return async (url, init) => {
    const headers = new Headers(init?.headers);
    headers.delete(VERIFIED_CALLER_HEADER);
    headers.delete(VERIFIED_CALLER_IDENTITY_HEADER);
    if (requestExecutesBackendCode(init)) {
      const caller = getCallerContext();
      const userId = verifiedCallerUserId(caller);
      if (userId) headers.set(VERIFIED_CALLER_HEADER, userId);
      const identity = encodeVerifiedCaller(caller);
      if (identity) headers.set(VERIFIED_CALLER_IDENTITY_HEADER, identity);
    }
    return baseFetch(url, { ...init, headers });
  };
}

/**
 * The `client.ts` wiring hook: the wrapped fetch for a named server, and
 * `baseFetch` itself (the same function, untouched) for every other server.
 * Throws for a server that is also in the m365 list; the boot check makes
 * that unreachable in a running gateway, and this keeps it unreachable for
 * any caller that bypasses the boot path.
 */
export function getVerifiedCallerFetchForServer(
  serverName: string,
  baseFetch: FetchLike,
): FetchLike {
  if (!getVerifiedCallerServerNames().has(serverName)) return baseFetch;
  if (getInjectedServerNames().has(serverName)) {
    throw overlapError([serverName]);
  }
  return withVerifiedCaller(baseFetch);
}

const VERIFIED_CALLER_HEADER_NAMES: ReadonlySet<string> = new Set([
  VERIFIED_CALLER_HEADER,
  VERIFIED_CALLER_IDENTITY_HEADER,
]);

/**
 * Whether a header name is one of the two verified caller headers
 * (`X-Umbrella-User-Id`, `X-Umbrella-Caller`), in any casing and with
 * surrounding whitespace ignored. The admin Inspector uses it to refuse an
 * `x-custom-auth-header` that names either (`routers/mcp-proxy/server.ts`).
 */
export function isVerifiedCallerHeaderName(name: unknown): boolean {
  return (
    typeof name === "string" &&
    VERIFIED_CALLER_HEADER_NAMES.has(name.trim().toLowerCase())
  );
}

/**
 * A copy of a stored-headers object with both verified caller headers
 * removed in every casing. The pool applies it to every remote row's stored
 * headers (`storedHeadersForPool` in `client.ts`). The Inspector's direct
 * transports do not go through the pooled fetch, so it applies this to every
 * matched row's stored headers itself, whatever the row's name.
 */
export function withoutVerifiedCallerHeader(
  headers: Record<string, string>,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers).filter(
      ([name]) => !isVerifiedCallerHeaderName(name),
    ),
  );
}
