import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";

import { FetchLike } from "@modelcontextprotocol/sdk/shared/transport.js";
import { Agent, fetch as undiciFetch } from "undici";

import logger from "@/utils/logger";

/**
 * Destination validation for the mcp-proxy's REMOTE-URL transports (SSE and
 * STREAMABLE_HTTP).
 *
 * Those two branches take `url` off the request query and have the backend
 * open a connection to it, forwarding the caller's `Authorization` header and
 * the matched server row's stored headers. The route is admin-gated, but the
 * gate is a session cookie, and a `SameSite=Lax` cookie rides along on a
 * top-level GET — so any page an admin visits can name a destination and the
 * backend will connect to it from INSIDE the network, with whatever the
 * backend's own network position reaches. That is the whole vulnerability
 * class: server-side request forgery, blind but sufficient, with cloud
 * instance-metadata sitting at a fixed link-local address behind it.
 *
 * The fix is a destination check, not a registry check: the operator's
 * "point the Inspector at a new server and see if it works" flow has to keep
 * working, so this refuses by ADDRESS RANGE rather than by "is this row
 * already in the database". A URL whose host resolves anywhere on the public
 * internet still connects exactly as before.
 *
 * Two layers, because one is not enough:
 *  - `assertPublicMcpUrl` runs before the transport is constructed, so a
 *    hostile URL is refused before anything is opened.
 *  - `createGuardedFetch` re-runs the same check on EVERY request the
 *    transport makes, including redirect hops and — for SSE — the POST
 *    endpoint the remote server itself advertises in its `endpoint` event,
 *    which is remote-controlled input that never passes through the route
 *    handler at all.
 */

/**
 * One refusal string for every way a destination can fail this check.
 *
 * Deliberately says nothing about WHICH rule refused and never echoes the
 * caller's URL. A caller who can tell "blocked because private" from "blocked
 * because it did not resolve" has a network-mapping oracle: the difference
 * between those two answers is exactly the information a blind SSRF is trying
 * to recover. The specific reason goes to the log, where an operator
 * debugging their own misconfiguration can read it.
 */
export const NOT_A_PERMITTED_TARGET =
  "The requested MCP server URL is not a permitted destination. Remote MCP servers must be reachable at a public address.";

/** A redirect chain that never terminates is refused rather than followed. */
export const TOO_MANY_REDIRECTS =
  "The MCP server URL redirected too many times.";

/**
 * A body that cannot be replayed onto a method-preserving redirect.
 *
 * Both transports here send JSON strings, so this is a guard against a future
 * caller that streams a body, not a live case.
 */
export const UNREPLAYABLE_REDIRECT_BODY =
  "The MCP server URL redirected a request whose body cannot be resent.";

/** A response body that exceeded the byte ceiling and was aborted. */
export const RESPONSE_TOO_LARGE =
  "The MCP server response exceeded the maximum allowed size.";

/**
 * A redirect to a different origin, refused rather than followed.
 *
 * Used only under `refuseCrossOriginRedirect` (the pooled data plane): a
 * trusted internal backend does not redirect the gateway to another origin,
 * so one that tries is answering a request with a hostile hop.
 */
export const CROSS_ORIGIN_REDIRECT_REFUSED =
  "The MCP server URL redirected across origins, which is not permitted here.";

/**
 * Default response-byte ceiling and dispatcher idle timeout, both env-tunable.
 *
 * The byte ceiling (100 MiB) is a memory-exhaustion backstop, not an
 * operational limit; a single JSON-RPC response never approaches it. The
 * timeout (300000 ms) matches undici's own default, made explicit and tunable;
 * it is the headers/body IDLE timeout, so it bounds a stalled upstream without
 * capping a long-lived active stream. Read per call rather than captured at
 * import so a value can be corrected without a rebuild and varied by a test,
 * matching `allowedHostsFromEnv`.
 */
const DEFAULT_MAX_RESPONSE_BYTES = 100 * 1024 * 1024;
const DEFAULT_REQUEST_TIMEOUT_MS = 300000;

const envPositiveInt = (name: string, fallback: number): number => {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

const maxResponseBytesFromEnv = (): number =>
  envPositiveInt("MCP_PROXY_MAX_RESPONSE_BYTES", DEFAULT_MAX_RESPONSE_BYTES);

const requestTimeoutMsFromEnv = (): number =>
  envPositiveInt("MCP_PROXY_REQUEST_TIMEOUT_MS", DEFAULT_REQUEST_TIMEOUT_MS);

interface Ipv4Range {
  readonly base: string;
  readonly prefix: number;
  /** Why this range is not a legitimate destination for a remote MCP server. */
  readonly why: string;
  /**
   * True for the private ranges where a trusted, operator-configured backend
   * legitimately lives (RFC 1918 and loopback). The `allowPrivate` posture
   * (used by the pooled data plane, whose targets are DB-configured internal
   * services, not caller-supplied) permits these while still refusing the
   * ranges that are never a real backend: the cloud metadata address, CGNAT,
   * multicast and the reserved blocks stay blocked in both postures.
   */
  readonly internalService?: boolean;
}

/**
 * Every IPv4 range that is not "somewhere on the public internet".
 *
 * 169.254.0.0/16 is the one with teeth — 169.254.169.254 is the instance
 * metadata endpoint on every major cloud, unauthenticated and answering to
 * whatever process can reach it. The RFC 1918 blocks and loopback are the rest
 * of the internal network. 100.64.0.0/10 is carrier-grade NAT, which is also
 * how several overlay/VPN products address their private fabric. Multicast and
 * the 240/4 reserved block (255.255.255.255 included) are never a destination
 * anyone meant to type.
 */
const BLOCKED_IPV4_RANGES: readonly Ipv4Range[] = [
  { base: "0.0.0.0", prefix: 8, why: "this-network / unspecified" },
  {
    base: "10.0.0.0",
    prefix: 8,
    why: "private (RFC 1918)",
    internalService: true,
  },
  { base: "100.64.0.0", prefix: 10, why: "carrier-grade NAT (RFC 6598)" },
  { base: "127.0.0.0", prefix: 8, why: "loopback", internalService: true },
  {
    base: "169.254.0.0",
    prefix: 16,
    why: "link-local, including the cloud instance-metadata address",
  },
  {
    base: "172.16.0.0",
    prefix: 12,
    why: "private (RFC 1918)",
    internalService: true,
  },
  {
    base: "192.0.0.0",
    prefix: 24,
    why: "IETF protocol assignments (RFC 6890)",
  },
  {
    base: "192.88.99.0",
    prefix: 24,
    why: "6to4 relay anycast (RFC 7526) — reaches a relay, not a server",
  },
  {
    base: "192.168.0.0",
    prefix: 16,
    why: "private (RFC 1918)",
    internalService: true,
  },
  {
    base: "198.18.0.0",
    prefix: 15,
    why: "benchmarking (RFC 2544) — several VPN/SD-WAN products address their private fabric here",
  },
  { base: "224.0.0.0", prefix: 4, why: "multicast" },
  { base: "240.0.0.0", prefix: 4, why: "reserved, including broadcast" },
];

/** Dotted quad to a 32-bit value, or null if it is not one. */
const ipv4ToInt = (address: string): number | null => {
  const octets = address.split(".");
  if (octets.length !== 4) return null;

  let value = 0;
  for (const octet of octets) {
    if (!/^\d{1,3}$/.test(octet)) return null;
    const parsed = Number(octet);
    if (parsed > 255) return null;
    value = value * 256 + parsed;
  }
  return value;
};

const inIpv4Range = (value: number, base: number, prefix: number): boolean => {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (value & mask) >>> 0 === (base & mask) >>> 0;
};

const allZero = (bytes: Uint8Array, from: number, until: number): boolean => {
  for (let i = from; i < until; i += 1) {
    if (bytes[i] !== 0) return false;
  }
  return true;
};

const embeddedIpv4 = (bytes: Uint8Array, offset: number): string =>
  `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;

/**
 * Expand an IPv6 literal to its 16 bytes, or null if it is not one.
 *
 * `isIP` has already accepted the shape, so this only has to handle the two
 * legal spellings that make the text form non-uniform: `::` compression and a
 * trailing dotted quad.
 */
const ipv6ToBytes = (address: string): Uint8Array | null => {
  if (isIP(address) !== 6) return null;

  // "::ffff:127.0.0.1" carries its last four bytes as IPv4 text. Fold that
  // into two hextets first so the group parse below is uniform.
  let text = address;
  const dotted = /:((?:\d{1,3}\.){3}\d{1,3})$/.exec(text);
  if (dotted) {
    const embedded = ipv4ToInt(dotted[1]);
    if (embedded === null) return null;
    text =
      text.slice(0, dotted.index + 1) +
      ((embedded >>> 16) & 0xffff).toString(16) +
      ":" +
      (embedded & 0xffff).toString(16);
  }

  const [head, tail] = text.split("::");
  const headGroups = head ? head.split(":") : [];
  const tailGroups = tail ? tail.split(":") : [];

  let groups: string[];
  if (tail === undefined) {
    if (headGroups.length !== 8) return null;
    groups = headGroups;
  } else {
    const missing = 8 - headGroups.length - tailGroups.length;
    if (missing < 0) return null;
    groups = [
      ...headGroups,
      ...Array<string>(missing).fill("0"),
      ...tailGroups,
    ];
  }

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i += 1) {
    const group = parseInt(groups[i], 16);
    if (!Number.isFinite(group)) return null;
    bytes[i * 2] = (group >> 8) & 0xff;
    bytes[i * 2 + 1] = group & 0xff;
  }
  return bytes;
};

/**
 * Why an IPv6 address is not public, or null if it is.
 *
 * The four "unwrap" branches exist because IPv6 has four different ways to
 * write an IPv4 destination, and each one reaches the same internal host as
 * the plain v4 literal would. Judging the text form instead of the address it
 * denotes is how these checks get bypassed.
 */
const blockedIpv6Reason = (
  bytes: Uint8Array,
  allowPrivate: boolean,
): string | null => {
  // ::ffff:0:0/96 — IPv4-mapped. `http://[::ffff:127.0.0.1]` is loopback.
  if (allZero(bytes, 0, 10) && bytes[10] === 0xff && bytes[11] === 0xff) {
    const inner = isBlockedSsrfAddress(embeddedIpv4(bytes, 12), allowPrivate);
    return inner ? `IPv4-mapped ::ffff:0:0/96 -> ${inner}` : null;
  }

  // ::ffff:0:0:0/96 — the IPv4-TRANSLATED form (SIIT, RFC 2765). Same idea as
  // the mapped form one hextet to the left, and mutually exclusive with it
  // because that one requires bytes 8-9 to be zero.
  if (
    allZero(bytes, 0, 8) &&
    bytes[8] === 0xff &&
    bytes[9] === 0xff &&
    allZero(bytes, 10, 12)
  ) {
    const inner = isBlockedSsrfAddress(embeddedIpv4(bytes, 12), allowPrivate);
    return inner ? `IPv4-translated ::ffff:0:0:0/96 -> ${inner}` : null;
  }

  // ::/96 — the deprecated IPv4-compatible form. `::` and `::1` live in this
  // prefix but are the unspecified and loopback addresses, not v4 wrappers.
  if (allZero(bytes, 0, 12)) {
    if (allZero(bytes, 12, 15) && bytes[15] <= 1) {
      // `::` (unspecified) is never a real backend and stays blocked in both
      // postures; `::1` (loopback) is where an internal backend can live, so
      // the allowPrivate posture permits it.
      if (bytes[15] === 0) return "::/128 unspecified";
      return allowPrivate ? null : "::1/128 loopback";
    }
    const inner = isBlockedSsrfAddress(embeddedIpv4(bytes, 12), allowPrivate);
    return inner ? `IPv4-compatible ::/96 -> ${inner}` : null;
  }

  // 64:ff9b:1::/48 — the LOCAL-USE NAT64 prefix (RFC 8215). Unlike the
  // well-known prefix below, the embedded v4 sits at a position that depends on
  // the deployed prefix length, so there is nothing dependable to unwrap and
  // judge. It is refused wholesale: a local NAT64 prefix exists precisely to
  // reach the local v4 network.
  if (
    bytes[0] === 0x00 &&
    bytes[1] === 0x64 &&
    bytes[2] === 0xff &&
    bytes[3] === 0x9b &&
    bytes[4] === 0x00 &&
    bytes[5] === 0x01
  ) {
    return "64:ff9b:1::/48 local-use NAT64";
  }

  // 64:ff9b::/96 — the well-known NAT64 prefix. A NAT64 gateway forwards to
  // the embedded v4, so this is a second route to the same internal hosts.
  if (
    bytes[0] === 0x00 &&
    bytes[1] === 0x64 &&
    bytes[2] === 0xff &&
    bytes[3] === 0x9b &&
    allZero(bytes, 4, 12)
  ) {
    const inner = isBlockedSsrfAddress(embeddedIpv4(bytes, 12), allowPrivate);
    return inner ? `NAT64 64:ff9b::/96 -> ${inner}` : null;
  }

  // 2002::/16 — 6to4 carries the v4 site address in the next four bytes.
  if (bytes[0] === 0x20 && bytes[1] === 0x02) {
    const inner = isBlockedSsrfAddress(embeddedIpv4(bytes, 2), allowPrivate);
    return inner ? `6to4 2002::/16 -> ${inner}` : null;
  }

  if (bytes[0] === 0xff) return "ff00::/8 multicast";
  if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80) {
    return "fe80::/10 link-local";
  }
  if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0xc0) {
    return "fec0::/10 site-local (deprecated)";
  }
  // fc00::/7 unique local is the IPv6 analogue of RFC 1918: an internal
  // backend can live here, so the allowPrivate posture permits it.
  if ((bytes[0] & 0xfe) === 0xfc) {
    return allowPrivate ? null : "fc00::/7 unique local";
  }

  return null;
};

/**
 * Why this address is not a public destination, or null if it is one.
 *
 * Anything that is not a recognisable IP literal is REFUSED rather than
 * passed. The only callers hand this either a URL host that `isIP` already
 * accepted or a string a resolver returned, so an unrecognisable value means
 * an assumption broke — and the safe reading of a broken assumption on this
 * path is "block".
 *
 * `allowPrivate` (default false) permits the private ranges where a trusted,
 * operator-configured backend legitimately lives (RFC 1918, loopback, and
 * their IPv6 unique-local/loopback/mapped forms). It NEVER relaxes the ranges
 * that are never a real backend: the cloud metadata address, CGNAT, multicast,
 * the unspecified address and the reserved blocks stay blocked either way.
 */
export const isBlockedSsrfAddress = (
  address: string,
  allowPrivate: boolean = false,
): string | null => {
  const family = isIP(address);

  if (family === 4) {
    const value = ipv4ToInt(address);
    if (value === null) return "unparsable IPv4 address";

    for (const range of BLOCKED_IPV4_RANGES) {
      const base = ipv4ToInt(range.base);
      if (base !== null && inIpv4Range(value, base, range.prefix)) {
        if (allowPrivate && range.internalService) return null;
        return `${range.base}/${range.prefix} ${range.why}`;
      }
    }
    return null;
  }

  if (family === 6) {
    const bytes = ipv6ToBytes(address);
    if (!bytes) return "unparsable IPv6 address";
    return blockedIpv6Reason(bytes, allowPrivate);
  }

  return "not a recognisable IP address";
};

/**
 * Reduce a host to the form the allowlist and the resolver both agree on.
 *
 * `URL.hostname` keeps the brackets on an IPv6 literal, and a trailing dot
 * names the same host in DNS as the form without one — so `example.com.` must
 * not be a way to look different from `example.com` to an allowlist while
 * resolving identically.
 */
const normalizeHostname = (value: string): string => {
  let host = value.trim().toLowerCase();
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  while (host.endsWith(".")) host = host.slice(0, -1);
  return host;
};

/**
 * Hosts exempted from the range check, from `MCP_PROXY_URL_ALLOWED_HOSTS`.
 *
 * Read on every call rather than captured at import: this module is imported
 * by a router, and a value frozen at import time is one that cannot be
 * corrected without a rebuild, nor varied by a test.
 *
 * Empty by default. The default posture is block-internal / allow-public, and
 * this exists only for the deployment that genuinely fronts an MCP server on
 * a private address — most visibly the one running with
 * `TRANSFORM_LOCALHOST_TO_DOCKER_INTERNAL=true`, where a `localhost` URL is
 * rewritten to `host.docker.internal` and therefore resolves into the Docker
 * bridge network.
 */
const allowedHostsFromEnv = (): ReadonlySet<string> =>
  new Set(
    (process.env.MCP_PROXY_URL_ALLOWED_HOSTS ?? "")
      .split(",")
      .map(normalizeHostname)
      .filter((host) => host.length > 0),
  );

/**
 * Resolve through getaddrinfo, NOT through `dns.resolve4`/`resolve6`.
 *
 * The check is only meaningful if it resolves the host the same way the HTTP
 * client is about to. `dns.lookup` goes through the platform resolver, so
 * `/etc/hosts` and nsswitch are in play exactly as they are for the connection
 * itself; `dns.resolve*` queries DNS directly and would happily call a host
 * public that the hosts file points at an internal address.
 */
const resolveHost = async (hostname: string): Promise<string[]> => {
  const records = await dnsLookup(hostname, { all: true, verbatim: true });
  return records.map((record) => record.address);
};

export interface McpUrlGuardOptions {
  /** Resolver seam. Production uses getaddrinfo via `resolveHost`. */
  lookup?: (hostname: string) => Promise<string[]>;
  /** Overrides `MCP_PROXY_URL_ALLOWED_HOSTS`. */
  allowedHosts?: Iterable<string>;
  /** Transport seam for `createGuardedFetch`. Production uses undici's fetch. */
  baseFetch?: PinnedFetch;
  /**
   * The ONE origin at which an allowlist entry may apply — the URL the
   * operator typed, already validated by the route. Every other destination
   * this fetch is asked for (a redirect target, the SSE back-channel endpoint
   * the remote server names) validates with an EMPTY allowlist.
   *
   * Without this the allowlist is a hole rather than an exemption: an
   * attacker's public server answers `302 http://host.docker.internal/` and
   * the entry that was meant to unblock the operator's own Docker host
   * unblocks the attacker's redirect into it instead.
   */
  allowlistOrigin?: string;
  /**
   * Permit the private ranges where a trusted, operator-configured backend
   * legitimately lives (RFC 1918, loopback, IPv6 unique-local) while still
   * pinning the socket and still refusing the never-a-backend ranges (cloud
   * metadata, CGNAT, multicast, reserved). The pooled data plane sets this:
   * its targets are DB-configured internal services, not caller-supplied URLs
   * like the Inspector's, so blocking every internal address (the default
   * posture) would refuse every legitimate backend. Off by default so the
   * Inspector path keeps its strict block-internal / allow-public posture.
   */
  allowPrivateAddresses?: boolean;
  /**
   * Refuse a redirect to a different origin outright instead of following it
   * with credentials stripped. The pooled data plane sets this: a
   * compromised backend answering `302` toward the metadata address or any
   * other host is the exact vector this closes, and legitimate internal
   * backends do not cross-origin-redirect. Same-origin redirects are still
   * followed and re-validated. Off by default so the Inspector keeps
   * following cross-origin redirects (for example an http->https upgrade
   * mid-session) with credentials dropped.
   */
  refuseCrossOriginRedirect?: boolean;
  /**
   * Hard ceiling on the bytes read from a single response body before the
   * request is aborted, guarding the gateway against a hostile or misbehaving
   * upstream that streams an unbounded response. Defaults to
   * `MCP_PROXY_MAX_RESPONSE_BYTES` (100 MiB). For a long-lived SSE stream the
   * count is cumulative over the connection, so the default is a generous
   * memory-exhaustion backstop, not an operational limit.
   */
  maxResponseBytes?: number;
  /**
   * Undici headers-and-body idle timeout (ms) applied to the pinned
   * dispatcher, defaulting to `MCP_PROXY_REQUEST_TIMEOUT_MS` (300000). It is
   * an idle timeout, reset on every received chunk, NOT a total-duration cap:
   * a total cap would kill a legitimately long-lived SSE stream, whereas this
   * bounds a hung or stalled upstream without that regression.
   */
  requestTimeoutMs?: number;
}

/**
 * The result of a passed check: the parsed URL, plus the addresses it resolved
 * to at that instant.
 *
 * `addresses` is what closes DNS rebinding. Validating a NAME and then handing
 * the URL to an HTTP client means the client resolves it a second time, and
 * nothing makes the second answer match the first — glibc and musl
 * getaddrinfo do not cache without nscd, which no container here runs, so a
 * TTL-0 record simply answers again. Callers pin the socket to these addresses
 * instead.
 *
 * EMPTY means "no pin": the host matched the operator's allowlist, was never
 * resolved here, and is trusted by configuration rather than by address.
 */
export interface ValidatedMcpTarget {
  url: URL;
  addresses: string[];
}

/**
 * Build the single refusal Error and log the real reason beside it.
 *
 * CALLER CONTRACT: `reason` is interpolated raw, so anything caller-supplied
 * inside it — a hostname above all — must already be `JSON.stringify`'d by the
 * caller. A refused URL is by definition attacker-chosen, and an unescaped
 * newline in one forges whole log lines.
 */
const refuse = (reason: string): Error => {
  logger.warn(`MCP proxy remote URL refused: ${reason}`);
  return new Error(NOT_A_PERMITTED_TARGET);
};

/**
 * Validate that a remote MCP URL names a public destination, or throw.
 *
 * Returns the parsed URL together with the addresses it resolved to, so the
 * caller connects to the value that was checked rather than re-parsing the
 * string or re-resolving the name.
 */
export const assertPublicMcpUrl = async (
  rawUrl: string | URL,
  options: McpUrlGuardOptions = {},
): Promise<ValidatedMcpTarget> => {
  let url: URL;
  try {
    url = rawUrl instanceof URL ? rawUrl : new URL(rawUrl);
  } catch {
    throw refuse("not a parsable absolute URL");
  }

  // `file:`, `gopher:` and friends are how an SSRF turns into a file read or a
  // protocol-smuggling primitive. Both transports here only ever speak HTTP.
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw refuse(`scheme ${JSON.stringify(url.protocol)} is not http(s)`);
  }

  const hostname = normalizeHostname(url.hostname);
  if (!hostname) throw refuse("no host");

  const allowedHosts = options.allowedHosts
    ? new Set([...options.allowedHosts].map(normalizeHostname))
    : allowedHostsFromEnv();
  // No addresses: an allowlisted host is trusted by NAME, so there is nothing
  // to pin it to and the connection resolves normally.
  if (allowedHosts.has(hostname)) return { url, addresses: [] };

  // An IP literal needs no resolver. WHATWG URL parsing has already normalised
  // every alternate IPv4 spelling for us — `http://2130706433/`,
  // `http://0x7f000001/` and `http://127.1/` all arrive here as "127.0.0.1" —
  // so there is no second encoding to strip.
  let addresses: string[];
  if (isIP(hostname)) {
    addresses = [hostname];
  } else {
    try {
      addresses = await (options.lookup ?? resolveHost)(hostname);
    } catch {
      throw refuse(`${JSON.stringify(hostname)} did not resolve`);
    }
  }

  if (addresses.length === 0) {
    throw refuse(`${JSON.stringify(hostname)} resolved to nothing`);
  }

  // EVERY answer has to be public (or, under allowPrivate, an internal-service
  // range). A host that returns one allowed and one refused address is a
  // rebinding attempt that got greedy, and connecting is a coin flip over
  // which record the client picks.
  const allowPrivate = options.allowPrivateAddresses ?? false;
  for (const address of addresses) {
    const blockedBy = isBlockedSsrfAddress(address, allowPrivate);
    if (blockedBy) {
      throw refuse(`${JSON.stringify(hostname)} resolves into ${blockedBy}`);
    }
  }

  return { url, addresses };
};

/**
 * A `connect.lookup` that answers ONLY with addresses already validated.
 *
 * This is the pin. undici calls it in place of getaddrinfo when opening the
 * socket, so the hostname it is handed is ignored entirely and the connection
 * cannot land anywhere the check above did not clear. Everything else about
 * the request still derives from the URL, `Host` and the TLS SNI included.
 */
const pinnedLookup =
  (addresses: string[]) =>
  (
    _hostname: string,
    options: { all?: boolean },
    callback: (
      err: NodeJS.ErrnoException | null,
      address: string | { address: string; family: number }[],
      family?: number,
    ) => void,
  ): void => {
    const entries = addresses.map((address) => ({
      address,
      family: address.includes(":") ? 6 : 4,
    }));
    if (options?.all) {
      callback(null, entries);
      return;
    }
    callback(null, entries[0].address, entries[0].family);
  };

/** Undici dispatcher timeouts, applied to the pinned Agent. */
interface DispatcherTimeouts {
  /** Max ms to receive the response headers. */
  readonly headersTimeout?: number;
  /** Max ms of inactivity between body chunks (idle, reset per chunk). */
  readonly bodyTimeout?: number;
}

/**
 * An undici dispatcher whose connections can only land on `addresses`.
 *
 * Exported for the test that proves the pin at socket level: given a hostname
 * that cannot resolve at all, a request through this agent still connects.
 *
 * `timeouts` bounds a hung or stalled upstream. `bodyTimeout` is undici's idle
 * timeout (reset on every received chunk), not a total-duration cap, so it
 * does not sever a legitimately long-lived-but-active SSE stream.
 */
export const createPinnedAgent = (
  addresses: string[],
  timeouts: DispatcherTimeouts = {},
): Agent =>
  new Agent({
    connect: { lookup: pinnedLookup(addresses) },
    ...(timeouts.headersTimeout !== undefined
      ? { headersTimeout: timeouts.headersTimeout }
      : {}),
    ...(timeouts.bodyTimeout !== undefined
      ? { bodyTimeout: timeouts.bodyTimeout }
      : {}),
  });

/**
 * What `createGuardedFetch` calls, and the reason it is undici's `fetch` rather
 * than the global one: `dispatcher` is the only way to reach `connect.lookup`,
 * and the global fetch on this runtime takes its dispatcher from a different
 * copy of undici than the `Agent` above comes from.
 *
 * The undici response is re-wrapped in a NATIVE `Response` streaming from the
 * same body, so every consumer downstream — the MCP SDK, the `eventsource`
 * package — sees the global class it type-checks and `instanceof`-checks
 * against. `url` and `redirected` are restored by hand because a constructed
 * `Response` reports an empty url, and `eventsource` resolves a relative SSE
 * endpoint against exactly that.
 *
 * The dispatcher travels as its OWN argument rather than on the init object.
 * `@types/node` declares `RequestInit.dispatcher` against the undici copy
 * bundled with Node, which is a different major from the `Agent` here, so
 * putting it on the init makes the two type worlds collide for no benefit.
 */
type PinnedFetch = (
  url: URL,
  init: RequestInit,
  dispatcher?: Agent,
) => Promise<Response>;

const pinnedFetch: PinnedFetch = async (url, init, dispatcher) => {
  const response = await undiciFetch(url, {
    ...(init as unknown as Parameters<typeof undiciFetch>[1]),
    dispatcher,
  });

  const wrapped = new Response(
    // 204/205/304 must be constructed with a null body; undici gives null.
    response.body as unknown as ConstructorParameters<typeof Response>[0],
    {
      status: response.status,
      statusText: response.statusText,
      headers: [...response.headers] as [string, string][],
    },
  );
  Object.defineProperty(wrapped, "url", { value: response.url });
  Object.defineProperty(wrapped, "redirected", { value: response.redirected });
  return wrapped;
};

/** The origin of a fetch input, or undefined when it does not parse. */
const originOf = (input: string | URL): string | undefined => {
  try {
    return (input instanceof URL ? input : new URL(input)).origin;
  } catch {
    return undefined;
  }
};

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const MAX_REDIRECT_HOPS = 5;

/** Headers that describe a body, and so must go when the body does. */
const BODY_HEADERS = [
  "content-type",
  "content-length",
  "content-encoding",
  "content-language",
  "content-location",
];

/**
 * The only headers that survive a redirect to a different origin.
 *
 * An allowlist, not a denylist of `authorization`/`cookie`. The headers on
 * these requests are the server row's stored `headers` jsonb merged with the
 * request's passthrough `Authorization` — vendor API keys and a caller bearer
 * token — and `x-custom-auth-header` means a credential can arrive under any
 * name the operator chose. Naming the safe ones is the only version of this
 * that stays correct as that set grows.
 */
const FORWARDABLE_ON_ORIGIN_CHANGE = new Set([
  "accept",
  "content-type",
  "user-agent",
]);

/**
 * A `fetch` that validates its destination before every connection, PINS the
 * socket to the address it validated, and re-validates every redirect hop.
 *
 * Handed to both remote transports as their `fetch` implementation, so it
 * covers the requests the route handler never sees: SSE's POST back-channel
 * goes to the endpoint the REMOTE SERVER advertises, and the streamable-HTTP
 * transport reconnects on its own schedule.
 *
 * DNS REBINDING IS CLOSED BY PINNING, not narrowed by timing. Validating a
 * NAME and handing the URL onward means the HTTP client resolves it a second
 * time, and nothing makes the second answer agree with the first: glibc and
 * musl getaddrinfo hold no cache of their own without nscd, which none of
 * these containers run, so a TTL-0 record just answers again — and the second
 * answer is the one the socket uses. Instead the validated addresses go into
 * an undici `Agent` whose `connect.lookup` returns ONLY those, so the socket
 * lands on the address that was checked and the name is never resolved twice.
 * `Host` and the TLS SNI still come from the URL, so virtual hosting and
 * certificate validation are unaffected.
 *
 * REDIRECTS ARE FOLLOWED HERE, NOT BY THE HTTP CLIENT. Left at the default
 * `redirect: "follow"`, undici resolves and connects to a `Location` target
 * itself, with none of these checks applied to it — so a URL that validates as
 * public could answer `302 Location: http://169.254.169.254/` and win. Manual
 * following puts every hop back through `assertPublicMcpUrl` AND gives every
 * hop its own pin.
 *
 * THE ALLOWLIST APPLIES TO HOP 0 ONLY, and only at the origin the operator
 * actually typed (`allowlistOrigin`). Everything else — redirect targets, the
 * back-channel endpoint the remote server chooses — is judged with an empty
 * allowlist. Otherwise the entry that unblocks the operator's own internal
 * host also unblocks an attacker's `302` into it.
 *
 * THE POOLED DATA PLANE uses a different posture, set through options: its
 * targets are DB-configured internal services, so `allowPrivateAddresses`
 * permits the RFC-1918/loopback ranges where they live (the socket is still
 * pinned and the metadata address is still refused), and
 * `refuseCrossOriginRedirect` rejects any redirect to another origin outright
 * rather than following it, because a trusted backend never redirects the
 * gateway elsewhere and one that tries is answering with a hostile hop.
 *
 * EVERY RESPONSE IS BOUNDED. The final body is capped at `maxResponseBytes`
 * (aborting the request when exceeded) so a hostile or misbehaving upstream
 * cannot exhaust gateway memory, and the pinned dispatcher carries a
 * headers/body idle timeout (`requestTimeoutMs`) so a hung upstream cannot
 * stall a pool slot forever.
 */
/**
 * Wrap a response so reading its body aborts the request once `maxBytes` is
 * exceeded.
 *
 * The count is cumulative over the stream, so on a long-lived SSE connection
 * this is a memory-exhaustion backstop rather than a per-message limit.
 * `onExceed` tears down the underlying connection (via the request's
 * AbortController) so undici stops pulling bytes, then the stream errors so the
 * consumer sees the refusal rather than a silently-truncated body. A body-less
 * response (204/304 and friends) is returned untouched.
 */
const capResponseBody = (
  response: Response,
  maxBytes: number,
  onExceed: () => void,
): Response => {
  if (!response.body) return response;
  const source = response.body.getReader();
  let seen = 0;
  const capped = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { done, value } = await source.read();
        if (done) {
          controller.close();
          return;
        }
        seen += value.byteLength;
        if (seen > maxBytes) {
          onExceed();
          await source.cancel().catch(() => {});
          logger.warn(
            "MCP proxy remote URL refused: response exceeded the byte ceiling",
          );
          controller.error(new Error(RESPONSE_TOO_LARGE));
          return;
        }
        controller.enqueue(value);
      } catch (error) {
        controller.error(error);
      }
    },
    cancel(reason) {
      void source.cancel(reason).catch(() => {});
    },
  });
  const wrapped = new Response(capped, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
  // A constructed Response reports an empty url and redirected=false; restore
  // both because `eventsource` resolves a relative SSE endpoint against `url`.
  Object.defineProperty(wrapped, "url", { value: response.url });
  Object.defineProperty(wrapped, "redirected", {
    value: response.redirected,
  });
  return wrapped;
};

export const createGuardedFetch = (
  options: McpUrlGuardOptions = {},
): FetchLike => {
  const baseFetch = options.baseFetch ?? pinnedFetch;
  const maxBytes = options.maxResponseBytes ?? maxResponseBytesFromEnv();
  const timeoutMs = options.requestTimeoutMs ?? requestTimeoutMsFromEnv();
  const timeouts: DispatcherTimeouts = {
    headersTimeout: timeoutMs,
    bodyTimeout: timeoutMs,
  };

  /**
   * One dispatcher per validated address set, for the life of this transport.
   * Rebuilding an Agent per request would throw away connection reuse, which
   * on the streamable-HTTP transport is a TLS handshake for every JSON-RPC
   * message. Keyed by the addresses, so a host that legitimately moves gets a
   * new pool rather than a stale one. An allowlisted host (no addresses) is
   * trusted by name and not pinned, so it rides the runtime default dispatcher.
   */
  const agents = new Map<string, Agent>();
  const agentFor = (addresses: string[]): Agent | undefined => {
    if (addresses.length === 0) return undefined;
    const key = [...addresses].sort().join(",");
    let agent = agents.get(key);
    if (!agent) {
      agent = createPinnedAgent(addresses, timeouts);
      agents.set(key, agent);
    }
    return agent;
  };

  return async (input, init) => {
    // Byte-ceiling teardown: an oversized final body aborts THIS request so
    // undici stops pulling bytes. Chained with any caller-supplied signal so
    // request cancellation still propagates through the guard.
    const controller = new AbortController();
    const signal =
      init?.signal != null
        ? AbortSignal.any([init.signal, controller.signal])
        : controller.signal;

    // Hop 0 is the only destination an allowlist entry can speak for, and only
    // when it is the origin the route already validated.
    const firstHopOptions =
      options.allowlistOrigin !== undefined &&
      originOf(input) !== options.allowlistOrigin
        ? { ...options, allowedHosts: [] }
        : options;
    const laterHopOptions: McpUrlGuardOptions = {
      ...options,
      allowedHosts: [],
    };

    let target = await assertPublicMcpUrl(input, firstHopOptions);
    let method = init?.method ?? "GET";
    let body = init?.body ?? undefined;
    let headers = new Headers(init?.headers);

    for (let hop = 0; ; hop += 1) {
      const response = await baseFetch(
        target.url,
        {
          ...init,
          method,
          body,
          headers,
          redirect: "manual",
          signal,
        },
        agentFor(target.addresses),
      );

      const location = REDIRECT_STATUSES.has(response.status)
        ? response.headers.get("location")
        : null;
      // Only the final (non-redirect) body is capped; redirect bodies are
      // drained below.
      if (!location) {
        return capResponseBody(response, maxBytes, () => controller.abort());
      }

      // Drain the redirect body so the connection is released rather than held
      // open for the life of the chain.
      await response.body?.cancel().catch(() => {});

      if (hop >= MAX_REDIRECT_HOPS) {
        logger.warn("MCP proxy remote URL refused: redirect chain too long");
        throw new Error(TOO_MANY_REDIRECTS);
      }

      let nextUrl: URL;
      try {
        nextUrl = new URL(location, target.url);
      } catch {
        throw refuse("redirect target is not a parsable URL");
      }

      // Pooled posture: a redirect to another origin is refused outright, not
      // followed with credentials stripped. A trusted internal backend never
      // redirects the gateway elsewhere, so one that tries is the SSRF hop this
      // closes; same-origin redirects still fall through and are re-validated.
      if (
        options.refuseCrossOriginRedirect &&
        nextUrl.origin !== target.url.origin
      ) {
        logger.warn(
          "MCP proxy remote URL refused: cross-origin redirect on the pooled path",
        );
        throw new Error(CROSS_ORIGIN_REDIRECT_REFUSED);
      }

      const next = await assertPublicMcpUrl(nextUrl, laterHopOptions);

      if (
        response.status === 303 ||
        ((response.status === 301 || response.status === 302) &&
          method !== "GET" &&
          method !== "HEAD")
      ) {
        // The rewrite every HTTP client performs: the follow-up is a plain GET
        // carrying no body.
        method = "GET";
        body = undefined;
        for (const name of BODY_HEADERS) headers.delete(name);
      } else if (
        body !== undefined &&
        body !== null &&
        typeof body !== "string"
      ) {
        // 307/308 replay the body, and a stream body was consumed by the
        // request above.
        logger.warn(
          "MCP proxy remote URL refused: redirect would resend an unreplayable body",
        );
        throw new Error(UNREPLAYABLE_REDIRECT_BODY);
      }

      if (next.url.origin !== target.url.origin) {
        // The body is deliberately still replayed across an origin change on a
        // 307/308. It is a JSON-RPC message, not a credential — the credentials
        // are in the headers, and those are dropped here. Refusing instead
        // would break a legitimate http->https upgrade mid-session, which is
        // the common cross-origin redirect in practice.
        headers = new Headers(
          [...headers.entries()].filter(([name]) =>
            FORWARDABLE_ON_ORIGIN_CHANGE.has(name),
          ),
        );
      }

      target = next;
    }
  };
};
