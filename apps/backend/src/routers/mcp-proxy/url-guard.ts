import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";

import { FetchLike } from "@modelcontextprotocol/sdk/shared/transport.js";

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

interface Ipv4Range {
  readonly base: string;
  readonly prefix: number;
  /** Why this range is not a legitimate destination for a remote MCP server. */
  readonly why: string;
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
  { base: "10.0.0.0", prefix: 8, why: "private (RFC 1918)" },
  { base: "100.64.0.0", prefix: 10, why: "carrier-grade NAT (RFC 6598)" },
  { base: "127.0.0.0", prefix: 8, why: "loopback" },
  {
    base: "169.254.0.0",
    prefix: 16,
    why: "link-local, including the cloud instance-metadata address",
  },
  { base: "172.16.0.0", prefix: 12, why: "private (RFC 1918)" },
  { base: "192.168.0.0", prefix: 16, why: "private (RFC 1918)" },
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
const blockedIpv6Reason = (bytes: Uint8Array): string | null => {
  // ::ffff:0:0/96 — IPv4-mapped. `http://[::ffff:127.0.0.1]` is loopback.
  if (allZero(bytes, 0, 10) && bytes[10] === 0xff && bytes[11] === 0xff) {
    const inner = isBlockedSsrfAddress(embeddedIpv4(bytes, 12));
    return inner ? `IPv4-mapped ::ffff:0:0/96 -> ${inner}` : null;
  }

  // ::/96 — the deprecated IPv4-compatible form. `::` and `::1` live in this
  // prefix but are the unspecified and loopback addresses, not v4 wrappers.
  if (allZero(bytes, 0, 12)) {
    if (allZero(bytes, 12, 15) && bytes[15] <= 1) {
      return bytes[15] === 0 ? "::/128 unspecified" : "::1/128 loopback";
    }
    const inner = isBlockedSsrfAddress(embeddedIpv4(bytes, 12));
    return inner ? `IPv4-compatible ::/96 -> ${inner}` : null;
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
    const inner = isBlockedSsrfAddress(embeddedIpv4(bytes, 12));
    return inner ? `NAT64 64:ff9b::/96 -> ${inner}` : null;
  }

  // 2002::/16 — 6to4 carries the v4 site address in the next four bytes.
  if (bytes[0] === 0x20 && bytes[1] === 0x02) {
    const inner = isBlockedSsrfAddress(embeddedIpv4(bytes, 2));
    return inner ? `6to4 2002::/16 -> ${inner}` : null;
  }

  if (bytes[0] === 0xff) return "ff00::/8 multicast";
  if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80) {
    return "fe80::/10 link-local";
  }
  if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0xc0) {
    return "fec0::/10 site-local (deprecated)";
  }
  if ((bytes[0] & 0xfe) === 0xfc) return "fc00::/7 unique local";

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
 */
export const isBlockedSsrfAddress = (address: string): string | null => {
  const family = isIP(address);

  if (family === 4) {
    const value = ipv4ToInt(address);
    if (value === null) return "unparsable IPv4 address";

    for (const range of BLOCKED_IPV4_RANGES) {
      const base = ipv4ToInt(range.base);
      if (base !== null && inIpv4Range(value, base, range.prefix)) {
        return `${range.base}/${range.prefix} ${range.why}`;
      }
    }
    return null;
  }

  if (family === 6) {
    const bytes = ipv6ToBytes(address);
    if (!bytes) return "unparsable IPv6 address";
    return blockedIpv6Reason(bytes);
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
  /** Transport seam for `createGuardedFetch`. Production uses global fetch. */
  baseFetch?: FetchLike;
}

/**
 * Caller-supplied text is logged through `JSON.stringify`, never interpolated
 * raw: an embedded newline in a hostname would otherwise forge whole log
 * lines, and a refused URL is by definition attacker-chosen.
 */
const refuse = (reason: string): Error => {
  logger.warn(`MCP proxy remote URL refused: ${reason}`);
  return new Error(NOT_A_PERMITTED_TARGET);
};

/**
 * Validate that a remote MCP URL names a public destination, or throw.
 *
 * Returns the parsed URL so callers connect to the value that was checked
 * rather than re-parsing the string.
 */
export const assertPublicMcpUrl = async (
  rawUrl: string | URL,
  options: McpUrlGuardOptions = {},
): Promise<URL> => {
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
  if (allowedHosts.has(hostname)) return url;

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

  // EVERY answer has to be public. A host that returns one public and one
  // internal address is a rebinding attempt that got greedy, and connecting is
  // a coin flip over which record the client picks.
  for (const address of addresses) {
    const blockedBy = isBlockedSsrfAddress(address);
    if (blockedBy) {
      throw refuse(`${JSON.stringify(hostname)} resolves into ${blockedBy}`);
    }
  }

  return url;
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
 * A `fetch` that validates its destination before every connection, including
 * each redirect hop.
 *
 * Handed to both remote transports as their `fetch` implementation, so it
 * covers the requests the route handler never sees: SSE's POST back-channel
 * goes to the endpoint the REMOTE SERVER advertises, and the streamable-HTTP
 * transport reconnects on its own schedule.
 *
 * REDIRECTS ARE FOLLOWED HERE, NOT BY THE HTTP CLIENT. Left at the default
 * `redirect: "follow"`, undici resolves and connects to a `Location` target
 * itself, with none of these checks applied to it — so a URL that validates as
 * public could answer `302 Location: http://169.254.169.254/` and win. Manual
 * following puts every hop back through `assertPublicMcpUrl`.
 *
 * KNOWN RESIDUAL — DNS REBINDING. This validates the name and then hands the
 * URL to `fetch`, which resolves it a second time; a host whose records change
 * between those two resolutions can still be answered with an internal address
 * on the second. Closing that would mean pinning the connection to the
 * validated IP, which needs a dispatcher-level `lookup` hook that Node does
 * not expose on the built-in fetch — the alternative is reimplementing the
 * HTTP client on `node:https` for a transport that streams SSE, which is a
 * larger regression risk than the window it closes. The window is narrowed
 * rather than left open: the check runs immediately before each connect,
 * re-runs on every request the transport makes rather than once per session,
 * and both resolutions go through the same platform resolver, so anything
 * cached between them agrees.
 */
export const createGuardedFetch = (
  options: McpUrlGuardOptions = {},
): FetchLike => {
  const baseFetch = options.baseFetch ?? fetch;

  return async (input, init) => {
    let target = await assertPublicMcpUrl(input, options);
    let method = init?.method ?? "GET";
    let body = init?.body ?? undefined;
    let headers = new Headers(init?.headers);

    for (let hop = 0; ; hop += 1) {
      const response = await baseFetch(target, {
        ...init,
        method,
        body,
        headers,
        redirect: "manual",
      });

      const location = REDIRECT_STATUSES.has(response.status)
        ? response.headers.get("location")
        : null;
      if (!location) return response;

      // Drain the redirect body so the connection is released rather than held
      // open for the life of the chain.
      await response.body?.cancel().catch(() => {});

      if (hop >= MAX_REDIRECT_HOPS) {
        logger.warn("MCP proxy remote URL refused: redirect chain too long");
        throw new Error(TOO_MANY_REDIRECTS);
      }

      let next: URL;
      try {
        next = new URL(location, target);
      } catch {
        throw refuse("redirect target is not a parsable URL");
      }
      next = await assertPublicMcpUrl(next, options);

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

      if (next.origin !== target.origin) {
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
