// rateLimiting.ts
// Rate limiting for protecting MCP servers from abuse

import logger from "../utils/logger";
import { CLIENT_IP_HEADER, resolveClientIp } from "./client-ip";
import { mcpServerPool } from "./metamcp/mcp-server-pool";
import { resolveSessionIdentity } from "./metamcp/session-auth";

type Context = Record<string, any>;
type CallNext = (context: Context) => Promise<any>;

/**
 * Forwarding / hop headers a client sets on its own request.
 *
 * A per-client limiter keyed on any of these enforces nothing: the caller
 * rotates (or omits) the value to mint a fresh bucket per request. The auth
 * plane keys on the edge-overwritten CF-Connecting-IP for exactly this reason
 * (see lib/client-ip). The data plane now defaults to that same header and
 * refuses a configured strategy-key override that names one of these,
 * degrading to the safe default instead of a limiter that can be walked past.
 */
const FORGEABLE_RATE_KEY_HEADERS = new Set([
  "x-forwarded-for",
  "x-forwarded",
  "forwarded",
  "forwarded-for",
  "x-real-ip",
  "x-client-ip",
  "x-cluster-client-ip",
  "true-client-ip",
  "via",
]);

export class RateLimitError extends Error {
  public code: number;

  constructor(message: string = "Rate limit exceeded") {
    super(message);
    this.code = -32000;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Token bucket implementation for rate limiting.
 */
export class TokenBucketRateLimiter {
  private capacity: number;
  private refillRate: number;
  private tokens: number;
  private lastRefill: number;

  constructor(capacity: number, refillRate: number) {
    this.capacity = capacity;
    this.refillRate = refillRate;
    this.tokens = capacity;
    this.lastRefill = Date.now() / 1000; // seconds
  }

  async consume(tokens: number = 1): Promise<boolean> {
    const now = Date.now() / 1000;
    const elapsed = now - this.lastRefill;

    this.tokens = Math.min(
      this.capacity,
      this.tokens + elapsed * this.refillRate,
    );
    this.lastRefill = now;
    logger.debug("tokens", this.tokens);

    if (this.tokens >= tokens) {
      this.tokens -= tokens;
      return true;
    }
    return false;
  }
}

/**
 * Sliding window rate limiter.
 */
export class SlidingWindowRateLimiter {
  private clientMaxRate: number;
  private clientMaxRateSeconds: number;
  private requests: number[] = [];

  constructor(clientMaxRate: number, clientMaxRateSeconds: number) {
    this.clientMaxRate = clientMaxRate;
    this.clientMaxRateSeconds = clientMaxRateSeconds;
  }

  async isAllowed(): Promise<boolean> {
    const now = Date.now() / 1000;
    const cutoff = now - this.clientMaxRateSeconds;
    // Remove old requests
    this.requests = this.requests.filter((t) => t >= cutoff);
    if (this.requests.length < this.clientMaxRate) {
      this.requests.push(now);
      return true;
    }
    return false;
  }

  /**
   * True when this limiter holds nothing the current window would keep, so the
   * eviction sweep can drop it without changing any decision. Exposed here
   * rather than reaching into `requests` from the sweep, which is private.
   */
  isExpired(now: number = Date.now() / 1000): boolean {
    if (this.requests.length === 0) return true;
    const newest = this.requests[this.requests.length - 1];
    return newest < now - this.clientMaxRateSeconds;
  }
}

/**
 * Rate limiting (token bucket): the per-credential tool-call ceiling on the
 * data plane.
 *
 * `max_rate` is the bucket CAPACITY (burst) and `max_rate_seconds` is the
 * REFILL rate in tokens per second, one token per data-plane request. The
 * middleware only invokes this when the endpoint has `enable_max_rate` set; a
 * non-positive `max_rate` then makes it inert (nothing to enforce) rather than
 * refusing every request.
 *
 * TWO deliberate departures from the earlier shape:
 *
 *  - It enforces INDEPENDENTLY of the background-idle-session gate. The old
 *    code only built and consumed a limiter while `getBackgroundIdleSessions`
 *    was non-empty, so on a gateway with no warmed idle sessions (the common
 *    steady state), the ceiling silently did nothing and authenticated tool
 *    calls were unbounded.
 *
 *  - The bucket is keyed PER CREDENTIAL within the namespace, not per
 *    namespace. A shared per-namespace bucket lets one busy credential drain
 *    the budget for every other consumer of the same endpoint, the
 *    noisy-neighbour availability class this quota exists to bound. The map is
 *    keyed on the api-key uuid or OAuth user id (bounded, admin-controlled
 *    values, so the map cannot be grown per-request by a caller); an anonymous
 *    endpoint has no per-caller identity, so all its callers share one bucket.
 */
export class RateLimiting {
  private limiters: Map<string, TokenBucketRateLimiter>;

  constructor() {
    this.limiters = new Map();
  }

  async onRequest(context: Context, callNext: CallNext): Promise<any> {
    const { endpoint } = context.req;
    const { namespace_uuid } = endpoint;

    const maxRate = endpoint.max_rate ?? 0;
    const refillPerSecond = endpoint.max_rate_seconds ?? 0;

    // A non-positive budget is a no-op: there is nothing to enforce, so pass
    // rather than refuse. (A zero-capacity bucket that refuses every request is
    // the spurious-503 failure mode the data plane already fought elsewhere.)
    if (maxRate > 0) {
      const identity = resolveSessionIdentity(context.req);
      const credentialKey =
        identity.credentialId !== null
          ? `${identity.method}:${identity.credentialId}`
          : "anonymous";
      const key = `${namespace_uuid}::${credentialKey}`;

      let limiter = this.limiters.get(key);
      if (!limiter) {
        limiter = new TokenBucketRateLimiter(maxRate, refillPerSecond);
        this.limiters.set(key, limiter);
      }
      if (!(await limiter.consume())) {
        throw new RateLimitError(`Rate limit exceeded`);
      }
    }
    return callNext(context);
  }
}

/**
 * Sliding window rate limiting.
 */
export class SlidingWindowRateLimiting {
  private limiters: Map<string, Map<string, SlidingWindowRateLimiter>>;
  private clientMaxRate: number;
  private clientMaxRateSeconds: number;
  private clientMaxRateStrategy: string;
  private clientMaxRateStrategyKey: string;
  constructor() {
    this.clientMaxRate = 0;
    this.clientMaxRateSeconds = 0;
    this.clientMaxRateStrategy = "ip";
    // Default to the edge-overwritten client IP, never the forgeable XFF: see
    // FORGEABLE_RATE_KEY_HEADERS and the per-request validation below.
    this.clientMaxRateStrategyKey = CLIENT_IP_HEADER;
    this.limiters = new Map();
  }

  async onRequest(context: Context, callNext: CallNext): Promise<any> {
    const { endpoint, socket, headers } = context.req;
    const { namespace_uuid } = endpoint;
    this.clientMaxRate = endpoint.client_max_rate;
    this.clientMaxRateSeconds = endpoint.client_max_rate_seconds;
    this.clientMaxRateStrategy =
      endpoint.client_max_rate_strategy === ""
        ? this.clientMaxRateStrategy
        : endpoint.client_max_rate_strategy;

    // Resolve which header the per-client bucket is keyed on. An empty
    // override takes the safe default; an override naming a caller-settable
    // forwarding header is refused (it would let the caller mint a fresh
    // bucket per request) and degrades to the default.
    const requestedKey = String(endpoint.client_max_rate_strategy_key ?? "")
      .trim()
      .toLowerCase();
    if (requestedKey === "" || FORGEABLE_RATE_KEY_HEADERS.has(requestedKey)) {
      if (requestedKey !== "") {
        logger.warn(
          `Ignoring client_max_rate_strategy_key ${JSON.stringify(
            requestedKey,
          )}: a caller-settable forwarding header cannot key a rate limiter; using ${CLIENT_IP_HEADER}.`,
        );
      }
      this.clientMaxRateStrategyKey = CLIENT_IP_HEADER;
    } else {
      this.clientMaxRateStrategyKey = requestedKey;
    }

    const backgroundIdleSessions =
      mcpServerPool.getBackgroundIdleSessionsByNamespace();

    // The default path routes through resolveClientIp so a duplicated
    // CF-Connecting-IP is collapsed the same way the auth plane collapses it;
    // a validated custom header is read directly with the same first-value
    // handling, falling back to the socket address when absent.
    let key;
    if (this.clientMaxRateStrategyKey === CLIENT_IP_HEADER) {
      key = resolveClientIp(headers) || socket.remoteAddress;
    } else {
      const raw = headers[this.clientMaxRateStrategyKey];
      const value = Array.isArray(raw) ? raw[0] : raw;
      key =
        typeof value === "string" && value.trim() !== ""
          ? value.trim()
          : socket.remoteAddress;
    }

    let limiter = this.limiters.get(key);

    if (backgroundIdleSessions.size > 0) {
      if (
        backgroundIdleSessions.get(namespace_uuid)?.get("status") === "created"
      ) {
        if (!backgroundIdleSessions.get(namespace_uuid)?.has(key)) {
          backgroundIdleSessions.get(namespace_uuid)?.set(key, "initialized");
          if (!limiter) {
            this.limiters.set(
              key,
              new Map().set(
                namespace_uuid,
                new SlidingWindowRateLimiter(
                  this.clientMaxRate,
                  this.clientMaxRateSeconds,
                ),
              ),
            );
            limiter = this.limiters.get(key);
          } else {
            // `limiter` is keyed by namespace_uuid (set above), not by the
            // client key -- checking `.has(key)` here almost never matched,
            // so this branch silently replaced the already-tracked
            // SlidingWindowRateLimiter (and its accumulated request
            // history) on every call, and the client rate limit was never
            // enforced. Ported fix from upstream metamcp PR #258.
            if (!limiter.has(namespace_uuid)) {
              limiter.set(
                namespace_uuid,
                new SlidingWindowRateLimiter(
                  this.clientMaxRate,
                  this.clientMaxRateSeconds,
                ),
              );
            }
          }
        }
      }

      const slidingWindowLimiter = limiter?.get(namespace_uuid);
      if (slidingWindowLimiter) {
        const allowed = await slidingWindowLimiter?.isAllowed();
        if (!allowed) {
          throw new RateLimitError(
            `Rate limit exceeded: ${this.clientMaxRate} requests per ${this.clientMaxRateSeconds} second/s`,
          );
        }
      }
    }

    return callNext(context);
  }

  async onResponse(context: Context, callNext: CallNext): Promise<any> {
    return callNext(context);
  }

  /**
   * Drop limiters whose window has fully drained.
   *
   * WHY THIS EXISTS. The per-(client, namespace) map is populated on every
   * new key and never pruned by the request path. With a distinct key per
   * request -- which a rotated header would give even after the edge-IP default, and which
   * distinct real callers give normally -- the map grows for the life of the
   * process, a slow leak. `lib/client-ip` used to claim the auth limiter's
   * sweep bounded this map; it does not (that sweep iterates AuthRateLimiter
   * instances only), so this map carries its own. Wired to an unref'd
   * ten-minute timer at the singleton site in
   * `middleware/rate-limit.middleware`, mirroring `lib/auth-rate-limiter`.
   */
  cleanup(): void {
    const now = Date.now() / 1000;
    const backgroundIdleSessions =
      mcpServerPool.getBackgroundIdleSessionsByNamespace();
    for (const [clientKey, perNamespace] of this.limiters.entries()) {
      for (const [ns, limiter] of perNamespace.entries()) {
        if (limiter.isExpired(now)) {
          perNamespace.delete(ns);
          // Drop the pool's matching "initialized" marker in lockstep. onRequest
          // only builds a limiter for a (clientKey, namespace) whose marker is
          // unset; when the namespace's idle session is stable the marker
          // sticks, so evicting the limiter while leaving the marker would send
          // the next request from a returning client down the skip-creation
          // path with no limiter -- an unlimited pass, the limit silently gone.
          // Deleting the marker forces a rebuild, re-limiting the client with a
          // fresh budget. (When the idle session churns the marker is already
          // reopened every call, so this is a no-op there.)
          backgroundIdleSessions.get(ns)?.delete(clientKey);
        }
      }
      if (perNamespace.size === 0) {
        this.limiters.delete(clientKey);
      }
    }
  }
}
