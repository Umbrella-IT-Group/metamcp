import logger from "@/utils/logger";

/**
 * Idle-TTL sweeper for public-endpoint (API-key / OAuth) StreamableHTTP
 * sessions.
 *
 * WHY THIS EXISTS (2026-07-14 pool-cap incident, METAMCP-POOL-1):
 * A public endpoint session is created per API-key request stream and is
 * only torn down when the client sends an explicit `DELETE`. Most clients
 * never send it, so sessions accumulate indefinitely (prod: 241 → 1363
 * sessions in 17h). Each holds backend pool connections; once the global
 * backend pool reaches `MAX_TOTAL_CONNECTIONS` every new connect
 * LRU-evicts a LIVE connection, surfacing as transient
 * "Failed to re-initialize session ... after backend session loss"
 * tool failures. Persistent sessions (`sessionLifetime` null, the prod
 * default) never expire by design, so the existing age-based
 * `SessionLifetimeManagerImpl` cleanup timer never fires.
 *
 * This sweeper reaps on a DIFFERENT axis than that age-based timer:
 * last-request IDLE time, not session CREATION age. A reaped session's
 * consumer reconnects transparently on its next request (the fork's
 * lazy session-recovery path rebuilds the transport — verified live). The
 * reap runs the SAME cleanup path a client `DELETE` runs (injected as
 * `reapSession`); it introduces NO new teardown mechanism.
 *
 * Conventions mirror the PR #70 tool-definition sweep in
 * `mcp-server-pool.ts`: env-tunable interval, a single-in-flight
 * re-entrancy guard, cleanup on dispose, and WARN/INFO discipline (one
 * INFO line only when a sweep actually reaps something, debug otherwise).
 */

// 24h default. Long-idle-but-real consumers (e.g. Hermes/Tara connecting a
// namespace once and calling tools sporadically across a workday) must
// survive an idle stretch; a shorter default would reap a live consumer
// mid-day and force a reconnect. Generous by design — the cap-saturation
// problem is abandoned sessions that never come back, not sessions idle for
// a few hours.
const DEFAULT_TTL_SECONDS = 86400;

// 5 min sweep cadence. Frequent enough to keep the pool tracking real usage,
// infrequent enough that the scan cost is negligible.
const DEFAULT_INTERVAL_SECONDS = 300;

/**
 * Parse a non-negative integer seconds env value. `0` is a VALID value that
 * disables the knob (no reaping / no timer) — only a malformed or negative
 * value falls back to the default (with a WARN so a typo is visible).
 */
function parseSeconds(
  raw: string | undefined,
  name: string,
  fallback: number,
): number {
  if (raw === undefined || raw === "") return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed) || parsed < 0) {
    logger.warn(
      `${name}=${raw} invalid; falling back to default ${fallback}s.`,
    );
    return fallback;
  }
  return parsed;
}

export interface PublicSessionSweeperConfig {
  // Idle threshold in ms. A session whose last request is older than this is
  // eligible for reaping. `<= 0` disables reaping entirely.
  ttlMs: number;
  // Sweep cadence in ms. `<= 0` disables the interval timer.
  intervalMs: number;
}

export interface PublicSessionSweeperDeps {
  // Reap one session through the SAME path a client DELETE runs (release /
  // recycle backend connections, drop session state). Injected so this
  // module never authors its own teardown.
  reapSession: (sessionId: string) => Promise<void>;
  // Current backend-pool ACTIVE connection count, sampled before/after a
  // reap batch to report how many connections the sweep released. Optional:
  // when absent the released count is reported as 0 (the reaped count still
  // logs). Sampling `active` (not idle+active) keeps the delta clean — the
  // async idle-server recreation a reap triggers lands in `idle`, not
  // `active`, so it can't understate the release.
  measureActiveConnections?: () => number;
  // Injectable clock for deterministic tests. Defaults to `Date.now`.
  now?: () => number;
}

export interface PublicSessionSweeperStats {
  enabled: boolean;
  ttlSeconds: number;
  intervalSeconds: number;
  trackedSessions: number;
  inFlightSessions: number;
  totalSweeps: number;
  totalReaped: number;
  totalConnectionsReleased: number;
  lastSweepAt: string | null;
  lastReapedCount: number;
  lastReleasedCount: number;
}

export interface SweepResult {
  scanned: number;
  reaped: number;
  released: number;
  failed: number;
}

export class PublicSessionSweeper {
  private readonly name: string;
  private readonly ttlMs: number;
  private readonly intervalMs: number;
  private readonly reapSession: (sessionId: string) => Promise<void>;
  private readonly measureActiveConnections: () => number;
  private readonly now: () => number;

  // Per-session last-activity stamp (ms). Cheap in-memory map; updated on
  // every request touching the session.
  private readonly lastActivity = new Map<string, number>();

  // Per-session in-flight request count. A session with any in-flight
  // request is never reaped, so a tool call that runs longer than the TTL
  // survives (a long call is live use, not idleness).
  private readonly inFlight = new Map<string, number>();

  private sweepTimer: NodeJS.Timeout | null = null;

  // Re-entrancy guard: at most one sweep runs at a time. An interval tick
  // that fires while the previous sweep is still awaiting reaps is skipped
  // (mirrors #70's `toolsSweepInProgress`). Cleared in `finally`.
  private sweepInProgress = false;

  // Cumulative observability counters (surfaced via getStats()).
  private totalSweeps = 0;
  private totalReaped = 0;
  private totalConnectionsReleased = 0;
  private lastSweepAt: number | null = null;
  private lastReapedCount = 0;
  private lastReleasedCount = 0;

  constructor(
    name: string,
    config: PublicSessionSweeperConfig,
    deps: PublicSessionSweeperDeps,
  ) {
    this.name = name;
    this.ttlMs = config.ttlMs;
    this.intervalMs = config.intervalMs;
    this.reapSession = deps.reapSession;
    this.measureActiveConnections = deps.measureActiveConnections ?? (() => 0);
    this.now = deps.now ?? (() => Date.now());
  }

  /**
   * Build a sweeper reading its TTL + interval from the environment:
   *   PUBLIC_SESSION_TTL_SECONDS      (default 86400; 0 disables reaping)
   *   SESSION_SWEEP_INTERVAL_SECONDS  (default 300;   0 disables the timer)
   */
  static fromEnv(
    name: string,
    deps: PublicSessionSweeperDeps,
  ): PublicSessionSweeper {
    const ttlSeconds = parseSeconds(
      process.env.PUBLIC_SESSION_TTL_SECONDS,
      "PUBLIC_SESSION_TTL_SECONDS",
      DEFAULT_TTL_SECONDS,
    );
    const intervalSeconds = parseSeconds(
      process.env.SESSION_SWEEP_INTERVAL_SECONDS,
      "SESSION_SWEEP_INTERVAL_SECONDS",
      DEFAULT_INTERVAL_SECONDS,
    );
    return new PublicSessionSweeper(
      name,
      { ttlMs: ttlSeconds * 1000, intervalMs: intervalSeconds * 1000 },
      deps,
    );
  }

  /** Stamp last-activity = now for a session. Cheap; called on every request. */
  touch(sessionId: string): void {
    this.lastActivity.set(sessionId, this.now());
  }

  /** Mark a request arriving on a session (increments in-flight + stamps activity). */
  markInFlight(sessionId: string): void {
    this.inFlight.set(sessionId, (this.inFlight.get(sessionId) ?? 0) + 1);
    this.touch(sessionId);
  }

  /** Mark a request completing on a session (decrements in-flight + re-stamps activity). */
  markSettled(sessionId: string): void {
    const remaining = (this.inFlight.get(sessionId) ?? 0) - 1;
    if (remaining > 0) {
      this.inFlight.set(sessionId, remaining);
    } else {
      this.inFlight.delete(sessionId);
    }
    // Re-stamp on completion so a call that ran longer than the TTL doesn't
    // become instantly reapable the moment it settles.
    this.touch(sessionId);
  }

  /** Drop all tracking for a session. Called from the reap/DELETE cleanup path. */
  forget(sessionId: string): void {
    this.lastActivity.delete(sessionId);
    this.inFlight.delete(sessionId);
  }

  /** True when idle reaping is enabled (TTL > 0). */
  isEnabled(): boolean {
    return this.ttlMs > 0;
  }

  private safeMeasure(): number {
    try {
      return this.measureActiveConnections();
    } catch (error) {
      logger.warn(
        `Public-session sweep (${this.name}): connection-count probe failed; reporting 0 released.`,
        error,
      );
      return 0;
    }
  }

  /**
   * One reap pass. Reaps every tracked session idle beyond the TTL that has
   * no in-flight request. Runs the injected `reapSession` (= the DELETE
   * cleanup path) per victim, tolerating per-victim failure.
   */
  async sweepOnce(): Promise<SweepResult> {
    const empty: SweepResult = {
      scanned: 0,
      reaped: 0,
      released: 0,
      failed: 0,
    };
    if (!(this.ttlMs > 0)) return empty; // disabled — no reaping
    if (this.sweepInProgress) return empty; // overlapping tick skipped
    this.sweepInProgress = true;
    try {
      const now = this.now();
      const scanned = this.lastActivity.size;

      // Collect victims into an array BEFORE reaping — reapSession →
      // cleanupSession → forget() mutates lastActivity mid-loop otherwise.
      const victims: string[] = [];
      for (const [sessionId, last] of this.lastActivity) {
        if ((this.inFlight.get(sessionId) ?? 0) > 0) continue; // never reap in-flight
        if (now - last > this.ttlMs) victims.push(sessionId);
      }

      this.totalSweeps += 1;
      this.lastSweepAt = now;

      if (victims.length === 0) {
        this.lastReapedCount = 0;
        this.lastReleasedCount = 0;
        logger.debug(
          `Public-session sweep (${this.name}): nothing to reap ` +
            `(${scanned} tracked, ttl ${this.ttlMs / 1000}s).`,
        );
        return { scanned, reaped: 0, released: 0, failed: 0 };
      }

      const before = this.safeMeasure();
      const results = await Promise.allSettled(
        victims.map((sessionId) => this.reapSession(sessionId)),
      );
      const failed = results.filter((r) => r.status === "rejected").length;

      // Drop tracking for every victim even on reap failure. cleanupSession
      // logs its own error and still tears down the maps it can; a session
      // we can't reap must not be re-selected every tick forever (same
      // map-consistency-over-cleanup rule as metamcp-server-pool
      // .cleanupSession). forget() may already have run inside a successful
      // reap — deleting an absent key is a no-op.
      for (const sessionId of victims) this.forget(sessionId);

      const after = this.safeMeasure();
      const released = Math.max(0, before - after);
      const reaped = victims.length - failed;

      this.lastReapedCount = reaped;
      this.lastReleasedCount = released;
      this.totalReaped += reaped;
      this.totalConnectionsReleased += released;

      logger.info(
        `Public-session sweep (${this.name}): reaped ${reaped} idle public ` +
          `session(s) (ttl ${this.ttlMs / 1000}s), released ${released} ` +
          `backend connection(s)` +
          (failed > 0 ? `; ${failed} reap(s) failed (see prior errors)` : "") +
          ".",
      );

      return { scanned, reaped, released, failed };
    } finally {
      this.sweepInProgress = false;
    }
  }

  /**
   * Arm the periodic sweep timer. No-op when either knob disables it
   * (TTL <= 0 or interval <= 0). Idempotent — a second call while armed
   * does nothing.
   */
  start(): void {
    if (this.sweepTimer) return;
    if (!(this.ttlMs > 0) || !(this.intervalMs > 0)) {
      logger.info(
        `Public-session TTL sweeper (${this.name}) disabled ` +
          `(PUBLIC_SESSION_TTL_SECONDS=${this.ttlMs / 1000}, ` +
          `SESSION_SWEEP_INTERVAL_SECONDS=${this.intervalMs / 1000}; ` +
          `either <= 0 disables).`,
      );
      return;
    }
    this.sweepTimer = setInterval(() => {
      void this.sweepOnce();
    }, this.intervalMs);
    // Don't keep the process alive on shutdown for the sake of sweeping.
    if (this.sweepTimer.unref) this.sweepTimer.unref();
    logger.info(
      `Public-session TTL sweeper (${this.name}) armed ` +
        `(ttl=${this.ttlMs / 1000}s, interval=${this.intervalMs / 1000}s).`,
    );
  }

  /** Clear the sweep timer (dispose). */
  stop(): void {
    if (this.sweepTimer) {
      clearInterval(this.sweepTimer);
      this.sweepTimer = null;
    }
  }

  getStats(): PublicSessionSweeperStats {
    return {
      enabled: this.isEnabled(),
      ttlSeconds: this.ttlMs / 1000,
      intervalSeconds: this.intervalMs / 1000,
      trackedSessions: this.lastActivity.size,
      inFlightSessions: this.inFlight.size,
      totalSweeps: this.totalSweeps,
      totalReaped: this.totalReaped,
      totalConnectionsReleased: this.totalConnectionsReleased,
      lastSweepAt:
        this.lastSweepAt === null
          ? null
          : new Date(this.lastSweepAt).toISOString(),
      lastReapedCount: this.lastReapedCount,
      lastReleasedCount: this.lastReleasedCount,
    };
  }

  // ---- test-only introspection ----
  getLastActivity(sessionId: string): number | undefined {
    return this.lastActivity.get(sessionId);
  }

  getInFlight(sessionId: string): number {
    return this.inFlight.get(sessionId) ?? 0;
  }

  hasTimer(): boolean {
    return this.sweepTimer !== null;
  }
}
