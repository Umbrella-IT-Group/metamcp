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
 * consumer reconnects transparently on its next request via the fork's
 * lazy session-recovery path (`recoverPersistedSession` in
 * `streamable-http.ts`) — which requires the `mcp_sessions` ROW to still
 * exist. `reapSession` (injected by the caller) MUST be a row-preserving
 * teardown variant (close transport, drop in-memory session state,
 * release pool connections — skip the DB row delete), not the same
 * variant a client `DELETE` uses. Foreman review (PR #72 fixes round)
 * caught an earlier version of this PR wired to the row-DELETING variant,
 * which made a reaped session's next request 404 instead of lazily
 * recovering — harmless for spec-conformant clients (they just
 * re-`initialize`), but the Anthropic/claude.ai connector wraps that 404
 * as `-32600 "Anthropic Proxy: Invalid content from server"` and stays
 * broken until a manual `/mcp reconnect`, exactly the failure mode PR
 * #22/#23's capability-hash refusal narrowing exists to avoid. See
 * `streamable-http.ts`'s `reapIdleSession` for the row-preserving variant
 * and its accepted-tradeoff note (reaped rows linger until the
 * `MCP_SESSION_TTL_DAYS` pruner catches them).
 *
 * Conventions mirror the PR #70 tool-definition sweep in
 * `mcp-server-pool.ts`: env-tunable interval, a single-in-flight
 * re-entrancy guard, cleanup on dispose, and WARN/INFO discipline (one
 * INFO line only when a sweep actually reaps something, debug otherwise).
 *
 * Known blind spot (accepted, not fixed here): a half-open TCP connection
 * — client process died or a network path silently dropped packets
 * without FIN/RST — keeps an open standalone GET stream's `dispatchTracked`
 * call pending indefinitely from Node's perspective, so the in-flight
 * guard below never releases and the session is never reaped even though
 * no real client is listening. See the comment on `dispatchTracked` in
 * `streamable-http.ts` for the full writeup and the named follow-up
 * (SO_KEEPALIVE / an app-level SSE heartbeat).
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

  /**
   * Seed tracking for a session at the two legitimate "this session now
   * exists in memory" moments: fresh creation and lazy recovery after a
   * reap. Unconditional by design — `touch()` / `markInFlight()` /
   * `markSettled()` below are deliberately guarded (foreman review, PR
   * #72 fixes round) so a trailing call that lands after `forget()` has
   * already run (a request racing a concurrent DELETE, or a reap's own
   * teardown) can't resurrect a zombie tracking entry for a session
   * whose transport/pool state is already gone. `beginTracking` is the
   * one call site allowed to create a fresh entry from nothing.
   */
  beginTracking(sessionId: string): void {
    this.lastActivity.set(sessionId, this.now());
  }

  /**
   * Stamp last-activity = now for a session. No-op if the session isn't
   * currently tracked — a request that lands after `forget()` has
   * already run (concurrent DELETE, or the tail of a reap) must not
   * resurrect a tracking entry for a session that no longer has a live
   * transport/pool state behind it. Use `beginTracking` to seed a new
   * entry.
   */
  touch(sessionId: string): void {
    if (!this.lastActivity.has(sessionId)) return;
    this.lastActivity.set(sessionId, this.now());
  }

  /**
   * Mark a request arriving on a session (increments in-flight + stamps
   * activity). No-op entirely — including the in-flight increment — for
   * a session that isn't tracked, so a request racing a concurrent
   * `forget()` can't leave a dangling in-flight count with no
   * corresponding activity entry.
   */
  markInFlight(sessionId: string): void {
    if (!this.lastActivity.has(sessionId)) return;
    this.inFlight.set(sessionId, (this.inFlight.get(sessionId) ?? 0) + 1);
    this.touch(sessionId);
  }

  /**
   * Mark a request completing on a session (decrements in-flight +
   * re-stamps activity). No-op if the session isn't tracked: a trailing
   * `markSettled` that lands after a concurrent DELETE's `forget()` has
   * already run must not resurrect the entry — the un-guarded version of
   * this method previously did exactly that (foreman review, PR #72
   * fixes round).
   */
  markSettled(sessionId: string): void {
    if (!this.lastActivity.has(sessionId)) return;
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
   * cleanup path, row-preserving variant) per candidate, tolerating
   * per-candidate failure.
   *
   * Candidates are processed SEQUENTIALLY, with a recheck (still idle
   * beyond TTL AND still no in-flight request) evaluated fresh
   * immediately before each individual `reapSession` call — not just
   * once at snapshot time (foreman review, PR #72 fixes round). The
   * initial scan below is a snapshot; a real request can land on any
   * not-yet-reaped candidate while an EARLIER candidate's reap is
   * awaiting real I/O (transport close, backend pool teardown), and
   * sequential processing is what makes that window real (a fire-all-
   * concurrently batch kicks off every reap in the same synchronous
   * tick, before any request has a chance to interleave). The recheck
   * means a session that became live again since the snapshot is
   * skipped instead of having its transport torn down under a request
   * that's using it. Accepted tradeoff: a large reap batch (e.g. the
   * first sweep after this ships, against an existing idle-session
   * backlog) takes longer wall-clock than a parallel-fire batch would —
   * correctness under concurrent traffic matters more here than sweep
   * throughput, and steady-state batches are small.
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

      // Snapshot candidates BEFORE reaping — reaping mutates lastActivity
      // (via forget()) mid-loop otherwise.
      const candidates: string[] = [];
      for (const [sessionId, last] of this.lastActivity) {
        if ((this.inFlight.get(sessionId) ?? 0) > 0) continue; // never reap in-flight
        if (now - last > this.ttlMs) candidates.push(sessionId);
      }

      this.totalSweeps += 1;
      this.lastSweepAt = now;

      if (candidates.length === 0) {
        this.lastReapedCount = 0;
        this.lastReleasedCount = 0;
        logger.debug(
          `Public-session sweep (${this.name}): nothing to reap ` +
            `(${scanned} tracked, ttl ${this.ttlMs / 1000}s).`,
        );
        return { scanned, reaped: 0, released: 0, failed: 0 };
      }

      const before = this.safeMeasure();
      let reaped = 0;
      let failed = 0;

      for (const sessionId of candidates) {
        // Recheck against CURRENT state, not the snapshot above — this is
        // the fix for the snapshot-to-reap race (see method doc).
        const stillInFlight = (this.inFlight.get(sessionId) ?? 0) > 0;
        const last = this.lastActivity.get(sessionId);
        if (
          stillInFlight ||
          last === undefined || // forgotten by something else since the snapshot
          this.now() - last <= this.ttlMs // touched again since the snapshot
        ) {
          continue; // saved by the recheck — leave its tracking alone
        }
        try {
          await this.reapSession(sessionId);
          reaped += 1;
        } catch (error) {
          failed += 1;
          logger.warn(
            `Public-session sweep (${this.name}): reap failed for session ${sessionId}.`,
            error,
          );
        }
        // Forget regardless of success. cleanupSession logs its own error
        // and still tears down what it can; a session we can't fully reap
        // must not be re-selected every tick forever (same
        // map-consistency-over-cleanup rule as metamcp-server-pool
        // .cleanupSession). forget() may already have run inside a
        // successful reap — deleting an absent key is a no-op.
        this.forget(sessionId);
      }

      // Sampled once before and once after the whole batch, so this is a
      // best-effort DELTA, not a per-session audit trail — concurrent
      // traffic (new sessions connecting, other pool activity) during the
      // batch can shift the count independently of this sweep's own
      // reaps. Logged with a leading "~" for exactly that reason.
      const after = this.safeMeasure();
      const released = Math.max(0, before - after);

      this.lastReapedCount = reaped;
      this.lastReleasedCount = released;
      this.totalReaped += reaped;
      this.totalConnectionsReleased += released;

      if (reaped > 0 || failed > 0) {
        logger.info(
          `Public-session sweep (${this.name}): reaped ${reaped} idle public ` +
            `session(s) (ttl ${this.ttlMs / 1000}s), released ~${released} ` +
            `backend connection(s)` +
            (failed > 0
              ? `; ${failed} reap(s) failed (see prior errors)`
              : "") +
            ".",
        );
      } else {
        // Every candidate was saved by the pre-reap recheck — nothing
        // actually happened, so this stays at debug per the "INFO only
        // when a sweep reaps something" discipline.
        logger.debug(
          `Public-session sweep (${this.name}): all ${candidates.length} ` +
            `candidate(s) became active again before their recheck; nothing reaped.`,
        );
      }

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
