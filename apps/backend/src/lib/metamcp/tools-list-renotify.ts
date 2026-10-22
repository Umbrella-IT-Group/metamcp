/**
 * Re-notify a session whose tools/list left out a backend it could not reach.
 *
 * THE DEFECT THIS CLOSES. When a backend container restarts, the pool's drop
 * detectors (the transport-drop callback, the active health check, request
 * recovery) run `invalidateServerConnection`, which sends
 * `notifications/tools/list_changed` to every session subscribed on the dead
 * clients at that moment, before any replacement backend exists. A client
 * that re-lists on the notification (as the spec intends) lands its
 * tools/list inside the restart window: the connect fails, the handler leaves
 * that server out, and the client replaces its tool set with what it got.
 * When the backend came back, nothing told that session again: list_changed
 * subscribers attach only to a client the session actually obtained, the
 * failed connect gave it none, and the health check and tool sweep only act
 * on clients that already exist. A long-lived session kept its reduced tool
 * list until it reconnected. For a namespace that holds one server, that was
 * every tool of the namespace.
 *
 * WHAT THIS DOES. A proxy whose listing left a server out because the server
 * could not be reached owes that session one `list_changed`. It registers a
 * watch here; one probe loop per backend (shared by every session owed for
 * it) checks, on a capped backoff, whether the backend answers tools/list
 * again, and as soon as it does every watcher is told once, so its session
 * gets the notification and re-lists. A successful pool connect to that
 * backend (from any session, or the pool's own idle refill) triggers an
 * immediate probe, so the usual delay after a restart is the connect itself,
 * not the backoff.
 *
 * WHY THE PROBE DECIDES, NOT THE CONNECT EVENT. A connect proves the
 * transport, not that tools/list answers; telling a session to re-list into
 * a backend that still cannot list would only produce another reduced
 * listing. The probe (`McpServerPool.probeServerTools`) lists over a real
 * pooled connection, with a timeout.
 *
 * PURE: no imports beyond the logger, so the pool can notify it without an
 * import cycle and tests can drive it with fake timers.
 */

import logger from "@/utils/logger";

/** Answers whether the backend lists its tools right now. */
export type ToolsListProbe = () => Promise<boolean>;

/**
 * Probe delays after the first watcher arrives. The first probes are quick
 * because a container restart is usually back within seconds; the last value
 * repeats, so a backend that stays down costs one probe a minute (the same
 * cadence the pool's own idle refill already connects at).
 */
export const DEFAULT_RENOTIFY_PROBE_DELAYS_MS: readonly number[] = [
  2_000, 4_000, 8_000, 15_000, 30_000, 60_000,
];

/** `MCP_TOOLS_LIST_RENOTIFY=false` (or `off`, `0`) disables arming new watches. */
export function toolsListRenotifyEnabled(
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  const raw = (env.MCP_TOOLS_LIST_RENOTIFY ?? "true").trim().toLowerCase();
  return !["false", "off", "0"].includes(raw);
}

interface Watcher {
  onRecovered: () => void;
}

interface ServerWatch {
  watchers: Set<Watcher>;
  probe: ToolsListProbe;
  attempt: number;
  timer?: ReturnType<typeof setTimeout>;
  probing: boolean;
  /** A connect landed while a probe was in flight: probe again right after. */
  probeAgain: boolean;
}

export interface ToolsListRenotifyOptions {
  delaysMs?: readonly number[];
}

export class ToolsListRenotifyWatch {
  private readonly delaysMs: readonly number[];
  private readonly watches = new Map<string, ServerWatch>();

  constructor(options: ToolsListRenotifyOptions = {}) {
    const delays = options.delaysMs ?? DEFAULT_RENOTIFY_PROBE_DELAYS_MS;
    if (delays.length === 0 || delays.some((d) => !(d >= 0))) {
      throw new Error("ToolsListRenotifyWatch needs non-negative delays");
    }
    this.delaysMs = delays;
  }

  /**
   * Call `onRecovered` once, the first time `serverUuid` answers tools/list
   * after this call. Returns the function that cancels this watch. The probe
   * of the first watcher of a server is the one the loop uses; every caller
   * passes the same pool's probe. `startAttempt` skips the first steps of
   * the backoff, for a server that was already re-notified once and failed
   * the session's re-list again (a flapping backend must not drive a re-list
   * every two seconds).
   */
  watch(
    serverUuid: string,
    probe: ToolsListProbe,
    onRecovered: () => void,
    startAttempt = 0,
  ): () => void {
    const watcher: Watcher = { onRecovered };
    let state = this.watches.get(serverUuid);
    if (!state) {
      state = {
        watchers: new Set(),
        probe,
        attempt: Math.max(0, Math.floor(startAttempt)),
        probing: false,
        probeAgain: false,
      };
      this.watches.set(serverUuid, state);
      state.watchers.add(watcher);
      this.schedule(serverUuid, state, this.delayFor(state.attempt));
    } else {
      state.watchers.add(watcher);
    }
    return () => this.unwatch(serverUuid, watcher);
  }

  /**
   * The pool connected to this backend. Probe now instead of waiting for the
   * backoff; a no-op for a backend nobody is owed.
   */
  notifyConnected(serverUuid: string): void {
    const state = this.watches.get(serverUuid);
    if (!state) return;
    if (state.probing) {
      state.probeAgain = true;
      return;
    }
    this.schedule(serverUuid, state, 0);
  }

  /** Backends with at least one owed session (for tests and diagnostics). */
  watchedServerCount(): number {
    return this.watches.size;
  }

  private delayFor(attempt: number): number {
    return this.delaysMs[Math.min(attempt, this.delaysMs.length - 1)];
  }

  private unwatch(serverUuid: string, watcher: Watcher): void {
    const state = this.watches.get(serverUuid);
    if (!state || !state.watchers.delete(watcher)) return;
    if (state.watchers.size === 0) {
      if (state.timer) clearTimeout(state.timer);
      this.watches.delete(serverUuid);
    }
  }

  private schedule(
    serverUuid: string,
    state: ServerWatch,
    delay: number,
    connectRetry = false,
  ) {
    if (state.timer) clearTimeout(state.timer);
    state.timer = setTimeout(() => {
      state.timer = undefined;
      void this.runProbe(serverUuid, state, connectRetry);
    }, delay);
    // A pending probe must never keep the process alive on shutdown.
    state.timer.unref?.();
  }

  private async runProbe(
    serverUuid: string,
    state: ServerWatch,
    connectRetry: boolean,
  ) {
    // A cancelled watch (every watcher gone) or one replaced by a newer
    // watch for the same server never probes.
    if (this.watches.get(serverUuid) !== state) return;
    if (state.probing) {
      state.probeAgain = true;
      return;
    }
    state.probing = true;
    let answered = false;
    try {
      answered = await state.probe();
    } catch (error) {
      logger.warn(
        `tools/list re-notify: probe of server ${serverUuid} threw; treating the server as not answering yet:`,
        error,
      );
    } finally {
      state.probing = false;
    }

    if (this.watches.get(serverUuid) !== state) return;

    if (answered) {
      this.watches.delete(serverUuid);
      if (state.timer) clearTimeout(state.timer);
      const watchers = Array.from(state.watchers);
      state.watchers.clear();
      for (const watcher of watchers) {
        try {
          watcher.onRecovered();
        } catch (error) {
          logger.warn(
            `tools/list re-notify: a watcher of server ${serverUuid} threw while being told the server answers again:`,
            error,
          );
        }
      }
      return;
    }

    const probeAgain = state.probeAgain;
    state.probeAgain = false;
    // A probe can establish its own idle connection, triggering
    // notifyConnected before that connection's tools/list fails. Permit one
    // immediate retry for a connect during an older probe, then back off:
    // repeating that self-generated signal would otherwise spin forever.
    if (probeAgain && !connectRetry) {
      this.schedule(serverUuid, state, 0, true);
      return;
    }
    state.attempt += 1;
    this.schedule(serverUuid, state, this.delayFor(state.attempt));
  }
}

/** The process-wide watch the proxy arms and the pool notifies. */
export const toolsListRenotifyWatch = new ToolsListRenotifyWatch();
