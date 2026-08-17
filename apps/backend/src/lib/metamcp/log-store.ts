import { recordGatewayEvent } from "@/lib/gateway-events/sink";
import logger from "@/utils/logger";

// Event class for a log entry. Lets the Live Logs view show real activity
// (connections, tool calls, who's connecting) and filter by kind.
//   connection — gateway↔backend connect attempt / success / transport drop
//   client     — a CONSUMER (claude.ai/n8n/agents) opened a session at an endpoint
//   tool_call  — a tools/call proxied to a backend (name, duration, ok/fail)
//   server     — backend-emitted output (stderr) or a server config error
//   system     — gateway lifecycle / pool events
export type MetaMcpLogCategory =
  | "connection"
  | "client"
  | "tool_call"
  | "server"
  | "system";

export interface MetaMcpLogEntry {
  id: string;
  timestamp: Date;
  category: MetaMcpLogCategory;
  serverName: string;
  serverUuid?: string;
  level: "error" | "info" | "warn";
  message: string;
  toolName?: string;
  durationMs?: number;
  // The authenticated consumer that drove this event (api-key name or OAuth
  // user email). Present on tool_call + client events; absent on internal
  // gateway↔backend connection/server events (no consumer involved).
  clientName?: string;
  // The MCP session this event belongs to, where one exists. Set on the
  // client-session events emitted by the public StreamableHTTP router; absent
  // on gateway↔backend connection/server events, which have no client session.
  sessionId?: string;
  error?: string;
}

function normalizeError(error?: unknown): string | undefined {
  if (!error) return undefined;
  return error instanceof Error ? error.message : String(error);
}

class MetaMcpLogStore {
  private logs: MetaMcpLogEntry[] = [];
  // Ring buffer: keep only the newest maxLogs entries. Bumped 1000 -> 2000
  // because tool_call events (added 2026-06-29) churn the buffer faster than
  // the old connection-error-only stream did.
  private readonly maxLogs = 2000;
  private readonly listeners: Set<(log: MetaMcpLogEntry) => void> = new Set();

  /**
   * Structured entry point — prefer this for new call sites. Carries the event
   * category plus optional server identity, tool name, and duration so the
   * Live Logs view surfaces real activity and can filter by category.
   */
  record(entry: {
    category: MetaMcpLogCategory;
    serverName: string;
    level: MetaMcpLogEntry["level"];
    message: string;
    serverUuid?: string;
    toolName?: string;
    durationMs?: number;
    clientName?: string;
    sessionId?: string;
    error?: unknown;
  }): void {
    const logEntry: MetaMcpLogEntry = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      category: entry.category,
      serverName: entry.serverName,
      serverUuid: entry.serverUuid,
      level: entry.level,
      message: entry.message,
      toolName: entry.toolName,
      durationMs: entry.durationMs,
      clientName: entry.clientName,
      sessionId: entry.sessionId,
      error: normalizeError(entry.error),
    };

    this.logs.push(logEntry);
    if (this.logs.length > this.maxLogs) {
      this.logs = this.logs.slice(-this.maxLogs);
    }

    // Mirror to stdout — Promtail ships this to Loki/Grafana, the durable
    // system of record. The in-memory store is the fast, ephemeral view.
    const who = entry.clientName ? ` ← ${entry.clientName}` : "";
    const fullMessage = `[MetaMCP][${entry.category}][${entry.serverName}] ${entry.message}${who}`;
    switch (entry.level) {
      case "error":
        logger.error(fullMessage, entry.error || "");
        break;
      case "warn":
        logger.warn(fullMessage, entry.error || "");
        break;
      case "info":
        logger.info(fullMessage, entry.error || "");
        break;
    }

    this.listeners.forEach((listener) => {
      try {
        listener(logEntry);
      } catch (err) {
        logger.error("Error notifying log listener:", err);
      }
    });

    // Durable half of the same event (`gateway_events`, migration 0031). The
    // ring buffer above is 2000 entries and dies with the process; this is what
    // makes "was this failing yesterday too?" answerable after a restart.
    //
    // Wired HERE rather than at each call site, and rather than through
    // `addListener`, because coverage-by-construction is the point: every
    // present and future emitter is persisted without anyone remembering to opt
    // in, and a registration that lives somewhere else can be dropped in a
    // refactor without a single test noticing. `recordGatewayEvent` is
    // fire-and-forget, never throws, filters out `tool_call` (already persisted
    // to `tool_call_audit` with more detail), and keeps this module's STATIC
    // graph database-free via a lazy repository import — see
    // lib/gateway-events/sink.
    //
    // LAST, and GUARDED, and the two together are what make the claim true.
    //
    // Last, because everything above it — the ring push, the stdout mirror
    // Promtail ships, the listener fan-out — is the behaviour this module had
    // before there was a history to write, and none of it may become
    // conditional on a database.
    //
    // Guarded, because ordering alone only protects what runs BEFORE the call.
    // `record()` is invoked from inside transport `onclose`/`onerror` handlers
    // in `client.ts`, which go on to fire `onTransportDrop` — the reconnect and
    // eviction callback — AFTER returning from here. A throw escaping this line
    // would skip that, so a broken history write could stop a backend from
    // being reconnected. `recordGatewayEvent` is built never to throw; this is
    // the belt that makes a future change to it unable to reach the caller.
    try {
      recordGatewayEvent({
        category: logEntry.category,
        level: logEntry.level,
        serverUuid: logEntry.serverUuid,
        serverName: logEntry.serverName,
        clientName: logEntry.clientName,
        sessionId: logEntry.sessionId,
        message: logEntry.message,
        metadata:
          logEntry.error !== undefined ? { error: logEntry.error } : undefined,
      });
    } catch (err) {
      // Logged rather than swallowed: reaching here means the sink's own
      // guarantees are broken, which is a real defect worth seeing, just not
      // one worth breaking a reconnect over.
      logger.error("Error persisting gateway event:", err);
    }
  }

  /**
   * Legacy positional entry point. Retained for existing call sites; defaults
   * the category to "server" (these were all backend-emitted stderr / config
   * errors). New code should call record().
   */
  addLog(
    serverName: string,
    level: MetaMcpLogEntry["level"],
    message: string,
    error?: unknown,
  ): void {
    this.record({ category: "server", serverName, level, message, error });
  }

  getLogs(limit?: number): MetaMcpLogEntry[] {
    const logsToReturn = limit ? this.logs.slice(-limit) : this.logs;
    return [...logsToReturn].reverse(); // Return newest first
  }

  // There is deliberately no clearLogs(). Its only caller was the `logs.clear`
  // tRPC mutation, removed with migration 0028's audit_log: the one admin
  // gesture that erased the live security view mid-investigation. Leaving an
  // unused wipe method behind is how it comes back. The buffer still rolls at
  // maxLogs — bounded, but never emptied on command.

  addListener(listener: (log: MetaMcpLogEntry) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  getLogCount(): number {
    return this.logs.length;
  }
}

// Singleton instance
export const metamcpLogStore = new MetaMcpLogStore();
