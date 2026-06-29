import logger from "@/utils/logger";

// Event class for a log entry. Lets the Live Logs view show real activity
// (connections, tool calls, who's connecting) and filter by kind.
//   connection — gateway↔backend connect attempt / success / transport drop
//   client     — a CONSUMER (claude.ai/Tara/n8n) opened a session at an endpoint
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

  clearLogs(): void {
    this.logs = [];
  }

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
