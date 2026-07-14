import {
  createWriteStream,
  openSync,
  renameSync,
  statSync,
  WriteStream,
} from "fs";
import { format } from "util";
const { LOG_LEVEL } = process.env;

// Severity ordering used by BOTH the console-mirror threshold and any
// future level gating. DEBUG is least severe, ERROR most severe.
const SEVERITY_RANK: Record<"DEBUG" | "INFO" | "WARN" | "ERROR", number> = {
  DEBUG: 0,
  INFO: 1,
  WARN: 2,
  ERROR: 3,
};

// Minimum severity each console mode mirrors to stdout/stderr. Threshold
// semantics: a mode mirrors its own level AND everything MORE severe.
// This is the fix for the 2026-07-14 incident where prod (LOG_LEVEL=info)
// showed a clean `docker logs` while app.log carried 278 cap-refusal WARNs —
// the old logic mirrored ONLY level==="INFO" for the "info" mode, so WARN
// and ERROR never reached the console. Operators watch the console; a mode
// that hides everything above its own name is a silent blind spot.
const CONSOLE_FLOOR: Record<"all" | "info" | "errors-only" | "none", number> = {
  all: SEVERITY_RANK.DEBUG, // DEBUG + INFO + WARN + ERROR
  info: SEVERITY_RANK.INFO, // INFO + WARN + ERROR
  "errors-only": SEVERITY_RANK.WARN, // WARN + ERROR (unchanged)
  none: Number.POSITIVE_INFINITY, // nothing
};

const validLogLevels = ["all", "info", "errors-only", "none"] as const;
type ValidLogLevel = (typeof validLogLevels)[number];

const getValidLogLevel = (
  level: string | undefined,
): LoggerOptions["shouldConsoleLog"] => {
  if (!level) return "errors-only";
  if (validLogLevels.includes(level as ValidLogLevel)) {
    return level as ValidLogLevel;
  }
  return "errors-only";
};

export interface LoggerOptions {
  logFilePath?: string;
  errorFilePath?: string;
  shouldConsoleLog?: boolean | "all" | "info" | "errors-only" | "none";
  // Rotation threshold in BYTES. Tests set this small to exercise rotation
  // without writing tens of MB; production leaves it undefined so the
  // LOG_MAX_SIZE_MB env (default 50MB) governs. Overrides the env when set.
  maxSizeBytes?: number;
}

export class Logger {
  public static readonly defaultLogFilePath = "app.log";
  public static readonly defaultErrorFilePath = "error.log";

  private logFile: WriteStream;
  private errorFile: WriteStream;
  private consoleMode: "all" | "info" | "errors-only" | "none";

  // Rotation bookkeeping. app.log grew 98MB in 25h in prod with no external
  // logrotate inside the container; we roll a single generation in-process.
  private readonly logFilePath: string;
  private readonly errorFilePath: string;
  private readonly maxSizeBytes: number;
  private logBytes: number;
  private errorBytes: number;

  constructor(options: LoggerOptions = {}) {
    const {
      logFilePath = Logger.defaultLogFilePath,
      errorFilePath = Logger.defaultErrorFilePath,
      shouldConsoleLog = "all",
      maxSizeBytes,
    } = options;

    this.logFilePath = logFilePath;
    this.errorFilePath = errorFilePath;
    this.maxSizeBytes = maxSizeBytes ?? Logger.resolveMaxSizeBytes();

    this.logFile = Logger.openStream(logFilePath);
    this.errorFile = Logger.openStream(errorFilePath);

    // Files open in append mode, so they may already hold bytes from a prior
    // process. Seed the counters from the on-disk size so rotation is driven
    // by the real file size, not just this process's writes.
    this.logBytes = Logger.fileSize(logFilePath);
    this.errorBytes = Logger.fileSize(errorFilePath);

    this.consoleMode =
      typeof shouldConsoleLog === "boolean"
        ? shouldConsoleLog
          ? "all"
          : "none"
        : shouldConsoleLog;
  }

  // LOG_MAX_SIZE_MB (env, default 50) as bytes. A non-numeric or non-positive
  // value falls back to the 50MB default rather than disabling rotation — a
  // typo'd env must never silently let the file grow unbounded again.
  private static resolveMaxSizeBytes(): number {
    const mb = parseInt(process.env.LOG_MAX_SIZE_MB || "50", 10);
    const safeMb = Number.isFinite(mb) && mb > 0 ? mb : 50;
    return safeMb * 1024 * 1024;
  }

  private static fileSize(filePath: string): number {
    try {
      return statSync(filePath).size;
    } catch {
      return 0;
    }
  }

  // Open the file descriptor SYNCHRONOUSLY (openSync), then wrap it in a
  // WriteStream. This matters for rotation: createWriteStream opens its fd
  // asynchronously, so a rotation firing before that open (e.g. a restart
  // against an already-oversized file, where the seeded counter trips on the
  // first write) would renameSync a path the stream hasn't bound yet and
  // orphan the buffered line. Owning the fd up front makes rename + reopen
  // race-free while keeping non-blocking stream writes. openSync(...,"a")
  // creates the file if absent; the stream's autoClose closes the fd on end.
  private static openStream(filePath: string): WriteStream {
    const fd = openSync(filePath, "a");
    return createWriteStream(filePath, { fd });
  }

  private formatDate(date: Date): string {
    const pad = (n: number) => n.toString().padStart(2, "0");

    return (
      `${date.getFullYear()}/${pad(date.getMonth() + 1)}/${pad(date.getDate())} - ` +
      `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
    );
  }

  private customLog(
    target: "log" | "error",
    level: "DEBUG" | "INFO" | "WARN" | "ERROR",
    ...args: unknown[]
  ) {
    const logMessage = format(...(args as unknown[]));
    const formattedMessage = `[${level}] ${this.formatDate(new Date())} | ${logMessage}\n`;

    const outputStream = target === "log" ? this.logFile : this.errorFile;
    outputStream.write(formattedMessage);

    // Track bytes written and roll a single generation once we cross the
    // threshold. The message that tips the file over is kept in the file
    // being rotated; the next write lands in the fresh file.
    const written = Buffer.byteLength(formattedMessage);
    if (target === "log") {
      this.logBytes += written;
      if (this.logBytes > this.maxSizeBytes) this.rotate("log");
    } else {
      this.errorBytes += written;
      if (this.errorBytes > this.maxSizeBytes) this.rotate("error");
    }

    // Console mirroring is threshold-based: each mode mirrors its own level
    // AND everything more severe (see CONSOLE_FLOOR). File writes above are
    // unaffected by the console mode.
    if (SEVERITY_RANK[level] >= CONSOLE_FLOOR[this.consoleMode]) {
      const trimmed = formattedMessage.trim();
      if (level === "INFO") {
        console.info(trimmed);
      } else if (level === "ERROR") {
        console.error(trimmed);
      } else if (level === "WARN") {
        console.warn(trimmed);
      } else {
        console.log(trimmed);
      }
    }
  }

  // Roll <name> to <name>.1 (single generation, prior .1 overwritten) and
  // reopen a fresh <name>. Kept dependency-free and crash-safe: a rotation
  // failure must NEVER throw into the logging call path — a logger that
  // crashes the request it was recording is strictly worse than an oversized
  // file. On failure we swallow, emit one console line, and reset the counter
  // so a persistent fault yields one line per size-window, not one per write.
  private rotate(target: "log" | "error"): void {
    const filePath = target === "log" ? this.logFilePath : this.errorFilePath;
    try {
      const old = target === "log" ? this.logFile : this.errorFile;
      // POSIX rename is atomic and overwrites any existing <name>.1. The old
      // fd follows the inode to <name>.1, so buffered writes still flush there.
      renameSync(filePath, `${filePath}.1`);
      // Fresh file + fd bound synchronously — no async-open race with the
      // rename above.
      const fresh = Logger.openStream(filePath);
      if (target === "log") {
        this.logFile = fresh;
      } else {
        this.errorFile = fresh;
      }
      old.end();
    } catch (err) {
      console.error(
        `[LOGGER] log rotation failed for ${filePath}: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    } finally {
      if (target === "log") {
        this.logBytes = 0;
      } else {
        this.errorBytes = 0;
      }
    }
  }

  public debug = (...args: unknown[]) =>
    this.customLog("log", "DEBUG", ...args);
  public info = (...args: unknown[]) => this.customLog("log", "INFO", ...args);
  public warn = (...args: unknown[]) => this.customLog("log", "WARN", ...args);
  public error = (...args: unknown[]) =>
    this.customLog("error", "ERROR", ...args);

  public close(): void {
    this.logFile.end();
    this.errorFile.end();
  }
}

const logger = new Logger({
  shouldConsoleLog: getValidLogLevel(LOG_LEVEL),
});

export default logger;
