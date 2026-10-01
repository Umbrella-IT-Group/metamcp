/**
 * Retired-tool map: loader, validator, cache and message renderer.
 *
 * WHAT THIS IS FOR. Tools get renamed and removed. A client that cached an
 * older tool list, or an automation node that still names a removed tool, calls
 * a name nobody serves and gets a bare "Unknown tool" that says nothing about
 * what replaced it. This module holds a small data file mapping each retired
 * name to its replacement, so the gateway can answer such a call with the
 * replacement instead of a dead end. The redirect itself lives in
 * `metamcp-middleware/retired-tool.functional`; this module is only the data.
 *
 * DATA ONLY, FAIL OPEN, NEVER ROUTING. The map is consulted solely AFTER a call
 * has already failed as an unknown tool, and the only thing it can change is the
 * text of that failure. It cannot make a live tool unreachable, cannot grant or
 * widen access, and cannot reroute a call: a stale, wrong or too-early entry
 * degrades to today's bare error. Everything here is therefore written to keep
 * working with the last good map, or with no map at all, rather than to fail.
 *
 * INERT WHEN UNSET. `RETIRED_TOOLS_FILE` unset means no filesystem access at
 * all, so this change can ship before the file is mounted.
 *
 * WHERE THE FILE COMES FROM. The gateway image does not carry it. It is a
 * reviewed file in the platform repository, mounted read-only into the
 * container from the host's checkout, which that host re-pulls on a short
 * timer. A DIRECTORY is mounted rather than the file, because replacing a
 * checked-out file replaces its inode and a single-file bind mount would keep
 * serving the old content forever. The file is re-read lazily, on the failure
 * path only, at most once per `RETIRED_TOOLS_RELOAD_SECONDS`.
 *
 * FILE SCHEMA (version 1):
 *   { "version": 1,
 *     "retired": { "<server>__<tool>": Entry, ... } }
 * Key: a server part of 1-48 chars [A-Za-z0-9-] and a tool part of 1-64 chars
 * [A-Za-z0-9_-], joined by `__` (server names keep hyphens). Entry:
 *   since        required, YYYY-MM-DD, a real date, not in the future
 *   replacement  tool name in the key syntax, or null / absent
 *   args         optional, at most 4 keys: key [a-z_]{1,24}, value a string of
 *                at most 80 chars from [A-Za-z0-9_|.-]  (e.g. {"mode":"note_add"})
 *   call         optional explicit suggested call, at most 160 chars
 *   also         optional array of at most 4 tool names in the key syntax
 *   skill        optional, at most 80 chars
 *   hint         optional, at most 280 chars
 * At least one of replacement, also, skill, hint is required. An invalid entry
 * is dropped alone with a warning naming the key; a wrong version, a non-object
 * root, a file over 262144 bytes or more than 500 entries rejects the whole
 * file and the last good map is kept. Unknown fields are ignored here (the
 * platform repository's CI check is the strict validator and rejects them).
 *
 * THE VALIDATOR IS DUPLICATED, on purpose. The same limits are enforced by
 * `platform/scripts/check-retired-tools.py` in the platform repository, which
 * gates the file before it can reach a host. Keep the constants below identical
 * to that script's; a drift would make this loader drop an entry CI accepted
 * (visible as "dropped N" in the boot log line).
 *
 * LOG WORDING. Every line avoids the words error, fatal, panic and exception:
 * log-based error panels count those, and a degraded map is not a gateway fault.
 */

import { readFileSync, statSync } from "node:fs";
import { readFile, stat } from "node:fs/promises";

import logger from "@/utils/logger";

// ---- limits (mirrored in the platform repository's check script) ----------
export const RETIRED_FILE_VERSION = 1;
export const MAX_FILE_BYTES = 262144;
export const MAX_ENTRIES = 500;
export const MAX_ALSO = 4;
export const MAX_ARGS = 4;
export const MAX_ARG_VALUE = 80;
export const MAX_CALL = 160;
export const MAX_SKILL = 80;
export const MAX_HINT = 280;

export const DEFAULT_RELOAD_SECONDS = 30;
export const MIN_RELOAD_SECONDS = 5;
export const MAX_RELOAD_SECONDS = 3600;
/** A parse failure is retried once after this pause: a checkout is not atomic. */
const PARSE_RETRY_DELAY_MS = 250;
/** One degraded-map warning per this interval, however often a reload is tried. */
const WARN_INTERVAL_MS = 5 * 60 * 1000;

const TOOL_KEY = /^[A-Za-z0-9-]{1,48}__[A-Za-z0-9_-]{1,64}$/;
const ARG_KEY = /^[a-z_]{1,24}$/;
const ARG_VALUE = /^[A-Za-z0-9_|.-]{1,80}$/;
const SINCE = /^(\d{4})-(\d{2})-(\d{2})$/;
// Printable text: no C0/C1 control characters, no DEL, no line separators.
// eslint-disable-next-line no-control-regex
const NO_CONTROL = /^[^\u0000-\u001F\u007F-\u009F\u2028\u2029]*$/;

export interface RetiredEntry {
  since: string;
  replacement: string | null;
  args?: Record<string, string>;
  call?: string;
  also?: string[];
  skill?: string;
  hint?: string;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") return false;
  if (Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function isoDay(date: Date): string {
  return date.toISOString().slice(0, 10);
}

function validDate(since: string): boolean {
  const match = SINCE.exec(since);
  if (!match) return false;
  const [, y, m, d] = match.map(Number) as [number, number, number, number];
  const date = new Date(Date.UTC(y, m - 1, d));
  return (
    date.getUTCFullYear() === y &&
    date.getUTCMonth() === m - 1 &&
    date.getUTCDate() === d
  );
}

function printable(value: unknown, max: number): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= max &&
    NO_CONTROL.test(value)
  );
}

/** Validate one entry. Returns the entry, or the reason it is dropped. */
export function validateRetiredEntry(
  key: string,
  raw: unknown,
  today: string,
): { entry: RetiredEntry } | { reason: string } {
  if (!TOOL_KEY.test(key)) {
    return { reason: "key is not <server>__<tool> in the allowed syntax" };
  }
  if (!isPlainObject(raw)) return { reason: "entry is not an object" };

  const since = raw.since;
  if (typeof since !== "string" || !validDate(since)) {
    return { reason: "since is missing or not a real YYYY-MM-DD date" };
  }
  if (since > today) return { reason: "since is in the future" };

  let replacement: string | null = null;
  if (raw.replacement !== undefined && raw.replacement !== null) {
    if (
      typeof raw.replacement !== "string" ||
      !TOOL_KEY.test(raw.replacement)
    ) {
      return { reason: "replacement is not a tool name in the key syntax" };
    }
    replacement = raw.replacement;
  }

  const entry: RetiredEntry = { since, replacement };

  if (raw.args !== undefined) {
    if (!isPlainObject(raw.args)) return { reason: "args is not an object" };
    const pairs = Object.entries(raw.args);
    if (pairs.length > MAX_ARGS) return { reason: "args has too many keys" };
    const args: Record<string, string> = {};
    for (const [argKey, argValue] of pairs) {
      if (!ARG_KEY.test(argKey)) return { reason: "args has an invalid key" };
      if (typeof argValue !== "string" || !ARG_VALUE.test(argValue)) {
        return { reason: "args has an invalid value" };
      }
      args[argKey] = argValue;
    }
    if (pairs.length > 0) entry.args = args;
  }

  if (raw.call !== undefined) {
    if (!printable(raw.call, MAX_CALL)) {
      return { reason: "call is not printable text within its limit" };
    }
    entry.call = raw.call;
  }

  if (raw.also !== undefined) {
    if (!Array.isArray(raw.also) || raw.also.length > MAX_ALSO) {
      return { reason: "also is not an array within its limit" };
    }
    for (const name of raw.also) {
      if (typeof name !== "string" || !TOOL_KEY.test(name)) {
        return { reason: "also has a name outside the key syntax" };
      }
    }
    if (raw.also.length > 0) entry.also = [...(raw.also as string[])];
  }

  if (raw.skill !== undefined) {
    if (!printable(raw.skill, MAX_SKILL)) {
      return { reason: "skill is not printable text within its limit" };
    }
    entry.skill = raw.skill;
  }

  if (raw.hint !== undefined) {
    if (!printable(raw.hint, MAX_HINT)) {
      return { reason: "hint is not printable text within its limit" };
    }
    entry.hint = raw.hint;
  }

  if (
    entry.replacement === null &&
    entry.also === undefined &&
    entry.skill === undefined &&
    entry.hint === undefined
  ) {
    return {
      reason: "no replacement, also, skill or hint: nothing to tell the caller",
    };
  }
  return { entry };
}

export type ParseOutcome =
  | { ok: true; entries: Map<string, RetiredEntry>; dropped: string[] }
  | { ok: false; reason: string; transient: boolean };

/**
 * Parse and validate a whole file. A JSON parse failure is `transient` (a
 * checkout writes the file non-atomically, so a read can land mid-write); every
 * other rejection is definitive.
 */
export function parseRetiredToolsFile(text: string, now: Date): ParseOutcome {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, reason: "file is not valid JSON", transient: true };
  }
  if (!isPlainObject(parsed)) {
    return { ok: false, reason: "root is not an object", transient: false };
  }
  if (parsed.version !== RETIRED_FILE_VERSION) {
    return {
      ok: false,
      reason: `version is not ${RETIRED_FILE_VERSION}`,
      transient: false,
    };
  }
  if (!isPlainObject(parsed.retired)) {
    return { ok: false, reason: "retired is not an object", transient: false };
  }

  const pairs = Object.entries(parsed.retired);
  if (pairs.length > MAX_ENTRIES) {
    return {
      ok: false,
      reason: `more than ${MAX_ENTRIES} entries`,
      transient: false,
    };
  }

  const today = isoDay(now);
  const entries = new Map<string, RetiredEntry>();
  const dropped: string[] = [];
  for (const [key, raw] of pairs) {
    const verdict = validateRetiredEntry(key, raw, today);
    if ("entry" in verdict) {
      entries.set(key, verdict.entry);
    } else {
      dropped.push(
        `entry ${JSON.stringify(key.slice(0, 120))} dropped: ${verdict.reason}`,
      );
    }
  }
  return { ok: true, entries, dropped };
}

/** Render the call the caller should make instead. Null when none is named. */
export function renderReplacementCall(entry: RetiredEntry): string | null {
  if (entry.call) return entry.call;
  if (!entry.replacement) return null;
  const args = entry.args
    ? Object.entries(entry.args)
        .map(([key, value]) => `${key}="${value}"`)
        .join(", ")
    : "";
  return `${entry.replacement}(${args})`;
}

export interface RetiredEnvelope {
  error: true;
  code: "tool_retired";
  message: string;
  context: {
    retired: string;
    since: string;
    replacement?: string;
    replacement_call?: string;
    also?: string[];
    skill?: string;
    hint?: string;
  };
}

const ENDS_WITH_PUNCTUATION = /[.!?]$/;

/**
 * The envelope a retired call returns. Same shape every platform tool refusal
 * uses (`error: true`, `code`, `message`, `context`), so an agent that already
 * handles those handles this. Absent fields are omitted. Bounded: every part
 * has a loader cap, so the message cannot grow past about a kilobyte.
 */
export function renderEnvelope(
  name: string,
  entry: RetiredEntry,
): RetiredEnvelope {
  const call = renderReplacementCall(entry);
  const parts = [
    `${name} was retired on ${entry.since} and is no longer served.`,
  ];
  parts.push(call ? `Use ${call}.` : "It has no one-to-one replacement.");
  if (entry.also && entry.also.length > 0) {
    parts.push(`Related: ${entry.also.join(", ")}.`);
  }
  if (entry.skill) parts.push(`See skill ${entry.skill}.`);
  if (entry.hint) {
    parts.push(
      ENDS_WITH_PUNCTUATION.test(entry.hint) ? entry.hint : `${entry.hint}.`,
    );
  }
  parts.push(
    "Refresh your tool list (tools/list) if your client cached an older one.",
  );

  const context: RetiredEnvelope["context"] = {
    retired: name,
    since: entry.since,
  };
  if (entry.replacement) context.replacement = entry.replacement;
  if (call) context.replacement_call = call;
  if (entry.also && entry.also.length > 0) context.also = entry.also;
  if (entry.skill) context.skill = entry.skill;
  if (entry.hint) context.hint = entry.hint;

  return {
    error: true,
    code: "tool_retired",
    message: parts.join(" "),
    context,
  };
}

/** Resolve the reload interval. Invalid falls back to the default, with a warning. */
export function resolveReloadSeconds(raw: string | undefined): number {
  if (raw === undefined || raw.trim() === "") return DEFAULT_RELOAD_SECONDS;
  if (!/^\d+$/.test(raw.trim())) {
    logger.warn(
      `[retired-tools] RETIRED_TOOLS_RELOAD_SECONDS="${raw}" is not a whole number; using ${DEFAULT_RELOAD_SECONDS}`,
    );
    return DEFAULT_RELOAD_SECONDS;
  }
  const parsed = Number.parseInt(raw, 10);
  if (parsed < MIN_RELOAD_SECONDS || parsed > MAX_RELOAD_SECONDS) {
    const clamped = Math.min(
      MAX_RELOAD_SECONDS,
      Math.max(MIN_RELOAD_SECONDS, parsed),
    );
    logger.warn(
      `[retired-tools] RETIRED_TOOLS_RELOAD_SECONDS=${parsed} is outside ${MIN_RELOAD_SECONDS}-${MAX_RELOAD_SECONDS}; using ${clamped}`,
    );
    return clamped;
  }
  return parsed;
}

export interface RetiredToolsRegistryOptions {
  /** Path of the file. Unset means the feature is inert. */
  path?: string;
  reloadSeconds?: number;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

interface FileSignature {
  mtimeMs: number;
  size: number;
}

/**
 * The cached map and its reload logic. Never throws out of any public method.
 */
export class RetiredToolsRegistry {
  private readonly path: string | undefined;
  private readonly intervalMs: number;
  private readonly now: () => number;
  private readonly sleep: (ms: number) => Promise<void>;

  private map = new Map<string, RetiredEntry>();
  private signature: FileSignature | undefined;
  private lastCheckAt: number;
  private lastWarnAt = Number.NEGATIVE_INFINITY;
  private inflight: Promise<void> | null = null;

  constructor(options: RetiredToolsRegistryOptions = {}) {
    this.path =
      options.path && options.path.trim() !== "" ? options.path : undefined;
    this.intervalMs = (options.reloadSeconds ?? DEFAULT_RELOAD_SECONDS) * 1000;
    this.now = options.now ?? Date.now;
    this.sleep =
      options.sleep ??
      ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.lastCheckAt = this.now();
    if (this.path) this.loadAtBoot(this.path);
  }

  /** True when a file path is configured. */
  get enabled(): boolean {
    return this.path !== undefined;
  }

  /** Number of entries in the current map. */
  get size(): number {
    return this.map.size;
  }

  /**
   * The entry for a retired name, or null. Reloads the file first when the
   * interval has elapsed. Call it ONLY on a path where the call has already
   * failed as an unknown tool: a successful call must never reach here.
   */
  async get(name: string): Promise<RetiredEntry | null> {
    if (!this.path) return null;
    try {
      await this.refreshIfDue();
    } catch {
      // refresh() already contains its own faults; this is the last guard.
    }
    return this.map.get(name) ?? null;
  }

  private loadAtBoot(path: string): void {
    try {
      const st = statSync(path);
      if (st.size > MAX_FILE_BYTES) {
        this.warnDegraded(`file is larger than ${MAX_FILE_BYTES} bytes`);
        return;
      }
      const outcome = parseRetiredToolsFile(
        readFileSync(path, "utf8"),
        new Date(this.now()),
      );
      if (!outcome.ok) {
        this.warnDegraded(outcome.reason);
        return;
      }
      this.adopt(outcome, { mtimeMs: st.mtimeMs, size: st.size }, "loaded");
    } catch (cause) {
      this.warnDegraded(`file is not readable (${errno(cause)})`);
    }
  }

  private async refreshIfDue(): Promise<void> {
    // A reload already running is awaited by every concurrent caller, so a
    // second failure arriving mid-reload sees the new map, not the old one.
    // Checked BEFORE the interval: refresh() stamps lastCheckAt synchronously
    // when it starts, so the interval test alone would let a concurrent caller
    // return early and read the stale map.
    if (this.inflight) return this.inflight;
    if (this.now() - this.lastCheckAt < this.intervalMs) return;
    this.inflight = this.refresh()
      .catch(() => undefined)
      .finally(() => {
        this.inflight = null;
      });
    return this.inflight;
  }

  private async refresh(): Promise<void> {
    const path = this.path;
    if (!path) return;
    this.lastCheckAt = this.now();

    let st;
    try {
      st = await stat(path);
    } catch (cause) {
      this.warnDegraded(`file is not readable (${errno(cause)})`);
      return;
    }
    if (st.size > MAX_FILE_BYTES) {
      this.warnDegraded(`file is larger than ${MAX_FILE_BYTES} bytes`);
      return;
    }
    if (
      this.signature &&
      this.signature.mtimeMs === st.mtimeMs &&
      this.signature.size === st.size
    ) {
      return;
    }

    let outcome = await this.readAndParse(path);
    if (!outcome.ok && outcome.transient) {
      // A checkout writes the file non-atomically; give a writer in progress a
      // moment, then read once more before giving up on this interval.
      await this.sleep(PARSE_RETRY_DELAY_MS);
      outcome = await this.readAndParse(path);
    }
    if (!outcome.ok) {
      this.warnDegraded(outcome.reason);
      return;
    }
    // Stat again after the read so the signature describes what was parsed.
    let after = st;
    try {
      after = await stat(path);
    } catch {
      // Keep the pre-read signature; the next interval re-checks.
    }
    this.adopt(
      outcome,
      { mtimeMs: after.mtimeMs, size: after.size },
      "reloaded",
    );
  }

  private async readAndParse(path: string): Promise<ParseOutcome> {
    try {
      const text = await readFile(path, "utf8");
      return parseRetiredToolsFile(text, new Date(this.now()));
    } catch (cause) {
      return {
        ok: false,
        reason: `file is not readable (${errno(cause)})`,
        transient: false,
      };
    }
  }

  private adopt(
    outcome: Extract<ParseOutcome, { ok: true }>,
    signature: FileSignature,
    verb: "loaded" | "reloaded",
  ): void {
    for (const line of outcome.dropped) {
      logger.warn(`[retired-tools] ${line}`);
    }
    this.map = outcome.entries;
    this.signature = signature;
    logger.info(
      `[retired-tools] ${verb} ${outcome.entries.size} entries (dropped ${outcome.dropped.length}) from ${this.path}`,
    );
  }

  /** One degraded-map warning per interval, so a bad file cannot flood the logs. */
  private warnDegraded(reason: string): void {
    const at = this.now();
    if (at - this.lastWarnAt < WARN_INTERVAL_MS) return;
    this.lastWarnAt = at;
    logger.warn(
      `[retired-tools] ${reason}; keeping the last good map (${this.map.size} entries)`,
    );
  }
}

function errno(cause: unknown): string {
  const code = (cause as { code?: unknown } | null)?.code;
  return typeof code === "string" ? code : "unknown";
}

let registry: RetiredToolsRegistry | undefined;

/**
 * The process-wide registry. Created on first use from the environment, so the
 * boot load happens when the first call arrives at the middleware rather than
 * at import time of unrelated modules. With `RETIRED_TOOLS_FILE` unset it holds
 * no file and never touches the filesystem.
 */
export function getRetiredToolsRegistry(): RetiredToolsRegistry {
  if (!registry) {
    registry = new RetiredToolsRegistry({
      path: process.env.RETIRED_TOOLS_FILE,
      reloadSeconds: resolveReloadSeconds(
        process.env.RETIRED_TOOLS_RELOAD_SECONDS,
      ),
    });
  }
  return registry;
}

/**
 * Boot hook, called once from the app start sequence. Builds the registry (which
 * loads the file synchronously) so the boot log states how many entries are in
 * play, and says plainly when the feature is inactive. Never throws.
 */
export function initializeRetiredTools(): void {
  const current = getRetiredToolsRegistry();
  if (!current.enabled) {
    logger.info(
      "[retired-tools] inactive: RETIRED_TOOLS_FILE is not set, retired names get the plain unknown-tool answer",
    );
  }
}

/** The entry for a retired name from the process-wide registry, or null. */
export function getRetiredEntry(name: string): Promise<RetiredEntry | null> {
  return getRetiredToolsRegistry().get(name);
}

/** Test seam: replace (or clear, with undefined) the process-wide registry. */
export function setRetiredToolsRegistryForTesting(
  next: RetiredToolsRegistry | undefined,
): void {
  registry = next;
}
