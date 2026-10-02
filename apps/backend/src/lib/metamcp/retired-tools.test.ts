import {
  mkdirSync,
  mkdtempSync,
  renameSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { fsCalls, fsRaces } = vi.hoisted(() => ({
  fsCalls: { stat: 0, readFile: 0, statSync: 0, readFileSync: 0 },
  fsRaces: {
    beforeSyncRead: undefined as (() => void) | undefined,
    beforeAsyncRead: undefined as (() => void) | undefined,
    afterAsyncRead: undefined as (() => void) | undefined,
  },
}));

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

// Call-through wrappers so the tests can prove "no filesystem access" and
// count how many reads a scenario really performed.
vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    stat: (...args: Parameters<typeof actual.stat>) => {
      fsCalls.stat += 1;
      return actual.stat(...args);
    },
    readFile: (...args: Parameters<typeof actual.readFile>) => {
      fsCalls.readFile += 1;
      const before = fsRaces.beforeAsyncRead;
      fsRaces.beforeAsyncRead = undefined;
      before?.();
      return actual.readFile(...args).then((text) => {
        const after = fsRaces.afterAsyncRead;
        fsRaces.afterAsyncRead = undefined;
        after?.();
        return text;
      });
    },
  };
});
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    statSync: (...args: Parameters<typeof actual.statSync>) => {
      fsCalls.statSync += 1;
      return actual.statSync(...args);
    },
    readFileSync: (...args: Parameters<typeof actual.readFileSync>) => {
      fsCalls.readFileSync += 1;
      const before = fsRaces.beforeSyncRead;
      fsRaces.beforeSyncRead = undefined;
      before?.();
      return actual.readFileSync(...args);
    },
  };
});

import logger from "@/utils/logger";

import {
  DEFAULT_RELOAD_SECONDS,
  MAX_ENTRIES,
  MAX_FILE_BYTES,
  MAX_HINT,
  parseRetiredToolsFile,
  renderEnvelope,
  renderReplacementCall,
  resolveReloadSeconds,
  RetiredEntry,
  RetiredToolsRegistry,
  validateRetiredEntry,
} from "./retired-tools";

const DASHBOARD_ERROR_WORDS = /\b(error|fatal|panic|exception)\b/i;
const NOW = Date.UTC(2026, 9, 1, 12, 0, 0); // 2026-10-01

const goodFile = () => ({
  version: 1,
  retired: {
    autotask__add_note: {
      since: "2026-09-02",
      replacement: "autotask__ticket_manage",
      args: { mode: "note_add" },
      hint: "pass ticket and note",
    },
    "retired-server__lookup": {
      since: "2026-09-28",
      replacement: "registry__universal_lookup",
      also: ["unifi__health"],
    },
  },
});

let dir: string;
let file: string;
let clock: number;
let mtimeCounter: number;

const write = (content: unknown, target = file) => {
  writeFileSync(
    target,
    typeof content === "string" ? content : JSON.stringify(content),
  );
  // Distinct, explicit mtimes: two writes in the same millisecond would
  // otherwise look unchanged to the signature check.
  mtimeCounter += 10;
  utimesSync(target, mtimeCounter, mtimeCounter);
};

const makeRegistry = (
  extra: Partial<ConstructorParameters<typeof RetiredToolsRegistry>[0]> = {},
) =>
  new RetiredToolsRegistry({
    path: file,
    reloadSeconds: 30,
    now: () => clock,
    sleep: async () => undefined,
    ...extra,
  });

const warnings = () =>
  vi.mocked(logger.warn).mock.calls.map((call) => String(call[0]));
const infos = () =>
  vi.mocked(logger.info).mock.calls.map((call) => String(call[0]));

beforeEach(() => {
  dir = mkdtempSync(path.join(tmpdir(), "retired-tools-"));
  file = path.join(dir, "retired-tools.json");
  clock = NOW;
  mtimeCounter = 1_000_000;
  fsRaces.beforeSyncRead = undefined;
  fsRaces.beforeAsyncRead = undefined;
  fsRaces.afterAsyncRead = undefined;
  for (const key of Object.keys(fsCalls) as (keyof typeof fsCalls)[]) {
    fsCalls[key] = 0;
  }
  vi.mocked(logger.warn).mockClear();
  vi.mocked(logger.info).mockClear();
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("RetiredToolsRegistry: boot", () => {
  it("loads a valid file and reports the count at INFO", async () => {
    write(goodFile());
    const registry = makeRegistry();

    expect(registry.enabled).toBe(true);
    expect(registry.size).toBe(2);
    expect(infos()).toEqual([
      `[retired-tools] loaded 2 entries (dropped 0) from ${file}`,
    ]);
    await expect(registry.get("autotask__add_note")).resolves.toMatchObject({
      since: "2026-09-02",
      replacement: "autotask__ticket_manage",
      args: { mode: "note_add" },
    });
    await expect(registry.get("autotask__search")).resolves.toBeNull();
  });

  it("is inert when no path is configured: no filesystem access at all", async () => {
    const registry = new RetiredToolsRegistry({ now: () => clock });
    clock += 10 * 60 * 1000;

    await expect(registry.get("autotask__add_note")).resolves.toBeNull();
    expect(registry.enabled).toBe(false);
    expect(fsCalls).toEqual({
      stat: 0,
      readFile: 0,
      statSync: 0,
      readFileSync: 0,
    });
  });

  it("treats a blank path as unset", () => {
    expect(new RetiredToolsRegistry({ path: "   " }).enabled).toBe(false);
  });

  it("a missing file gives an empty map and one warning, never a throw", async () => {
    const registry = makeRegistry({ path: path.join(dir, "absent.json") });

    expect(registry.size).toBe(0);
    expect(warnings()).toHaveLength(1);
    expect(warnings()[0]).toContain("ENOENT");
    await expect(registry.get("autotask__add_note")).resolves.toBeNull();
  });

  it("an unreadable path (a directory) gives an empty map and a warning", () => {
    const sub = path.join(dir, "a-directory");
    mkdirSync(sub);
    const registry = makeRegistry({ path: sub });

    expect(registry.size).toBe(0);
    expect(warnings()).toHaveLength(1);
  });

  it("an invalid file at boot leaves an empty map", () => {
    write("{ not json");
    const registry = makeRegistry();
    expect(registry.size).toBe(0);
    expect(warnings()[0]).toContain("not valid JSON");
  });

  it("rejects oversized bytes when the file grows after the boot stat", () => {
    write(goodFile());
    fsRaces.beforeSyncRead = () =>
      write(`${JSON.stringify(goodFile())}${" ".repeat(MAX_FILE_BYTES)}`);
    expect(makeRegistry().size).toBe(0);
    expect(warnings().some((w) => w.includes("larger than"))).toBe(true);
  });
});

describe("RetiredToolsRegistry: reload", () => {
  it("does not touch the filesystem again inside the interval", async () => {
    write(goodFile());
    const registry = makeRegistry();
    const before = { ...fsCalls };

    clock += 29_000;
    await registry.get("autotask__add_note");
    await registry.get("autotask__add_note");

    expect(fsCalls.stat).toBe(before.stat);
    expect(fsCalls.readFile).toBe(before.readFile);
  });

  it("stats once the interval has elapsed but does not re-read an unchanged file", async () => {
    write(goodFile());
    const registry = makeRegistry();
    const reads = fsCalls.readFile;

    clock += 31_000;
    await registry.get("autotask__add_note");

    expect(fsCalls.stat).toBeGreaterThanOrEqual(1);
    expect(fsCalls.readFile).toBe(reads);
  });

  it("picks up a file replaced by rename (a new inode) on the next due check", async () => {
    write(goodFile());
    const registry = makeRegistry();
    await expect(registry.get("autotask__new_thing")).resolves.toBeNull();

    const replacement = goodFile();
    (replacement.retired as Record<string, unknown>).autotask__new_thing = {
      since: "2026-09-30",
      replacement: "autotask__search",
    };
    const staging = path.join(dir, "staging.json");
    write(replacement, staging);
    renameSync(staging, file);

    // Inside the interval nothing is re-read, so the new entry is not seen yet.
    clock += 10_000;
    await expect(registry.get("autotask__new_thing")).resolves.toBeNull();

    clock += 21_000;
    await expect(registry.get("autotask__new_thing")).resolves.toMatchObject({
      replacement: "autotask__search",
    });
    expect(registry.size).toBe(3);
    expect(infos().some((line) => line.includes("reloaded 3 entries"))).toBe(
      true,
    );
  });

  it("a truncated file retries once, then keeps the last good map", async () => {
    write(goodFile());
    const sleep = vi.fn().mockResolvedValue(undefined);
    const registry = makeRegistry({ sleep });

    write('{"version": 1, "retired": {"autotask__add_n');
    clock += 31_000;
    await expect(registry.get("autotask__add_note")).resolves.toMatchObject({
      replacement: "autotask__ticket_manage",
    });

    expect(sleep).toHaveBeenCalledTimes(1);
    expect(sleep).toHaveBeenCalledWith(250);
    expect(registry.size).toBe(2);
    expect(
      warnings().some((w) => w.includes("keeping the last good map")),
    ).toBe(true);

    // The writer finishes; the next due check adopts the complete file.
    write(goodFile());
    clock += 31_000;
    await registry.get("autotask__add_note");
    expect(infos().some((line) => line.includes("reloaded 2 entries"))).toBe(
      true,
    );
  });

  it("a write that completes during the retry pause is adopted in the same check", async () => {
    write(goodFile());
    const registry = makeRegistry({
      sleep: async () => {
        write(goodFile());
      },
    });

    write('{"version": 1,');
    clock += 31_000;
    await registry.get("autotask__add_note");

    expect(infos().some((line) => line.includes("reloaded 2 entries"))).toBe(
      true,
    );
  });

  it("a definitive rejection (wrong version) is not retried and keeps the last good map", async () => {
    write(goodFile());
    const sleep = vi.fn().mockResolvedValue(undefined);
    const registry = makeRegistry({ sleep });

    write({ version: 2, retired: {} });
    clock += 31_000;
    await expect(registry.get("autotask__add_note")).resolves.not.toBeNull();

    expect(sleep).not.toHaveBeenCalled();
    expect(registry.size).toBe(2);
  });

  it("two concurrent failures cause one read (single flight)", async () => {
    write(goodFile());
    const registry = makeRegistry();
    const replacement = goodFile();
    (replacement.retired as Record<string, unknown>).autotask__more = {
      since: "2026-09-30",
      hint: "x",
    };
    write(replacement);
    const reads = fsCalls.readFile;

    clock += 31_000;
    const [a, b] = await Promise.all([
      registry.get("autotask__more"),
      registry.get("autotask__more"),
    ]);

    expect(a).not.toBeNull();
    expect(b).not.toBeNull();
    expect(fsCalls.readFile - reads).toBe(1);
  });

  it("keeps the last good map when the file disappears, with one warning per five minutes", async () => {
    write(goodFile());
    const registry = makeRegistry();
    rmSync(file);

    clock += 31_000;
    await expect(registry.get("autotask__add_note")).resolves.not.toBeNull();
    clock += 31_000;
    await registry.get("autotask__add_note");
    clock += 31_000;
    await registry.get("autotask__add_note");

    const degraded = warnings().filter((w) =>
      w.includes("keeping the last good map"),
    );
    expect(degraded).toHaveLength(1);

    clock += 5 * 60 * 1000;
    await registry.get("autotask__add_note");
    expect(
      warnings().filter((w) => w.includes("keeping the last good map")),
    ).toHaveLength(2);
  });

  it("rejects a file over the size cap and keeps the last good map", async () => {
    write(goodFile());
    const registry = makeRegistry();

    write(`{"version":1,"retired":{},"pad":"${"x".repeat(MAX_FILE_BYTES)}"}`);
    clock += 31_000;
    await registry.get("autotask__add_note");

    expect(registry.size).toBe(2);
    expect(warnings().some((w) => w.includes("larger than"))).toBe(true);
  });

  it("rejects oversized bytes when the file grows after the reload stat", async () => {
    write(goodFile());
    const registry = makeRegistry();
    write({ version: 1, retired: {} });
    fsRaces.beforeAsyncRead = () =>
      write(
        `${JSON.stringify({ version: 1, retired: {} })}${" ".repeat(MAX_FILE_BYTES)}`,
      );
    clock += 31_000;
    await expect(registry.get("autotask__add_note")).resolves.not.toBeNull();
    expect(warnings().some((w) => w.includes("larger than"))).toBe(true);
  });

  it("rechecks a replacement that arrives after reading the previous contents", async () => {
    write(goodFile());
    const registry = makeRegistry();
    write({ version: 1, retired: {} });
    fsRaces.afterAsyncRead = () => write(goodFile());
    clock += 31_000;
    await expect(registry.get("autotask__add_note")).resolves.toBeNull();
    clock += 31_000;
    await expect(registry.get("autotask__add_note")).resolves.not.toBeNull();
    expect(fsCalls.readFile).toBe(2);
  });

  it("never throws out of get", async () => {
    write(goodFile());
    const registry = makeRegistry();
    rmSync(file);
    write(goodFile(), path.join(dir, "elsewhere.json"));
    mkdirSync(file); // the path is now a directory
    clock += 31_000;
    await expect(registry.get("autotask__add_note")).resolves.not.toBeNull();
  });
});

describe("parseRetiredToolsFile: whole-file rules", () => {
  const now = new Date(NOW);

  it.each([
    ["an array root", "[]", false],
    ["a scalar root", "5", false],
    ["a wrong version", JSON.stringify({ version: 2, retired: {} }), false],
    ["a missing version", JSON.stringify({ retired: {} }), false],
    [
      "a non-object retired",
      JSON.stringify({ version: 1, retired: [] }),
      false,
    ],
  ])("rejects %s without a retry", (_label, text, transient) => {
    const outcome = parseRetiredToolsFile(text, now);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.transient).toBe(transient);
  });

  it("flags broken JSON as transient (a write may be in progress)", () => {
    const outcome = parseRetiredToolsFile("{ broken", now);
    expect(outcome).toMatchObject({ ok: false, transient: true });
  });

  it("enforces the byte cap before parsing, including multibyte text", () => {
    const text = JSON.stringify({
      version: 1,
      retired: {},
      pad: "é".repeat(MAX_FILE_BYTES / 2),
    });
    expect(text.length).toBeLessThan(MAX_FILE_BYTES);
    expect(parseRetiredToolsFile(text, now)).toMatchObject({
      ok: false,
      transient: false,
    });
  });

  it("rejects more than the maximum entry count", () => {
    const retired: Record<string, unknown> = {};
    for (let i = 0; i <= MAX_ENTRIES; i += 1) {
      retired[`server__tool_${i}`] = { since: "2026-09-02", hint: "x" };
    }
    const outcome = parseRetiredToolsFile(
      JSON.stringify({ version: 1, retired }),
      now,
    );
    expect(outcome).toMatchObject({ ok: false, transient: false });
  });

  it("accepts exactly the maximum entry count", () => {
    const retired: Record<string, unknown> = {};
    for (let i = 0; i < MAX_ENTRIES; i += 1) {
      retired[`server__tool_${i}`] = { since: "2026-09-02", hint: "x" };
    }
    const outcome = parseRetiredToolsFile(
      JSON.stringify({ version: 1, retired }),
      now,
    );
    expect(outcome.ok && outcome.entries.size).toBe(MAX_ENTRIES);
  });

  it("drops one bad entry with a warning naming its key and loads its siblings", () => {
    const outcome = parseRetiredToolsFile(
      JSON.stringify({
        version: 1,
        retired: {
          good__one: { since: "2026-09-02", hint: "fine" },
          bad__two: { since: "2099-01-01", hint: "future" },
          good__three: { since: "2026-09-03", replacement: "good__one" },
        },
      }),
      now,
    );
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect([...outcome.entries.keys()]).toEqual(["good__one", "good__three"]);
      expect(outcome.dropped).toHaveLength(1);
      expect(outcome.dropped[0]).toContain("bad__two");
      expect(outcome.dropped[0]).toContain("future");
    }
  });
});

describe("validateRetiredEntry: per-entry rules", () => {
  const today = "2026-10-01";
  const base = { since: "2026-09-02", hint: "x" };
  const longName = "a".repeat(65);

  const rejected = [
    ["a key without the separator", "noseparator", base],
    ["a key with a space", "bad key__tool", base],
    ["an empty server part", "__tool", base],
    ["a tool part over 64 characters", `s__${longName}`, base],
    ["a server part over 48 characters", `${"s".repeat(49)}__t`, base],
    ["a since in the future", "s__t", { ...base, since: "2026-10-02" }],
    ["a malformed since", "s__t", { ...base, since: "2026-9-2" }],
    ["an impossible calendar date", "s__t", { ...base, since: "2026-02-30" }],
    ["a missing since", "s__t", { hint: "x" }],
    ["a non-string since", "s__t", { since: 20260902, hint: "x" }],
    [
      "a hint over the limit",
      "s__t",
      { ...base, hint: "h".repeat(MAX_HINT + 1) },
    ],
    ["a hint with a control character", "s__t", { ...base, hint: "a\nb" }],
    ["a hint with a line separator", "s__t", { ...base, hint: "a b" }],
    [
      "an empty hint and nothing else",
      "s__t",
      { since: "2026-09-02", hint: "" },
    ],
    [
      "more than four also entries",
      "s__t",
      { ...base, also: ["a__1", "a__2", "a__3", "a__4", "a__5"] },
    ],
    ["an also entry outside the syntax", "s__t", { ...base, also: ["nope"] }],
    [
      "more than four args",
      "s__t",
      {
        ...base,
        replacement: "a__b",
        args: { a: "1", b: "2", c: "3", d: "4", e: "5" },
      },
    ],
    [
      "an args key outside the syntax",
      "s__t",
      { ...base, replacement: "a__b", args: { "Bad-Key": "1" } },
    ],
    [
      "an args value with a space",
      "s__t",
      { ...base, replacement: "a__b", args: { mode: "has space" } },
    ],
    [
      "an args value over 80 chars",
      "s__t",
      { ...base, replacement: "a__b", args: { mode: "v".repeat(81) } },
    ],
    [
      "a replacement outside the syntax",
      "s__t",
      { ...base, replacement: "no separator" },
    ],
    ["a call over the limit", "s__t", { ...base, call: "c".repeat(161) }],
    ["a skill over the limit", "s__t", { ...base, skill: "k".repeat(81) }],
    [
      "a null replacement and no also, skill or hint",
      "s__t",
      { since: "2026-09-02", replacement: null },
    ],
    ["an entry that is not an object", "s__t", "text"],
    ["an array entry", "s__t", []],
  ] as const;

  it.each(rejected)("drops %s", (_label, key, entry) => {
    expect(validateRetiredEntry(key, entry, today)).toHaveProperty("reason");
  });

  it("accepts boundary values exactly at the limits", () => {
    const verdict = validateRetiredEntry(
      `${"s".repeat(48)}__${"t".repeat(64)}`,
      {
        since: "2026-10-01",
        replacement: "a__b",
        args: { a: "v".repeat(80), b: "x|y", c: "d.e", d: "f-g" },
        call: "c".repeat(160),
        also: ["a__1", "a__2", "a__3", "a__4"],
        skill: "k".repeat(80),
        hint: "h".repeat(MAX_HINT),
      },
      today,
    );
    expect(verdict).toHaveProperty("entry");
  });

  it("accepts a retirement with no replacement when a hint explains it", () => {
    expect(
      validateRetiredEntry(
        "s__t",
        { since: "2026-09-02", replacement: null, hint: "dropped" },
        today,
      ),
    ).toHaveProperty("entry");
  });

  it("ignores unknown fields instead of dropping the entry", () => {
    const verdict = validateRetiredEntry(
      "s__t",
      { ...base, future_field: { anything: true } },
      today,
    );
    expect(verdict).toHaveProperty("entry");
    if ("entry" in verdict) {
      expect(verdict.entry).not.toHaveProperty("future_field");
    }
  });
});

describe("resolveReloadSeconds", () => {
  beforeEach(() => vi.mocked(logger.warn).mockClear());

  it.each([
    [undefined, DEFAULT_RELOAD_SECONDS, false],
    ["", DEFAULT_RELOAD_SECONDS, false],
    ["60", 60, false],
    ["5", 5, false],
    ["3600", 3600, false],
    ["4", 5, true],
    ["99999", 3600, true],
    ["x", DEFAULT_RELOAD_SECONDS, true],
    ["-3", DEFAULT_RELOAD_SECONDS, true],
    ["1.5", DEFAULT_RELOAD_SECONDS, true],
  ])("%j resolves to %j (warning: %j)", (raw, expected, warns) => {
    expect(resolveReloadSeconds(raw)).toBe(expected);
    expect(vi.mocked(logger.warn).mock.calls.length > 0).toBe(warns);
  });
});

describe("renderEnvelope", () => {
  const entry = (extra: Partial<RetiredEntry> = {}): RetiredEntry => ({
    since: "2026-09-02",
    replacement: "autotask__ticket_manage",
    ...extra,
  });

  it("renders a replacement with its arguments", () => {
    const envelope = renderEnvelope(
      "autotask__add_note",
      entry({ args: { mode: "note_add" } }),
    );

    expect(envelope.error).toBe(true);
    expect(envelope.code).toBe("tool_retired");
    expect(envelope.message).toContain(
      "autotask__add_note was retired on 2026-09-02 and is no longer served.",
    );
    expect(envelope.message).toContain(
      'Use autotask__ticket_manage(mode="note_add").',
    );
    expect(envelope.message).toContain("Refresh your tool list (tools/list)");
    expect(envelope.context).toMatchObject({
      retired: "autotask__add_note",
      since: "2026-09-02",
      replacement: "autotask__ticket_manage",
      replacement_call: 'autotask__ticket_manage(mode="note_add")',
    });
  });

  it("renders a pipe list of alternatives and several arguments", () => {
    expect(
      renderReplacementCall(
        entry({ replacement: "a__b", args: { mode: "list|detail", x: "y" } }),
      ),
    ).toBe('a__b(mode="list|detail", x="y")');
  });

  it("renders a bare replacement with empty parentheses", () => {
    expect(renderReplacementCall(entry({ replacement: "a__b" }))).toBe(
      "a__b()",
    );
  });

  it("an explicit call wins over the rendered one", () => {
    const envelope = renderEnvelope(
      "autotask__get_status_batch",
      entry({
        args: { mode: "ignored" },
        call: "autotask__search(ids=[<ticket ids>])",
      }),
    );
    expect(envelope.message).toContain(
      "Use autotask__search(ids=[<ticket ids>]).",
    );
    expect(envelope.context.replacement_call).toBe(
      "autotask__search(ids=[<ticket ids>])",
    );
  });

  it("with no replacement it names also, skill and hint", () => {
    const envelope = renderEnvelope(
      "networks__investigate_site",
      entry({
        replacement: null,
        also: ["unifi__health", "meraki__health"],
        skill: "umbrella-investigation (references/network-investigation.md)",
        hint: "use each vendor health overview",
      }),
    );

    expect(envelope.message).toContain("It has no one-to-one replacement.");
    expect(envelope.message).toContain(
      "Related: unifi__health, meraki__health.",
    );
    expect(envelope.message).toContain("See skill umbrella-investigation");
    expect(envelope.message).toContain("use each vendor health overview.");
    expect(envelope.context).not.toHaveProperty("replacement");
    expect(envelope.context).not.toHaveProperty("replacement_call");
  });

  it("keeps a hint's own punctuation", () => {
    const envelope = renderEnvelope(
      "a__b",
      entry({ hint: "Read this first!" }),
    );
    expect(envelope.message).toContain("Read this first! Refresh");
  });

  it("round-trips through JSON and stays bounded", () => {
    const worst = entry({
      args: {
        a: "v".repeat(80),
        b: "v".repeat(80),
        c: "v".repeat(80),
        d: "v".repeat(80),
      },
      call: "c".repeat(160),
      also: ["a__1", "a__2", "a__3", "a__4"],
      skill: "k".repeat(80),
      hint: "h".repeat(MAX_HINT),
    });
    const envelope = renderEnvelope(
      `${"s".repeat(48)}__${"t".repeat(64)}`,
      worst,
    );
    const text = JSON.stringify(envelope);
    expect(JSON.parse(text)).toEqual(envelope);
    expect(envelope.message.length).toBeLessThan(1000);
  });

  it("omits absent context fields", () => {
    const envelope = renderEnvelope("a__b", entry({ replacement: "c__d" }));
    expect(Object.keys(envelope.context).sort()).toEqual([
      "replacement",
      "replacement_call",
      "retired",
      "since",
    ]);
  });
});

describe("log wording", () => {
  it("no loader line uses the words the error panels count", async () => {
    // Exercise every logging path: boot, drops, degraded warnings, reload.
    write({
      version: 1,
      retired: {
        ok__tool: { since: "2026-09-02", hint: "fine" },
        bad__tool: { since: "2099-01-01", hint: "future" },
      },
    });
    const registry = makeRegistry();
    write("{ broken");
    clock += 31_000;
    await registry.get("ok__tool");
    rmSync(file);
    clock += 6 * 60 * 1000;
    await registry.get("ok__tool");
    resolveReloadSeconds("x");
    resolveReloadSeconds("99999");
    makeRegistry({ path: path.join(dir, "absent.json") });

    const lines = [...warnings(), ...infos()];
    expect(lines.length).toBeGreaterThan(3);
    for (const line of lines) {
      expect(DASHBOARD_ERROR_WORDS.test(line)).toBe(false);
    }
  });
});
