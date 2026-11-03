/**
 * Per-proxy record of each exposed tool's top-level argument names, taken
 * from the `inputSchema` the backend publishes in tools/list.
 *
 * WHY THIS EXISTS. `tool_call_audit.args_shape` stores argument KEY NAMES. A key
 * name is caller-chosen before any tool validates it, so identifier syntax alone
 * cannot stop a caller from writing `Alice_Smith` or `client_secret_x` into an
 * immutable audit row (Sol review, 2026-10-02). Recording only the names a tool's
 * own schema declares closes that channel: a caller can choose which declared
 * parameters to send, never what the stored names are.
 *
 * Keyed by the final exposed name exactly as this proxy's clients call it.
 * A process-global name map is unsafe: namespaces can have different servers
 * with the same name, and even two proxies in one namespace can have different
 * routing winners. Each proxy owns a complete post-middleware listing snapshot.
 *
 * A CALLER THAT NEVER LISTS. A snapshot used to come only from a client's own
 * tools/list on that proxy, so n8n on the OpenAPI bridge, a session rebuilt by
 * lazy recovery and a long session whose snapshot a list_changed cleared all
 * stored counts only (2026-11-02: about 22k n8n rows a week and most of an
 * always-on agent's rows had no key names, which hid an authorless note from an
 * audit query). `AuditSchemaRefresher` closes that: on a miss the routing
 * instance runs its OWN listing (the same chain its tools/list serves) and
 * records it, so every stored name still comes from the tool's own published
 * schema as that instance exposes it. The cost is bounded per instance (one
 * listing per AUDIT_LISTING_INTERVAL_MS, in-flight listings shared) and per
 * process (MAX_CONCURRENT_AUDIT_LISTINGS); past either bound the row keeps
 * the count-only shape.
 *
 * PURE apart from the registry map and the refresher's in-flight counter, never
 * throws, and bounded: past MAX_TOOLS the oldest entry is evicted (Map keeps
 * insertion order; a re-record moves a tool to the end).
 */

import {
  KEY_MAX_LEN,
  SELECTOR_KEYS,
  SELECTOR_VALUE_MAX,
} from "./metamcp-middleware/audit-args-shape";

export interface ToolArgSchema {
  /** Declared top-level property names. */
  keys: ReadonlySet<string>;
  /** Per selector, declared string values; an empty set means no value is verified. */
  enums: ReadonlyMap<string, ReadonlySet<string>>;
}

export const MAX_TOOLS = 5000;
export const MAX_SCHEMA_KEYS = 256;
export const MAX_ENUM_VALUES = 256;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Build the allowlist entry for one inputSchema; undefined when it has no properties object. */
export function schemaFromInputSchema(
  inputSchema: unknown,
): ToolArgSchema | undefined {
  try {
    if (!isRecord(inputSchema)) return undefined;
    const props = inputSchema.properties;
    if (!isRecord(props)) return undefined;
    // A tool-count cap alone does not bound retained schema data. Oversized
    // schemas remain unknown rather than retaining unbounded names or enums.
    const names = Object.keys(props);
    if (names.length > MAX_SCHEMA_KEYS) return undefined;
    const keys = new Set<string>();
    const enums = new Map<string, ReadonlySet<string>>();
    for (const name of names) {
      if (name.length > KEY_MAX_LEN) continue;
      keys.add(name);
      // Only these six values can ever be stored; other property enums need
      // not consume cache space or be inspected.
      if (!(SELECTOR_KEYS as readonly string[]).includes(name)) continue;
      const def = props[name];
      if (!isRecord(def)) {
        if (def !== true) enums.set(name, new Set());
        continue;
      }
      // An enum may sit on the property itself or on an anyOf branch
      // (FastMCP renders `Literal[...] | None` as anyOf [{enum}, {type: null}]).
      const anyOf = Array.isArray(def.anyOf) ? def.anyOf : [];
      if (anyOf.length >= MAX_ENUM_VALUES) {
        enums.set(name, new Set());
        continue;
      }
      const branches: unknown[] = [def, ...anyOf];
      const values = new Set<string>();
      let restricted = false;
      let unsupported = false;
      for (const branch of branches) {
        if (!isRecord(branch)) {
          unsupported = true;
          break;
        }
        // Never treat an unresolved reference/composition as "no enum": that
        // would let invalid caller-chosen values bypass a declared restriction.
        if (
          ["$ref", "oneOf", "allOf", "not", "if", "then", "else"].some((key) =>
            Object.prototype.hasOwnProperty.call(branch, key),
          ) ||
          (branch !== def &&
            Object.prototype.hasOwnProperty.call(branch, "anyOf"))
        ) {
          unsupported = true;
          break;
        }
        if (Object.prototype.hasOwnProperty.call(branch, "const")) {
          restricted = true;
          if (
            typeof branch.const === "string" &&
            branch.const.length <= SELECTOR_VALUE_MAX
          ) {
            values.add(branch.const);
          }
        }
        if (!Object.prototype.hasOwnProperty.call(branch, "enum")) continue;
        restricted = true;
        if (
          !Array.isArray(branch.enum) ||
          branch.enum.length > MAX_ENUM_VALUES
        ) {
          unsupported = true;
          break;
        }
        for (const v of branch.enum) {
          if (typeof v === "string" && v.length <= SELECTOR_VALUE_MAX)
            values.add(v);
        }
        if (values.size > MAX_ENUM_VALUES) {
          unsupported = true;
          break;
        }
      }
      // An empty enum still forbids arbitrary string values. Unsupported
      // schemas keep the key but record only the misuse marker for its value.
      if (restricted || unsupported)
        enums.set(name, unsupported ? new Set() : values);
    }
    return { keys, enums };
  } catch {
    return undefined;
  }
}

/** One routing instance's bounded schema snapshot. Never shared with another proxy. */
export class ToolArgSchemaRegistry {
  private readonly schemas = new Map<string, ToolArgSchema>();
  // Set only by a snapshot an audit listing took (see AuditSchemaRefresher):
  // nothing re-lists for the client on that path, so its age is bounded.
  private expiresAt: number | undefined;

  /** Record (or refresh) one exposed tool's schema. Never throws. */
  record(exposedName: string, inputSchema: unknown): void {
    try {
      const entry = schemaFromInputSchema(inputSchema);
      this.schemas.delete(exposedName);
      if (!entry || exposedName.length > 256) return;
      this.schemas.set(exposedName, entry);
      while (this.schemas.size > MAX_TOOLS) {
        const oldest = this.schemas.keys().next().value;
        if (oldest === undefined) break;
        this.schemas.delete(oldest);
      }
    } catch {
      // A schema the gateway cannot read leaves the tool unknown (counts only).
      this.schemas.delete(exposedName);
    }
  }

  /**
   * Replace after a complete final listing; removed names and duplicates are
   * unknown. `expiresAt` (epoch ms) bounds how long this snapshot is trusted;
   * omitted, it is trusted until the next replace (a client listing, whose
   * servers' list_changed subscribers invalidate it).
   */
  replace(
    tools: ReadonlyArray<{ name: string; inputSchema: unknown }>,
    expiresAt?: number,
  ): void {
    this.schemas.clear();
    this.expiresAt = expiresAt;
    try {
      if (tools.length > MAX_TOOLS) return;
      const seen = new Set<string>();
      for (const tool of tools) {
        if (seen.has(tool.name)) {
          // Overrides can create an ambiguous exposed name after raw routing
          // collision checks. Neither schema is safe to attribute to that call.
          this.schemas.delete(tool.name);
          continue;
        }
        seen.add(tool.name);
        this.record(tool.name, tool.inputSchema);
      }
    } catch {
      // Do not retain a partly read snapshot, and never interrupt tools/list.
      this.schemas.clear();
    }
  }

  get(exposedName: string): ToolArgSchema | undefined {
    if (this.expiresAt !== undefined && Date.now() >= this.expiresAt) {
      // An expired audit snapshot is unknown, not stale-but-verified.
      this.schemas.clear();
      this.expiresAt = undefined;
      return undefined;
    }
    return this.schemas.get(exposedName);
  }
}

/** Per routing instance: a new audit listing starts at most once per this interval. */
export const AUDIT_LISTING_INTERVAL_MS = 60_000;
/** Per process: audit listings running at once, across every proxy and the bridge. */
export const MAX_CONCURRENT_AUDIT_LISTINGS = 4;
/** How long a snapshot an audit listing took is trusted. */
export const AUDIT_SNAPSHOT_MAX_AGE_MS = 10 * 60_000;

/**
 * An audit has no authority to choose a routing winner. Counting duplicate
 * tool names alone is insufficient: if one of two prefix-matched servers
 * cannot list, the other's schema must not describe a call to the missing
 * winner. Exclude every ambiguous mounted prefix, even if only one lists.
 * An unresolved backend-reported prefix could collide with any listed one,
 * so it leaves the entire snapshot unknown. Callers fill such prefixes from
 * the acquired backend's version before passing them here.
 */
export function unambiguousAuditTools<T extends { name: string }>(
  tools: ReadonlyArray<T>,
  mountedPrefixes: Iterable<string | undefined>,
): T[] {
  const owners = new Map<string, number>();
  for (const prefix of mountedPrefixes) {
    if (prefix === undefined) return [];
    owners.set(prefix, (owners.get(prefix) ?? 0) + 1);
  }
  return tools.filter((tool) => {
    const separator = tool.name.indexOf("__");
    return separator >= 0 && owners.get(tool.name.slice(0, separator)) === 1;
  });
}

// Process-wide, because the storm this bounds is many instances missing at
// once (every lazily recovered session after a gateway restart, or a burst of
// short sessions), each of which would fan a listing out to every backend.
let auditListingsRunning = 0;

/** What a routing instance gives the refresher. */
export interface AuditListingSource {
  /**
   * The instance's own final listing: the chain its tools/list runs (overrides
   * and filter included), so names and schemas are the ones it exposes. Must
   * not change what the instance's client receives.
   */
  list: () => Promise<ReadonlyArray<{ name: string; inputSchema: unknown }>>;
  /**
   * The instance's snapshot generation. A client listing or a list_changed
   * bumps it; an audit listing that started under an older generation is
   * discarded, as an overlapping client listing is.
   */
  generation: () => number;
  /** A client tools/list on this instance still running; joined, not repeated. */
  pendingClientListing?: () => Promise<unknown> | undefined;
  /** False once the instance is closed: a closed session starts no listing. */
  isOpen?: () => boolean;
  /** Told why an audit listing failed. The row keeps the count-only shape. */
  onFailure: (error: unknown) => void;
}

/**
 * Fills one instance's registry from the instance's own listing when a call
 * names a tool the registry does not hold. Bounded (see the module header) and
 * never rejects: every failure resolves to `undefined`, which the auditing
 * middleware records as the count-only shape. It never touches the call.
 */
export class AuditSchemaRefresher {
  private inFlight: Promise<void> | undefined;
  private lastStartedAt = Number.NEGATIVE_INFINITY;

  constructor(
    private readonly registry: ToolArgSchemaRegistry,
    private readonly source: AuditListingSource,
  ) {}

  /**
   * The schema for `exposedName` once this instance's listing settles, or
   * undefined when no listing may start now (closed, inside the interval, or at
   * the process cap). The promise never rejects.
   */
  resolve(exposedName: string): Promise<ToolArgSchema | undefined> | undefined {
    try {
      const known = this.registry.get(exposedName);
      if (known) return Promise.resolve(known);
      if (this.source.isOpen && !this.source.isOpen()) return undefined;
      const lookUp = () => this.registry.get(exposedName);
      const client = this.source.pendingClientListing?.();
      if (client) return client.then(lookUp, () => undefined);
      return (this.inFlight ?? this.start())?.then(lookUp, () => undefined);
    } catch (error) {
      this.report(error);
      return undefined;
    }
  }

  private start(): Promise<void> | undefined {
    const now = Date.now();
    if (now - this.lastStartedAt < AUDIT_LISTING_INTERVAL_MS) return undefined;
    // At the cap the interval is not consumed: the next miss may try again.
    if (auditListingsRunning >= MAX_CONCURRENT_AUDIT_LISTINGS) return undefined;
    this.lastStartedAt = now;
    auditListingsRunning += 1;
    const generation = this.source.generation();
    // Deferred one microtask so `inFlight` is set before the body runs: a
    // listing that throws synchronously must still clear it in `finally`.
    const run: Promise<void> = Promise.resolve().then(async () => {
      try {
        const tools = await this.source.list();
        if (generation === this.source.generation()) {
          this.registry.replace(tools, Date.now() + AUDIT_SNAPSHOT_MAX_AGE_MS);
        }
      } catch (error) {
        this.report(error);
      } finally {
        auditListingsRunning -= 1;
        if (this.inFlight === run) this.inFlight = undefined;
      }
    });
    this.inFlight = run;
    return run;
  }

  private report(error: unknown): void {
    try {
      this.source.onFailure(error);
    } catch {
      // A throwing reporter must not turn a count-only row into a lost row.
    }
  }
}
