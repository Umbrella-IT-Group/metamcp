import type {
  CallToolRequest,
  CallToolResult,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";

/**
 * The lean tool listing: four meta tools that stand in for the whole catalog
 * on an endpoint whose consumers would otherwise load every tool definition up
 * front. Pure and dependency-free (no database, no logger, no SDK runtime
 * import), like `endpoint-presentation.ts`, because the proxy imports it and
 * its own suites mock no database. `lean-prelude.ts` is the glue that reads the
 * real listing and logs.
 *
 * WHAT THIS MODULE MUST NEVER DO: authorize anything. Search and describe read
 * a snapshot of the post-policy listing (what a normal client `tools/list`
 * returns, overrides and filter applied), and the snapshot may lag a policy
 * change by up to its lifetime. Nothing here decides whether a tool may RUN:
 * both call meta tools are rewritten into an ordinary `tools/call` for the real
 * tool name and enter the proxy's own middleware chain, where audit, retired
 * tools, overrides, the policy filter and the timeout hint judge the call live,
 * exactly as for a direct call. The one decision this module makes is which of
 * the two call meta tools a tool belongs to, and that is a routing answer for
 * the client (see `classifyCallTarget`), not an access verdict. That answer is
 * about one tool, so the snapshot also says which tool each listed name stood
 * for (`listedTargetOf`), and the call chain refuses a `call_tool` call whose
 * name no longer leads to that tool (`classified-target.functional.ts`): a
 * verdict is never spent on a different tool than it was given for.
 */

export const SEARCH_TOOL = "search_tools";
export const DESCRIBE_TOOL = "describe_tool";
export const CALL_TOOL = "call_tool";
export const CALL_WRITE_TOOL = "call_write_tool";

/**
 * None of these contains the `__` separator, so `parseToolName` answers null
 * for every one of them and no real tool (always `<server>__<tool>`) can
 * collide with them. A test pins the invariant: the policy filter's call-side
 * verdict for a name with no separator would otherwise apply to a meta name.
 */
export const LEAN_META_TOOL_NAMES = [
  SEARCH_TOOL,
  DESCRIBE_TOOL,
  CALL_TOOL,
  CALL_WRITE_TOOL,
] as const;
export type LeanMetaToolName = (typeof LEAN_META_TOOL_NAMES)[number];

export function isLeanMetaToolName(name: string): name is LeanMetaToolName {
  return (LEAN_META_TOOL_NAMES as readonly string[]).includes(name);
}

/**
 * How long a search snapshot may serve. Equal to the policy filter's own cache
 * lifetime on purpose: the snapshot can then be no staler than what a direct
 * `tools/list` would have shown anyway, and it is dropped by every
 * list-changed or mount event.
 */
export const LEAN_CATALOG_TTL_MS = 1000;

export const SEARCH_LIMIT_DEFAULT = 10;
export const SEARCH_LIMIT_MAX = 25;
export const SEARCH_QUERY_MAX = 200;
export const DESCRIBE_NAMES_MAX = 10;
export const TOOL_NAME_MAX = 256;
export const DESCRIPTION_SNIPPET_MAX = 300;
export const SCHEMAS_DETAIL_MAX_RESULTS = 5;
export const DOWNGRADE_BYTES = 64 * 1024;
export const REFUSE_BYTES = 200 * 1024;

/**
 * The tools a lean session lists. No `outputSchema`: results are unchanged, and
 * a tool listed without one has no client-side validator for its
 * `structuredContent` (SDK client.index.js), so a real tool's result passes
 * through `call_tool` as it would directly.
 *
 * ANNOTATIONS, and why there are two call tools. A client that gates on hints
 * treats a read-only tool as safe to run without asking. One call tool that
 * could run anything would therefore either have to claim read-only, and let
 * one approval cover every write tool on the endpoint, or claim the MCP
 * defaults and make every read prompt. So `call_tool` runs ONLY tools whose
 * effective (post-override) `readOnlyHint` is true and says so, and
 * `call_write_tool` runs anything and carries the MCP defaults, written out
 * (ToolAnnotations: readOnlyHint false, destructiveHint true, idempotentHint
 * false, openWorldHint true; omitting them reads the same). `openWorldHint` is
 * true on `call_tool` too: the tools behind it reach external systems.
 */
const READ_ONLY_META = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

const META_TOOLS: readonly Tool[] = deepFreeze([
  {
    name: SEARCH_TOOL,
    title: "Search tools",
    description:
      "Find tools on this endpoint. Describe the task in a few words, such as 'reset user password' or 'list open tickets'. Matches names, descriptions and parameter names. Returns up to 10 matches by default, best first, each with read_only and destructive flags, the meta tool that runs it (runs_with), and a meta block that lists the servers and how many tools exist. Use detail 'names' for a compact list, 'descriptions' (default) for short descriptions, or 'schemas' to include input schemas when there are 5 or fewer matches.",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          maxLength: SEARCH_QUERY_MAX,
          description:
            "What you want to do, in a few words. Leave empty to list tools by name.",
        },
        detail: {
          type: "string",
          enum: ["names", "descriptions", "schemas"],
          description:
            "How much to return for each match. Default descriptions.",
        },
        limit: {
          type: "integer",
          minimum: 1,
          maximum: SEARCH_LIMIT_MAX,
          description: "How many matches to return. Default 10, at most 25.",
        },
      },
    },
    annotations: { ...READ_ONLY_META },
  },
  {
    name: DESCRIBE_TOOL,
    title: "Describe tools",
    description:
      "Get the full definition of one or more tools by exact name (as returned by search_tools): description, input schema, annotations such as readOnlyHint and destructiveHint, and runs_with, which says whether call_tool or call_write_tool runs the tool. Read the annotations before you run a tool that might change data. Pass up to 10 names. Set include_output_schema to true to also get the output schema.",
    inputSchema: {
      type: "object",
      properties: {
        names: {
          type: "array",
          items: { type: "string", maxLength: TOOL_NAME_MAX },
          minItems: 1,
          maxItems: DESCRIBE_NAMES_MAX,
          description: "Exact tool names, as returned by search_tools.",
        },
        include_output_schema: {
          type: "boolean",
          description:
            "Also return each tool's output schema. Off by default because output schemas can be large.",
        },
      },
      required: ["names"],
    },
    annotations: { ...READ_ONLY_META },
  },
  {
    name: CALL_TOOL,
    title: "Call read-only tool",
    description:
      "Run one read-only tool by its exact full name with its arguments, as described by describe_tool. Only tools whose read-only hint is true run here; for any other tool the answer is an error that names call_write_tool. It runs the same tool as a direct call and returns its result unchanged.",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          maxLength: TOOL_NAME_MAX,
          description: "The full tool name, as returned by search_tools.",
        },
        arguments: {
          type: "object",
          description: "The tool's arguments, as its input schema describes.",
        },
      },
      required: ["name"],
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  {
    name: CALL_WRITE_TOOL,
    title: "Call tool",
    description:
      "Run any tool by its exact full name with its arguments, as described by describe_tool, including tools that create, change or delete data. Use call_tool for tools whose read-only hint is true. It runs the same tool as a direct call and returns its result unchanged. Read a tool's description and hints with describe_tool before you run one that changes data.",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          maxLength: TOOL_NAME_MAX,
          description: "The full tool name, as returned by search_tools.",
        },
        arguments: {
          type: "object",
          description: "The tool's arguments, as its input schema describes.",
        },
      },
      required: ["name"],
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
] as Tool[]);

/** The four definitions, frozen. The same objects on every call. */
export function leanMetaTools(): readonly Tool[] {
  return META_TOOLS;
}

function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

// ---------------------------------------------------------------------------
// The listing, the hints, and which call tool runs a tool
// ---------------------------------------------------------------------------

/**
 * What search and describe read: the post-policy listing, and how many servers
 * the listing could not reach (a count and never names: a server the policy
 * hides from this caller can fail too, and naming it would disclose it).
 */
export interface LeanListing {
  readonly tools: readonly Tool[];
  readonly unavailable: number;
  /**
   * For each listed name, the ORIGINAL full name (`<server>__<tool>`: the
   * backend server and the backend's own tool name) of each entry listed under
   * it, as the overrides resolved it when this listing was built. Absent when
   * the listing could not say, and then no name has an identity
   * (`listedTargetOf`), so `call_tool` runs nothing from it.
   */
  readonly origins?: ReadonlyMap<string, readonly string[]>;
  /** Backend UUID by original full name, captured by this listing, never a route read later. */
  readonly serverUuids?: ReadonlyMap<string, string>;
  /**
   * False after an invalidation, including for an old load still returning to
   * its waiters. A re-verification (`createLeanPrelude`) accepts a listing only
   * while this is defined and true, and hands it on as the call's new proof.
   */
  readonly isCurrent?: () => boolean;
}

/**
 * The hints as the MCP defaults read them (ToolAnnotations: `readOnlyHint`
 * defaults false, `destructiveHint` defaults true and means something only
 * while `readOnlyHint` is false). Read from the post-override listing, so they
 * are the annotations a direct client sees. Strictly `true`: a string or any
 * other value is not a read-only claim.
 */
export function hintFlags(tool: Tool): {
  read_only: boolean;
  destructive: boolean;
} {
  const readOnly = tool.annotations?.readOnlyHint === true;
  return {
    read_only: readOnly,
    destructive: !readOnly && tool.annotations?.destructiveHint !== false,
  };
}

export function runsWith(
  tool: Tool,
): typeof CALL_TOOL | typeof CALL_WRITE_TOOL {
  return hintFlags(tool).read_only ? CALL_TOOL : CALL_WRITE_TOOL;
}

/**
 * May `call_tool` run this name? Only when the listing holds the name and EVERY
 * entry under it is read-only (two entries can share a name when namespace
 * overrides collide, and the call chain would resolve it to just one of them,
 * so a doubtful name is treated as not read-only). A name the listing does not
 * hold is not read-only either: nothing here can vouch for its hints, and the
 * client is sent to `call_write_tool`, which runs whatever the call chain lets
 * through.
 *
 * This reads a snapshot that may be up to `LEAN_CATALOG_TTL_MS` old, the same
 * bound as every cache in the call chain (and it is dropped when the
 * namespace's overrides change). It decides which call tool a tool belongs to
 * and nothing else: a tool this lets through still faces the chain's live
 * policy filter, and the chain, not this function, is what refuses a tool the
 * namespace has switched off. The hints it read belong to the tool the name
 * stood for in the snapshot, which is why `call_tool` also records that tool
 * (`listedTargetOf`) and the chain refuses the call if the name has since come
 * to lead to another one.
 */
export function classifyCallTarget(
  listing: LeanListing,
  name: string,
): { readOnly: boolean } {
  let seen = false;
  for (const tool of listing.tools) {
    if (tool.name !== name) continue;
    seen = true;
    if (!hintFlags(tool).read_only) return { readOnly: false };
  }
  return { readOnly: seen };
}

/**
 * The tool a listed name stood for in this snapshot: its original full name
 * (`<server>__<tool>`), or `undefined` when the snapshot cannot name exactly
 * one tool for it (no origins recorded, the name not listed, or two entries
 * listed under it).
 *
 * `call_tool` records this when it gives a read-only verdict and the call chain
 * compares it with the tool the name resolves to when the call runs. A verdict
 * without an identity is not given: the caller fails closed.
 */
export function listedTargetOf(
  listing: LeanListing,
  name: string,
): string | undefined {
  const entries = listing.origins?.get(name);
  return entries?.length === 1 ? entries[0] : undefined;
}

// ---------------------------------------------------------------------------
// Tokenizing and ranking
// ---------------------------------------------------------------------------

const STOPWORDS: ReadonlySet<string> = new Set(
  "a an and are as at be by for from how i in is it of on or that the this to with".split(
    " ",
  ),
);
const TOKEN_MAX_LENGTH = 64;
const QUERY_TOKEN_MAX = 16;
const DESCRIPTION_INDEX_CHARS = 2000;
/**
 * What is indexed of a tool's name, prefix and each parameter key, and how many
 * parameters. The camelCase split is quadratic in the length of an uppercase
 * run, and a listing is backend-supplied, so one pathological tool name would
 * otherwise stall every search of the session. Real names are far shorter.
 */
const INDEX_NAME_CHARS = 256;
const MAX_INDEXED_PROPERTIES = 256;
const DESCRIPTION_INDEX_TOKENS = 400;
const PARAM_VALUES_PER_PROPERTY = 64;
const PARAM_VALUE_MAX_CHARS = 48;

function rawTokens(text: string): string[] {
  return text
    .replace(/(\p{Ll}|\p{N})(\p{Lu})/gu, "$1 $2")
    .replace(/(\p{Lu}+)(\p{Lu}\p{Ll})/gu, "$1 $2")
    .toLowerCase()
    .split(/[^\p{L}\p{N}]+/u)
    .filter((token) => token !== "" && token.length <= TOKEN_MAX_LENGTH);
}

/**
 * One shared light stem for both sides of a match: drop a single trailing `s`
 * from a token longer than three characters unless it ends in `ss`, `us` or
 * `is`. Crude on purpose (it turns "mailboxes" into "mailboxe"), and that is
 * harmless because the query and the document are stemmed the same way.
 */
function stem(token: string): string {
  return token.length > 3 && token.endsWith("s") && !/(ss|us|is)$/.test(token)
    ? token.slice(0, -1)
    : token;
}

/**
 * camelCase and every non-letter, non-digit run split words; stopwords drop;
 * the rest is stemmed. Letters and digits are Unicode-aware.
 */
export function tokenize(text: string): string[] {
  return rawTokens(text)
    .filter((token) => !STOPWORDS.has(token))
    .map(stem);
}

/**
 * The query's tokens: unique, at most 16. A query made only of stopwords
 * ("the") falls back to its unfiltered tokens rather than matching nothing.
 */
export function tokenizeQuery(text: string): string[] {
  const raw = rawTokens(text);
  const kept = raw.filter((token) => !STOPWORDS.has(token));
  const unique: string[] = [];
  for (const token of (kept.length > 0 ? kept : raw).map(stem)) {
    if (!unique.includes(token)) unique.push(token);
    if (unique.length === QUERY_TOKEN_MAX) break;
  }
  return unique;
}

interface SearchDocument {
  readonly tool: Tool;
  readonly prefix: readonly string[];
  readonly name: readonly string[];
  readonly params: readonly string[];
  readonly description: readonly string[];
  readonly length: number;
}

// Field weights of the BM25F-style score. The prefix counts for most on a
// multi-server endpoint and is close to nothing on a single-server one; the
// name outranks parameters and parameters outrank prose, because most gateway
// tools are `<noun>_manage(mode=...)` selectors whose enum values say what
// they do.
const W_PREFIX = 2;
const W_NAME = 3;
const W_PARAMS = 2;
const W_DESCRIPTION = 1;
const BM25_K1 = 1.2;
const BM25_B = 0.75;
/** A query that is exactly a tool's full name puts that tool first. */
const EXACT_NAME_BONUS = 1000;

function splitName(fullName: string): { prefix: string; name: string } {
  const at = fullName.indexOf("__");
  return at === -1
    ? { prefix: "", name: fullName }
    : { prefix: fullName.slice(0, at), name: fullName.slice(at + 2) };
}

/**
 * The string values a property schema can take, from `enum`, `const` and the
 * same on `anyOf` branches, bounded per property and per value so a schema
 * with a thousand enum members cannot swamp a document.
 */
function propertyValues(schema: unknown): string[] {
  const values: string[] = [];
  const take = (node: unknown): void => {
    if (typeof node !== "object" || node === null) return;
    const { const: constant, enum: members } = node as {
      const?: unknown;
      enum?: unknown;
    };
    if (typeof constant === "string") values.push(constant);
    if (Array.isArray(members)) {
      for (const member of members) {
        if (typeof member === "string") values.push(member);
      }
    }
  };
  take(schema);
  const branches = (schema as { anyOf?: unknown } | null | undefined)?.anyOf;
  if (Array.isArray(branches)) branches.forEach(take);
  return values
    .filter((value) => value.length <= PARAM_VALUE_MAX_CHARS)
    .slice(0, PARAM_VALUES_PER_PROPERTY);
}

function buildDocument(tool: Tool): SearchDocument {
  const { prefix, name } = splitName(tool.name);
  const params: string[] = [];
  const properties = (tool.inputSchema as { properties?: unknown } | undefined)
    ?.properties;
  if (typeof properties === "object" && properties !== null) {
    for (const [key, schema] of Object.entries(properties).slice(
      0,
      MAX_INDEXED_PROPERTIES,
    )) {
      params.push(...tokenize(key.slice(0, INDEX_NAME_CHARS)));
      for (const value of propertyValues(schema)) {
        params.push(...tokenize(value));
      }
    }
  }
  const description = tokenize(
    (tool.description ?? "").slice(0, DESCRIPTION_INDEX_CHARS),
  ).slice(0, DESCRIPTION_INDEX_TOKENS);
  const document = {
    tool,
    prefix: tokenize(prefix.slice(0, INDEX_NAME_CHARS)),
    name: tokenize(name.slice(0, INDEX_NAME_CHARS)),
    params,
    description,
  };
  return {
    ...document,
    length:
      W_PREFIX * document.prefix.length +
      W_NAME * document.name.length +
      W_PARAMS * params.length +
      W_DESCRIPTION * description.length,
  };
}

function weightedFrequency(document: SearchDocument, term: string): number {
  const count = (tokens: readonly string[]) =>
    tokens.reduce((n, token) => (token === term ? n + 1 : n), 0);
  return (
    W_PREFIX * count(document.prefix) +
    W_NAME * count(document.name) +
    W_PARAMS * count(document.params) +
    W_DESCRIPTION * count(document.description)
  );
}

export interface RankedTool {
  readonly tool: Tool;
  readonly score: number;
}

/**
 * BM25 (Robertson and Zaragoza 2009) over four weighted fields, with the
 * non-negative idf Lucene uses: `ln(1 + (N - n + 0.5) / (n + 0.5))`. Only tools
 * that score above zero are returned, best first, ties by name ascending, so
 * the order is deterministic. An empty query is browse mode: every tool, by
 * name. A query with no letters or digits (only punctuation) matches nothing.
 */
export function rankTools(tools: readonly Tool[], query: string): RankedTool[] {
  if (query.trim() === "") {
    return [...tools].sort(compareByName).map((tool) => ({ tool, score: 0 }));
  }
  const documents = tools.map(buildDocument);
  const terms = tokenizeQuery(query);
  const total = documents.length;
  const averageLength =
    total === 0
      ? 0
      : documents.reduce((sum, document) => sum + document.length, 0) / total;
  const idf = new Map<string, number>();
  for (const term of terms) {
    const containing = documents.filter(
      (document) => weightedFrequency(document, term) > 0,
    ).length;
    idf.set(
      term,
      Math.log(1 + (total - containing + 0.5) / (containing + 0.5)),
    );
  }
  const exact = query.trim().toLowerCase();
  const ranked: RankedTool[] = [];
  for (const document of documents) {
    let score = 0;
    for (const term of terms) {
      const frequency = weightedFrequency(document, term);
      if (frequency === 0) continue;
      const lengthRatio =
        averageLength === 0 ? 1 : document.length / averageLength;
      score +=
        ((idf.get(term) ?? 0) * frequency * (BM25_K1 + 1)) /
        (frequency + BM25_K1 * (1 - BM25_B + BM25_B * lengthRatio));
    }
    if (exact === document.tool.name.toLowerCase()) score += EXACT_NAME_BONUS;
    if (score > 0) ranked.push({ tool: document.tool, score });
  }
  return ranked.sort(
    (a, b) => b.score - a.score || compareByName(a.tool, b.tool),
  );
}

function compareByName(a: Tool, b: Tool): number {
  return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
}

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

export type SearchDetail = "names" | "descriptions" | "schemas";

export interface SearchArgs {
  readonly query: string;
  readonly queryTruncated: boolean;
  readonly detail: SearchDetail;
  readonly limit: number;
}

export interface DescribeArgs {
  readonly names: readonly string[];
  readonly includeOutputSchema: boolean;
}

/**
 * What `routeLeanCall` decided for one incoming `tools/call`.
 *
 * - `passthrough`: not a meta call. A real tool name, called directly, goes
 *   to the middleware chain untouched (direct calls keep working in a lean
 *   session).
 * - `answer`: a refusal of malformed arguments, final.
 * - `search` and `describe`: answered from the listing by the pure functions
 *   below.
 * - `call`: a rewritten `tools/call` for the real name. `via` says which
 *   meta tool asked, because `call_tool` first needs the target's hints.
 */
export type LeanRoute =
  | { readonly kind: "passthrough" }
  | { readonly kind: "answer"; readonly result: CallToolResult }
  | { readonly kind: "search"; readonly args: SearchArgs }
  | { readonly kind: "describe"; readonly args: DescribeArgs }
  | {
      readonly kind: "call";
      readonly via: typeof CALL_TOOL | typeof CALL_WRITE_TOOL;
      readonly name: string;
      readonly request: CallToolRequest;
    };

/**
 * Refusals are constant text that echoes nothing from the request, so a caller
 * cannot use a meta tool to reflect its own input into logs or another
 * consumer's view.
 */
const REFUSE_SEARCH =
  "search_tools: invalid arguments (query: text; detail: names, descriptions or schemas; limit: a number, applied between 1 and 25).";
const REFUSE_DESCRIBE =
  "describe_tool: invalid arguments (names: a list of 1 to 10 tool names, each up to 256 characters; include_output_schema: true or false).";
const refuseCall = (via: string): string =>
  `${via}: invalid arguments (name: the full tool name, up to 256 characters; arguments: an object).`;
const refuseNested = (via: string): string =>
  `${via} cannot run ${SEARCH_TOOL}, ${DESCRIBE_TOOL}, ${CALL_TOOL} or ${CALL_WRITE_TOOL}. Call those directly.`;

/** A refusal or routing answer as the MCP tool result it is. */
export function toolError(text: string): CallToolResult {
  return { isError: true, content: [{ type: "text", text }] };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The `arguments` of a meta call as an object, `{}` when absent. */
function argumentRecord(value: unknown): Record<string, unknown> | undefined {
  if (value === undefined || value === null) return {};
  return isRecord(value) ? value : undefined;
}

function parseSearchArgs(raw: unknown): SearchArgs | undefined {
  const args = argumentRecord(raw);
  if (args === undefined) return undefined;
  let query = "";
  let queryTruncated = false;
  if (args.query !== undefined && args.query !== null) {
    if (typeof args.query !== "string") return undefined;
    query = args.query;
    if (query.length > SEARCH_QUERY_MAX) {
      query = query.slice(0, SEARCH_QUERY_MAX);
      // Never leave half a surrogate pair at the cut.
      if (/[\uD800-\uDBFF]$/.test(query)) query = query.slice(0, -1);
      queryTruncated = true;
    }
  }
  let detail: SearchDetail = "descriptions";
  if (args.detail !== undefined && args.detail !== null) {
    if (
      args.detail !== "names" &&
      args.detail !== "descriptions" &&
      args.detail !== "schemas"
    ) {
      return undefined;
    }
    detail = args.detail;
  }
  let limit = SEARCH_LIMIT_DEFAULT;
  if (args.limit !== undefined && args.limit !== null) {
    const numeric =
      typeof args.limit === "number"
        ? args.limit
        : typeof args.limit === "string" && args.limit.trim() !== ""
          ? Number(args.limit)
          : Number.NaN;
    if (!Number.isFinite(numeric)) return undefined;
    // Truncated toward zero, then clamped: 0, negatives and fractions land in
    // range instead of being refused, and the applied value is reported.
    limit = Math.min(SEARCH_LIMIT_MAX, Math.max(1, Math.trunc(numeric)));
  }
  return { query, queryTruncated, detail, limit };
}

function parseDescribeArgs(raw: unknown): DescribeArgs | undefined {
  const args = argumentRecord(raw);
  if (args === undefined) return undefined;
  const names = args.names;
  if (
    !Array.isArray(names) ||
    names.length < 1 ||
    names.length > DESCRIBE_NAMES_MAX
  ) {
    return undefined;
  }
  const unique: string[] = [];
  for (const name of names) {
    if (
      typeof name !== "string" ||
      name.length < 1 ||
      name.length > TOOL_NAME_MAX
    ) {
      return undefined;
    }
    if (!unique.includes(name)) unique.push(name);
  }
  const include = args.include_output_schema;
  if (
    include !== undefined &&
    include !== null &&
    typeof include !== "boolean"
  ) {
    return undefined;
  }
  return { names: unique, includeOutputSchema: include === true };
}

/**
 * Decide what a `tools/call` is, before anything runs.
 *
 * THE REWRITE. A call meta tool becomes the request a client would have sent
 * for the real tool: the same request with the real `name`, the inner
 * `arguments` as given, every other param (`_meta`, so a progress token
 * survives) untouched. The `arguments` key is DELETED when the caller gave
 * none rather than set to `{}`, because the audit `params_hash` is computed
 * from the arguments as sent and is null for a call without any: an injected
 * `{}` would hash to a value a direct call never has. The rewritten request is
 * handed straight to the call chain and never to this function again, so a
 * nested meta call is structurally impossible as well as refused up front.
 *
 * A real-looking name with no `__` is passed on as written. The chain then
 * answers exactly as it would for a direct call to that name.
 */
export function routeLeanCall(request: CallToolRequest): LeanRoute {
  const name = request.params.name;
  const raw = request.params.arguments;
  switch (name) {
    case SEARCH_TOOL: {
      const args = parseSearchArgs(raw);
      return args
        ? { kind: "search", args }
        : { kind: "answer", result: toolError(REFUSE_SEARCH) };
    }
    case DESCRIBE_TOOL: {
      const args = parseDescribeArgs(raw);
      return args
        ? { kind: "describe", args }
        : { kind: "answer", result: toolError(REFUSE_DESCRIBE) };
    }
    case CALL_TOOL:
    case CALL_WRITE_TOOL: {
      const outer = argumentRecord(raw);
      const innerName = outer?.name;
      const innerArgs = outer?.arguments;
      if (
        outer === undefined ||
        typeof innerName !== "string" ||
        innerName.length < 1 ||
        innerName.length > TOOL_NAME_MAX ||
        (innerArgs !== undefined && innerArgs !== null && !isRecord(innerArgs))
      ) {
        return { kind: "answer", result: toolError(refuseCall(name)) };
      }
      if (isLeanMetaToolName(innerName)) {
        return { kind: "answer", result: toolError(refuseNested(name)) };
      }
      const { arguments: _outerArguments, ...rest } = request.params;
      return {
        kind: "call",
        via: name,
        name: innerName,
        request: {
          ...request,
          params: {
            ...rest,
            name: innerName,
            ...(isRecord(innerArgs) ? { arguments: innerArgs } : {}),
          },
        },
      };
    }
    default:
      return { kind: "passthrough" };
  }
}

/**
 * The answer a `call_tool` for a tool that is not known to be read-only gets.
 * A routing answer, not an access refusal: the same session reaches the tool
 * through `call_write_tool`, where the call chain applies its own policy. Constant
 * text, so nothing from the request is echoed.
 */
export const CALL_TOOL_ROUTING_ANSWER =
  "call_tool runs only tools whose read-only hint is true, and this tool is not listed as read-only on this endpoint (or is not listed at all). Run it with call_write_tool, which runs any tool, or read its hints with describe_tool.";

/** Answer when the catalog cannot be read for a search or a describe. */
export const CATALOG_UNAVAILABLE_ANSWER =
  "The tool catalog could not be read right now. Retry shortly.";

/** Answer when it cannot be read for the read-only check of `call_tool`. */
export const CALL_TOOL_CATALOG_UNAVAILABLE_ANSWER =
  "The tool catalog could not be read right now, so call_tool cannot tell whether this tool is read-only. Retry shortly, or run the tool with call_write_tool.";

// ---------------------------------------------------------------------------
// Answers
// ---------------------------------------------------------------------------

const TOO_LARGE_ANSWER =
  "The answer would be too large. Ask for fewer results (a lower limit or a narrower query), or fewer names.";

function byteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}

function answerWith(payload: unknown): CallToolResult {
  return { content: [{ type: "text", text: JSON.stringify(payload) }] };
}

/** Cut at a sentence end, else a word end, within the limit, then "...". */
function snippet(text: string): { text: string; truncated: boolean } {
  if (text.length <= DESCRIPTION_SNIPPET_MAX) return { text, truncated: false };
  const head = text.slice(0, DESCRIPTION_SNIPPET_MAX);
  const sentence = Math.max(
    head.lastIndexOf(". "),
    head.lastIndexOf("? "),
    head.lastIndexOf("! "),
    head.lastIndexOf("\n"),
  );
  // A sentence break only counts when it keeps a useful amount of text.
  const cut =
    sentence >= DESCRIPTION_SNIPPET_MAX / 3
      ? sentence + 1
      : head.lastIndexOf(" ") > 0
        ? head.lastIndexOf(" ")
        : DESCRIPTION_SNIPPET_MAX;
  return { text: `${head.slice(0, cut).trimEnd()}...`, truncated: true };
}

function serverSummary(
  tools: readonly Tool[],
): Array<{ prefix: string; tool_count: number }> {
  const counts = new Map<string, number>();
  for (const tool of tools) {
    const { prefix } = splitName(tool.name);
    counts.set(prefix, (counts.get(prefix) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([prefix, tool_count]) => ({ prefix, tool_count }));
}

function searchItem(tool: Tool, detail: SearchDetail): Record<string, unknown> {
  const base = {
    name: tool.name,
    server: splitName(tool.name).prefix,
    ...hintFlags(tool),
    runs_with: runsWith(tool),
  };
  if (detail === "names") return base;
  if (detail === "descriptions") {
    const short = snippet(tool.description ?? "");
    return {
      ...base,
      description: short.text,
      ...(short.truncated ? { description_truncated: true } : {}),
    };
  }
  return {
    ...base,
    ...(tool.title !== undefined ? { title: tool.title } : {}),
    description: tool.description ?? "",
    input_schema: tool.inputSchema,
    ...(tool.annotations !== undefined
      ? { annotations: tool.annotations }
      : {}),
  };
}

/**
 * `search_tools`: rank the listing and answer with one compact JSON text
 * block (no `structuredContent`, which would double the bytes and is optional
 * for a tool listed without an output schema).
 *
 * Every result carries `read_only`, `destructive` and `runs_with` at every
 * detail level, so a model sees the hints and which call tool applies without
 * a describe round trip. Schemas are included only for five results or fewer
 * and only while the answer stays under 64 KiB; past that the answer is
 * quietly the descriptions level with `schemas_omitted`. Past 200 KiB at any
 * level it is a constant refusal. Server names appear only as prefixes of
 * listed tools; an unreachable server is a count.
 */
export function runSearch(
  listing: LeanListing,
  args: SearchArgs,
): CallToolResult {
  const ranked = rankTools(listing.tools, args.query);
  const browse = args.query.trim() === "";
  const build = (detail: SearchDetail, schemasOmitted: boolean) => {
    const shown = ranked.slice(0, args.limit);
    const hint = schemasOmitted
      ? "Schemas are included only when 5 or fewer tools match and the answer is small; narrow the query or use describe_tool."
      : browse
        ? "Browse mode: all tools in name order. Add words to query to rank by relevance."
        : ranked.length === 0
          ? "No tool matched. Try other words, or leave query empty to browse all tools by name."
          : undefined;
    return {
      results: shown.map(({ tool }) => searchItem(tool, detail)),
      meta: {
        total_tools: listing.tools.length,
        servers: serverSummary(listing.tools),
        result_count: shown.length,
        matched_count: ranked.length,
        detail,
        limit: args.limit,
        ...(args.queryTruncated ? { query_truncated: true } : {}),
        ...(schemasOmitted ? { schemas_omitted: true } : {}),
        ...(listing.unavailable > 0
          ? { unavailable_server_count: listing.unavailable }
          : {}),
        ...(hint !== undefined ? { hint } : {}),
      },
    };
  };

  let payload = build(args.detail, false);
  if (args.detail === "schemas") {
    const tooMany = payload.meta.result_count > SCHEMAS_DETAIL_MAX_RESULTS;
    const text = JSON.stringify(payload);
    if (tooMany || byteLength(text) > DOWNGRADE_BYTES) {
      payload = build("descriptions", true);
    }
  }
  const text = JSON.stringify(payload);
  if (byteLength(text) > REFUSE_BYTES) return toolError(TOO_LARGE_ANSWER);
  return { content: [{ type: "text", text }] };
}

function describeItem(
  tool: Tool,
  includeOutputSchema: boolean,
): Record<string, unknown> {
  return {
    name: tool.name,
    ...(tool.title !== undefined ? { title: tool.title } : {}),
    description: tool.description ?? "",
    input_schema: tool.inputSchema,
    ...(tool.annotations !== undefined
      ? { annotations: tool.annotations }
      : {}),
    ...hintFlags(tool),
    runs_with: runsWith(tool),
    ...(includeOutputSchema && tool.outputSchema !== undefined
      ? { output_schema: tool.outputSchema }
      : {}),
  };
}

/**
 * `describe_tool`: the full definition of tools named exactly. A name the
 * post-policy listing does not hold (hidden, inactive, retired away, or never
 * there) is simply not found, and its suggestions are drawn from that same
 * listing, so nothing the policy hides can be learned from a suggestion.
 *
 * Output schemas are on request only: one tool's output schema can be nearly
 * the whole of its listing entry, so a default describe of a few tools would
 * be enormous. Past 64 KiB they are dropped with a flag; past 200 KiB (input
 * schemas alone) the answer is a constant refusal.
 */
export function runDescribe(
  listing: LeanListing,
  args: DescribeArgs,
): CallToolResult {
  const found: Tool[] = [];
  const notFound: Array<{ name: string; did_you_mean: string[] }> = [];
  for (const name of args.names) {
    const match = listing.tools.find((tool) => tool.name === name);
    if (match) {
      found.push(match);
    } else {
      notFound.push({
        name,
        did_you_mean: rankTools(listing.tools, name)
          .slice(0, 3)
          .map(({ tool }) => tool.name),
      });
    }
  }
  const build = (includeOutputSchema: boolean, omittedForSize: boolean) => ({
    tools: found.map((tool) => describeItem(tool, includeOutputSchema)),
    not_found: notFound,
    meta: {
      requested: args.names.length,
      found: found.length,
      output_schema_included:
        includeOutputSchema && found.some((t) => t.outputSchema !== undefined),
      ...(omittedForSize
        ? {
            output_schema_omitted_for_size: true,
            hint: "Output schemas were left out because the answer was large; describe fewer tools at a time to include them.",
          }
        : {}),
    },
  });
  let payload = build(args.includeOutputSchema, false);
  if (
    args.includeOutputSchema &&
    byteLength(JSON.stringify(payload)) > DOWNGRADE_BYTES
  ) {
    payload = build(false, true);
  }
  const text = JSON.stringify(payload);
  if (byteLength(text) > REFUSE_BYTES) {
    return toolError(TOO_LARGE_ANSWER);
  }
  return answerWith(payload);
}

// ---------------------------------------------------------------------------
// The catalog snapshot
// ---------------------------------------------------------------------------

/**
 * A single-flight, short-lived snapshot of the post-policy listing, so any
 * number of searches, describes and read-only checks in one session cost at
 * most one real listing per `ttlMs`, and none while the session is idle. It
 * bounds backend load without refusing anything.
 *
 * Staleness is at most `ttlMs`, the policy filter's own cache lifetime, and the
 * snapshot is never what authorizes a call (see the header). `invalidate()` is
 * called on every list-changed and mount event and whenever the namespace's
 * overrides change (`onOverrideCacheCleared`), so a search after an override
 * change shows it. A load that was running when it fired hands its result to
 * the callers that were already waiting but is not kept, and the next `get()`
 * starts fresh; those waiting callers hold a listing that may predate the
 * change. `captureValidity()` lets their calls reject revoked hints, even for
 * the same target, immediately before backend dispatch. The clock is injected so the tests need no real time.
 */
export class LeanCatalog {
  private snapshot: { value: LeanListing; at: number } | undefined;
  private inflight: Promise<LeanListing> | undefined;
  private epoch = 0;

  constructor(
    private readonly options: {
      load: () => Promise<LeanListing>;
      now: () => number;
      ttlMs: number;
    },
  ) {}

  /**
   * Capture before loading: invalidation revokes hints already handed to a
   * caller too. Identity alone cannot detect a same-target annotation change.
   * Expiry still controls reuse through get(); this guard tracks changes.
   *
   * The closure a load captured BEFORE it started is the only proof that
   * listing carries, and it is what a re-verification of a revoked verdict
   * returns (`createLeanPrelude`). Invalidation revokes conservatively, and
   * only a listing read after it can give a verdict again; one captured after
   * a load returned would vouch for hints that an invalidation overtook while
   * the load ran. An old load still returns its listing to its original
   * waiters, with its own closure already false.
   */
  captureValidity(): () => boolean {
    const epoch = this.epoch;
    return () => epoch === this.epoch;
  }

  get(): Promise<LeanListing> {
    const startedAt = this.options.now();
    if (this.snapshot && startedAt - this.snapshot.at < this.options.ttlMs) {
      return Promise.resolve(this.snapshot.value);
    }
    if (this.inflight) return this.inflight;
    const epoch = this.epoch;
    const load = Promise.resolve()
      .then(() => this.options.load())
      .then((value) => {
        // Measured from when the load STARTED: the data is no younger.
        if (epoch === this.epoch) this.snapshot = { value, at: startedAt };
        return value;
      });
    const settled = () => {
      // By identity, so a load started after an invalidate is not cleared.
      if (this.inflight === load) this.inflight = undefined;
    };
    load.then(settled, settled);
    this.inflight = load;
    return load;
  }

  invalidate(): void {
    this.epoch += 1;
    this.snapshot = undefined;
    this.inflight = undefined;
  }
}
