/**
 * The lean listing's pure half: tokenizing, ranking, argument rules, the
 * rewrite of a call meta tool into a real call, the read-only routing of
 * `call_tool`, the size guards and the catalog snapshot.
 *
 * ORACLES. Ranking: the expected scores were computed by an independent script
 * written from the BM25 formula (Robertson and Zaragoza 2009, with the
 * non-negative idf Lucene uses: ln(1 + (N - n + 0.5) / (n + 0.5))), the field
 * weights prefix 2, name 3, parameters 2, description 1, k1 = 1.2, b = 0.75,
 * and the tokenization rules of the lean-listing brief. The script shares no
 * code with the module and was run with `python -I`; its numbers are pasted
 * here as constants. Tokenizer: hand-written arrays from the brief's rules
 * (split on `_ - . space` and camelCase, stopwords out, one light stem).
 * Hints: MCP ToolAnnotations defaults (readOnlyHint false, destructiveHint
 * true, meaningful only while readOnlyHint is false; SDK 1.32.0 types.js
 * 1178-1210). Audit hash rule: `hashParams` is null for a call with no
 * arguments (auditing.functional.ts), which is why the rewrite deletes the
 * `arguments` key instead of writing `{}`.
 */
import type {
  CallToolRequest,
  CallToolResult,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";

import {
  CALL_TOOL,
  CALL_TOOL_ROUTING_ANSWER,
  CALL_WRITE_TOOL,
  classifyCallTarget,
  DESCRIBE_TOOL,
  hintFlags,
  isLeanMetaToolName,
  LEAN_CATALOG_TTL_MS,
  LEAN_META_TOOL_NAMES,
  LeanCatalog,
  type LeanListing,
  leanMetaTools,
  rankTools,
  routeLeanCall,
  runDescribe,
  runSearch,
  runsWith,
  SEARCH_TOOL,
  tokenize,
  tokenizeQuery,
} from "./lean-listing";
import { parseToolName } from "./tool-name-parser";

function mk(
  name: string,
  description: string,
  properties: Record<string, unknown> = {},
  extra: Partial<Tool> = {},
): Tool {
  return {
    name,
    description,
    inputSchema: { type: "object", properties },
    ...extra,
  } as Tool;
}

const request = (
  name: string,
  args?: unknown,
  extraParams: Record<string, unknown> = {},
): CallToolRequest =>
  ({
    method: "tools/call",
    params: {
      name,
      ...(args !== undefined ? { arguments: args } : {}),
      ...extraParams,
    },
  }) as CallToolRequest;

const textOf = (result: CallToolResult): string =>
  (result.content[0] as { type: "text"; text: string }).text;
const payloadOf = (result: CallToolResult) =>
  JSON.parse(textOf(result)) as Record<string, any>;

function search(listing: LeanListing, args?: unknown): CallToolResult {
  const route = routeLeanCall(request(SEARCH_TOOL, args));
  expect(route.kind).toBe("search");
  if (route.kind !== "search") throw new Error("not a search route");
  return runSearch(listing, route.args);
}

function describeTools(listing: LeanListing, args?: unknown): CallToolResult {
  const route = routeLeanCall(request(DESCRIBE_TOOL, args));
  expect(route.kind).toBe("describe");
  if (route.kind !== "describe") throw new Error("not a describe route");
  return runDescribe(listing, route.args);
}

const listingOf = (tools: Tool[], unavailable = 0): LeanListing => ({
  tools,
  unavailable,
});

// ---------------------------------------------------------------------------
// Corpora (the same ones the oracle script scored)
// ---------------------------------------------------------------------------

const DESK: Tool[] = [
  mk("desk__ticket_manage", "Create and update support tickets", {
    mode: { type: "string", enum: ["create", "update", "close"] },
    ticket_id: { type: "string" },
  }),
  mk("desk__user_manage", "Reset passwords and manage users", {
    mode: { type: "string", enum: ["reset_password", "disable"] },
    user_id: { type: "string" },
  }),
  mk("desk__report_run", "Run a saved report", {
    report_id: { type: "string" },
  }),
];

const PREFIXED: Tool[] = [
  mk("alpha__tenant_list", "List all tenants", { limit: { type: "number" } }),
  mk("alpha__widget_get", "Fetch one widget", {
    widget_id: { type: "string" },
  }),
  mk("bravo__report_run", "Run the tenant report", {
    report_id: { type: "string" },
  }),
  mk("bravo__tenant_sync", "Sync a tenant with the portal", {
    mode: { type: "string", enum: ["full", "delta"] },
  }),
];

const FIELDS: Tool[] = [
  mk("desk__mailbox_audit", "Review how mail forwarding is configured", {
    scope: {
      anyOf: [
        { type: "string", enum: ["forwarding_rules", "delegates"] },
        { const: "shared_mailboxes" },
      ],
    },
    userPrincipalName: { type: "string" },
  }),
  mk(
    "desk__getUserMFAStatus",
    "Read the multi factor sign in state for one user",
    { tenantId: { type: "string" } },
  ),
  mk("desk__device_wipe", "Erase a managed device", {
    deviceId: { type: "string" },
  }),
];

const bulk = (count: number, prefix = "bulk"): Tool[] =>
  Array.from({ length: count }, (_, i) =>
    mk(`${prefix}__item_${String(i).padStart(2, "0")}`, `Item number ${i}`),
  );

// ---------------------------------------------------------------------------

describe("tokenizing", () => {
  it.each<[string, string[]]>([
    ["getUserMFAStatus", ["get", "user", "mfa", "status"]],
    ["a.b-c d_e", ["b", "c", "d", "e"]],
    ["Tickets", ["ticket"]],
    ["status", ["status"]],
    ["address", ["address"]],
    ["analysis", ["analysis"]],
    ["ÉcoleÉlève", ["école", "élève"]],
    ["Café Menü", ["café", "menü"]],
    ["uuid2Email", ["uuid2", "email"]],
    ["ipv6Address", ["ipv6", "address"]],
    ["The ids of Users", ["ids", "user"]],
    ["is this it", []],
    ["", []],
    ["!!! --- ???", []],
  ])("splits %j into %j", (text, expected) => {
    expect(tokenize(text)).toEqual(expected);
  });

  it("drops a token longer than 64 characters and keeps one of exactly 64", () => {
    expect(tokenize(`${"x".repeat(65)} ok`)).toEqual(["ok"]);
    expect(tokenize(`${"x".repeat(64)} ok`)).toEqual(["x".repeat(64), "ok"]);
  });

  it("builds a query of unique stemmed tokens, at most 16", () => {
    expect(tokenizeQuery("ticket tickets Ticket")).toEqual(["ticket"]);
    const many = Array.from({ length: 20 }, (_, i) => `word${i}`).join(" ");
    expect(tokenizeQuery(many)).toHaveLength(16);
    expect(tokenizeQuery(many)[15]).toBe("word15");
  });

  it("falls back to the unfiltered tokens when a query is only stopwords", () => {
    expect(tokenizeQuery("is this it")).toEqual(["is", "this", "it"]);
    expect(tokenizeQuery("the user")).toEqual(["user"]);
  });
});

describe("ranking", () => {
  const SCORES: Array<[Tool[], string, Array<[string, number]>]> = [
    // desk corpus: N = 3, average document length 21 (24, 24, 15)
    [DESK, "reset password", [["desk__user_manage", 2.9910436626496213]]],
    [DESK, "ticket", [["desk__ticket_manage", 1.7666398241380803]]],
    [
      DESK,
      "manage users",
      [
        ["desk__user_manage", 2.5428388472355956],
        ["desk__ticket_manage", 0.7166391970677554],
      ],
    ],
    [DESK, "tickets close", [["desk__ticket_manage", 3.063186647861736]]],
    [
      DESK,
      "desk",
      [
        ["desk__report_run", 0.1996488782929755],
        ["desk__ticket_manage", 0.17651360055087106],
        ["desk__user_manage", 0.17651360055087106],
      ],
    ],
    [DESK, "reset_password", [["desk__user_manage", 2.9910436626496213]]],
    [DESK, "report", [["desk__report_run", 1.8647864810346402]]],
    [
      DESK,
      "DESK__USER_MANAGE",
      [
        ["desk__user_manage", 1002.7193524477865],
        ["desk__ticket_manage", 0.8931527976186264],
        ["desk__report_run", 0.1996488782929755],
      ],
    ],
    [DESK, "the", []],
    [
      PREFIXED,
      "alpha tenant",
      [
        ["alpha__tenant_list", 1.6080723655531814],
        ["alpha__widget_get", 0.9530773732699247],
        ["bravo__tenant_sync", 0.5899886290715874],
        ["bravo__report_run", 0.3566749439387324],
      ],
    ],
    [
      PREFIXED,
      "tenant",
      [
        ["alpha__tenant_list", 0.6178621076104026],
        ["bravo__tenant_sync", 0.5899886290715874],
        ["bravo__report_run", 0.3566749439387324],
      ],
    ],
    [
      PREFIXED,
      "bravo tenant",
      [
        ["bravo__tenant_sync", 1.5086174225847677],
        ["bravo__report_run", 1.3097523172086571],
        ["alpha__tenant_list", 0.6178621076104026],
      ],
    ],
    [FIELDS, "forwarding", [["desk__mailbox_audit", 1.4523817784981332]]],
    [FIELDS, "delegates", [["desk__mailbox_audit", 1.2483281401967425]]],
    [FIELDS, "shared mailboxes", [["desk__mailbox_audit", 2.496656280393485]]],
    [FIELDS, "mfa status", [["desk__getUserMFAStatus", 3.0361347731418262]]],
    [FIELDS, "principal", [["desk__mailbox_audit", 1.2483281401967425]]],
    [
      FIELDS,
      "tenant id",
      [
        ["desk__getUserMFAStatus", 1.9556084364783297],
        ["desk__device_wipe", 0.718417458102663],
      ],
    ],
    [FIELDS, "wipe device", [["desk__device_wipe", 3.5512498060370525]]],
    [
      FIELDS,
      "user",
      [
        ["desk__getUserMFAStatus", 0.7856777085898865],
        ["desk__mailbox_audit", 0.5981864372218454],
      ],
    ],
  ];

  it.each(SCORES)("scores %#: %j", (tools, query, expected) => {
    const ranked = rankTools(tools, query);
    expect(ranked.map((r) => r.tool.name)).toEqual(expected.map(([n]) => n));
    ranked.forEach((r, i) => {
      expect(r.score).toBeCloseTo(expected[i]?.[1] ?? Number.NaN, 9);
    });
  });

  it("finds a tool whose words sit in the description and the enum, in either word order", () => {
    // The mcp-use search matches one case-insensitive substring of the whole
    // query, so "password reset" finds nothing there. Here it finds the tool.
    for (const query of ["reset password", "password reset"]) {
      expect(rankTools(DESK, query).map((r) => r.tool.name)).toEqual([
        "desk__user_manage",
      ]);
    }
  });

  it("ranks a tool whose full name is the whole query first, ahead of any other match", () => {
    expect(rankTools(DESK, "desk__report_run")[0]?.tool.name).toBe(
      "desk__report_run",
    );
    expect(rankTools(DESK, "DESK__USER_MANAGE")[0]?.score).toBeGreaterThan(
      1000,
    );
  });

  it("boosts the server prefix, so an alpha query ranks alpha tools above bravo tools that mention the word", () => {
    const names = rankTools(PREFIXED, "alpha tenant").map((r) => r.tool.name);
    expect(names.indexOf("alpha__widget_get")).toBeLessThan(
      names.indexOf("bravo__tenant_sync"),
    );
    expect(names.indexOf("alpha__widget_get")).toBeLessThan(
      names.indexOf("bravo__report_run"),
    );
  });

  it("searches parameter names, enum values, anyOf branches and const values", () => {
    expect(rankTools(FIELDS, "delegates")[0]?.tool.name).toBe(
      "desk__mailbox_audit",
    );
    expect(rankTools(FIELDS, "shared mailboxes")[0]?.tool.name).toBe(
      "desk__mailbox_audit",
    );
    expect(rankTools(FIELDS, "principal")[0]?.tool.name).toBe(
      "desk__mailbox_audit",
    );
  });

  it("indexes at most 64 values per property and ignores a value over 48 characters", () => {
    const members = [
      ...Array.from({ length: 64 }, (_, i) => `choice${i}`),
      "beyond64",
    ];
    const tools = [
      mk("a__pick", "Pick one", { kind: { enum: members } }),
      mk("a__long", "Pick another", {
        kind: { enum: [`${"y".repeat(49)}`, "shortone"] },
      }),
    ];
    expect(rankTools(tools, "choice63")[0]?.tool.name).toBe("a__pick");
    expect(rankTools(tools, "beyond64")).toEqual([]);
    expect(rankTools(tools, "y".repeat(49))).toEqual([]);
    expect(rankTools(tools, "shortone")[0]?.tool.name).toBe("a__long");
  });

  it("indexes the first 2000 characters of a description and the first 400 tokens", () => {
    const wordy = `${"filler ".repeat(300)}lateword`;
    const tools = [mk("a__one", wordy), mk("a__two", "lateword is here")];
    // "lateword" is past 2000 characters in the first description.
    expect(rankTools(tools, "lateword").map((r) => r.tool.name)).toEqual([
      "a__two",
    ]);
    const manyTokens = `${Array.from({ length: 400 }, (_, i) => `t${i}`).join(" ")} tailtoken`;
    expect(rankTools([mk("a__three", manyTokens)], "tailtoken")).toEqual([]);
    expect(
      rankTools([mk("a__three", manyTokens)], "t399").map((r) => r.tool.name),
    ).toEqual(["a__three"]);
  });

  it("returns every tool by name in browse mode, and nothing for a query with no words", () => {
    const names = rankTools(DESK, "").map((r) => r.tool.name);
    expect(names).toEqual([
      "desk__report_run",
      "desk__ticket_manage",
      "desk__user_manage",
    ]);
    expect(rankTools(DESK, "   ").map((r) => r.tool.name)).toEqual(names);
    expect(rankTools(DESK, "!!!")).toEqual([]);
  });

  it("breaks ties by name ascending, whatever order the listing came in", () => {
    const tools = [
      mk("bb__run", "Run it"),
      mk("aa__run", "Run it"),
      mk("cc__run", "Run it"),
    ];
    const first = rankTools(tools, "run").map((r) => r.tool.name);
    const second = rankTools([...tools].reverse(), "run").map(
      (r) => r.tool.name,
    );
    expect(first).toEqual(["aa__run", "bb__run", "cc__run"]);
    expect(second).toEqual(first);
  });

  it("answers an empty listing without error", () => {
    expect(rankTools([], "anything")).toEqual([]);
    expect(rankTools([], "")).toEqual([]);
  });
});

describe("search_tools arguments", () => {
  const big = listingOf(bulk(40));

  it("defaults to 10 results at the descriptions level", () => {
    const meta = payloadOf(search(big, { query: "item" })).meta;
    expect(meta.limit).toBe(10);
    expect(meta.detail).toBe("descriptions");
    expect(meta.result_count).toBe(10);
    expect(meta.matched_count).toBe(40);
  });

  it.each<[unknown, number]>([
    [25, 25],
    [26, 25],
    [1000, 25],
    [0, 1],
    [-3, 1],
    [7.9, 7],
    ["5", 5],
    ["7.9", 7],
    [null, 10],
  ])("applies limit %j as %j and reports it", (limit, applied) => {
    const answer = payloadOf(search(big, { query: "item", limit }));
    expect(answer.meta.limit).toBe(applied);
    expect(answer.results).toHaveLength(applied);
  });

  it.each<unknown>(["abc", "", "  ", Number.NaN, Infinity, true, {}, [5]])(
    "refuses limit %j",
    (limit) => {
      const route = routeLeanCall(request(SEARCH_TOOL, { limit }));
      expect(route.kind).toBe("answer");
      if (route.kind === "answer") {
        expect(route.result.isError).toBe(true);
        expect(textOf(route.result)).toMatch(/search_tools: invalid arguments/);
      }
    },
  );

  it("keeps a 200-character query and cuts a longer one, saying so", () => {
    const kept = payloadOf(search(big, { query: "a".repeat(200) })).meta;
    expect(kept.query_truncated).toBeUndefined();
    const cut = payloadOf(search(big, { query: "a".repeat(201) })).meta;
    expect(cut.query_truncated).toBe(true);
  });

  it("does not leave half a surrogate pair at the cut", () => {
    const query = `${"a".repeat(199)}\u{1F600}`;
    const route = routeLeanCall(request(SEARCH_TOOL, { query }));
    expect(route.kind).toBe("search");
    if (route.kind === "search") {
      expect(route.args.query).toBe("a".repeat(199));
      expect(route.args.queryTruncated).toBe(true);
    }
  });

  it("refuses a non-string query, an unknown detail and non-object arguments, with text that echoes nothing", () => {
    const secret = "do-not-echo-this";
    for (const args of [
      { query: 5 },
      { query: { secret } },
      { detail: secret },
      { detail: 3 },
      secret,
      [secret],
      7,
    ]) {
      const route = routeLeanCall(request(SEARCH_TOOL, args));
      expect(route.kind).toBe("answer");
      if (route.kind === "answer") {
        expect(route.result.isError).toBe(true);
        expect(textOf(route.result)).not.toContain(secret);
      }
    }
  });

  it("treats absent and null arguments as an empty query (browse mode) and ignores unknown keys", () => {
    for (const args of [undefined, null, {}, { unknown: 1 }]) {
      const answer = payloadOf(search(listingOf(DESK), args));
      expect(answer.meta.matched_count).toBe(3);
      expect(answer.meta.hint).toMatch(/Browse mode/);
    }
  });
});

describe("search_tools answers", () => {
  const listing = listingOf(DESK);

  it("says so when nothing matches, and lists the servers", () => {
    const answer = payloadOf(search(listing, { query: "zebra" }));
    expect(answer.results).toEqual([]);
    expect(answer.meta.matched_count).toBe(0);
    expect(answer.meta.hint).toMatch(/No tool matched/);
    expect(answer.meta.servers).toEqual([{ prefix: "desk", tool_count: 3 }]);
  });

  it("reports the post-policy count, the servers sorted by prefix, and the counts before and after the limit", () => {
    const answer = payloadOf(
      search(listingOf([...PREFIXED, ...DESK]), { query: "tenant", limit: 1 }),
    );
    expect(answer.meta.total_tools).toBe(7);
    expect(answer.meta.servers).toEqual([
      { prefix: "alpha", tool_count: 2 },
      { prefix: "bravo", tool_count: 2 },
      { prefix: "desk", tool_count: 3 },
    ]);
    expect(answer.meta.result_count).toBe(1);
    expect(answer.meta.matched_count).toBe(3);
  });

  it("reports unreachable servers as a count only, and only when there are some", () => {
    const some = payloadOf(
      search(listingOf(DESK, 2), { query: "ticket" }),
    ).meta;
    expect(some.unavailable_server_count).toBe(2);
    expect(JSON.stringify(some)).not.toMatch(/unreachable|down|failed/);
    const none = payloadOf(search(listingOf(DESK, 0), { query: "ticket" }));
    expect("unavailable_server_count" in none.meta).toBe(false);
  });

  it("carries the hint flags and the call tool that runs it at every detail level", () => {
    const tools = [
      mk("s__reader", "Reads", {}, { annotations: { readOnlyHint: true } }),
      mk(
        "s__writer",
        "Writes",
        {},
        { annotations: { readOnlyHint: false, destructiveHint: false } },
      ),
      mk("s__deleter", "Deletes", {}, { annotations: { readOnlyHint: false } }),
      mk("s__bare", "No annotations"),
      mk(
        "s__stringly",
        "String hint",
        {},
        { annotations: { readOnlyHint: "true" as unknown as boolean } },
      ),
    ];
    for (const detail of ["names", "descriptions", "schemas"]) {
      const answer = payloadOf(search(listingOf(tools), { detail, limit: 5 }));
      const by = Object.fromEntries(
        answer.results.map((r: Record<string, unknown>) => [r.name, r]),
      );
      expect(by["s__reader"]).toMatchObject({
        read_only: true,
        destructive: false,
        runs_with: CALL_TOOL,
      });
      expect(by["s__writer"]).toMatchObject({
        read_only: false,
        destructive: false,
        runs_with: CALL_WRITE_TOOL,
      });
      expect(by["s__deleter"]).toMatchObject({
        read_only: false,
        destructive: true,
        runs_with: CALL_WRITE_TOOL,
      });
      // No annotations reads as the MCP defaults: not read-only, destructive.
      expect(by["s__bare"]).toMatchObject({
        read_only: false,
        destructive: true,
        runs_with: CALL_WRITE_TOOL,
      });
      // Only the boolean true is a read-only claim.
      expect(by["s__stringly"]).toMatchObject({
        read_only: false,
        runs_with: CALL_WRITE_TOOL,
      });
    }
  });

  it("returns names only, then short descriptions, then schemas, by detail level", () => {
    const names = payloadOf(
      search(listing, { query: "ticket", detail: "names" }),
    );
    expect(Object.keys(names.results[0]).sort()).toEqual([
      "destructive",
      "name",
      "read_only",
      "runs_with",
      "server",
    ]);
    const descriptions = payloadOf(search(listing, { query: "ticket" }));
    expect(descriptions.results[0].description).toBe(
      "Create and update support tickets",
    );
    expect(descriptions.results[0].input_schema).toBeUndefined();
    const schemas = payloadOf(
      search(listing, { query: "ticket", detail: "schemas" }),
    );
    expect(schemas.results[0].input_schema).toEqual(DESK[0]?.inputSchema);
    expect(schemas.meta.schemas_omitted).toBeUndefined();
  });

  it("cuts a long description at a sentence, else a word, within 300 characters, and says so", () => {
    const sentenceCut = `${"Alpha beta gamma delta. ".repeat(10)}${"tail ".repeat(60)}`;
    const wordCut = "word ".repeat(120);
    const noSpace = "z".repeat(400);
    const answer = payloadOf(
      search(
        listingOf([
          mk("s__a", sentenceCut),
          mk("s__b", wordCut),
          mk("s__c", noSpace),
          mk("s__d", "x".repeat(300)),
        ]),
        { limit: 4 },
      ),
    );
    const by = Object.fromEntries(
      answer.results.map((r: Record<string, any>) => [r.name, r]),
    );
    expect(by["s__a"].description).toMatch(/delta\.\.\.\.$/);
    expect(by["s__a"].description.length).toBeLessThanOrEqual(304);
    expect(by["s__a"].description_truncated).toBe(true);
    expect(by["s__b"].description).toMatch(/word\.\.\.$/);
    expect(by["s__b"].description.length).toBeLessThanOrEqual(303);
    expect(by["s__c"].description).toBe(`${"z".repeat(300)}...`);
    // Exactly 300 characters is kept whole.
    expect(by["s__d"].description).toBe("x".repeat(300));
    expect(by["s__d"].description_truncated).toBeUndefined();
  });

  it("gives schemas only for 5 or fewer matches, otherwise the descriptions level with schemas_omitted", () => {
    const six = listingOf(bulk(6));
    const five = payloadOf(
      search(listingOf(bulk(5)), { query: "item", detail: "schemas" }),
    );
    expect(five.results).toHaveLength(5);
    expect(five.results[0].input_schema).toBeDefined();
    expect(five.meta.detail).toBe("schemas");
    const over = payloadOf(search(six, { query: "item", detail: "schemas" }));
    expect(over.results).toHaveLength(6);
    expect(over.results[0].input_schema).toBeUndefined();
    expect(over.meta.detail).toBe("descriptions");
    expect(over.meta.schemas_omitted).toBe(true);
    expect(over.meta.hint).toMatch(/5 or fewer/);
    // With a limit of 5 over many matches, 5 results are shown with schemas.
    const limited = payloadOf(
      search(listingOf(bulk(9)), {
        query: "item",
        detail: "schemas",
        limit: 5,
      }),
    );
    expect(limited.meta.detail).toBe("schemas");
    expect(limited.results).toHaveLength(5);
  });

  it("downgrades schemas to descriptions when the answer passes 64 KiB, and refuses past 200 KiB", () => {
    const heavy = (name: string, kib: number) =>
      mk(name, "Heavy", {
        blob: { type: "string", description: "q".repeat(kib * 1024) },
      });
    const downgraded = payloadOf(
      search(
        listingOf([heavy("s__a", 30), heavy("s__b", 30), heavy("s__c", 30)]),
        { query: "heavy", detail: "schemas" },
      ),
    );
    expect(downgraded.meta.detail).toBe("descriptions");
    expect(downgraded.meta.schemas_omitted).toBe(true);
    expect(downgraded.results[0].input_schema).toBeUndefined();
    // Past 200 KiB at any level the answer is a constant refusal: 25 results
    // whose names alone are about 9000 characters each.
    const longNames = Array.from({ length: 25 }, (_, i) =>
      mk(`s__${String(i).padStart(2, "0")}${"n".repeat(9000)}`, "Long"),
    );
    const refused = search(listingOf(longNames), { limit: 25 });
    expect(refused.isError).toBe(true);
    expect(textOf(refused)).toMatch(/too large/);
  });
});

describe("describe_tool", () => {
  const withOutput = mk(
    "desk__ticket_manage",
    "Create and update support tickets",
    { mode: { type: "string" } },
    {
      title: "Tickets",
      annotations: { readOnlyHint: false, destructiveHint: true },
      outputSchema: { type: "object", properties: { id: { type: "string" } } },
    },
  );
  const listing = listingOf([withOutput, ...DESK.slice(1)]);

  it("returns the definition, the annotations as listed, and the call tool that runs it", () => {
    const answer = payloadOf(
      describeTools(listing, { names: ["desk__ticket_manage"] }),
    );
    expect(answer.tools).toHaveLength(1);
    expect(answer.tools[0]).toMatchObject({
      name: "desk__ticket_manage",
      title: "Tickets",
      description: "Create and update support tickets",
      annotations: { readOnlyHint: false, destructiveHint: true },
      read_only: false,
      destructive: true,
      runs_with: CALL_WRITE_TOOL,
    });
    expect(answer.tools[0].input_schema).toEqual(withOutput.inputSchema);
    expect(answer.meta).toMatchObject({ requested: 1, found: 1 });
  });

  it("returns the output schema only when asked", () => {
    const without = payloadOf(
      describeTools(listing, { names: ["desk__ticket_manage"] }),
    );
    expect(without.tools[0].output_schema).toBeUndefined();
    expect(without.meta.output_schema_included).toBe(false);
    const withIt = payloadOf(
      describeTools(listing, {
        names: ["desk__ticket_manage"],
        include_output_schema: true,
      }),
    );
    expect(withIt.tools[0].output_schema).toEqual(withOutput.outputSchema);
    expect(withIt.meta.output_schema_included).toBe(true);
  });

  it("reports read-only tools as run by call_tool", () => {
    const answer = payloadOf(
      describeTools(
        listingOf([
          mk("s__reader", "Reads", {}, { annotations: { readOnlyHint: true } }),
        ]),
        { names: ["s__reader"] },
      ),
    );
    expect(answer.tools[0]).toMatchObject({
      read_only: true,
      destructive: false,
      runs_with: CALL_TOOL,
    });
  });

  it("answers not found with up to three suggestions drawn from the listing only", () => {
    const answer = payloadOf(
      describeTools(listing, { names: ["desk__ticket_managr", "nowhere__x"] }),
    );
    expect(answer.tools).toEqual([]);
    expect(answer.not_found).toHaveLength(2);
    expect(answer.not_found[0].name).toBe("desk__ticket_managr");
    expect(answer.not_found[0].did_you_mean.length).toBeLessThanOrEqual(3);
    const listed = new Set(listing.tools.map((t) => t.name));
    for (const entry of answer.not_found) {
      for (const suggestion of entry.did_you_mean) {
        expect(listed.has(suggestion)).toBe(true);
      }
    }
    expect(answer.not_found[1].did_you_mean).toEqual([]);
    expect(answer.meta).toMatchObject({ requested: 2, found: 0 });
  });

  it("never suggests a name the listing does not hold", () => {
    // A tool the policy hides is not in the listing, so asking for it names
    // only visible tools and nothing about the hidden one.
    const visible = listingOf([mk("desk__ticket_manage", "Visible tickets")]);
    const answer = payloadOf(
      describeTools(visible, { names: ["desk__ticket_admin"] }),
    );
    expect(answer.not_found[0].did_you_mean).toEqual(["desk__ticket_manage"]);
    expect(JSON.stringify(answer.not_found[0].did_you_mean)).not.toContain(
      "admin",
    );
  });

  it("removes duplicate names and counts each once", () => {
    const answer = payloadOf(
      describeTools(listing, {
        names: ["desk__report_run", "desk__report_run", "desk__user_manage"],
      }),
    );
    expect(answer.tools.map((t: { name: string }) => t.name)).toEqual([
      "desk__report_run",
      "desk__user_manage",
    ]);
    expect(answer.meta.requested).toBe(2);
  });

  it("takes 10 names and refuses 11, 256-character names and refuses 257, and refuses malformed input", () => {
    const ten = Array.from({ length: 10 }, (_, i) => `x__${i}`);
    expect(routeLeanCall(request(DESCRIBE_TOOL, { names: ten })).kind).toBe(
      "describe",
    );
    expect(
      routeLeanCall(request(DESCRIBE_TOOL, { names: [...ten, "x__10"] })).kind,
    ).toBe("answer");
    expect(
      routeLeanCall(request(DESCRIBE_TOOL, { names: ["n".repeat(256)] })).kind,
    ).toBe("describe");
    expect(
      routeLeanCall(request(DESCRIBE_TOOL, { names: ["n".repeat(257)] })).kind,
    ).toBe("answer");
    for (const args of [
      undefined,
      {},
      { names: [] },
      { names: "desk__x" },
      { names: [""] },
      { names: [5] },
      { names: ["a__b"], include_output_schema: "yes" },
      "desk__x",
    ]) {
      const route = routeLeanCall(request(DESCRIBE_TOOL, args));
      expect(route.kind).toBe("answer");
      if (route.kind === "answer") {
        expect(route.result.isError).toBe(true);
        expect(textOf(route.result)).toMatch(
          /describe_tool: invalid arguments/,
        );
      }
    }
  });

  it("drops output schemas past 64 KiB with a flag, and refuses past 200 KiB", () => {
    const heavyOutput = mk(
      "s__big",
      "Big output",
      {},
      {
        outputSchema: {
          type: "object",
          properties: { blob: { description: "o".repeat(70 * 1024) } },
        },
      },
    );
    const dropped = payloadOf(
      describeTools(listingOf([heavyOutput]), {
        names: ["s__big"],
        include_output_schema: true,
      }),
    );
    expect(dropped.tools[0].output_schema).toBeUndefined();
    expect(dropped.meta.output_schema_omitted_for_size).toBe(true);
    expect(dropped.meta.output_schema_included).toBe(false);
    expect(dropped.meta.hint).toMatch(/fewer tools/);
    const hugeInput = mk("s__huge", "Huge input", {
      blob: { description: "i".repeat(210 * 1024) },
    });
    const refused = describeTools(listingOf([hugeInput]), {
      names: ["s__huge"],
    });
    expect(refused.isError).toBe(true);
    expect(textOf(refused)).toMatch(/too large/);
  });
});

describe("call meta tools", () => {
  const FORWARDED = { ticket_id: "T-1", mode: "close" };

  it.each([CALL_TOOL, CALL_WRITE_TOOL])(
    "%s becomes a call for the real name with the arguments as given",
    (via) => {
      const route = routeLeanCall(
        request(via, { name: "desk__ticket_manage", arguments: FORWARDED }),
      );
      expect(route.kind).toBe("call");
      if (route.kind !== "call") return;
      expect(route.via).toBe(via);
      expect(route.name).toBe("desk__ticket_manage");
      expect(route.request.params.name).toBe("desk__ticket_manage");
      expect(route.request.params.arguments).toEqual(FORWARDED);
      expect(route.request.params.arguments).toBe(FORWARDED);
    },
  );

  it.each([CALL_TOOL, CALL_WRITE_TOOL])(
    "%s keeps _meta and every other param, and the request around them",
    (via) => {
      const incoming = {
        ...request(
          via,
          { name: "desk__report_run", arguments: { report_id: "r" } },
          { _meta: { progressToken: "tok-1" }, task: { ttl: 5 } },
        ),
        id: 17,
        jsonrpc: "2.0",
      } as CallToolRequest;
      const route = routeLeanCall(incoming);
      expect(route.kind).toBe("call");
      if (route.kind !== "call") return;
      expect(route.request).toMatchObject({
        id: 17,
        jsonrpc: "2.0",
        method: "tools/call",
        params: {
          name: "desk__report_run",
          arguments: { report_id: "r" },
          _meta: { progressToken: "tok-1" },
          task: { ttl: 5 },
        },
      });
    },
  );

  it.each([CALL_TOOL, CALL_WRITE_TOOL])(
    "%s deletes the arguments key when none were given, so the audit hash is the direct call's null",
    (via) => {
      for (const inner of [
        { name: "desk__report_run" },
        { name: "desk__report_run", arguments: null },
        { name: "desk__report_run", arguments: undefined },
      ]) {
        const route = routeLeanCall(request(via, inner));
        expect(route.kind).toBe("call");
        if (route.kind !== "call") continue;
        expect("arguments" in route.request.params).toBe(false);
      }
    },
  );

  it.each([CALL_TOOL, CALL_WRITE_TOOL])(
    "%s keeps an empty arguments object as {} and ignores the outer arguments' other keys",
    (via) => {
      const route = routeLeanCall(
        request(via, {
          name: "desk__report_run",
          arguments: {},
          unrelated: true,
        }),
      );
      expect(route.kind).toBe("call");
      if (route.kind !== "call") return;
      expect(route.request.params.arguments).toEqual({});
      expect("unrelated" in route.request.params).toBe(false);
    },
  );

  it.each([CALL_TOOL, CALL_WRITE_TOOL])(
    "%s takes a 256-character name and refuses 257, a missing name, a non-string name and non-object arguments",
    (via) => {
      expect(
        routeLeanCall(request(via, { name: `s__${"n".repeat(253)}` })).kind,
      ).toBe("call");
      const refused: unknown[] = [
        { name: `s__${"n".repeat(254)}` },
        {},
        { name: "" },
        { name: 5 },
        { name: ["a__b"] },
        { name: "a__b", arguments: [] },
        { name: "a__b", arguments: "{}" },
        { name: "a__b", arguments: 7 },
        undefined,
        null,
        "a__b",
      ];
      for (const args of refused) {
        const route = routeLeanCall(request(via, args));
        expect(route.kind).toBe("answer");
        if (route.kind === "answer") {
          expect(route.result.isError).toBe(true);
          expect(textOf(route.result)).toContain(`${via}: invalid arguments`);
        }
      }
    },
  );

  it.each([CALL_TOOL, CALL_WRITE_TOOL])(
    "%s refuses to run any of the four meta tools, which keeps nested meta calls impossible",
    (via) => {
      for (const meta of LEAN_META_TOOL_NAMES) {
        const route = routeLeanCall(
          request(via, { name: meta, arguments: { name: "desk__report_run" } }),
        );
        expect(route.kind).toBe("answer");
        if (route.kind === "answer") {
          expect(route.result.isError).toBe(true);
          expect(textOf(route.result)).toMatch(/cannot run/);
        }
      }
    },
  );

  it("passes a direct real-name call, and a name with no separator, through unchanged", () => {
    expect(routeLeanCall(request("desk__ticket_manage", {})).kind).toBe(
      "passthrough",
    );
    // A name with no separator is not a meta tool, so the chain answers it as
    // it answers a direct call: not special-cased here.
    expect(routeLeanCall(request("nonsense", {})).kind).toBe("passthrough");
    expect(routeLeanCall(request("Search_Tools", {})).kind).toBe("passthrough");
    const route = routeLeanCall(
      request(CALL_TOOL, { name: "nonsense", arguments: {} }),
    );
    expect(route.kind).toBe("call");
    if (route.kind === "call")
      expect(route.request.params.name).toBe("nonsense");
  });
});

describe("which call tool runs a tool", () => {
  const readOnly = mk(
    "s__read",
    "r",
    {},
    { annotations: { readOnlyHint: true } },
  );
  const write = mk(
    "s__write",
    "w",
    {},
    { annotations: { readOnlyHint: false } },
  );
  const bare = mk("s__bare", "b");

  it("lets call_tool run a listed tool whose readOnlyHint is true, and nothing else", () => {
    const listing = listingOf([readOnly, write, bare]);
    expect(classifyCallTarget(listing, "s__read")).toEqual({ readOnly: true });
    expect(classifyCallTarget(listing, "s__write")).toEqual({
      readOnly: false,
    });
    expect(classifyCallTarget(listing, "s__bare")).toEqual({ readOnly: false });
  });

  it("does not take a name the listing does not hold, or a hint that is not the boolean true", () => {
    const listing = listingOf([
      mk("s__x", "x", {}, { annotations: { readOnlyHint: "true" as never } }),
      mk("s__y", "y", {}, { annotations: { readOnlyHint: 1 as never } }),
    ]);
    expect(classifyCallTarget(listing, "s__missing")).toEqual({
      readOnly: false,
    });
    expect(classifyCallTarget(listing, "s__x")).toEqual({ readOnly: false });
    expect(classifyCallTarget(listing, "s__y")).toEqual({ readOnly: false });
    expect(classifyCallTarget(listingOf([]), "s__read")).toEqual({
      readOnly: false,
    });
  });

  it("treats a name two entries share as read-only only when every entry is", () => {
    const both = listingOf([readOnly, { ...readOnly }]);
    expect(classifyCallTarget(both, "s__read")).toEqual({ readOnly: true });
    const mixed = listingOf([readOnly, { ...readOnly, annotations: {} }]);
    expect(classifyCallTarget(mixed, "s__read")).toEqual({ readOnly: false });
  });

  it("derives hints and the call tool from the annotations alone", () => {
    expect(hintFlags(readOnly)).toEqual({
      read_only: true,
      destructive: false,
    });
    expect(hintFlags(write)).toEqual({ read_only: false, destructive: true });
    expect(
      hintFlags(
        mk("s__w", "w", {}, { annotations: { destructiveHint: false } }),
      ),
    ).toEqual({ read_only: false, destructive: false });
    expect(runsWith(readOnly)).toBe(CALL_TOOL);
    expect(runsWith(write)).toBe(CALL_WRITE_TOOL);
    expect(runsWith(bare)).toBe(CALL_WRITE_TOOL);
  });

  it("answers a non-read-only target with a constant routing message that names call_write_tool", () => {
    expect(CALL_TOOL_ROUTING_ANSWER).toContain("call_write_tool");
    expect(CALL_TOOL_ROUTING_ANSWER).not.toMatch(/denied|refused|not allowed/i);
  });
});

describe("the catalog snapshot", () => {
  function catalog(initial = 1_000_000) {
    let now = initial;
    const loads: Array<{
      resolve: (value: LeanListing) => void;
      reject: (error: Error) => void;
    }> = [];
    const instance = new LeanCatalog({
      load: () =>
        new Promise<LeanListing>((resolve, reject) => {
          loads.push({ resolve, reject });
        }),
      now: () => now,
      ttlMs: LEAN_CATALOG_TTL_MS,
    });
    return {
      instance,
      loads,
      advance: (ms: number) => {
        now += ms;
      },
    };
  }
  const L1: LeanListing = { tools: [mk("a__one", "1")], unavailable: 0 };
  const L2: LeanListing = { tools: [mk("a__two", "2")], unavailable: 0 };
  const flush = () => new Promise((resolve) => setImmediate(resolve));

  it("shares one load between concurrent gets", async () => {
    const { instance, loads } = catalog();
    const first = instance.get();
    const second = instance.get();
    await flush();
    expect(loads).toHaveLength(1);
    loads[0]?.resolve(L1);
    await expect(first).resolves.toBe(L1);
    await expect(second).resolves.toBe(L1);
  });

  it("serves the snapshot without loading, a hit at 999 ms and a miss at 1000 ms", async () => {
    const { instance, loads, advance } = catalog();
    const first = instance.get();
    await flush();
    loads[0]?.resolve(L1);
    await first;
    advance(999);
    await expect(instance.get()).resolves.toBe(L1);
    expect(loads).toHaveLength(1);
    advance(1);
    const miss = instance.get();
    await flush();
    expect(loads).toHaveLength(2);
    loads[1]?.resolve(L2);
    await expect(miss).resolves.toBe(L2);
  });

  it("starts a fresh load when invalidated inside the lifetime", async () => {
    const { instance, loads } = catalog();
    const first = instance.get();
    await flush();
    loads[0]?.resolve(L1);
    await first;
    instance.invalidate();
    const again = instance.get();
    await flush();
    expect(loads).toHaveLength(2);
    loads[1]?.resolve(L2);
    await expect(again).resolves.toBe(L2);
  });

  it("hands an invalidated load's result to its waiters and keeps none of it", async () => {
    const { instance, loads } = catalog();
    const waiting = instance.get();
    await flush();
    instance.invalidate();
    loads[0]?.resolve(L1);
    await expect(waiting).resolves.toBe(L1);
    const next = instance.get();
    await flush();
    // The result that finished after the invalidation was not stored.
    expect(loads).toHaveLength(2);
    loads[1]?.resolve(L2);
    await expect(next).resolves.toBe(L2);
  });

  it("caches nothing from a failed load and lets the next get try again", async () => {
    const { instance, loads } = catalog();
    const failing = instance.get();
    await flush();
    loads[0]?.reject(new Error("backend unavailable"));
    await expect(failing).rejects.toThrow("backend unavailable");
    const retry = instance.get();
    await flush();
    expect(loads).toHaveLength(2);
    loads[1]?.resolve(L1);
    await expect(retry).resolves.toBe(L1);
  });

  it("is not cleared by an older load that settles after a newer one started", async () => {
    const { instance, loads } = catalog();
    const older = instance.get();
    await flush();
    instance.invalidate();
    const newer = instance.get();
    await flush();
    expect(loads).toHaveLength(2);
    loads[0]?.resolve(L1);
    await older;
    // The newer load is still the one in flight: a third get joins it.
    const joined = instance.get();
    await flush();
    expect(loads).toHaveLength(2);
    loads[1]?.resolve(L2);
    await expect(newer).resolves.toBe(L2);
    await expect(joined).resolves.toBe(L2);
  });

  it("treats a load that throws before returning a promise as a failed load", async () => {
    const instance = new LeanCatalog({
      load: () => {
        throw new Error("synchronous");
      },
      now: () => 1,
      ttlMs: LEAN_CATALOG_TTL_MS,
    });
    await expect(instance.get()).rejects.toThrow("synchronous");
    await expect(instance.get()).rejects.toThrow("synchronous");
  });
});

describe("the meta tool definitions", () => {
  const tools = leanMetaTools();
  const byName = Object.fromEntries(tools.map((t) => [t.name, t]));

  it("lists the four tools in order, and no name could be a real tool", () => {
    expect(tools.map((t) => t.name)).toEqual([
      "search_tools",
      "describe_tool",
      "call_tool",
      "call_write_tool",
    ]);
    for (const name of LEAN_META_TOOL_NAMES) {
      expect(name).not.toContain("__");
      expect(parseToolName(name)).toBeNull();
      expect(isLeanMetaToolName(name)).toBe(true);
    }
    expect(isLeanMetaToolName("desk__report_run")).toBe(false);
  });

  it("describes object inputs, lists no output schema, and uses no em dash", () => {
    for (const tool of tools) {
      expect(tool.inputSchema.type).toBe("object");
      expect(tool.outputSchema).toBeUndefined();
      expect(JSON.stringify(tool)).not.toContain("—");
      expect(tool.description?.length ?? 0).toBeGreaterThan(40);
    }
    expect(byName["describe_tool"]?.inputSchema.required).toEqual(["names"]);
    expect(byName["call_tool"]?.inputSchema.required).toEqual(["name"]);
    expect(byName["call_write_tool"]?.inputSchema.required).toEqual(["name"]);
  });

  it("annotates the search, describe and call_tool as read-only and call_write_tool with the MCP defaults, written out", () => {
    expect(byName["search_tools"]?.annotations).toEqual({
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    });
    expect(byName["describe_tool"]?.annotations).toEqual(
      byName["search_tools"]?.annotations,
    );
    expect(byName["call_tool"]?.annotations).toMatchObject({
      readOnlyHint: true,
      destructiveHint: false,
    });
    expect(byName["call_write_tool"]?.annotations).toEqual({
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    });
  });

  it("points a model from each tool to the one it needs next", () => {
    expect(byName["call_tool"]?.description).toContain("describe_tool");
    expect(byName["call_tool"]?.description).toContain("call_write_tool");
    expect(byName["call_tool"]?.description).toMatch(/read-only/);
    expect(byName["call_write_tool"]?.description).toContain("describe_tool");
    expect(byName["call_write_tool"]?.description).toContain("call_tool");
    expect(byName["describe_tool"]?.description).toContain("annotations");
    expect(byName["describe_tool"]?.description).toContain("runs_with");
    expect(byName["search_tools"]?.description).toContain("read_only");
  });

  it("is frozen, so a handler cannot change what every session is told", () => {
    expect(Object.isFrozen(tools)).toBe(true);
    expect(Object.isFrozen(tools[0])).toBe(true);
    expect(Object.isFrozen(tools[0]?.inputSchema)).toBe(true);
    expect(leanMetaTools()).toBe(tools);
  });
});
