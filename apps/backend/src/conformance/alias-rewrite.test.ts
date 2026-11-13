/**
 * The alias proxy sits between the conformance runner and the gateway so the
 * runner's fixed, unprefixed tool names reach the gateway's `Server__tool`
 * names. These tests pin the two JSON paths it rewrites and, as hard, what it
 * must NOT touch: anything wider would hide a gateway defect behind the proxy.
 *
 * Oracles: JSON-RPC 2.0 section 6 (a batch is an array of requests), the MCP
 * 2025-11-25 tools spec (`tools/call` names its tool in `params.name`;
 * `tools/list` answers `result.tools[].name`), and the WHATWG HTML Standard
 * section 9.2 "event stream interpretation" for the SSE framing cases.
 */
import { describe, expect, it } from "vitest";

import {
  addPrefixToToolCalls,
  SseEventRewriter,
  stripPrefixFromToolList,
} from "./alias-rewrite";

const P = "Fixture";

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object") {
    for (const v of Object.values(value)) deepFreeze(v);
    Object.freeze(value);
  }
  return value;
}

const call = (name: unknown, id = 1) => ({
  jsonrpc: "2.0",
  id,
  method: "tools/call",
  params: { name, arguments: {} },
});

describe("addPrefixToToolCalls", () => {
  it("adds the prefix to a tools/call name", () => {
    expect(addPrefixToToolCalls(call("test_simple_text"), P)).toEqual(
      call("Fixture__test_simple_text"),
    );
  });

  it("works element-wise on a JSON-RPC batch and leaves the other members alone", () => {
    const ping = { jsonrpc: "2.0", id: 2, method: "ping" };
    const out = addPrefixToToolCalls([call("a", 1), ping, call("b", 3)], P);
    expect(out).toEqual([call("Fixture__a", 1), ping, call("Fixture__b", 3)]);
  });

  it("keeps an already-prefixed name and returns the same message object", () => {
    const msg = call("Fixture__a");
    expect(addPrefixToToolCalls(msg, P)).toBe(msg);
  });

  it("prefixes a single-underscore lookalike (only a double underscore counts)", () => {
    expect(addPrefixToToolCalls(call("Fixture_a"), P)).toEqual(
      call("Fixture__Fixture_a"),
    );
  });

  it("leaves tools/list, ping and non-call methods that carry a name untouched", () => {
    const list = { jsonrpc: "2.0", id: 1, method: "tools/list" };
    const ping = { jsonrpc: "2.0", id: 2, method: "ping" };
    const prompt = {
      jsonrpc: "2.0",
      id: 3,
      method: "prompts/get",
      params: { name: "simple" },
    };
    for (const msg of [list, ping, prompt]) {
      expect(addPrefixToToolCalls(msg, P)).toEqual(msg);
    }
  });

  it("leaves a tools/call without a string name untouched", () => {
    for (const name of [undefined, 7, null, { x: 1 }]) {
      const msg = call(name);
      expect(addPrefixToToolCalls(msg, P)).toEqual(msg);
    }
    const noParams = { jsonrpc: "2.0", id: 1, method: "tools/call" };
    expect(addPrefixToToolCalls(noParams, P)).toEqual(noParams);
  });

  it("does not mutate its input", () => {
    const input = deepFreeze([call("a"), call("b", 2)]);
    expect(() => addPrefixToToolCalls(input, P)).not.toThrow();
  });
});

const listResult = (names: string[], extra: Record<string, unknown> = {}) => ({
  jsonrpc: "2.0",
  id: 1,
  result: {
    tools: names.map((name) => ({
      name,
      description: `About ${name}`,
      inputSchema: { type: "object" },
    })),
    ...extra,
  },
});

describe("stripPrefixFromToolList", () => {
  it("strips only the exact `${prefix}__` from result.tools[].name", () => {
    const out = stripPrefixFromToolList(
      listResult(["Fixture__a", "Fixture__b"]),
      P,
    ) as ReturnType<typeof listResult>;
    expect(out.result.tools.map((t) => t.name)).toEqual(["a", "b"]);
    // Everything else on the tool survives.
    expect(out.result.tools[0].description).toBe("About Fixture__a");
  });

  it("is a no-op for lookalikes (negative controls)", () => {
    const msg = listResult(["Fixture_x", "Other__x", "fixture__x"]);
    const out = stripPrefixFromToolList(msg, P) as ReturnType<
      typeof listResult
    >;
    expect(out.result.tools.map((t) => t.name)).toEqual([
      "Fixture_x",
      "Other__x",
      "fixture__x",
    ]);
  });

  it("does not touch prefix text inside content or an error message", () => {
    const callResult = {
      jsonrpc: "2.0",
      id: 2,
      result: { content: [{ type: "text", text: "ran Fixture__a" }] },
    };
    const failure = {
      jsonrpc: "2.0",
      id: 3,
      error: { code: -32602, message: "Unknown tool: Fixture__a" },
    };
    expect(stripPrefixFromToolList(callResult, P)).toEqual(callResult);
    expect(stripPrefixFromToolList(failure, P)).toEqual(failure);
  });

  it("works element-wise on a batch", () => {
    const out = stripPrefixFromToolList(
      [listResult(["Fixture__a"]), { jsonrpc: "2.0", id: 2, result: {} }],
      P,
    ) as Array<{ result: { tools?: Array<{ name: string }> } }>;
    expect(out[0].result.tools?.[0].name).toBe("a");
    expect(out[1].result.tools).toBeUndefined();
  });

  it("does not mutate its input", () => {
    const input = deepFreeze(listResult(["Fixture__a"]));
    expect(() => stripPrefixFromToolList(input, P)).not.toThrow();
  });
});

/** Feed chunks through a fresh rewriter and return everything it emits. */
function run(chunks: Array<string | Uint8Array>, prefix = P): string {
  const rw = new SseEventRewriter(prefix);
  let out = "";
  for (const c of chunks) out += rw.push(c);
  return out + rw.end();
}

const listJson = JSON.stringify(listResult(["Fixture__a", "Fixture__b"]));
// Only the names lose the prefix; the description text still says Fixture__.
const strippedJson = JSON.stringify({
  jsonrpc: "2.0",
  id: 1,
  result: {
    tools: ["a", "b"].map((name) => ({
      name,
      description: `About Fixture__${name}`,
      inputSchema: { type: "object" },
    })),
  },
});

describe("SseEventRewriter", () => {
  it("rewrites a tools/list result carried in one data line", () => {
    expect(run([`event: message\ndata: ${listJson}\n\n`])).toBe(
      `event: message\ndata: ${strippedJson}\n\n`,
    );
  });

  it("is chunk-boundary independent (split mid-line and inside `data:`)", () => {
    const whole = `data: ${listJson}\n\n`;
    for (let cut = 1; cut < whole.length; cut += 7) {
      expect(run([whole.slice(0, cut), whole.slice(cut)])).toBe(
        `data: ${strippedJson}\n\n`,
      );
    }
    expect(
      run([
        "da",
        "ta: ",
        listJson.slice(0, 20),
        listJson.slice(20),
        "\n",
        "\n",
      ]),
    ).toBe(`data: ${strippedJson}\n\n`);
  });

  it("handles CRLF and CR line endings", () => {
    expect(run([`data: ${listJson}\r\n\r\n`])).toBe(
      `data: ${strippedJson}\r\n\r\n`,
    );
    expect(run([`data: ${listJson}\r\r`])).toBe(`data: ${strippedJson}\r\r`);
    // A CRLF pair split between chunks is one terminator, not two.
    expect(run([`data: ${listJson}\r\n\r`, `\n`])).toBe(
      `data: ${strippedJson}\r\n\r\n`,
    );
  });

  it("joins multi-line data with a newline before parsing", () => {
    const half = listJson.indexOf('"tools"');
    const out = run([
      `data: ${listJson.slice(0, half)}\ndata: ${listJson.slice(half)}\n\n`,
    ]);
    expect(out).toBe(`data: ${strippedJson}\n\n`);
  });

  it("keeps id, retry, event and comment lines in order, byte for byte", () => {
    const input = `: keep-alive\nid: 7\nevent: message\ndata: ${listJson}\nretry: 1500\n\n`;
    expect(run([input])).toBe(
      `: keep-alive\nid: 7\nevent: message\ndata: ${strippedJson}\nretry: 1500\n\n`,
    );
  });

  it("leaves non-JSON data, empty priming events and non-list events untouched", () => {
    const priming = `id: 1\ndata:\n\n`;
    const text = `data: hello Fixture__a\n\n`;
    const progress = `data:{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}\n\n`;
    expect(run([priming + text + progress])).toBe(priming + text + progress);
  });

  it("leaves tool-call result content alone even when it names a prefixed tool", () => {
    const ev = `data: ${JSON.stringify({ jsonrpc: "2.0", id: 2, result: { content: [{ type: "text", text: "Fixture__a" }] } })}\n\n`;
    expect(run([ev])).toBe(ev);
  });

  it("flushes a trailing partial event unchanged at end()", () => {
    const partial = `data: ${listJson}`;
    expect(run([partial])).toBe(partial);
  });

  it("does not corrupt a multibyte character split across chunks", () => {
    const text = `data: {"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"café \u{1f600}"}]}}\n\n`;
    const bytes = new TextEncoder().encode(text);
    const at = bytes.indexOf(0xc3) + 1; // between the two bytes of "é"
    const emoji = bytes.indexOf(0xf0) + 2; // inside the four-byte emoji
    expect(run([bytes.slice(0, at), bytes.slice(at)])).toBe(text);
    expect(run([bytes.slice(0, emoji), bytes.slice(emoji)])).toBe(text);

    const listWithAccent = `data: ${JSON.stringify(listResult(["Fixture__café"]))}\n\n`;
    const lb = new TextEncoder().encode(listWithAccent);
    const cut = lb.indexOf(0xc3) + 1;
    expect(run([lb.slice(0, cut), lb.slice(cut)])).toBe(
      `data: ${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: {
          tools: [
            {
              name: "café",
              description: "About Fixture__café",
              inputSchema: { type: "object" },
            },
          ],
        },
      })}\n\n`,
    );
  });

  it("rewrites every event in a stream, not only the first", () => {
    const ev = `data: ${listJson}\n\n`;
    expect(run([ev + ev + ev])).toBe(`data: ${strippedJson}\n\n`.repeat(3));
  });
});
