/**
 * The two JSON paths the conformance alias proxy rewrites, and nothing else.
 *
 * The gateway names every tool `<server>__<tool>`; the conformance runner calls
 * `test_simple_text`. Adding the prefix to a `tools/call` name on the way in
 * and removing it from `result.tools[].name` on the way out lets the runner's
 * fixed names reach the gateway's prefixed ones. Both functions are
 * deliberately narrow: a wider rewrite (content text, error messages, other
 * methods) would hide a real gateway defect behind the proxy, so anything not
 * named here comes back as the same object, byte for byte.
 *
 * Both are immutable: they build new objects on a change and return the input
 * itself otherwise, which is what lets a caller skip re-serialising an
 * unchanged message.
 */

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Apply `fn` to a message, or element-wise to a JSON-RPC batch (RFC: an array). */
function mapMessage(msg: unknown, fn: (m: unknown) => unknown): unknown {
  if (!Array.isArray(msg)) return fn(msg);
  let changed = false;
  const out = msg.map((m) => {
    const next = fn(m);
    if (next !== m) changed = true;
    return next;
  });
  return changed ? out : msg;
}

export function addPrefixToToolCalls(msg: unknown, prefix: string): unknown {
  const marker = `${prefix}__`;
  return mapMessage(msg, (m) => {
    if (!isObject(m) || m.method !== "tools/call") return m;
    const params = m.params;
    if (!isObject(params) || typeof params.name !== "string") return m;
    if (params.name.startsWith(marker)) return m;
    return { ...m, params: { ...params, name: `${marker}${params.name}` } };
  });
}

export function stripPrefixFromToolList(msg: unknown, prefix: string): unknown {
  const marker = `${prefix}__`;
  return mapMessage(msg, (m) => {
    if (!isObject(m)) return m;
    const result = m.result;
    if (!isObject(result) || !Array.isArray(result.tools)) return m;
    let changed = false;
    const tools = result.tools.map((tool: unknown) => {
      if (
        isObject(tool) &&
        typeof tool.name === "string" &&
        tool.name.startsWith(marker) &&
        tool.name.length > marker.length
      ) {
        changed = true;
        return { ...tool, name: tool.name.slice(marker.length) };
      }
      return tool;
    });
    return changed ? { ...m, result: { ...result, tools } } : m;
  });
}

interface EventLine {
  text: string;
  eol: string;
}

/** Split raw event text into lines, keeping each line's own terminator. */
function splitLines(raw: string): EventLine[] {
  const lines: EventLine[] = [];
  let i = 0;
  while (i < raw.length) {
    let j = i;
    while (j < raw.length && raw[j] !== "\n" && raw[j] !== "\r") j++;
    let eol = "";
    if (j < raw.length) {
      eol = raw[j] === "\r" && raw[j + 1] === "\n" ? "\r\n" : raw[j];
    }
    lines.push({ text: raw.slice(i, j), eol });
    i = j + eol.length;
  }
  return lines;
}

function dataValue(line: string): string | undefined {
  if (line === "data") return "";
  if (!line.startsWith("data:")) return undefined;
  const value = line.slice(5);
  return value.startsWith(" ") ? value.slice(1) : value;
}

/**
 * Streams SSE text through `stripPrefixFromToolList` without buffering to the
 * end: progress and log events must reach the runner as they happen. An event
 * is rewritten only when its data parses as JSON AND the strip actually changed
 * something; every other event leaves exactly as it arrived.
 *
 * Framing follows the WHATWG HTML Standard section 9.2 ("event stream
 * interpretation"): lines end in LF, CRLF or CR, a blank line ends an event,
 * `data:` lines join with a newline after one leading space is dropped, and
 * every other field line is left alone.
 */
export class SseEventRewriter {
  private readonly decoder = new TextDecoder("utf-8");
  private pending = "";

  constructor(private readonly prefix: string) {}

  push(chunk: Uint8Array | string): string {
    // `stream: true` keeps a multibyte character that straddles two chunks
    // intact instead of emitting a replacement character for each half.
    this.pending +=
      typeof chunk === "string"
        ? chunk
        : this.decoder.decode(chunk, { stream: true });
    return this.drain(false);
  }

  /** Flush: a trailing partial event is emitted unchanged. */
  end(): string {
    this.pending += this.decoder.decode();
    return this.drain(true);
  }

  private drain(final: boolean): string {
    let out = "";
    for (;;) {
      const end = this.findEventEnd(final);
      if (end < 0) break;
      out += this.rewriteEvent(this.pending.slice(0, end));
      this.pending = this.pending.slice(end);
    }
    if (final) {
      out += this.pending;
      this.pending = "";
    }
    return out;
  }

  /** Index just past the blank line that ends the first event, or -1. */
  private findEventEnd(final: boolean): number {
    const s = this.pending;
    let i = 0;
    while (i < s.length) {
      let j = i;
      while (j < s.length && s[j] !== "\n" && s[j] !== "\r") j++;
      if (j >= s.length) return -1;
      let eolLength = 1;
      if (s[j] === "\r") {
        if (j + 1 < s.length) {
          if (s[j + 1] === "\n") eolLength = 2;
        } else if (!final) {
          // A lone CR at the end of the buffer may be the first half of a CRLF
          // whose LF is in the next chunk; wait rather than split the pair.
          return -1;
        }
      }
      if (j === i) return j + eolLength; // blank line: the event is complete
      i = j + eolLength;
    }
    return -1;
  }

  private rewriteEvent(raw: string): string {
    const lines = splitLines(raw);
    const dataIndexes: number[] = [];
    const values: string[] = [];
    lines.forEach((line, index) => {
      const value = dataValue(line.text);
      if (value !== undefined) {
        dataIndexes.push(index);
        values.push(value);
      }
    });
    if (dataIndexes.length === 0) return raw;

    let parsed: unknown;
    try {
      parsed = JSON.parse(values.join("\n"));
    } catch {
      return raw;
    }
    const stripped = stripPrefixFromToolList(parsed, this.prefix);
    if (stripped === parsed) return raw;

    return lines
      .map((line, index) => {
        if (index === dataIndexes[0]) {
          return `data: ${JSON.stringify(stripped)}${line.eol}`;
        }
        if (dataIndexes.includes(index)) return "";
        return `${line.text}${line.eol}`;
      })
      .join("");
  }
}
