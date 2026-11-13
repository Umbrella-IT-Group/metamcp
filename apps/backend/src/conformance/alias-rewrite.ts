// Stub: identity rewriters, committed first so the tests fail on assertions
// rather than on a missing import. Replaced by the real implementation in the
// next commit.

export function addPrefixToToolCalls(msg: unknown, _prefix: string): unknown {
  return msg;
}

export function stripPrefixFromToolList(
  msg: unknown,
  _prefix: string,
): unknown {
  return msg;
}

export class SseEventRewriter {
  private readonly decoder = new TextDecoder("utf-8");

  constructor(_prefix: string) {}

  push(chunk: Uint8Array | string): string {
    return typeof chunk === "string"
      ? chunk
      : this.decoder.decode(chunk, { stream: true });
  }

  end(): string {
    return this.decoder.decode();
  }
}
