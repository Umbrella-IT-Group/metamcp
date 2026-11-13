// Stub: every command exits 0, committed first so the tests fail on assertions
// rather than on a missing import. Replaced by the real implementation in the
// next commit.

export interface Io {
  out(text: string): void;
  err(text: string): void;
}

export async function main(_argv: readonly string[], _io: Io): Promise<number> {
  return 0;
}
