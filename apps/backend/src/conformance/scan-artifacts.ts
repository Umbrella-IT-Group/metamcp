// Stub: reports every tree as clean, committed first so the tests fail on
// assertions rather than on a missing import. Replaced by the real
// implementation in the next commit.

export const SECRET_PATTERN = /sk_mt_[0-9a-f]{64}|confsec_[0-9a-f]{64}/;

export interface ScanFs {
  readdirSync(dir: string): string[];
  lstatSync(file: string): {
    isFile(): boolean;
    isDirectory(): boolean;
    isSymbolicLink(): boolean;
  };
  readFileSync(file: string): Buffer;
}

export interface ScanResult {
  hits: string[];
  scanned: number;
}

export function scanDirectory(_root: string, _fs?: ScanFs): ScanResult {
  return { hits: [], scanned: 0 };
}
