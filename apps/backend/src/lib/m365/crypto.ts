/**
 * AES-256-GCM envelope encryption for stored Entra refresh tokens.
 *
 * Refresh tokens NEVER touch better-auth's `accounts` table (which
 * stores provider tokens plaintext); they live in `m365_user_tokens`
 * as an opaque envelope string produced here. The KEK comes from the
 * SOPS-vaulted `M365_TOKEN_KEK` env var (32 bytes, base64), so a
 * `pg_dump` of the database carries ciphertext only — DB custody and
 * key custody are separated.
 *
 * Envelope format (dot-separated, all segments base64url):
 *   `v1.<kek_id>.<iv>.<auth_tag>.<ciphertext>`
 *   `v2.<kek_id>.<iv>.<auth_tag>.<ciphertext>`
 *
 * `kek_id` is embedded (and duplicated in the table column for SQL
 * visibility) so a future KEK rotation can decrypt old envelopes while
 * encrypting new ones under the new key.
 *
 * TWO VERSIONS, ONE LAYOUT. The versions differ only in what the GCM tag
 * authenticates besides the ciphertext (the associated data):
 *
 *  - v1 authenticates `v1.<kek_id>`. Nothing about WHICH ROW holds the
 *    envelope is bound, so a database writer can copy one user's ciphertext
 *    into another user's row and that user's mint decrypts it.
 *  - v2 authenticates a length-prefixed `["v2", kek_id, context]`, where the
 *    caller supplies `context` (for a refresh token, a purpose label plus the
 *    owning user id, see `./envelope`). The same copy now fails
 *    authentication. The version label is inside the associated data, so a v2
 *    envelope whose header is rewritten to "v1" fails too: v1 and v2 never
 *    authenticate the same bytes, which is what stops a downgrade by header
 *    edit.
 *
 * This module is deliberately env-free and policy-free (which version to
 * write, whether to accept v1 at all, lives in `./envelope`), and it is also
 * the primitive behind `mcp_servers.bearer_token` (`server-bearer-crypto`),
 * which keeps calling it without a context and so stays on v1.
 */
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

export type EnvelopeVersion = "v1" | "v2";

const V1 = "v1";
const V2 = "v2";
const IV_BYTES = 12; // GCM standard nonce size
const TAG_BYTES = 16;
/** Longest bound context accepted, in UTF-8 bytes. */
const MAX_CONTEXT_BYTES = 512;

const b64u = (buf: Buffer) => buf.toString("base64url");
const fromB64u = (s: string) => Buffer.from(s, "base64url");

/**
 * The v2 associated data: `["v2", kekId, context]`, each field as a 4-byte
 * big-endian length followed by its UTF-8 bytes. The length prefix makes the
 * encoding injective, so no two (kekId, context) pairs can produce the same
 * bytes (`("k1","23")` and `("k12","3")` differ). Exported so a golden test can
 * freeze the layout: changing it silently orphans every stored v2 envelope.
 */
export function boundEnvelopeAad(kekId: string, context: string): Buffer {
  const chunks: Buffer[] = [];
  for (const field of [V2, kekId, context]) {
    const bytes = Buffer.from(field, "utf8");
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length, 0);
    chunks.push(length, bytes);
  }
  return Buffer.concat(chunks);
}

function assertValidContext(context: string): void {
  if (context.length === 0) {
    throw new Error("Envelope context must not be empty");
  }
  if (Buffer.byteLength(context, "utf8") > MAX_CONTEXT_BYTES) {
    throw new Error(`Envelope context exceeds ${MAX_CONTEXT_BYTES} bytes`);
  }
}

/** Version and kek id from an envelope header; throws on anything else. */
function parseEnvelope(envelope: string): {
  version: EnvelopeVersion;
  kekId: string;
  parts: string[];
} {
  const parts = envelope.split(".");
  if (parts.length !== 5 || (parts[0] !== V1 && parts[0] !== V2)) {
    throw new Error("Unrecognized refresh-token envelope format");
  }
  return { version: parts[0] as EnvelopeVersion, kekId: parts[1], parts };
}

/**
 * `context` undefined writes a v1 envelope exactly as before. A context writes
 * a v2 envelope bound to it. A present-but-invalid context (empty, over 512
 * bytes) THROWS and never falls back to v1: a caller that asked for binding
 * must not silently get an unbound envelope.
 */
export function encryptRefreshToken(
  plaintext: string,
  kek: Buffer,
  kekId: string,
  context?: string,
): string {
  if (kek.length !== 32) {
    throw new Error("KEK must be exactly 32 bytes for AES-256-GCM");
  }
  if (kekId.includes(".")) {
    throw new Error("kek_id must not contain '.' (envelope delimiter)");
  }
  if (context !== undefined) {
    assertValidContext(context);
  }
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", kek, iv);
  // Bind the envelope version + kek id (and, for v2, the context) as AAD so a
  // tampered header, or a ciphertext moved to another context, fails
  // authentication rather than silently decrypting under the wrong
  // parameters.
  const version = context === undefined ? V1 : V2;
  cipher.setAAD(
    context === undefined
      ? Buffer.from(`${V1}.${kekId}`)
      : boundEnvelopeAad(kekId, context),
  );
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return [version, kekId, b64u(iv), b64u(tag), b64u(ciphertext)].join(".");
}

/**
 * Dual-read. A v1 envelope ignores `context`. A v2 envelope REQUIRES one and
 * never falls back to the v1 associated data; under the wrong context it fails
 * authentication.
 */
export function decryptRefreshToken(
  envelope: string,
  kek: Buffer,
  context?: string,
): string {
  const { version, kekId, parts } = parseEnvelope(envelope);
  const [, , ivB64, tagB64, ctB64] = parts;
  const iv = fromB64u(ivB64);
  const tag = fromB64u(tagB64);
  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) {
    throw new Error("Malformed refresh-token envelope (iv/tag length)");
  }
  let aad: Buffer;
  if (version === V2) {
    if (context === undefined) {
      throw new Error("A v2 refresh-token envelope requires its context");
    }
    assertValidContext(context);
    aad = boundEnvelopeAad(kekId, context);
  } else {
    aad = Buffer.from(`${V1}.${kekId}`);
  }
  const decipher = createDecipheriv("aes-256-gcm", kek, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([
    decipher.update(fromB64u(ctB64)),
    decipher.final(),
  ]).toString("utf8");
}

/** kek_id embedded in an envelope (for rotation-aware key lookup). */
export function envelopeKekId(envelope: string): string {
  return parseEnvelope(envelope).kekId;
}

/** Envelope version from its header; throws on an unrecognised envelope. */
export function envelopeVersion(envelope: string): EnvelopeVersion {
  return parseEnvelope(envelope).version;
}

/** Constant-time string comparison for state/nonce values. */
export function constantTimeEquals(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}
