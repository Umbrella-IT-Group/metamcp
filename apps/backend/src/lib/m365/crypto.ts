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
 *
 * `kek_id` is embedded (and duplicated in the table column for SQL
 * visibility) so a future KEK rotation can decrypt old envelopes while
 * encrypting new ones under the new key.
 */
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

const VERSION = "v1";
const IV_BYTES = 12; // GCM standard nonce size
const TAG_BYTES = 16;

const b64u = (buf: Buffer) => buf.toString("base64url");
const fromB64u = (s: string) => Buffer.from(s, "base64url");

export function encryptRefreshToken(
  plaintext: string,
  kek: Buffer,
  kekId: string,
): string {
  if (kek.length !== 32) {
    throw new Error("KEK must be exactly 32 bytes for AES-256-GCM");
  }
  if (kekId.includes(".")) {
    throw new Error("kek_id must not contain '.' (envelope delimiter)");
  }
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", kek, iv);
  // Bind the envelope version + kek id as AAD so a tampered header
  // fails authentication rather than silently decrypting under the
  // wrong parameters.
  cipher.setAAD(Buffer.from(`${VERSION}.${kekId}`));
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return [VERSION, kekId, b64u(iv), b64u(tag), b64u(ciphertext)].join(".");
}

export function decryptRefreshToken(envelope: string, kek: Buffer): string {
  const parts = envelope.split(".");
  if (parts.length !== 5 || parts[0] !== VERSION) {
    throw new Error("Unrecognized refresh-token envelope format");
  }
  const [, kekId, ivB64, tagB64, ctB64] = parts;
  const iv = fromB64u(ivB64);
  const tag = fromB64u(tagB64);
  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) {
    throw new Error("Malformed refresh-token envelope (iv/tag length)");
  }
  const decipher = createDecipheriv("aes-256-gcm", kek, iv);
  decipher.setAAD(Buffer.from(`${VERSION}.${kekId}`));
  decipher.setAuthTag(tag);
  return Buffer.concat([
    decipher.update(fromB64u(ctB64)),
    decipher.final(),
  ]).toString("utf8");
}

/** kek_id embedded in an envelope (for rotation-aware key lookup). */
export function envelopeKekId(envelope: string): string {
  const parts = envelope.split(".");
  if (parts.length !== 5 || parts[0] !== VERSION) {
    throw new Error("Unrecognized refresh-token envelope format");
  }
  return parts[1];
}

/** Constant-time string comparison for state/nonce values. */
export function constantTimeEquals(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}
