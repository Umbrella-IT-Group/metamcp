/**
 * The capability set advertised on 8815f6b (the base of the branch that
 * stopped relaying prompts and resources), and the hash every session row
 * persisted by a build advertising it carries. Tests use it to pin that the
 * advertised set, and so GATEWAY_CAPABILITY_HASH, did not change, and that
 * such a row still recovers lazily.
 *
 * BASE_BUILD_CAPABILITIES is the object literal in gateway-capabilities.ts on
 * 8815f6b, in its source key order (the hash serializes with JSON.stringify,
 * so key order is part of the value). BASE_BUILD_CAPABILITY_HASH is computed
 * from it the way gateway-boot-id.ts computes GATEWAY_CAPABILITY_HASH.
 *
 * BASE_BUILD_CAPABILITY_DIGEST is the digest that build itself produced,
 * obtained by running 8815f6b's gateway-capabilities.ts and
 * gateway-boot-id.ts under tsx and printing GATEWAY_CAPABILITY_HASH. It is a
 * constant on purpose: it also pins the hashing (algorithm, serialization),
 * which a value computed here with the same code cannot.
 */
import { createHash } from "node:crypto";

export const BASE_BUILD_CAPABILITIES = {
  prompts: {},
  resources: {},
  tools: { listChanged: true },
};

export const BASE_BUILD_CAPABILITY_HASH = createHash("sha256")
  .update(JSON.stringify(BASE_BUILD_CAPABILITIES))
  .digest("hex");

export const BASE_BUILD_CAPABILITY_DIGEST =
  "e35d609eae0b97684237ee772160aea36b0e7d19534eb367ede4274716234a7e";
