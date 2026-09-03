/**
 * Boot-time converge that encrypts any legacy plaintext `mcp_servers.bearer_token`
 * once, then arms the read path's fail-closed rule.
 *
 * SEQUENCE. Runs at startup AFTER the 0036 schema migration has applied and
 * BEFORE the idle server pool is warmed, so every serverParams the pool builds
 * already reads a converged column. Idempotent and self-healing: it selects
 * only rows that are not yet `enc:v1:` envelopes, so a converged database reads
 * nothing and a partially-converged one finishes where it left off.
 *
 * KEK ABSENT. If no KEK is configured the converge cannot encrypt. It does NOT
 * crash the gateway and it does NOT silently rewrite anything: it logs (loudly,
 * with the count) and leaves the flag UNSET, which keeps the read path in its
 * pre-converge posture where a legacy plaintext value is still honoured. That
 * is the same behaviour as before this change, no regression, and the write
 * path already refuses to create new plaintext rows (encryptServerBearerToken
 * fails closed), so the set of plaintext rows can only shrink.
 *
 * FLAG. On a successful pass (KEK present, every legacy row encrypted) it marks
 * the converge complete, after which the read path treats any remaining
 * untagged value as a fault rather than a credential. Zero rows to convert is a
 * successful pass, the common case, since the census found no rows carrying a
 * bearer token.
 */
import { getTokenKek } from "@/lib/m365/config";
import logger from "@/utils/logger";

import { mcpServersRepository } from "../../db/repositories";
import {
  encryptServerBearerToken,
  markServerBearerConvergeComplete,
} from "./server-bearer-crypto";

export async function convergeServerBearerTokens(): Promise<void> {
  const pending =
    await mcpServersRepository.findServersWithPlaintextBearerToken();

  if (pending.length === 0) {
    // Nothing legacy to convert. Arm the fail-closed rule so any untagged value
    // written outside the app is refused from here on.
    markServerBearerConvergeComplete();
    return;
  }

  // There is legacy plaintext to encrypt, so a KEK is required. Without one,
  // leave the rows as-is (still honoured by the read path) and try again next
  // boot rather than crash or rewrite.
  if (!getTokenKek()) {
    logger.error(
      `Bearer-token converge: ${pending.length} MCP server(s) hold a plaintext bearer token but M365_TOKEN_KEK is not configured; leaving them until a KEK is present.`,
    );
    return;
  }

  let converted = 0;
  for (const server of pending) {
    try {
      const ciphertext = encryptServerBearerToken(server.bearerToken);
      await mcpServersRepository.writeBearerTokenCiphertext(
        server.uuid,
        ciphertext,
      );
      converted += 1;
    } catch (err) {
      // One bad row must not abort the whole pass or arm the fail-closed rule
      // while others remain plaintext.
      logger.error(
        `Bearer-token converge: failed to encrypt bearer token for server ${server.uuid}:`,
        err,
      );
    }
  }

  if (converted === pending.length) {
    logger.info(
      `Bearer-token converge: encrypted ${converted} plaintext bearer token(s) at rest.`,
    );
    markServerBearerConvergeComplete();
  } else {
    logger.error(
      `Bearer-token converge: encrypted ${converted}/${pending.length} bearer token(s); leaving the fail-closed rule unarmed until all convert.`,
    );
  }
}
