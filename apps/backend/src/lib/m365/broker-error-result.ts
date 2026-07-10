/**
 * Translate a typed `M365BrokerError` into the consumer-facing MCP
 * surface (design doc §4.3):
 *
 *  1. Best-effort SEP-1036 URL-mode elicitation — if the connected
 *     client declared the `elicitation` capability, fire an
 *     `elicitation/create` request carrying the enrollment URL so
 *     clients that render URL elicitations (Claude Code ≥ spec
 *     2025-11-25) show a clickable re-auth prompt. Fire-and-forget:
 *     SDK 1.16 predates URL mode, so we send a raw request with a
 *     permissive result schema and swallow every failure — a client
 *     that rejects the method just falls back to path 2.
 *  2. Always return a structured `isError` tool result whose text is a
 *     machine-readable JSON payload (code + human message + enroll
 *     URL). This is the guaranteed fallback path on every client.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

import logger from "@/utils/logger";

import { M365BrokerError } from "./errors";

const ACTION_HINT: Record<string, string> = {
  credential_missing:
    "Open the enrollment URL in your browser to connect your Microsoft 365 account, then retry the tool call.",
  credential_expired:
    "Open the enrollment URL in your browser to re-authorize your Microsoft 365 connection, then retry the tool call.",
  credential_revoked:
    "Your Microsoft 365 grant was revoked. Open the enrollment URL in your browser to re-connect, then retry.",
  mfa_required:
    "Microsoft requires interactive re-authentication (MFA / Conditional Access). Open the enrollment URL in your browser, complete the sign-in, then retry.",
  not_configured:
    "The gateway's M365 broker is not configured yet — contact the operator.",
  mint_failed:
    "Token mint failed for an operational reason — retry shortly; if it persists, contact the operator.",
};

export function buildM365BrokerErrorResult(
  error: M365BrokerError,
  server: Server,
): CallToolResult {
  // Path 1: best-effort URL-mode elicitation. Never await the user's
  // response — the elicitation is a side-channel prompt; the tool call
  // itself resolves immediately with the typed error result below.
  if (error.enrollUrl) {
    try {
      const capabilities = server.getClientCapabilities();
      if (capabilities?.elicitation) {
        server
          .request(
            {
              method: "elicitation/create",
              params: {
                mode: "url",
                message: `Microsoft 365 authorization required: ${error.message}`,
                url: error.enrollUrl,
                // Form-mode field kept for clients that predate URL
                // mode but still validate the params shape.
                requestedSchema: { type: "object", properties: {} },
              },
            },
            z.object({}).passthrough(),
          )
          .catch(() => {
            // Client rejected/ignored the elicitation — fallback text
            // path already carries the URL.
          });
      }
    } catch (elicitError) {
      logger.debug(
        "M365 broker: elicitation dispatch failed (falling back to typed error text):",
        elicitError,
      );
    }
  }

  // Path 2: guaranteed structured isError result.
  const payload = {
    error: error.code,
    message: error.message,
    ...(error.enrollUrl ? { enroll_url: error.enrollUrl } : {}),
    action: ACTION_HINT[error.code] ?? ACTION_HINT.mint_failed,
  };
  return {
    isError: true,
    content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
  };
}
