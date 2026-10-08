import { requestBodyTooLargeMessage } from "@modelcontextprotocol/sdk/server/requestBody.js";
import type { NextFunction, Request, Response } from "express";

import logger from "@/utils/logger";

/**
 * The largest POST body a Streamable HTTP server transport reads, in bytes.
 *
 * Passed as `maxRequestBodySize` at every place this gateway constructs a
 * `StreamableHTTPServerTransport`: the public `/metamcp/:endpoint/mcp` route
 * (a fresh session and a lazily recovered one) and the Inspector's
 * `/mcp-proxy/server/mcp` and `/mcp-proxy/metamcp/:uuid/mcp`. None of those
 * routes parses the body first (`globalBodyParser` leaves `/metamcp/` and
 * `/mcp-proxy/` raw, see lib/global-body-parser), so this is the backend's
 * only ceiling on what an authenticated caller can make it buffer and parse.
 * A body over it is answered 413 with a JSON-RPC error (-32000, "Payload Too
 * Large: Request body must not exceed N bytes") before anything is parsed.
 *
 * WHY THE OPTION HAS TO BE SET. Up to SDK 1.30.0 the transport read the body
 * with no bound. From 1.30.1 it caps the read at a 4 MiB default when no parsed
 * body is passed, which is every leg here, and that default refused tool calls
 * production was carrying (a base64 upload of about 3 MiB already exceeds it).
 *
 * WHY 10 MiB: it is what reaches this process intact. The container publishes
 * only the frontend's Next.js port, so every request arrives through Next,
 * which rewrites `/metamcp/*` and `/mcp-proxy/*` here
 * (apps/frontend/next.config.js). Next 15 forwards at most
 * `experimental.middlewareClientMaxBodySize` bytes of a rewritten request's
 * body, default 10485760, whether or not middleware runs on the path, and
 * keeps the original Content-Length. Measured against Next 15.5.24 with this
 * SDK transport behind it:
 *
 * - at a 10 MiB cap, a 10485760-byte call returns 200 and a 10485761-byte or
 *   12 MiB call returns this 413 within milliseconds (the declared length is
 *   over the cap, so nothing is read);
 * - at a higher cap, the same over-10-MiB calls do not complete: the transport
 *   waits for bytes Next dropped, and Next's 120 s proxyTimeout eventually
 *   answers 500.
 *
 * So below 10 MiB nothing that works today is refused, and above it a call
 * that already could not succeed now fails at once with a reason. Backends
 * that accept more do exist: autotask `ticket_manage` attachments (10 MiB
 * decoded, about 13.3 MiB of base64 JSON), wordpress `media_manage` uploads
 * (25 MiB decoded, about 33.3 MiB) and m365 `file_manage` uploads (150 MiB
 * decoded). Carrying those means raising this constant and Next's
 * `middlewareClientMaxBodySize` to the same value together, and budgeting the
 * heap: a body costs several times its size while it is read, parsed and
 * re-serialized to the backend, in a container shared with the frontend.
 * `mcp-request-body-limit.test.ts` fails if the two numbers drift apart.
 *
 * No environment override: the other body ceilings (GLOBAL_JSON_BODY_LIMIT,
 * AUTH_RELAY_BODY_LIMIT, TRPC_BODY_LIMIT, OAUTH_BODY_LIMIT) are constants too.
 *
 * Not covered: the SSE transports (`/sse` + `/message`) read with the SDK's
 * own fixed 4mb limit, which the SDK does not expose as an option.
 */
export const MCP_REQUEST_BODY_LIMIT_BYTES = 10 * 1024 * 1024;

/**
 * Express middleware, mounted ahead of the handler on each POST route above:
 * answers a request whose DECLARED body is over MCP_REQUEST_BODY_LIMIT_BYTES
 * before the route runs.
 *
 * WHY THE TRANSPORT'S OWN CHECK IS NOT ENOUGH. The transport refuses the same
 * request, but only once the route hands it over, and a request with no
 * session id has had a session allocated by then: the public route takes a
 * per-credential admission slot, a pooled server instance, a resident
 * registration and an `mcp_sessions` row, and `/mcp-proxy/server/mcp` starts
 * the upstream transport (a STDIO child or an SSE stream). The 413 carries no
 * session id, so nothing could ever use or close what was allocated, and a
 * caller repeating oversized initializes pinned it until the idle sweeper or
 * an eviction reached it. Refused here, a declared oversize allocates
 * nothing. A body found to be over the limit only while it is read (chunked,
 * so no Content-Length) still reaches the transport, and those two routes tear
 * down a session whose initialize the transport refused.
 *
 * The same test as the SDK's (`Number(Content-Length) > limit`, so an absent
 * or non-numeric header passes through to the transport) and the same answer:
 * 413 with the SDK's JSON-RPC error and message, so a caller cannot tell which
 * of the two refused it. The message comes from the SDK's own helper so the
 * two cannot drift apart. One difference: the transport checks Accept and
 * Content-Type first, so an oversized request that also has the wrong media
 * type gets this 413 rather than a 406 or 415.
 *
 * Requests on an existing session pass through here too and get the answer
 * the transport would have given; the session is untouched either way, since
 * the SDK answers an oversized body on an initialized session without closing
 * it.
 */
export function refuseDeclaredOversize(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const declared = Number(req.headers["content-length"]);
  if (declared > MCP_REQUEST_BODY_LIMIT_BYTES) {
    // Numbers and the mount path only: the query string on the Inspector
    // routes can carry a server's env from an older client.
    logger.warn(
      `Refused an MCP request on ${JSON.stringify(req.baseUrl)} declaring ${declared} body bytes, over the ${MCP_REQUEST_BODY_LIMIT_BYTES}-byte limit.`,
    );
    res
      .status(413)
      .setHeader("Content-Type", "application/json")
      .end(
        JSON.stringify({
          jsonrpc: "2.0",
          error: {
            code: -32000,
            message: requestBodyTooLargeMessage(MCP_REQUEST_BODY_LIMIT_BYTES),
          },
          id: null,
        }),
      );
    return;
  }
  next();
}
