/**
 * MCP_REQUEST_BODY_LIMIT_BYTES has to equal what the frontend's Next.js
 * server forwards intact.
 *
 * Every MCP request reaches the backend through a Next rewrite, and Next
 * forwards at most `experimental.middlewareClientMaxBodySize` bytes of the
 * body while keeping the original Content-Length. With the backend ceiling
 * equal to that number, an over-limit call is refused at once with 413 (the
 * declared length is over the ceiling, so nothing is read). With the backend
 * ceiling higher, the same call waits for bytes Next dropped until Next's
 * proxy timeout answers 500 two minutes later; with it lower, calls Next would
 * carry are refused for no reason. See mcp-request-body-limit.ts.
 *
 * So the two numbers move together. This reads the frontend's real config and
 * the installed Next's default, and fails when either moves without the other,
 * including a Next upgrade that changes the default.
 */
import { createRequire } from "node:module";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { MCP_REQUEST_BODY_LIMIT_BYTES } from "./mcp-request-body-limit";

const FRONTEND_DIR = join(__dirname, "../../../../frontend");

describe("MCP_REQUEST_BODY_LIMIT_BYTES", () => {
  it("equals the body size the frontend's Next.js rewrite forwards intact", async () => {
    const { default: nextConfig } = (await import(
      join(FRONTEND_DIR, "next.config.js")
    )) as {
      default: { experimental?: { middlewareClientMaxBodySize?: unknown } };
    };
    const requireFromFrontend = createRequire(
      join(FRONTEND_DIR, "package.json"),
    );
    const { defaultConfig } = requireFromFrontend(
      "next/dist/server/config-shared.js",
    ) as {
      defaultConfig: { experimental: { middlewareClientMaxBodySize: unknown } };
    };

    const forwarded =
      nextConfig.experimental?.middlewareClientMaxBodySize ??
      defaultConfig.experimental.middlewareClientMaxBodySize;

    // A string such as "64mb" is valid Next config but cannot be compared
    // here; set it as a number of bytes so the pairing stays checkable.
    expect(typeof forwarded).toBe("number");
    expect(forwarded).toBe(MCP_REQUEST_BODY_LIMIT_BYTES);
  });
});
