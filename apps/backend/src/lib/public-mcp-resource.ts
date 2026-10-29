/**
 * The one definition of "a protected resource this gateway publishes", shared
 * by the two places that turn a request path into a resource URL: the RFC 9728
 * discovery documents (`routers/oauth/metadata`) and the 401 challenge that
 * points a client at them (`lib/auth-challenge`).
 *
 * WHY ONE STRICT MATCHER. Both places copy request text into something a
 * client trusts. Discovery serves it back as the `resource` identifier, which
 * a strict client compares byte for byte with the URL it connected to and then
 * presents to the authorization server. The challenge interpolates it into the
 * quoted `resource_metadata` parameter of `WWW-Authenticate`. A loose match
 * ("starts with `/metamcp/`", "the second segment is the name") reflects
 * whatever follows: `/metamcp/<real-endpoint>/mcp/anything` would be served as
 * the resource `<base>/metamcp/<real-endpoint>/mcp/anything`, and a literal `"`
 * in a request path would end the quoted header parameter early. So a path is
 * a resource only when it is exactly `/metamcp/<name>/<transport>`, with the
 * name spelled in a closed alphabet and the transport one of three literals;
 * every other path is not a resource, and each caller keeps its own fallback
 * (discovery answers 404, the challenge advertises the unscoped document).
 *
 * The two callers must agree: a challenge that pointed at a scoped document
 * discovery refused would send every client on that path to a 404. Keeping one
 * function is what makes that impossible.
 *
 * DB-free on purpose, like `auth-challenge`: importing anything that reaches
 * `db/index` would make every 401 depend on a database connection string.
 */

/**
 * The mount `apps/backend/src/index.ts` gives the public MCP router
 * (`app.use("/metamcp", publicEndpointsRouter)`). A drift test reads that line
 * back out of `index.ts`.
 */
export const PUBLIC_MCP_MOUNT = "/metamcp";

/**
 * The transports a public endpoint is served on, and therefore the only final
 * segments a protected resource can have: `/:endpoint_name/mcp`
 * (Streamable HTTP), `/:endpoint_name/sse` and `/:endpoint_name/api`
 * (OpenAPI). `/message`, `/api/<tool>` and `/admin/*` are deliberately absent:
 * they are follow-on calls under one of these resources, or not OAuth
 * resources at all, and they keep the unscoped challenge they had before.
 */
export const PUBLIC_MCP_TRANSPORTS = ["mcp", "sse", "api"] as const;

export type PublicMcpTransport = (typeof PUBLIC_MCP_TRANSPORTS)[number];

/**
 * One path segment written only with RFC 3986 unreserved characters and
 * percent-encoded octets.
 *
 * Endpoint names are created under `^[a-zA-Z0-9_-]+$` (`@repo/zod-types`
 * endpoints schemas), so every name this gateway can create matches without
 * escaping. Percent-encoding is admitted so a name stored before that rule,
 * reached as `my%20endpoint`, still resolves the way `lookupEndpoint` resolves
 * it. What the alphabet keeps out is everything with a meaning in a URL or a
 * header: `"` and `\` (quoted-string syntax), `,` and `;` (parameter
 * separators), `/`, `?`, `#`, whitespace, controls and non-ASCII.
 */
const RESOURCE_NAME_SEGMENT = /^(?:[A-Za-z0-9._~-]|%[0-9A-Fa-f]{2})+$/;

export interface PublicMcpResourcePath {
  /**
   * The resource path, rebuilt from the checked name segment and the literal
   * transport, e.g. `/metamcp/my%20endpoint/mcp`. Safe to interpolate into a
   * URL or a quoted header parameter. Keeps the request's percent-encoded
   * spelling because a strict client compares the advertised `resource` with
   * the URL it actually used.
   */
  path: string;
  /** The decoded endpoint name, the value `findByName` is asked about. */
  name: string;
  transport: PublicMcpTransport;
}

function isPublicMcpTransport(value: string): value is PublicMcpTransport {
  return (PUBLIC_MCP_TRANSPORTS as readonly string[]).includes(value);
}

/**
 * Match `path` (still percent-encoded, without a query string, as Express's
 * `req.path` and `req.baseUrl` give it) against exactly
 * `/metamcp/<name>/(mcp|sse|api)`. Returns null for anything else: an extra
 * segment, a trailing slash, an empty or doubled segment, another mount, a
 * transport in another case, a name outside the alphabet above, an encoding
 * that does not decode, or a name that decodes to a dot segment (`.`, `..`,
 * `%2e%2e`), which a URL resolver would collapse into a different path.
 */
export function matchPublicMcpResourcePath(
  path: string,
): PublicMcpResourcePath | null {
  const segments = path.split("/");
  if (segments.length !== 4) {
    return null;
  }

  const [leading, mount, rawName, transport] = segments;
  if (
    leading !== "" ||
    `/${mount}` !== PUBLIC_MCP_MOUNT ||
    rawName === undefined ||
    transport === undefined ||
    !isPublicMcpTransport(transport) ||
    !RESOURCE_NAME_SEGMENT.test(rawName)
  ) {
    return null;
  }

  let name: string;
  try {
    // `req.path` is still percent-encoded; `lookupEndpoint` matches against
    // the DECODED `req.params.endpoint_name`, so decode to ask the same
    // question of the same table.
    name = decodeURIComponent(rawName);
  } catch {
    return null;
  }

  if (name === "." || name === "..") {
    return null;
  }

  return {
    path: `${PUBLIC_MCP_MOUNT}/${rawName}/${transport}`,
    name,
    transport,
  };
}
