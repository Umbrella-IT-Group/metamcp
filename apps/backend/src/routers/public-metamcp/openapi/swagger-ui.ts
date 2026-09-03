import crypto from "node:crypto";

/**
 * The Swagger UI documentation page, built as a pure function so its escaping,
 * its Subresource Integrity pins and its Content-Security-Policy are all
 * testable without a live endpoint, an API key or the MCP pool the route needs.
 *
 * The page loads swagger-ui from a CDN. Three things harden that:
 *
 *  1. The endpoint name is interpolated from the request URL, so it is HTML
 *     escaped in the title and JSON-escaped (with `<` neutralised so it cannot
 *     close the script element) in the inline bootstrap. Endpoint names are
 *     charset-restricted to `[A-Za-z0-9_-]` and matched exactly upstream, so
 *     this is defense in depth against a future loosening of that rule, not a
 *     live hole.
 *  2. Every CDN asset carries a Subresource Integrity hash, so a swapped or
 *     compromised CDN artifact is refused by the browser instead of executing
 *     in an admin's session.
 *  3. The response carries its own CSP. The single inline script gets a
 *     per-response nonce; everything else is `'self'` or the pinned CDN.
 */

// Pinned swagger-ui-dist version. The SRI hashes below are for exactly this
// version's files; bumping it means recomputing all three with
// `openssl dgst -sha384 -binary <file> | openssl base64 -A`.
export const SWAGGER_UI_VERSION = "5.10.3";

export const SWAGGER_UI_CDN_ORIGIN = "https://unpkg.com";
const CDN_BASE = `${SWAGGER_UI_CDN_ORIGIN}/swagger-ui-dist@${SWAGGER_UI_VERSION}`;

// sha384 SRI for the pinned assets, cross-checked against a second CDN.
const SRI = {
  css: "sha384-h0W3Vqg5Snxbn56nHu/JCHYsKdSuoEcQneezEWEYGsAdajQJkgD+v9Qy8cuv/1bA",
  bundle:
    "sha384-jVJWQ0wtFEKcwLYTTe3ZTkA8DbVK3s5bLmxjc30v16evmnx8m4NYVsc52bA+qIUl",
  standalone:
    "sha384-azzkurII4f+bjmZvm3hWhj7JezshyXtwobwneRyWCCIksK61Xi0Ry3xA2am9/TWp",
} as const;

/** HTML-escape a value for text and double-quoted attribute contexts. */
function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Encode a value as a JS string literal safe to embed inside `<script>`.
 * JSON.stringify handles quotes, backslashes and control characters; the extra
 * `<` escape stops a `</script>` (or `<!--`) in the value from closing the
 * script element, which JSON alone would not.
 */
function jsStringLiteral(value: string): string {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

/** A per-response nonce for the one inline script. */
export function swaggerUiNonce(): string {
  return crypto.randomBytes(16).toString("base64");
}

/**
 * The CSP for the Swagger UI response. default-src 'self' is the floor;
 * script-src adds the nonce and the pinned CDN (no 'unsafe-inline'); style-src
 * keeps 'unsafe-inline' because swagger-ui injects styles at runtime. The page
 * is framed by no one and frames no one.
 */
export function swaggerUiCsp(nonce: string): string {
  return [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    `script-src 'self' 'nonce-${nonce}' ${SWAGGER_UI_CDN_ORIGIN}`,
    `style-src 'self' 'unsafe-inline' ${SWAGGER_UI_CDN_ORIGIN}`,
    `img-src 'self' data: ${SWAGGER_UI_CDN_ORIGIN}`,
    `font-src 'self' data: ${SWAGGER_UI_CDN_ORIGIN}`,
    "connect-src 'self'",
  ].join("; ");
}

/** Build the Swagger UI HTML page for one endpoint, with the given nonce. */
export function renderSwaggerUiHtml(
  endpointName: string,
  nonce: string,
): string {
  const titleName = escapeHtml(endpointName);
  const openApiUrl = jsStringLiteral(
    `/metamcp/${endpointName}/api/openapi.json`,
  );

  return `
<!DOCTYPE html>
<html>
<head>
    <title>${titleName} API Documentation</title>
    <link rel="stylesheet" type="text/css" href="${CDN_BASE}/swagger-ui.css" integrity="${SRI.css}" crossorigin="anonymous" />
    <style>
        html {
            box-sizing: border-box;
            overflow: -moz-scrollbars-vertical;
            overflow-y: scroll;
        }
        *, *:before, *:after {
            box-sizing: inherit;
        }
        body {
            margin: 0;
            background: #fafafa;
        }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="${CDN_BASE}/swagger-ui-bundle.js" integrity="${SRI.bundle}" crossorigin="anonymous"></script>
    <script src="${CDN_BASE}/swagger-ui-standalone-preset.js" integrity="${SRI.standalone}" crossorigin="anonymous"></script>
    <script nonce="${nonce}">
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: ${openApiUrl},
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout"
            });
        }
    </script>
</body>
</html>`;
}
