/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  // Drop the `X-Powered-By: Next.js` banner: it names the framework on
  // every response for free reconnaissance and buys nothing. The backend's
  // equivalent (`X-Powered-By: Express`) is turned off with
  // `app.disable("x-powered-by")` in apps/backend/src/index.ts.
  poweredByHeader: false,
  experimental: {
    proxyTimeout: 1000 * 120,
  },
  async headers() {
    // The value-less security headers, applied to EVERY response, documents
    // and /_next static assets alike. The Content-Security-Policy is NOT here:
    // it carries a per-request nonce and is emitted from middleware.ts, because
    // a static config value cannot hold a nonce and the strict script policy
    // (no 'unsafe-inline') needs one. See lib/security-headers.ts.
    //
    // This replaces the former /consent-only block. Every page, /consent
    // included, now gets the full nonce'd CSP through middleware plus these
    // headers. /consent's former Referrer-Policy of no-referrer becomes
    // strict-origin-when-cross-origin, which still keeps the signed `areq`
    // query string from leaking cross-origin (only the bare origin is sent),
    // and the CSP now also bars /consent from loading any cross-origin
    // subresource that a referrer could leak to.
    const securityHeaders = [
      { key: "X-Frame-Options", value: "DENY" },
      { key: "X-Content-Type-Options", value: "nosniff" },
      { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
      {
        key: "Permissions-Policy",
        value: "camera=(), microphone=(), geolocation=()",
      },
    ];

    // HSTS only in production. The edge terminates TLS and owns the HSTS ramp;
    // this is defense in depth for any direct-to-origin reach. Gated off in
    // development so `next dev` over http://localhost is not force-upgraded to
    // https.
    if (process.env.NODE_ENV === "production") {
      securityHeaders.push({
        key: "Strict-Transport-Security",
        value: "max-age=63072000; includeSubDomains",
      });
    }

    return [
      {
        source: "/:path*",
        headers: securityHeaders,
      },
    ];
  },
  async rewrites() {
    // Use localhost for rewrites since frontend and backend run in the same container
    const backendUrl = "http://localhost:12009";

    return [
      {
        source: "/health",
        destination: `${backendUrl}/health`,
      },
      // Umbrella fork: /health/upstream rollup endpoint also lives on
      // the backend; needs a rewrite or Next.js 404s on the path.
      {
        source: "/health/:path*",
        destination: `${backendUrl}/health/:path*`,
      },
      // OAuth endpoints - proxy all oauth paths
      {
        source: "/oauth/:path*",
        destination: `${backendUrl}/oauth/:path*`,
      },
      // Well-known endpoints - proxy all well-known paths
      {
        source: "/.well-known/:path*",
        destination: `${backendUrl}/.well-known/:path*`,
      },
      // Auth API endpoints
      {
        source: "/api/auth/:path*",
        destination: `${backendUrl}/api/auth/:path*`,
      },
      // Umbrella fork: M365 delegated-token broker enrollment routes
      // (enroll/callback/status/disconnect) live on the backend; the
      // Entra redirect URI points at the public domain, which lands
      // here first — same rewrite requirement as /health.
      {
        source: "/m365/:path*",
        destination: `${backendUrl}/m365/:path*`,
      },
      // Register endpoint for dynamic client registration
      {
        source: "/register",
        destination: `${backendUrl}/api/auth/register`,
      },
      {
        source: "/trpc/:path*",
        destination: `${backendUrl}/trpc/frontend/:path*`,
      },
      {
        source: "/mcp-proxy/:path*",
        destination: `${backendUrl}/mcp-proxy/:path*`,
      },
      {
        source: "/metamcp/:path*",
        destination: `${backendUrl}/metamcp/:path*`,
      },
      {
        source: "/service/:path*",
        destination: "https://metatool-service.jczstudio.workers.dev/:path*",
      },
    ];
  },
};

export default nextConfig;
