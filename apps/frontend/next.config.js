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
    return [
      {
        // The OAuth consent screen is the trust anchor of the authorization
        // flow: it is where a human decides whether a client gets access to
        // their account. Framing it would allow a clickjacked Approve, and a
        // referrer leak would hand the signed `areq` token in the query string
        // to whatever the page links or fetches. The backend's own /oauth/*
        // routes get these from securityHeaders in the express router; this
        // page is served by Next.js and had none.
        source: "/:locale/consent",
        headers: [
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Content-Security-Policy", value: "frame-ancestors 'none'" },
          { key: "Referrer-Policy", value: "no-referrer" },
        ],
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
