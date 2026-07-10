/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  experimental: {
    proxyTimeout: 1000 * 120,
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
