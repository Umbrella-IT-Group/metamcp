import express from "express";

import { auth } from "./auth";
import { initializeIdleServers, initializeOnStartup } from "./lib/startup";
import mcpProxyRouter from "./routers/mcp-proxy";
import oauthRouter from "./routers/oauth";
import publicEndpointsRouter from "./routers/public-metamcp";
import trpcRouter from "./routers/trpc";
import logger from "./utils/logger";

const app = express();

// Global JSON middleware for non-proxy routes
app.use((req, res, next) => {
  if (req.path.startsWith("/mcp-proxy/") || req.path.startsWith("/metamcp/")) {
    // Skip JSON parsing for all MCP proxy routes and public endpoints to allow raw stream access
    next();
  } else {
    express.json({ limit: "50mb" })(req, res, next);
  }
});

// Mount OAuth metadata endpoints at root level for .well-known discovery
app.use(oauthRouter);

// Mount better-auth routes by calling auth API directly
app.use(async (req, res, next) => {
  if (req.path.startsWith("/api/auth")) {
    try {
      // Create a web Request object from Express request
      const url = new URL(req.url, `http://${req.headers.host}`);
      const headers = new Headers();

      // Copy headers from Express request
      Object.entries(req.headers).forEach(([key, value]) => {
        if (value) {
          headers.set(key, Array.isArray(value) ? value[0] : value);
        }
      });

      // Create Request object
      const request = new Request(url.toString(), {
        method: req.method,
        headers,
        body:
          req.method !== "GET" && req.method !== "HEAD"
            ? JSON.stringify(req.body)
            : undefined,
      });

      // Call better-auth directly
      const response = await auth.handler(request);

      // Convert Response back to Express response
      res.status(response.status);

      // Copy headers
      response.headers.forEach((value, key) => {
        res.setHeader(key, value);
      });

      // Send body
      const body = await response.text();
      res.send(body);
    } catch (error) {
      logger.error("Auth route error:", error);
      res.status(500).json({
        error: "Internal server error",
        details: error instanceof Error ? error.message : String(error),
      });
    }
    return;
  }
  next();
});

// Mount public endpoints routes (must be before JSON middleware to handle raw streams)
app.use("/metamcp", publicEndpointsRouter);

// Mount MCP proxy routes
app.use("/mcp-proxy", mcpProxyRouter);

// Mount tRPC routes
app.use("/trpc", trpcRouter);

async function start(): Promise<void> {
  // Startup initialization (must run after DB is reachable/migrations are applied, and before listening)
  await initializeOnStartup();

  app.listen(12009, async () => {
    console.log(`Server is running on port 12009`);
    console.log(`Auth routes available at: http://localhost:12009/api/auth`);
    console.log(
      `Public MetaMCP endpoints available at: http://localhost:12009/metamcp`,
    );
    console.log(
      `MCP Proxy routes available at: http://localhost:12009/mcp-proxy`,
    );
    console.log(`tRPC routes available at: http://localhost:12009/trpc`);

    // Wait a moment for the server to be fully ready to handle incoming connections,
    // then initialize idle servers (prevents connection errors when MCP servers connect back)
    console.log(
      "Waiting for server to be fully ready before initializing idle servers...",
    );
    await new Promise((resolve) => setTimeout(resolve, 3000)).then(
      initializeIdleServers,
    );
  });
}

start().catch((err) => {
  console.error("❌ Fatal startup error:", err);
  // Do not throw - keep consistent with other startup behavior
});

// Graceful shutdown: clean up MCP server pools on SIGTERM/SIGINT
// Prevents orphaned STDIO child processes when backend restarts
const gracefulShutdown = async (signal: string) => {
  console.log(`${signal} received, cleaning up MCP server pools...`);
  try {
    const { mcpServerPool } = await import("./lib/metamcp");
    const { metaMcpServerPool } = await import(
      "./lib/metamcp/metamcp-server-pool"
    );
    await Promise.allSettled([
      mcpServerPool.cleanupAll(),
      metaMcpServerPool.cleanupAll(),
    ]);
    console.log("MCP server pools cleaned up successfully");
  } catch (error) {
    console.error("Error during graceful shutdown:", error);
  }
  process.exit(0);
};

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
  });
});

// Umbrella fork: deep health check that rolls up per-backend-MCP state.
// Use case: external probes (Grafana, Cloudflare Healthchecks) want to
// know whether the gateway plus its backends are reachable as a unit,
// not just whether the gateway process is alive. Docker healthcheck
// keeps using the cheap /health above; this is the operational view.
//
// Returns 200 always. The aggregate `healthy` boolean tells the prober
// whether to alarm; the per-server detail tells the operator where to
// look when it flips. Status returns 200 not 503 because liveness is
// distinct from rollup health — Kubernetes-style probes can map both.
app.get("/health/upstream", async (req, res) => {
  try {
    const { mcpServersRepository } = await import("./db/repositories");
    const { mcpServerPool } = await import("./lib/metamcp/mcp-server-pool");
    const { serverErrorTracker } = await import(
      "./lib/metamcp/server-error-tracker"
    );

    const servers = await mcpServersRepository.findAll();
    const pool = mcpServerPool.getPoolStatus();
    const perServer = pool.perServerCounts ?? {};

    const details = await Promise.all(
      servers.map(async (s) => {
        const inError = await serverErrorTracker.isServerInErrorState(s.uuid);
        const connectionCount = perServer[s.uuid] ?? 0;
        return {
          uuid: s.uuid,
          name: s.name,
          in_error: inError,
          connection_count: connectionCount,
          // A server is "reachable" if it isn't in the error state and
          // it has at least one live connection in the pool, or if it
          // hasn't been needed yet (zero connections + no error). Pool
          // emptiness alone is not unhealthy — we cold-start lazily.
          reachable: !inError,
        };
      }),
    );

    const totalServers = details.length;
    const errored = details.filter((d) => d.in_error).length;
    const healthy = errored === 0;

    res.json({
      status: "ok",
      healthy,
      total_servers: totalServers,
      errored_servers: errored,
      pool: {
        idle: pool.idle,
        active: pool.active,
        max_connections_per_server: pool.maxConnectionsPerServer,
      },
      servers: details,
    });
  } catch (error) {
    res.status(500).json({
      status: "error",
      healthy: false,
      error: error instanceof Error ? error.message : String(error),
    });
  }
});
