import express from "express";

import { auth } from "./auth";
import { autoNukeStaleSessions } from "./lib/metamcp/session-auto-nuke";
import { initializeIdleServers, initializeOnStartup } from "./lib/startup";
import m365Router from "./routers/m365";
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

// Umbrella fork: M365 delegated-token broker enrollment routes
// (better-auth session-gated; boots cleanly when the broker env is
// absent — routes answer 503 not_configured until the secrets land).
app.use(m365Router);

// Mount public endpoints routes (must be before JSON middleware to handle raw streams)
app.use("/metamcp", publicEndpointsRouter);

// Mount MCP proxy routes
app.use("/mcp-proxy", mcpProxyRouter);

// Mount tRPC routes
app.use("/trpc", trpcRouter);

async function start(): Promise<void> {
  // Startup initialization (must run after DB is reachable/migrations are applied, and before listening)
  await initializeOnStartup();

  // Auto-nuke pre-deploy `mcp_sessions` rows ONLY when the advertised
  // MCP server-capability set has changed since the last boot.
  // Capability-neutral restarts (OAuth fixes, dep bumps, transport-
  // disconnect detector tweaks, lint sweeps — i.e. 95%+ of deploys)
  // preserve persistent sessions per PR #15's lazy-recovery design —
  // this helper is a no-op against them and DOES NOT touch those
  // rows.
  //
  // The narrow exception (capability-changing deploys like PR #19)
  // exists because MCP `initialize` negotiates capabilities once per
  // session AND Anthropic's claude.ai MCP connector doesn't honor
  // the spec's "client MUST start a new session on 404" requirement
  // (already documented for PR #18). PR #22 + #23 add the detection;
  // this module + PR #24 add the proactive cleanup so wedged claude.ai
  // sessions surface the issue at most once rather than indefinitely.
  // Full rationale: `lib/metamcp/session-auto-nuke.ts` file-top.
  //
  // Runs after migrations (`initializeOnStartup`) so the
  // `capability_hash` column is guaranteed to exist, and before
  // `app.listen()` so the first inbound request can't race the
  // cleanup. Errors are logged + swallowed inside the helper; the
  // gateway never fails to start because of a transient DB issue
  // here.
  try {
    await autoNukeStaleSessions();
  } catch (err) {
    // Defence-in-depth: the helper itself already try/catches every
    // DB call. This outer guard exists so any future refactor that
    // throws out of the helper (e.g. a constructor error) still
    // doesn't crash the gateway on boot.
    logger.error("Auto-nuke: unexpected error (ignored):", err);
  }

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
    const lastFailureAt = pool.lastConnectFailureAt ?? {};
    const lastSuccessAt = pool.lastConnectSuccessAt ?? {};
    const pingFailures = pool.pingFailures ?? {};

    const details = await Promise.all(
      servers.map(async (s) => {
        const inError = await serverErrorTracker.isServerInErrorState(s.uuid);
        const connectionCount = perServer[s.uuid] ?? 0;
        const failedAt = lastFailureAt[s.uuid];
        const succeededAt = lastSuccessAt[s.uuid];
        // A server is "reachable" unless (a) the ERROR circuit breaker
        // tripped, or (b) it holds zero live connections AND its most
        // recent connect attempt failed (the pool clears the failure
        // stamp on every successful connect). Case (b) is how a
        // hard-down HTTP/SSE backend looks — those never trip ERROR
        // because crash counting is STDIO-only. Zero connections with
        // NO failure stamp is just lazy cold-start: not unhealthy.
        const reachable =
          !inError && !(connectionCount === 0 && failedAt !== undefined);
        return {
          uuid: s.uuid,
          name: s.name,
          in_error: inError,
          connection_count: connectionCount,
          reachable,
          last_connect_failure_at: failedAt
            ? new Date(failedAt).toISOString()
            : null,
          last_connect_success_at: succeededAt
            ? new Date(succeededAt).toISOString()
            : null,
          ping_failures: pingFailures[s.uuid] ?? 0,
        };
      }),
    );

    const totalServers = details.length;
    const errored = details.filter((d) => d.in_error).length;
    const unreachable = details.filter((d) => !d.reachable).length;
    const healthy = unreachable === 0;

    res.json({
      status: "ok",
      healthy,
      total_servers: totalServers,
      errored_servers: errored,
      unreachable_servers: unreachable,
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
