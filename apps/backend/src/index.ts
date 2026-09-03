import express from "express";

import { verifyRuntimeDatabaseRole } from "./db/runtime-role-check";
import { authApiCorsMiddleware } from "./lib/cors-policy";
import { globalBodyParser } from "./lib/global-body-parser";
import {
  buildUpstreamHealthBody,
  buildUpstreamHealthErrorBody,
  isAdminHealthRequest,
} from "./lib/health-upstream";
import { convergeServerBearerTokens } from "./lib/metamcp/server-bearer-converge";
import { autoNukeStaleSessions } from "./lib/metamcp/session-auto-nuke";
import { initializeIdleServers, initializeOnStartup } from "./lib/startup";
import { auditContextMiddleware } from "./middleware/audit-context.middleware";
import { authSigninRateLimitMiddleware } from "./middleware/auth-signin-rate-limit.middleware";
import { errorHandler } from "./middleware/error-handler.middleware";
import { authApiRelay } from "./routers/auth-relay";
import m365Router from "./routers/m365";
import mcpProxyRouter from "./routers/mcp-proxy";
import oauthRouter from "./routers/oauth";
import publicEndpointsRouter from "./routers/public-metamcp";
import trpcRouter from "./routers/trpc";
import logger from "./utils/logger";

const app = express();

// Drop the `X-Powered-By: Express` banner. It names the framework on
// every response, which is free reconnaissance and buys the caller nothing.
// The frontend's equivalent (`X-Powered-By: Next.js`) is turned off with
// `poweredByHeader: false` in apps/frontend/next.config.js.
app.disable("x-powered-by");

// FIRST registration in this file, and it has to stay first — the mirror of
// the errorHandler's "has to stay last" at the bottom. Every audit row's
// `request_id` and `actor_ip` come from here, so any route mounted above it
// would emit rows with neither. It sits ahead of the body parser too, so the
// raw-stream `/mcp-proxy` and `/metamcp` legs (which deliberately skip JSON
// parsing) are covered as well: those are the MCP data plane, i.e. exactly
// the paths the 2026-08-13 attacker's stolen credential would have been used
// on. See ./middleware/audit-context.middleware for the CF-Connecting-IP
// trust assumption and for why `trust proxy` is deliberately NOT set with it.
app.use(auditContextMiddleware);

// Global JSON middleware for non-proxy routes.
//
// The branches live in ./lib/global-body-parser rather than inline here for
// one reason: this file calls `app.listen()` at module scope and so cannot be
// imported by a test. Inline, the only available coverage was a test that
// hand-copied these branches into a model app — which stayed green when the
// real ones were deleted. See that module's header for what each lane does and
// why the OAuth skip is what makes the 256kb router limit bind at all.
app.use(globalBodyParser);

// Mount OAuth metadata endpoints at root level for .well-known discovery
app.use(oauthRouter);

// `/api/auth` answers with the session cookie and with session contents, so it
// gets a CORS policy chosen here rather than whatever an earlier-mounted router
// leaves behind — which is what it had. An allowlisted origin is echoed back
// specifically; every other origin gets no `Access-Control-Allow-Origin` at
// all. Never `*` and never a blind reflection of the caller's `Origin`: either
// one turns a cookie-authenticated response into a cross-site read. The
// allowlist and the reasoning live in ./lib/cors-policy.
app.use(authApiCorsMiddleware);

// Per-caller cap on the password-carrying POSTs. AFTER the CORS policy above,
// so a 429 carries the headers a browser needs to surface it as a 429 rather
// than as an opaque network failure, and BEFORE the relay, because a request
// refused after `auth.handler` has run has already spent the password check and
// written the append-only `audit_log` row this limiter exists to bound. It
// answers `POST /api/auth/sign-in/email` and `POST /api/auth/sign-up/email`
// (sign-up also carries a password and, with signup disabled, each POST writes
// an append-only audit row); everything else on this surface — SSO, callbacks,
// session reads, sign-out, dynamic client registration — passes straight
// through. See ./middleware/auth-signin-rate-limit.middleware.
app.use(authSigninRateLimitMiddleware);

// Mount better-auth routes by calling auth API directly. The relay body lives
// in ./routers/auth-relay so it can be imported by a test — this file cannot,
// because it calls `app.listen()` at module scope.
app.use(authApiRelay);

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
  // FIRST, so the privilege the gateway is actually holding is the first thing
  // in the boot log rather than something an operator has to go and prove by
  // hand. Never fatal: a failed check must not turn a privilege question into
  // an outage, but it is always logged — see ./db/runtime-role-check.
  try {
    await verifyRuntimeDatabaseRole();
  } catch (err) {
    logger.error("Runtime DB role check failed (continuing):", err);
  }

  // Startup initialization (must run after DB is reachable/migrations are applied, and before listening)
  await initializeOnStartup();

  // Encrypt any legacy plaintext mcp_servers.bearer_token once, then arm the
  // read path's fail-closed rule. Sequenced AFTER
  // the 0036 migration (applied before start()) and BEFORE the idle pool warms
  // in initializeIdleServers() below, so every serverParams the pool builds
  // reads a converged column. The helper never throws (it logs and, when it
  // cannot encrypt for lack of a KEK, leaves legacy rows honoured and retries
  // next boot); this outer guard is defence-in-depth so the gateway still
  // starts if a future refactor throws out of it.
  try {
    await convergeServerBearerTokens();
  } catch (err) {
    logger.error("Bearer-token converge: unexpected error (ignored):", err);
  }

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
    // Part of the pool-cap work: clear the public-session idle-TTL
    // sweeper's timer on shutdown, same dispose discipline as PR #70's
    // tools sweep (`toolsSweepTimer` cleared in `mcp-server-pool.ts`'s
    // `cleanupAll`) — a sync call, no need for the Promise.allSettled
    // below.
    const { stopPublicSessionSweeper } = await import(
      "./routers/public-metamcp/streamable-http"
    );
    stopPublicSessionSweeper();
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
//
// The response is split by role — see ./lib/health-upstream, which owns
// that decision (and is tested). The liveness rollup stays unauthenticated
// because that is what external probes consume and gating it would break
// them; `servers` and `pool` are admin-only.
app.get("/health/upstream", async (req, res) => {
  try {
    const { mcpServersRepository } = await import("./db/repositories");
    const { mcpServerPool } = await import("./lib/metamcp/mcp-server-pool");
    const { serverErrorTracker } = await import(
      "./lib/metamcp/server-error-tracker"
    );

    const servers = await mcpServersRepository.findAll();
    const pool = mcpServerPool.getPoolStatus();
    const poolConfig = mcpServerPool.getPoolConfig();
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

    const isAdmin = await isAdminHealthRequest(req);

    res.json(
      buildUpstreamHealthBody(
        {
          healthy,
          total_servers: totalServers,
          errored_servers: errored,
          unreachable_servers: unreachable,
        },
        isAdmin
          ? {
              pool: {
                idle: pool.idle,
                active: pool.active,
                pending: pool.pending ?? 0,
                // pending-inclusive so `total` matches what
                // canCreateConnection's MAX_TOTAL_CONNECTIONS check actually
                // compares against (getTotalConnectionCount =
                // idle+active+pending) — a total that silently dropped
                // in-flight idle creations would read below the cap while the
                // pool itself refuses new connections at it (2026-07-14 audit
                // finding).
                total: pool.idle + pool.active + (pool.pending ?? 0),
                // Effective caps the pool actually enforces (from
                // getPoolConfig, the single source of truth), NOT a re-parse
                // of env with local defaults. The prior payload reported only
                // the per-server cap and never the global cap, so an operator
                // debugging saturation could not see it.
                max_connections_per_server: poolConfig.maxConnectionsPerServer,
                max_total_connections: poolConfig.maxTotalConnections,
              },
              servers: details,
            }
          : null,
      ),
    );
  } catch (error) {
    // Logged here, never serialised: the body is the constant from
    // ./lib/health-upstream, because this endpoint answers unauthenticated
    // callers and a driver error's message names internal hosts and SQL.
    logger.error("/health/upstream failed:", error);
    res.status(500).json(buildUpstreamHealthErrorBody());
  }
});

// LAST registration in this file, and it has to stay last. Express dispatches
// error middleware in registration order, so one mounted above a router never
// sees that router's errors — and `app.listen()` runs inside `start()` after
// an `await`, so every `app.use`/`app.get` at module scope (including this
// one) is registered before the first request can arrive.
//
// Until this existed, a malformed JSON body was answered by Express's built-in
// final handler with a full stack trace: `/app/...` paths, the pnpm store
// layout with dependency names and versions, node internals — to an
// unauthenticated caller. See ./middleware/error-handler.middleware.
app.use(errorHandler);
