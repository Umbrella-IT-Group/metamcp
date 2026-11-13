import express from "express";
import helmet from "helmet";

import { logBasicAuthEnforcementState } from "./auth";
import { verifyRuntimeDatabaseRole } from "./db/runtime-role-check";
import { convergeConfiguredAdmins } from "./lib/admin-converge";
import { warnIfAdminPlaneTokenAuthDisabled } from "./lib/admin-plane-auth";
import { warnIfApiKeyIpPolicyDisabled } from "./lib/api-key-ip-policy";
import { authApiCorsMiddleware } from "./lib/cors-policy";
import { warnOnUnpairedRestrictedEndpoints } from "./lib/endpoint-pairing-check";
import {
  declaredLengthGuard,
  globalBodyParser,
} from "./lib/global-body-parser";
import { createUpstreamHealthHandler } from "./lib/health-upstream-handler";
import { convergeM365Envelopes } from "./lib/m365/envelope-converge";
import { initializeRetiredTools } from "./lib/metamcp/retired-tools";
import { convergeServerBearerTokens } from "./lib/metamcp/server-bearer-converge";
import { autoNukeStaleSessions } from "./lib/metamcp/session-auto-nuke";
import { warnIfStdioServersAllowed } from "./lib/metamcp/stdio-policy";
import { warnIfGatewayBackendSecretUnset } from "./lib/metamcp/url-guard";
import { assertVerifiedCallerConfig } from "./lib/metamcp/verified-caller";
import { logOriginPolicyBootState } from "./lib/origin-policy";
import { initializeIdleServers, initializeOnStartup } from "./lib/startup";
import { auditContextMiddleware } from "./middleware/audit-context.middleware";
import { authSigninRateLimitMiddleware } from "./middleware/auth-signin-rate-limit.middleware";
import { errorHandler } from "./middleware/error-handler.middleware";
import { authApiRelay } from "./routers/auth-relay";
import m365Router from "./routers/m365";
import mcpProxyRouter from "./routers/mcp-proxy";
import oauthRouter from "./routers/oauth";
import { initOAuthDcrMode } from "./routers/oauth/dcr-mode";
import publicEndpointsRouter from "./routers/public-metamcp";
import trpcRouter from "./routers/trpc";
import logger from "./utils/logger";

// Refuse to start when one backend is named in both VERIFIED_CALLER_SERVER_NAMES
// and M365_INJECTED_SERVER_NAMES: that backend would have two writers for its
// X-Umbrella-User-Id, the header it trusts to say who is calling. At module
// scope, before any route is registered, so the throw exits the process with
// the reason instead of reaching start(), whose catch only logs. Logs which
// backends receive the verified caller when any are named. See
// ./lib/metamcp/verified-caller.
assertVerifiedCallerConfig();

// Resolve OAUTH_DCR_MODE (pending | off | open) once, at module scope for the
// same reason: OAUTH_DCR_MODE=open outside NODE_ENV development or test throws
// here and stops the process with its reason, and an unknown or empty value is
// logged as a boot warning (it resolves to off). Every registration request
// then reads the latched value. See ./routers/oauth/dcr-mode.
initOAuthDcrMode();

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

// Request-body policy: the declared-length guard, then the per-surface JSON
// lanes. Both ahead of every router, and the guard ahead of every body parser,
// including each router's own: it answers 413, from the headers alone, any
// request on any path or method whose declared Content-Length is over the
// largest body the frontend forwards (10 MiB). Mounted after the audit context
// above, which reads no body, so a refusal still carries its request id.
//
// The branches live in ./lib/global-body-parser rather than inline here for
// one reason: this file calls `app.listen()` at module scope and so cannot be
// imported by a test. Inline, the only available coverage was a test that
// hand-copied these branches into a model app — which stayed green when the
// real ones were deleted. See that module's header for what each lane does and
// why the OAuth skip is what makes the 256kb router limit bind at all.
app.use(declaredLengthGuard);
app.use(globalBodyParser);

// App-wide security response headers, ahead of every router. helmet was only
// mounted per-router on /trpc and /mcp-proxy, so the /api/auth relay (which
// answers with the session cookie), /health, /metamcp and the OAuth surface
// each carried whatever the framework left behind: no nosniff, no frame
// denial, no default CSP. Mounting it here gives them all the same baseline in
// one place. It sits BEFORE the routers on purpose: the OAuth router's own
// securityHeaders and the per-router helmet still run afterwards and override
// the specific headers they set (X-Frame-Options DENY, the OAuth CSP), so this
// only fills the gaps and never weakens their tighter values. It does not touch
// the request body or CORS, so the deliberate /api/auth CORS policy mounted
// below is unaffected.
app.use(helmet());

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

  // Promote the accounts METAMCP_ADMIN_EMAIL names, then warn if the gateway
  // still has no administrator (fork issue #196). AFTER bootstrap, so an
  // account BOOTSTRAP_USERS created on this boot can be promoted on this boot;
  // BEFORE listening, so no request is served under the pre-converge roles.
  // Independent of BOOTSTRAP_ENABLE on purpose: an install that never used
  // bootstrap is exactly the one #196 left with zero admins. Unset variable =
  // no writes. The helper logs and swallows its own failures; this guard is
  // defence-in-depth so a future throw cannot stop the gateway starting.
  try {
    await convergeConfiguredAdmins();
  } catch (err) {
    logger.error("Admin converge: unexpected error (ignored):", err);
  }

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

  // Converge the M365 refresh-token envelopes toward the explicit target in
  // M365_ENVELOPE_WRITE_VERSION (unset keeps every row as it is and only logs
  // the version counts; while M365_ENVELOPE_STRICT is on it rewraps nothing and
  // only counts the v1 rows that need re-enrollment), and log the envelope
  // posture (strict on/off, effective write version) so it is legible in the
  // boot log. Before listening, so no
  // request of this process mints against a half-converged table. Makes no Entra
  // call and never throws; the outer guard is defence-in-depth, same shape as
  // its neighbour. See ./lib/m365/envelope-converge.
  try {
    await convergeM365Envelopes();
  } catch (err) {
    logger.error("M365 envelope converge: unexpected error (ignored):", err);
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

  // Retired-tool map: load it now so the boot log says how many entries are in
  // play (and "dropped N" if the platform repository's validator and this
  // loader ever disagree), or that the feature is inactive. Data only and fail
  // open: it can only change the text of a call that already failed as an
  // unknown tool, so it is not fatal and never delays listening. The helper does
  // not throw; this guard is defence-in-depth.
  try {
    initializeRetiredTools();
  } catch (err) {
    logger.error("Retired-tools init: unexpected failure (ignored):", err);
  }

  // Surface any pre-existing endpoint left in the unpaired state
  // (restricted=true, require_scoped_api_key=false) so an operator can close
  // the still-open API-key path deliberately. Non-fatal and self-swallowing;
  // see ./lib/endpoint-pairing-check for why these rows are warned about rather
  // than auto-migrated.
  await warnOnUnpairedRestrictedEndpoints();

  // One boot-time signal for the gateway backend trust header: an absent or
  // short secret means backends receive no X-Gateway-Auth, and backends that
  // require it refuse every request but their health check. Kept near the
  // other boot warnings so the gateway's posture is legible from the boot log
  // rather than something to prove by hand.
  warnIfGatewayBackendSecretUnset();

  // One boot-time signal when the admin-plane (control-plane) bearer path has
  // been switched off with ADMIN_PLANE_TOKEN_AUTH_DISABLED=true (migration
  // 0038), so an emergency disable is legible in the boot log.
  warnIfAdminPlaneTokenAuthDisabled();

  // One boot-time signal when API-key IP allowlists are switched off with
  // API_KEY_IP_POLICY_DISABLED=true (migration 0041), so an emergency disable
  // is legible in the boot log rather than discovered when a policy that
  // looks enforced is not.
  warnIfApiKeyIpPolicyDisabled();

  // One boot-time signal when stdio MCP servers have been enabled with
  // ALLOW_STDIO_SERVERS=true, so a deployment that can start child processes
  // in this container says so in its boot log (see lib/metamcp/stdio-policy).
  warnIfStdioServersAllowed();

  // One boot-time line for the Origin policy on /metamcp (MCP_ORIGIN_POLICY:
  // off | audit | enforce, default audit), so the posture is legible from the
  // boot log. An unrecognised value is an ERROR line here and runs as audit,
  // never as off. See lib/origin-policy.
  logOriginPolicyBootState();

  // One boot-time signal for the effective DISABLE_BASIC_AUTH state, so the
  // boot log records whether password login is on. Reads the DB-backed setting,
  // so it runs here after initializeOnStartup(); the live per-request hook in
  // auth.ts is the enforcement point either way.
  await logBasicAuthEnforcementState();

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
// Returns 200 on every computed rollup (a constant 500 only when the rollup
// itself fails). The aggregate `healthy` boolean tells the prober
// whether to alarm; the per-server detail tells the operator where to
// look when it flips. Status returns 200 not 503 because liveness is
// distinct from rollup health — Kubernetes-style probes can map both.
//
// The response is split by role — see ./lib/health-upstream, which owns
// that decision (and is tested). The liveness rollup stays unauthenticated
// because that is what external probes consume and gating it would break
// them; `servers` and `pool` are admin-only.
//
// The handler, its rollup arithmetic and the ten-second cache of the
// anonymous rollup live in ./lib/health-upstream-handler, which is tested;
// this file cannot be imported by a test because it listens at load.
app.get("/health/upstream", createUpstreamHealthHandler());

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
