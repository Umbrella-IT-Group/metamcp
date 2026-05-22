# Umbrella IT Group fork of MetaMCP

This is a maintained downstream fork of [`metatool-ai/metamcp`](https://github.com/metatool-ai/metamcp). Upstream has been effectively unmaintained since 2026-02-08 (no merges in 88+ days as of fork creation). We carry community PRs that upstream isn't reviewing, plus our own targeted fixes, on the `umbrella` branch.

## Why fork

1. **OAuth refresh tokens.** Upstream advertises `refresh_token` in `/.well-known/oauth-authorization-server` but the token endpoint hard-rejects that grant. Result: Claude.ai's custom MCP connectors disconnect every 60 minutes (the hardcoded access-token TTL) and force re-authentication. Cherry-picked from upstream PR #276.
2. **Long-lived configurable TTLs.** Upstream hardcodes 1-hour access tokens. We make access + refresh + better-auth-session lifetimes env-var configurable, with defaults tuned for max connectivity (24h / 365d / 30d).
3. **Session lifecycle fixes.** Upstream PR #283 (ours), #260, #282 — sessions getting stuck in stale states.
4. **Subprocess cleanup.** Upstream PR #273 — child processes of terminated servers leak, eventually OOM the host.
5. **Per-server header forwarding.** Upstream PR #256 — flexibility for cross-tenant routing.

The MIT license permits this fork-and-maintain pattern explicitly.

## Branch model

- `main` — mirrors upstream `metatool-ai/metamcp:main`. **Never** push our changes here directly. `git pull --rebase upstream main` periodically to track.
- `umbrella` — our integration line. All deployable work lives here. Default branch on this fork.
- `feature/<short-name>` — short-lived per-PR branches off `umbrella`. Merge with squash. Delete after merge.

`umbrella` is the line that gets built into `ghcr.io/umbrella-it-group/metamcp:latest` and deployed to `mcp.umbrellaitgroup.com`.

## Remotes

| Remote | URL | What it tracks |
|---|---|---|
| `origin` | `git@github.com:Umbrella-IT-Group/metamcp.git` | This fork. Push to `umbrella` and feature branches here. |
| `upstream` | `https://github.com/metatool-ai/metamcp.git` | Canonical upstream. Read-only — fetch for rebase comparison and to grab new community PRs. |

Other forks worth watching when looking for community work to cherry-pick (add as remotes only when actively reviewing — don't keep them around as noise):

- `cjam28/metamcp` — heavy OAuth-discovery polish (35 commits ahead of upstream as of 2026-04-30). `userinfo` real-identity, public-URL `/oauth/register`, spec-strict discovery metadata, `[TRACE-OAUTH]` logging.
- `Janhouse/metamcp` — dependency line (zod 3→4, MCP SDK 1.16→1.29). Conflict-heavy, take last after other PRs land.

## Cherry-pick log

Track every commit we pull in. When upstream merges the same patch, we drop ours during the next rebase and replace with the upstream sha so history converges if upstream ever revives.

| Date | Source | Upstream PR | Commit on `umbrella` | Notes |
|---|---|---|---|---|
| 2026-05-07 | `loris-av` | [#276](https://github.com/metatool-ai/metamcp/pull/276) | `f446ce3`, `69e4b4f`, `138668a` (squashed into PR #1 on `umbrella`) | OAuth refresh-token grant + MAX_TOTAL_CONNECTIONS + SESSION_LIFETIME env vars. Umbrella patch on top: env-configurable TTLs (24h access / 365d refresh / 30d session). |
| 2026-05-07 | `UmbrellaITSolutions` | [#283](https://github.com/metatool-ai/metamcp/pull/283) | `1f1c937` | Re-init backend session on HTTP 404 "Session not found". Our PR. |
| 2026-05-07 | `tremlin` | [#273](https://github.com/metatool-ai/metamcp/pull/273) | `dcbe7bb`, `b63d709` | Subprocess leak fix — addresses upstream issues #128/#162 OOM cluster. Includes graceful SIGTERM + concurrency-safe creating-idle-sessions guard. |
| 2026-05-07 | `BTForIT` | [#260](https://github.com/metatool-ai/metamcp/pull/260) | `7a0535a`, `7289173`, `0cc901c`, `909ab61` | Per-server connection cap, cold-start warmup, idle-based session timestamps, admin reset/shutdown API. The `cee1356` per-server-cap commit conflicted with #273's concurrency guard — resolved by running cap check before entering critical section. |
| **DEFERRED** | `BenjaminAronsson` | [#256](https://github.com/metatool-ai/metamcp/pull/256) | — | Per-server client header forwarding (12 commits, conflicts with #273 + #260 in `mcp-server-pool.ts`). Deferred to Phase 2.5. Migration `0014_dapper_jigsaw.sql` will need renumbering to `0015` to land after #276's `0014_oauth_refresh_token.sql`. |

## Our own patches (no upstream PR)

These are Umbrella-specific deltas. Each one should eventually be either upstreamed or replaced by an upstream alternative.

| Date | Fork PR | Description | Files | Upstream candidate? |
|---|---|---|---|---|
| 2026-05-07 | [#1](https://github.com/Umbrella-IT-Group/metamcp/pull/1) | Make access + refresh TTLs env-configurable; bump defaults to 24h / 365d | `apps/backend/src/routers/oauth/token.ts` | Yes — wait for upstream PR #276 to merge first, then file the env-var overlay. |
| 2026-05-07 | [#1](https://github.com/Umbrella-IT-Group/metamcp/pull/1) | Make better-auth session lifetime env-configurable; bump defaults to 30d / 7d | `apps/backend/src/auth.ts` | Yes — already filed as [metatool-ai/metamcp#286](https://github.com/metatool-ai/metamcp/pull/286). |
| 2026-05-07 | [#3](https://github.com/Umbrella-IT-Group/metamcp/pull/3) | Drop arm64 cross-build from CI | `.github/workflows/umbrella-build.yml` | No — Umbrella-specific deploy target. |
| 2026-05-07 | [#4](https://github.com/Umbrella-IT-Group/metamcp/pull/4) | Add `0014_oauth_refresh_token` entry to drizzle journal that PR #276 cherry-pick missed | `apps/backend/drizzle/meta/_journal.json` | Yes — once upstream PR #276 merges, journal needs this entry. |
| 2026-05-07 | [#5](https://github.com/Umbrella-IT-Group/metamcp/pull/5) | Make `0014_oauth_refresh_token.sql` migration idempotent (`ADD COLUMN IF NOT EXISTS`) | `apps/backend/drizzle/0014_oauth_refresh_token.sql` | Yes — defends any deployer from hash-mismatch crash-loop. |
| 2026-05-07 | [#6](https://github.com/Umbrella-IT-Group/metamcp/pull/6) | `/health/upstream` rollup endpoint with per-backend-MCP reachability | `apps/backend/src/index.ts` | Yes — clean addition, useful for any operator. |
| 2026-05-07 | [#7](https://github.com/Umbrella-IT-Group/metamcp/pull/7) | Replace MetaMCP brand with Umbrella IT Group wordmark on sidebar + browser-tab metadata | `apps/frontend/app/[locale]/(sidebar)/layout.tsx`, `apps/frontend/app/layout.tsx`, `apps/frontend/public/umbrella-wordmark.png` | No — Umbrella-specific. |
| 2026-05-07 | [#8](https://github.com/Umbrella-IT-Group/metamcp/pull/8) | Proxy `/health/*` paths to backend (was 404 on `/health/upstream` because rewrite was exact-match only) | `apps/frontend/next.config.js` | Yes — pairs with #6 if that's upstreamed. |
| 2026-05-07 | [#9](https://github.com/Umbrella-IT-Group/metamcp/pull/9) | Copy `apps/frontend/public/` in Dockerfile (Next.js 15 standalone doesn't auto-copy) + use square `Umbrella Bug` brandmark | `Dockerfile`, `apps/frontend/app/[locale]/(sidebar)/layout.tsx`, `apps/frontend/public/umbrella-bug.png`, `apps/frontend/public/umbrella-logo-full.png` | Dockerfile fix yes, sidebar text no. |
| 2026-05-08 | [#11](https://github.com/Umbrella-IT-Group/metamcp/pull/11) | OAuth cleanup TypeError fix: `oauth.repo.ts:147` `isNotNull(refresh_token).not()` → `isNull(refresh_token)`. The `.not()` chain isn't valid on a Drizzle `SQL` predicate; the cleanup task throws every tick, expired access tokens with no refresh token accumulate forever, and the leaked rows trip `MAX_CONNECTIONS_PER_SERVER` for downstream consumers (see `Umbrella-MCP-Server` PR #124 for the cap-bump companion fix). Diagnosed via third-agent break-glass on `mcp-host-prod` 2026-05-08; intent confirmed by the on-line-133 comment "(or refresh token is null)". | `apps/backend/src/db/repositories/oauth.repo.ts` | Yes — straight bug fix, should be upstreamed (regardless of whether upstream's session lifecycle differs, this code path exists upstream and is broken there too). |
| 2026-05-08 | [#12](https://github.com/Umbrella-IT-Group/metamcp/pull/12) | Hardens PR #283's session-lost recovery — extends `isBackendSessionLostError` to walk `.cause` chains, accept non-Error throwables, inspect `.code` on object inputs, and JSON-stringify nested envelopes; also engages the same recovery path on the dynamic-find `tools/list` failure in `metamcp-proxy.ts`. Production observation: between an `mcp-autotask` Watchtower restart at 2026-05-08T20:58Z and a manual MetaMCP restart at 21:15Z, 138 `-32600 "Session not found"` events fired without the existing detector tripping, despite the rendered string clearly containing all three matched substrings. Root cause not reproducible against synthetic test fixtures, so the fix takes the defensive path: broaden the detector against every plausible wrap shape + close the dynamic-find gap that silently logged-and-continued. 9 new tests cover the new shapes (cause-walk, plain envelope object, custom toString, circular cause, etc.). Existing 5 tests still pass. | `apps/backend/src/lib/metamcp/session-error.ts`, `apps/backend/src/lib/metamcp/session-error.test.ts`, `apps/backend/src/lib/metamcp/metamcp-proxy.ts` | Yes — pairs with PR #283 (`1f1c937`); both should land upstream as a unit. |
| 2026-05-14 | [#13](https://github.com/Umbrella-IT-Group/metamcp/pull/13) | Broadens PR #12's session-lost recovery to also handle the SDK transport-lost (`"Not connected"`) envelope. Adds `isBackendTransportLostError` (sibling detector, same hardening posture) + `isRecoverableBackendError` (union predicate). Recovery callsites in `metamcp-proxy.ts` switched to the union. Production observation: 2026-05-14T08:00–08:02Z six Tara n8n execs failed with `"Not connected"` 500 during the Bravo[autotask] punch list rollout (#137–#142); 2026-05-14T14:32Z Captain's Claude.ai connector hit `-32603 "Not connected"` on every call — gateway alive (curl `/` → 307), backend container UP, cached pool entry dead. Operator escalation 2026-05-14T16:54Z: "It's not acceptable for having MCP servers down or needing reboots after small change applications." Retires the `sudo docker restart metamcp` workaround. 14 new tests on transport-lost + 4 on the union predicate, 29 total in the file. | `apps/backend/src/lib/metamcp/session-error.ts`, `apps/backend/src/lib/metamcp/session-error.test.ts`, `apps/backend/src/lib/metamcp/metamcp-proxy.ts` | Yes — bundled with PR #12's surface, filed upstream as [metatool-ai/metamcp#293](https://github.com/metatool-ai/metamcp/pull/293). |
| 2026-05-14 | [#15](https://github.com/Umbrella-IT-Group/metamcp/pull/15) | **Lazy session recovery** — closes the metamcp-restart cascade that PR #12/#13 don't address. When metamcp itself restarts, the in-memory `sessionManager` is empty, so every consumer's cached `Mcp-Session-Id` returns 404 "Session not found" until manual re-init. This PR persists session metadata (sessionId, namespace, endpoint, SHA-256 auth principal, init params) to `mcp_sessions` on init; on subsequent requests where the in-memory transport is missing, the router queries the table, re-validates the auth principal in constant time, rebuilds the transport, and replays the request. Cross-namespace replay defense: the stored namespace + endpoint must match the request's. Auth-method discriminator: api_key vs oauth sessions can't be swapped. Pruner reaps rows older than `MCP_SESSION_TTL_DAYS` (default 7) on boot + every `MCP_SESSION_PRUNER_INTERVAL_MS` (default 24h). New file `lib/metamcp/session-auth.ts` (hashing + constant-time compare), new repo `db/repositories/mcp-sessions.repo.ts`, new schema table + migration `0015_mcp_sessions.sql`. 17 new tests: 10 on the auth helpers, 7 on the repository contract. Operator quote 2026-05-14T17:24Z: "Option 1 would be perfect. Let's build it." Closes the documented stale-session workaround for good — Streamable-HTTP metamcp restarts are now transparent to consumers. Merged 2026-05-14T17:54Z (`f0f636f`). | `apps/backend/src/db/schema.ts`, `apps/backend/drizzle/0015_mcp_sessions.sql`, `apps/backend/drizzle/meta/_journal.json`, `apps/backend/src/db/repositories/mcp-sessions.repo.ts`, `apps/backend/src/lib/metamcp/session-auth.ts`, `apps/backend/src/routers/public-metamcp/streamable-http.ts`, `turbo.json` | Yes — files cleanly on top of `main` (no dependency on PR #283); will mirror upstream after fork merge. |
| 2026-05-14 | [#16](https://github.com/Umbrella-IT-Group/metamcp/pull/16) | **Cascade `invalidateServerConnection` across every session for the same `serverUuid`** — closes the recovery-doesn't-recover gap surfaced at 2026-05-14T17:29Z when PR #13's detector fired correctly (`"Backend connection lost ..."` logged) but `getSession`'s cap-reuse branch handed the recovery path a stale `ConnectedClient` cached under a sibling session's slot for the same `serverUuid`. Rewrites `invalidateServerConnection` to iterate every `activeSessions[*][serverUuid]` entry, await per-client `cleanup()` (with per-client try/catch so one failure can't strand siblings), drop the idle slot + `creatingIdleSessions` guard. 7 new vitest cases prove the cascade, the no-touch-other-serverUuids guarantee, idle/creating cleanup, defensive cleanup-throws posture, and the no-op-when-empty case. `vitest.config.ts` `@/` alias added so tests can import `@/utils/logger`. Merged 2026-05-14T17:53Z (`9bdd177`). | `apps/backend/src/lib/metamcp/mcp-server-pool.ts`, `apps/backend/src/lib/metamcp/mcp-server-pool.test.ts`, `apps/backend/vitest.config.ts` | Yes — surface change is contained to `mcp-server-pool`; mirror after the matching upstream `metamcp-proxy.ts` recovery wiring lands (companion to upstream PR #293). |
| 2026-05-14 | [#TBD](https://github.com/Umbrella-IT-Group/metamcp/pulls) | **OpenAPI bridge recovery cascade** — closes the PR #15 post-deploy regression at 2026-05-14T18:30Z where the autotask MCP container restart (PR #143 Watchtower pull) produced repeated `Error POSTing to endpoint (HTTP 404) ... Session not found` events with **no** recovery firing on the OpenAPI consumer path. Root cause: `routers/public-metamcp/openapi/handlers.ts` has its **own fork** of `createOriginalCallToolHandler` + `createOriginalListToolsHandler` that pre-dates PR #13/#15/#16's recovery wiring in `metamcp-proxy.ts`. The OpenAPI fork only logged-and-rethrew on tools/call failure and logged-and-swallowed on tools/list failure. Tara and every other OpenAPI consumer (registry-sync worker, n8n httpRequest node, external integrations) hit this handler. This PR mirrors the Streamable-HTTP path's invalidate-and-retry cascade into both OpenAPI handlers, with `OpenAPI bridge:` log-prefix so operators can split this recovery from the Streamable-HTTP one when investigating. 4 new vitest cases cover the success retry, non-recoverable pass-through, fresh-session-also-fails, and re-acquire-returns-null defensive paths. Operator escalation 2026-05-14T18:31Z: post-deploy traffic stuck behind this gap. | `apps/backend/src/routers/public-metamcp/openapi/handlers.ts`, `apps/backend/src/routers/public-metamcp/openapi/handlers.test.ts` | Yes — straight bug fix to a code path that exists upstream and has the same gap. Pairs with upstream PR #293's detector contribution. |
| 2026-05-21 | [#19](https://github.com/Umbrella-IT-Group/metamcp/pull/19) | **`tools/list_changed` propagation gateway → client** — closes the diagnosed gap where MetaMCP gateway never forwards backend `notifications/tools/list_changed` upstream and never advertises the `listChanged: true` capability on its own `Server`. Research-agent finding (parent context): "Zero `setNotificationHandler` calls anywhere in `apps/backend/src` for the list-changed schema; upstream `Server` capabilities declared `tools: {}` with no `listChanged`." Result before this PR: clients (Claude Code, Claude.ai custom connectors) NEVER learn about new/removed tools without a manual reconnect cycle. Surface: (a) `client.ts` registers a `ToolListChangedNotificationSchema` handler that fans out to a per-`ConnectedClient` `Set<ListChangedSubscriber>`; (b) `metamcp-proxy.ts` flips upstream capability to `tools: { listChanged: true }`, attaches a subscriber at every `getSession` callsite (originalListTools, dynamic-find, and both recovery paths from PR #12/#13/#16) that clears `toolsSyncCache` + emits upstream via `server.notification()`, detaches subscribers on `server.onclose`; (c) `mcp-server-pool.ts` `invalidateServerConnection` snapshots `listChangedSubscribers` BEFORE running cleanup and fires them — this is the watchtower-restart cycle-breaker (backend FastMCP doesn't emit on its own startup, so the invalidation path is the only signal consumers get that tools have moved). Subscriber dedupe is per-upstream-Server (Set semantics) so re-registration on recovery is idempotent. 5 new vitest cases on the fan-out dispatcher (`client.test.ts`) + 4 new cases on the pool's invalidation-fires-subscribers path (extends `mcp-server-pool.test.ts`). Backend FastMCP emit is intentionally out of scope — separate follow-up PR. | `apps/backend/src/lib/metamcp/client.ts`, `apps/backend/src/lib/metamcp/client.test.ts`, `apps/backend/src/lib/metamcp/metamcp-proxy.ts`, `apps/backend/src/lib/metamcp/mcp-server-pool.ts`, `apps/backend/src/lib/metamcp/mcp-server-pool.test.ts` | Yes — capability declaration is spec-conformance, propagation is bug-fix to a path upstream has the same gap on. Pairs with backend-emit follow-up. |
| 2026-05-21 | [#20](https://github.com/Umbrella-IT-Group/metamcp/pull/20) | **HTTP/SSE backend transport-drop detection + exponential reconnect backoff + circuit-breaker reset on recovery** — closes the diagnosed gap where HTTP/SSE backends had no `onclose`/`onerror` parity with STDIO's `ProcessManagedStdioTransport.onprocesscrash`. Watchtower-driven container restarts left the gateway's pooled `ConnectedClient` pointing at a dead socket; the next request hitting that pool entry tripped PR #13/#16's recovery cascade, but idle pool entries (no traffic) sat dead until manual reconnect. Surface: (a) `client.ts` attaches `transport.onclose`/`onerror` on `SSEClientTransport` and `StreamableHTTPClientTransport` instances, plumbs a new `onTransportDrop` callback through `connectMetaMcpClient` (sibling to `onProcessCrash`), tracks a `closing` flag so caller-driven `cleanup()` suppresses the drop callback during normal shutdown, and chains existing handlers so SDK-internal bookkeeping still runs; (b) replaces the fixed-5s `waitFor` reconnect sleep with a documented exponential schedule 1s / 2s / 4s / 8s / 16s / 30s-cap plus ±250ms jitter (`computeReconnectBackoffMs`), env-configurable via `MCP_RECONNECT_BACKOFF_INITIAL_MS` / `_MAX_MS` / `_MULTIPLIER`; (c) `mcp-server-pool.ts` wires `onTransportDrop` to a private `handleTransportDrop` that cascade-invalidates every pool slot for the affected serverUuid (reuses PR #16's path, so PR #19's `listChangedSubscribers` fan-out fires for free), and conditionally calls `serverErrorTracker.resetServerAttempts(uuid)` when the most recent success was within `MCP_RECOVERY_RESET_THRESHOLD_MS` (default 5 min) — transient watchtower bounces don't accumulate the sticky circuit breaker, but sustained failure clusters preserve their count; (d) `server-error-tracker.ts` adds a `markSuccess` method (intent-distinct sibling to `resetServerAttempts`) called on every successful connect. 5 new vitest cases on `handleTransportDrop` (cascade, list_changed synergy with PR #19, within-threshold reset, beyond-threshold no-reset, never-succeeded no-reset) + 2 new cases on the backoff schedule (documented schedule, jitter envelope). **Stacks on PR #19** — uses `listChangedSubscribers` infrastructure introduced there. | `apps/backend/src/lib/metamcp/client.ts`, `apps/backend/src/lib/metamcp/client.test.ts`, `apps/backend/src/lib/metamcp/mcp-server-pool.ts`, `apps/backend/src/lib/metamcp/mcp-server-pool.test.ts`, `apps/backend/src/lib/metamcp/server-error-tracker.ts`, `turbo.json` | Yes — STDIO `onprocesscrash` already exists upstream; this is the missing HTTP/SSE parity. File together with PR #19 if both land on upstream as a single propagation+reconnect surface. |

**Upstream PRs filed back from this fork:**

| Date | Upstream PR | What |
|---|---|---|
| 2026-05-07 | [metatool-ai/metamcp#286](https://github.com/metatool-ai/metamcp/pull/286) | Better-auth session env-var fallback. Branched off plain `main`, no dependency on #276. Awaiting maintainer review (upstream is largely unattended; may sit indefinitely). |
| 2026-05-14 | [metatool-ai/metamcp#293](https://github.com/metatool-ai/metamcp/pull/293) | Adds the recovery-error detectors (`isBackendSessionLostError` + `isBackendTransportLostError` + `isRecoverableBackendError`) that fork PRs #12 + #13 ship. Standalone file contribution — no `metamcp-proxy.ts` rewiring; the recovery callsite is in companion upstream PR #283. Either order works. Awaiting maintainer review. |

## How to update the fork against upstream

```bash
git fetch upstream
git checkout main
git rebase upstream/main
git push origin main

# Now reconcile umbrella against the new main.
git checkout umbrella
git rebase main
# Resolve conflicts. Drop any of our cherry-picks that upstream has merged
# (the cherry-pick log above tells you which).
git push --force-with-lease origin umbrella
```

Cadence: monthly minimum, or whenever a real upstream commit lands that we want.

## Build + deploy

`umbrella` is built by `.github/workflows/build.yml` on every push and tagged `ghcr.io/umbrella-it-group/metamcp:<sha>` + `:latest`. Pinned in `Umbrella-MCP-Server/metamcp/compose.fragment.yml`. Watchtower (with `scope=umbrella` label) auto-updates the running container within ~5 min of an image push.

To deploy a hotfix:

1. Branch off `umbrella`, commit, push, open PR against `umbrella`, get review, squash-merge.
2. CI builds `:latest` automatically.
3. Watchtower polls every 5 min; container restart picks up the new image.
4. If you need it instantly, mint a break-glass session and run `docker compose up -d --no-deps metamcp` from `mcp-host-prod`.

## Upstreaming our work

When we write a patch that's not Umbrella-specific (env-var fallbacks, bug fixes, etc.):

1. Branch off `main` (not `umbrella`) so the patch is clean against upstream.
2. Open PR against `metatool-ai/metamcp`.
3. Once merged upstream, drop our private cherry-pick during the next rebase.

The cherry-pick log doubles as our own upstream-PR backlog — anything in "Our own patches" is a candidate.

## Disclaimer

The `LICENSE` file is unchanged from upstream (MIT). Upstream copyright notice is preserved. Our fork-specific changes are clearly marked in commit messages and in this file's logs.
