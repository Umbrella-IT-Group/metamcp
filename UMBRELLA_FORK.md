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

| Date | Description | Files | Notes |
|---|---|---|---|
| 2026-05-07 | Make access + refresh TTLs env-configurable; bump defaults to 24h / 365d | `apps/backend/src/routers/oauth/token.ts` | `OAUTH_ACCESS_TOKEN_TTL_SECONDS`, `OAUTH_REFRESH_TOKEN_TTL_SECONDS` env vars. Defaults match Umbrella's max-connectivity policy. |
| 2026-05-07 | Make better-auth session lifetime env-configurable; bump defaults to 30d / 7d | `apps/backend/src/auth.ts` | `BETTER_AUTH_SESSION_EXPIRES_IN_SECONDS`, `BETTER_AUTH_SESSION_UPDATE_AGE_SECONDS`. |

Candidates to upstream: both. Mostly a one-line ENV-fallback pattern — non-breaking, opinion-free. File alongside our other PRs once stable.

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
