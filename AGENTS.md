# metamcp (Umbrella IT Group fork)

Guidance for coding agents working in this repo. Facts here come from [`UMBRELLA_FORK.md`](UMBRELLA_FORK.md) and [`CONTRIBUTING.md`](CONTRIBUTING.md); read `UMBRELLA_FORK.md` before changing anything, it holds the branch model, the patch ledger and the deploy path.

## What this repo is

A maintained downstream fork of [`metatool-ai/metamcp`](https://github.com/metatool-ai/metamcp), the MCP gateway Umbrella runs. Upstream's `main` has been frozen since 2026-02-08; upstream revived in June 2026 on a new default branch, `ai-dev` (`UMBRELLA_FORK.md`, Upstream revival). This fork stays on frozen `main` and carries community fixes plus Umbrella's own.

- `umbrella` is the default branch and the deployable line. It is what builds into `ghcr.io/umbrella-it-group/metamcp:latest`. Branch off it and open pull requests against it (squash merge).
- `main` mirrors upstream `metatool-ai/metamcp:main` and never carries our changes. Never push to it.
- Merging here does not change the running gateway. A merge that touches a path the build workflow watches publishes a new image, and the deploy happens only when the bump pull request in `Umbrella-IT-Group/Umbrella-MCP-Server` merges (`UMBRELLA_FORK.md`, Build + deploy).

## Build, test, land

Run what CI runs before you push (`CONTRIBUTING.md`, How to contribute):

```bash
pnpm install --frozen-lockfile
pnpm --filter @repo/zod-types build
pnpm --filter @repo/trpc build
pnpm -C apps/backend test
pnpm -C apps/frontend test
pnpm check-types
```

`pnpm lint` is advisory, not part of CI. Tests and docs land in the same change as the code. One concern per pull request. Every workflow `uses:` stays pinned to a commit SHA and the Dockerfile base image to a digest; a test guards this. No secrets or internal hostnames in code, comments, tests or commit messages. A change to the fork's behavior gets a row at the bottom of the patch table in `UMBRELLA_FORK.md` (newest last), with its pull request number once it has one.

## Ask before you build

Alex Ivantsov owns the architecture of this repo. Before writing code for a new path, a new component, or a mechanism that does what an existing one already does, get his yes first: send one short design question (what, why, what it overlaps, the alternatives you see) through team__ask or as a draft pull request that holds only a design note, then build after he answers. A teammate's go on a ticket is a go on the task, not a ruling on the design. If the work seems to need something this file lists as a non-goal, stop and ask instead of building around it. Link his answer in the pull request body.

Not for this repo (non-goals), from `UMBRELLA_FORK.md` and `CONTRIBUTING.md`:
- Fork-specific changes on `main`, or any direct push to it. `main` only tracks upstream.
- Rebasing `umbrella` onto upstream's `ai-dev` branch (upstream's live line since June 2026). Operator decision of 2026-07-21: stay on frozen `main`, and take individual community fixes on their own merits.
- Keeping a general fix to ourselves. A patch that is not Umbrella-specific is a candidate for upstream: branch it off `main` and open the pull request against `metatool-ai/metamcp` (`UMBRELLA_FORK.md`, Upstreaming our work). Carrying it here meanwhile is fine.
- Public issues for security vulnerabilities. Follow `SECURITY.md` (private advisory or email).
- Hand deploys. The gateway changes only through the bump pull request in `Umbrella-MCP-Server`; there is no manual `docker compose up` on the host.
