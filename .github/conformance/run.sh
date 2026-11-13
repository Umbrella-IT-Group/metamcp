#!/usr/bin/env bash
# Runs the official MCP conformance suite against a locally built gateway.
#
#   DATABASE_URL=postgresql://user@127.0.0.1:5432/metamcp_test \
#     bash .github/conformance/run.sh
#
# The database MUST be a throwaway: the gateway's bootstrap and idle warmup
# write to whatever they boot on. A loopback host and a name ending in `_test`
# (or starting with `conformance`) are required; CONFORMANCE_ALLOW_DB=1 waives
# only the name rule, never the host rule.
#
# Prerequisites: `pnpm install`, the zod-types and trpc builds, the migrations
# applied, `pnpm -C apps/backend build`, and the runner installed with
# `npm ci --ignore-scripts --prefix .github/conformance` on Node 22 or newer
# (the runner needs it). psql, jq, openssl and curl must be on PATH.
#
# Output goes to a fresh directory this script owns beneath CONFORMANCE_OUT
# (default: the system temp directory), never to CONFORMANCE_OUT itself, and
# only that directory is ever deleted. The workflow pre-allocates it
# (CONFORMANCE_RUN_DIR) so its scrub and upload steps know where to look even if
# this script dies early.
#
# Reading a red run, by the class in the ::error title:
#   BASELINE        expected-failures.yml is invalid; nothing was started
#   HARNESS         the stack, the smoke test or the runner itself failed; the
#                   suite result (if any) says nothing about the gateway
#   REGRESSION      a scenario fails that the baseline does not list, or a listed
#                   one now passes (delete its line and snapshot rows)
#   REASON CHANGED  a listed scenario fails for a new reason
#   LEAK            a credential-shaped value was found in the output, which was
#                   deleted
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
CONF="$ROOT/.github/conformance"
BACKEND="$ROOT/apps/backend"
RUNNER_JS="$CONF/node_modules/@modelcontextprotocol/conformance/dist/index.js"
EXPECT_COUNT=32
FIXTURE_PORT=3901
PROXY_PORT=3902
GATEWAY_PORT=12009

# The gateway runs on the Node the image uses; the runner and the harness
# scripts run on whatever `node` is first on PATH (Node 22 in CI).
GATEWAY_NODE="${GATEWAY_NODE:-$(command -v node)}"

FAILED_CLASSES=()
PIDS=()
RUN_DIR=""
PARENT="${CONFORMANCE_OUT:-${TMPDIR:-/tmp}/conformance}"
LEAK=0

# The harness tools run from the backend directory so tsx resolves.
tools() { (cd "$BACKEND" && node --import tsx src/conformance/ci-tools.ts "$@"); }
verify() { (cd "$BACKEND" && node --import tsx src/conformance/verify-results.ts "$@"); }

note() { echo "== $*"; }
annotate() { echo "::error title=$1::$2"; }

abort() {
  FAILED_CLASSES+=("$1")
  annotate "$1" "$2"
  exit 1
}

kill_owned() {
  # Only PIDs this script started. TERM first, KILL after a bounded wait.
  local pid i
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null || true
  done
  for i in 1 2 3 4 5 6 7 8 9 10; do
    local alive=0
    for pid in "${PIDS[@]:-}"; do
      [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && alive=1
    done
    [ "$alive" -eq 0 ] && return 0
    sleep 0.5
  done
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] && kill -KILL "$pid" 2>/dev/null || true
  done
}

finalize() {
  local status=$?
  set +e
  kill_owned
  if [ -n "$RUN_DIR" ] && [ -d "$RUN_DIR" ]; then
    # Scrub before anything else can publish the directory. A hit deletes it
    # (only if it is provably ours); a scanner that could not run leaves it for
    # the workflow's own scrub step, which fails the job and blocks the upload.
    tools scan --dir "$RUN_DIR" --remove-on-hit --parent "$PARENT" --repo-root "$ROOT"
    case $? in
      0) ;;
      1) LEAK=1; annotate LEAK "a credential-shaped value was found in the run output; the directory was deleted" ;;
      *) FAILED_CLASSES+=("HARNESS"); annotate HARNESS "the secret scan could not complete" ;;
    esac
  fi
  if [ "$status" -ne 0 ] || [ "${#FAILED_CLASSES[@]}" -gt 0 ] || [ "$LEAK" -ne 0 ]; then
    exit 1
  fi
  exit 0
}
trap finalize EXIT

# ---------------------------------------------------------------- 0. preflight
note "preflight"

for cmd in jq openssl curl node; do
  command -v "$cmd" >/dev/null 2>&1 || abort HARNESS "required command not found: $cmd"
done
if ! command -v psql >/dev/null 2>&1; then
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    sudo apt-get install -y --no-install-recommends postgresql-client >/dev/null
  else
    abort HARNESS "psql is required (install a PostgreSQL client)"
  fi
fi

[ -n "${DATABASE_URL:-}" ] || abort HARNESS "DATABASE_URL is required"
GUARD_FLAGS=()
if [ "${CONFORMANCE_ALLOW_DB:-}" = "1" ]; then
  GUARD_FLAGS+=(--allow-any-name)
  export PGOPTIONS="-c conformance.allow_db=1"
fi
tools guard-db --url "$DATABASE_URL" ${GUARD_FLAGS[@]+"${GUARD_FLAGS[@]}"} \
  || abort HARNESS "DATABASE_URL is not a throwaway database; refusing to seed or boot on it"

[ -f "$RUNNER_JS" ] || abort HARNESS "the conformance runner is not installed (run npm ci in .github/conformance)"
[ -f "$BACKEND/dist/index.js" ] || abort HARNESS "the backend is not built (run pnpm -C apps/backend build)"

for port in "$FIXTURE_PORT" "$PROXY_PORT" "$GATEWAY_PORT"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    abort HARNESS "port $port is already in use"
  fi
done

# The run directory: pre-allocated by the workflow, or allocated here.
if [ -n "${CONFORMANCE_RUN_DIR:-}" ]; then
  tools verify-run-dir --dir "$CONFORMANCE_RUN_DIR" --parent "$PARENT" --repo-root "$ROOT" \
    || abort HARNESS "CONFORMANCE_RUN_DIR is not a run directory this tooling owns"
  RUN_DIR="$CONFORMANCE_RUN_DIR"
else
  RUN_DIR="$(tools alloc-run-dir --parent "$PARENT" --repo-root "$ROOT")" \
    || abort HARNESS "could not allocate a run directory beneath $PARENT"
fi
mkdir -p "$RUN_DIR/gateway-cwd"
note "run directory: $RUN_DIR"

node "$RUNNER_JS" list --server >"$RUN_DIR/scenarios.txt"
verify baseline --scenarios "$RUN_DIR/scenarios.txt" --baseline "$CONF/expected-failures.yml" --expect-count "$EXPECT_COUNT" \
  || abort BASELINE "expected-failures.yml is invalid (see the lines above); nothing was started"

# ------------------------------------------------------------------ 1. secrets
KEY="sk_mt_$(openssl rand -hex 32)"
AUTH_SECRET="confsec_$(openssl rand -hex 32)"
echo "::add-mask::$KEY"
echo "::add-mask::$AUTH_SECRET"

# ---------------------------------------------------------------------- 2. seed
note "seed"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -f "$CONF/seed.sql" >/dev/null \
  || abort HARNESS "seed.sql failed"

# ------------------------------------------------------------------ 3. fixture
note "fixture"
(cd "$BACKEND" && exec env CONFORMANCE_FIXTURE_PORT="$FIXTURE_PORT" node --import tsx src/conformance/run-fixture.ts) \
  >"$RUN_DIR/fixture.log" 2>&1 &
PIDS+=("$!")
curl -fsS --retry-connrefused --retry 30 --retry-delay 1 --max-time 5 -o /dev/null \
  "http://127.0.0.1:$FIXTURE_PORT/health" \
  || abort HARNESS "the fixture did not come up: $(tail -n 20 "$RUN_DIR/fixture.log")"

# ------------------------------------------------------------------- 4. gateway
note "gateway"
BOOTSTRAP_API_KEYS="$(jq -cn --arg k "$KEY" '[{name:"conformance",is_public:true,key:$k}]')"
BOOTSTRAP_NAMESPACES='[{"name":"conformance","is_public":true}]'
BOOTSTRAP_ENDPOINTS='[{"name":"conformance","namespace":"conformance","enable_auth":true,"enable_auth_query":false,"enable_auth_oauth":false,"is_public":true}]'

# `env -i` with an allowlist: nothing from the caller's shell (an unauthenticated
# endpoint switch, stdio servers, the localhost rewrite, a fail-hard flag) can
# leak into the gateway. Production defaults otherwise. The gateway runs in the
# run directory so its app.log and error.log land inside the owned output, not
# in the checkout.
(cd "$RUN_DIR/gateway-cwd" && exec env -i \
  PATH="$PATH" HOME="${HOME:-/tmp}" NODE_ENV=production LOG_LEVEL=info \
  DATABASE_URL="$DATABASE_URL" BETTER_AUTH_SECRET="$AUTH_SECRET" \
  APP_URL="http://127.0.0.1:$GATEWAY_PORT" \
  BOOTSTRAP_API_KEYS="$BOOTSTRAP_API_KEYS" \
  BOOTSTRAP_NAMESPACES="$BOOTSTRAP_NAMESPACES" \
  BOOTSTRAP_ENDPOINTS="$BOOTSTRAP_ENDPOINTS" \
  "$GATEWAY_NODE" "$BACKEND/dist/index.js") >"$RUN_DIR/gateway.log" 2>&1 &
GATEWAY_PID="$!"
PIDS+=("$GATEWAY_PID")

# ------------------------------------------------------ 5. readiness + bootstrap
note "gateway readiness"
ready=0
for _ in $(seq 1 90); do
  if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
    abort HARNESS "the gateway exited during startup: $(tail -n 40 "$RUN_DIR/gateway.log")"
  fi
  if curl -fsS --max-time 2 -o /dev/null "http://127.0.0.1:$GATEWAY_PORT/health" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
[ "$ready" -eq 1 ] || abort HARNESS "the gateway did not answer /health within 90 s: $(tail -n 40 "$RUN_DIR/gateway.log")"

# Bootstrap failures are warnings, not exits: the log is the only evidence.
tools bootstrap-gate --log "$RUN_DIR/gateway.log" \
  || abort HARNESS "the gateway did not bootstrap the conformance key, namespace and endpoint (lines above)"

# -------------------------------------------------------------------- 6. proxy
note "alias proxy"
UPSTREAM_URL="http://127.0.0.1:$GATEWAY_PORT/metamcp/conformance/mcp"
(cd "$BACKEND" && exec env \
  CONFORMANCE_UPSTREAM_URL="$UPSTREAM_URL" CONFORMANCE_API_KEY="$KEY" \
  CONFORMANCE_TOOL_PREFIX=Fixture CONFORMANCE_PROXY_PORT="$PROXY_PORT" \
  node --import tsx src/conformance/run-alias-proxy.ts) >"$RUN_DIR/proxy.log" 2>&1 &
PIDS+=("$!")
curl -fsS --retry-connrefused --retry 30 --retry-delay 1 --max-time 5 -o /dev/null \
  "http://127.0.0.1:$PROXY_PORT/__health" \
  || abort HARNESS "the alias proxy did not come up: $(tail -n 20 "$RUN_DIR/proxy.log")"

# -------------------------------------------------------------------- 7. smoke
note "smoke"
set +e
(cd "$BACKEND" && \
  CONFORMANCE_UPSTREAM_URL="$UPSTREAM_URL" CONFORMANCE_API_KEY="$KEY" \
  CONFORMANCE_TOOL_PREFIX=Fixture CONFORMANCE_PROXY_PORT="$PROXY_PORT" \
  node --import tsx src/conformance/smoke.ts) 2>&1 | tee "$RUN_DIR/smoke.log"
smoke_rc=${PIPESTATUS[0]}
set -e
[ "$smoke_rc" -eq 0 ] || abort HARNESS "the smoke test failed; the suite was not run (see smoke.log)"

# -------------------------------------------------------------------- 8. suite
note "suite"
set +e
timeout 600 node "$RUNNER_JS" server \
  --url "http://127.0.0.1:$PROXY_PORT/mcp" --suite all --spec-version 2025-11-25 \
  --expected-failures "$CONF/expected-failures.yml" -o "$RUN_DIR/results" \
  2>&1 | tee "$RUN_DIR/runner.log"
runner_rc=${PIPESTATUS[0]}
set -e

verdict="$(tools classify-runner --log "$RUN_DIR/runner.log" --exit-code "$runner_rc")"
verdict_class="${verdict%% *}"
note "runner verdict: $verdict"
case "$verdict_class" in
  OK) ;;
  REGRESSION) FAILED_CLASSES+=("REGRESSION"); annotate REGRESSION "$verdict" ;;
  *) FAILED_CLASSES+=("HARNESS"); annotate HARNESS "$verdict" ;;
esac

# --------------------------------------------- 9. layer 2: the failing-check snapshot
if [ "$verdict_class" != "HARNESS" ]; then
  note "snapshot"
  update_flag=()
  [ "${CONFORMANCE_UPDATE_SNAPSHOT:-}" = "1" ] && update_flag=(--update)
  set +e
  verify results --results "$RUN_DIR/results" --scenarios "$RUN_DIR/scenarios.txt" \
    --baseline "$CONF/expected-failures.yml" --snapshot "$CONF/expected-checks.txt" ${update_flag[@]+"${update_flag[@]}"}
  snapshot_rc=$?
  set -e
  case "$snapshot_rc" in
    0) ;;
    12) FAILED_CLASSES+=("REASON CHANGED"); annotate "REASON CHANGED" "a scenario fails for a different reason than the committed snapshot records (rows above)" ;;
    *) FAILED_CLASSES+=("HARNESS"); annotate HARNESS "the results could not be read (exit $snapshot_rc)" ;;
  esac
fi

# --------------------------------------------------------------- 10. summary
if [ -f "$RUN_DIR/runner.log" ]; then
  {
    echo '```'
    sed -E 's/\x1b\[[0-9;]*m//g; s/(sk_mt_|confsec_)[0-9a-f]{64}/[redacted]/g' "$RUN_DIR/runner.log" | tail -n 80
    echo '```'
  } >>"${GITHUB_STEP_SUMMARY:-/dev/null}"
fi

if [ "${#FAILED_CLASSES[@]}" -gt 0 ]; then
  echo "conformance: FAILED (${FAILED_CLASSES[*]})"
  exit 1
fi
echo "conformance: ok"
