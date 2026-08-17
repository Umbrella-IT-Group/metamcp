#!/bin/sh

set -e

echo "🚀 Starting MetaMCP development services..."
echo "📁 Working directory: $(pwd)"
echo "🔍 Node version: $(node --version)"
echo "📦 pnpm version: $(pnpm --version)"

# Wait for Postgres if compose didn't already gate startup
if command -v pg_isready >/dev/null 2>&1; then
    echo "⏳ Checking PostgreSQL readiness..."
    until pg_isready -h "${POSTGRES_HOST:-postgres}" -p "${POSTGRES_PORT:-5432}" -U "${POSTGRES_USER:-metamcp_user}" >/dev/null 2>&1; do
        echo "🔁 PostgreSQL not ready yet, retrying in 2s..."
        sleep 2
    done
    echo "✅ PostgreSQL is ready"
else
    echo "ℹ️ pg_isready not found; relying on docker-compose healthcheck"
fi

# Function to cleanup on exit
cleanup_on_exit() {
    echo "🛑 SHUTDOWN: Received shutdown signal, cleaning up..."
    echo "🛑 SHUTDOWN: Signal received at $(date)"
    
    # Kill the pnpm dev process
    if [ -n "$PNPM_PID" ]; then
        echo "🛑 SHUTDOWN: Killing pnpm dev process (PID: $PNPM_PID)"
        kill -TERM "$PNPM_PID" 2>/dev/null || true
    fi
    
    # Kill any other background processes
    jobs -p | xargs -r kill 2>/dev/null || true
    echo "🛑 SHUTDOWN: Killed background processes"
    
    # Clean up managed containers
    echo "🛑 SHUTDOWN: Starting container cleanup..."
    cleanup_managed_containers
    
    echo "🛑 SHUTDOWN: Development services stopped"
    exit 0
}

# Setup cleanup trap for multiple signals
trap cleanup_on_exit TERM INT EXIT

echo "🔧 Setting up development environment..."
echo "📊 Backend will run on port 12009"
echo "🌐 Frontend will run on port 12008"
echo "🔄 Hot reloading is enabled for both frontend and backend"

# Ensure dependencies are up to date
echo "📦 Checking dependencies..."
pnpm install

# Run database migrations for development
echo "🛠 Running database migrations (dev)..."
(
    set -e
    cd apps/backend
    # drizzle-kit reads DATABASE_URL from env (compose provides it)
    if pnpm exec drizzle-kit migrate; then
        echo "✅ Migrations applied successfully"
    else
        echo "❌ Migration failed. See logs above."
        exit 1
    fi
)

# Converge the optional NOSUPERUSER runtime role — same step, same script and
# same ordering (after migrations, before the servers) as the production
# entrypoint.
#
# This exists because the dev compose reads the SAME .env as the production
# one. Without it, an operator who sets METAMCP_RUNTIME_DB_PASSWORD and then
# brings up the dev stack gets an app dialling a role that was never created,
# and the only symptom is a password-authentication failure that points at
# nothing. Unset, this is a no-op and dev behaves exactly as before.
#
# scripts/ is present without a COPY: docker-compose.dev.yml bind-mounts the
# repository at /app for hot reload.
# Blank means UNSET, matching db/runtime-connection.ts and the production
# entrypoint: a whitespace-only value skips the step, because the app will
# treat it as unset too.
case "${METAMCP_RUNTIME_DB_PASSWORD:-}" in
  *[![:space:]]*)
    echo "🔐 Ensuring runtime database role (dev)..."
    if /app/scripts/ensure-runtime-role.sh; then
        echo "✅ Runtime database role ready"
    else
        echo "❌ Failed to converge the runtime database role. See logs above."
        exit 1
    fi
    ;;
esac

# Start the development servers with proper signal handling
echo "🚀 Starting pnpm dev with turborepo..."
echo "💡 This will start both frontend and backend in development mode"
pnpm dev &
PNPM_PID=$!
echo "🚀 pnpm dev started with PID: $PNPM_PID"

# Wait for the pnpm dev process, but don't block cleanup
wait "$PNPM_PID" || true 
