#!/bin/sh

set -e

echo "Starting MetaMCP services..."

# Function to wait for postgres
wait_for_postgres() {
    echo "Waiting for PostgreSQL to be ready..."
    until pg_isready -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER"; do
        echo "PostgreSQL is not ready - sleeping 2 seconds"
        sleep 2
    done
    echo "PostgreSQL is ready!"
}

# Function to run migrations
run_migrations() {
    echo "Running database migrations..."
    cd /app/apps/backend
    
    # Check if migrations need to be run
    if [ -d "drizzle" ] && [ "$(ls -A drizzle/*.sql 2>/dev/null)" ]; then
        echo "Found migration files, running migrations..."
        # Use local drizzle-kit since env vars are available at system level in Docker
        if pnpm exec drizzle-kit migrate; then
            echo "Migrations completed successfully!"
        else
            echo "❌ Migration failed! Exiting..."
            exit 1
        fi
    else
        echo "No migrations found or directory empty"
    fi
    
    cd /app
}

# Umbrella fork: converge the optional NOSUPERUSER runtime role.
#
# Runs AFTER migrations and BEFORE either server process starts, and that order
# is the whole design. Migrations are DDL and need the owner/superuser
# credential in DATABASE_URL; the running gateway does not, and holding it is
# what lets a compromised gateway rewrite its own audit trail (superusers
# bypass GRANTs and can disable or drop a trigger). Granting after the
# migration also means a table a migration created seconds ago is already in
# `ALL TABLES IN SCHEMA public` when the grants run.
#
# Unset METAMCP_RUNTIME_DB_PASSWORD = the split is off and this is a no-op, so
# an existing deployment behaves exactly as before on upgrade. A FAILURE here
# is fatal on purpose: the alternative is booting with the superuser credential
# while the operator believes the split is on.
ensure_runtime_role() {
    if [ -z "${METAMCP_RUNTIME_DB_PASSWORD:-}" ]; then
        return 0
    fi

    if [ ! -x /app/scripts/ensure-runtime-role.sh ]; then
        echo "❌ METAMCP_RUNTIME_DB_PASSWORD is set but /app/scripts/ensure-runtime-role.sh is missing! Exiting..."
        exit 1
    fi

    if /app/scripts/ensure-runtime-role.sh; then
        echo "✅ Runtime database role ready"
    else
        echo "❌ Failed to converge the runtime database role! Exiting..."
        exit 1
    fi
}

# Umbrella fork: white-label branding aliases.
#
# The frontend reads branding through next-runtime-env, which only republishes
# NEXT_PUBLIC_-prefixed vars to the browser — and the sidebar brand is a client
# component, so the canonical names must carry that prefix. Operators should
# not have to care, so accept the short BRANDING_* names too and promote them
# here. Doing it in the entrypoint (rather than in docker-compose.yml) means it
# works for `docker run -e`, Kubernetes, and compose alike, and it happens
# before either server process starts — so the server render and the client
# hydration can never resolve different brands. Any NON-EMPTY NEXT_PUBLIC_
# value wins; an explicitly-empty one is treated as unset and the alias still
# promotes, matching resolveBrandText's empty-means-unset rule. Unset aliases
# are a no-op.
for _brand_key in PRODUCT_NAME ORG_NAME LOGO_PATH DESCRIPTION; do
    _public_var="NEXT_PUBLIC_BRANDING_${_brand_key}"
    _alias_var="BRANDING_${_brand_key}"
    _public_val=$(eval "printf '%s' \"\${${_public_var}:-}\"")
    _alias_val=$(eval "printf '%s' \"\${${_alias_var}:-}\"")
    if [ -z "$_public_val" ] && [ -n "$_alias_val" ]; then
        export "$_public_var=$_alias_val"
        echo "Branding: promoted ${_alias_var} -> ${_public_var}"
    fi
done
unset _brand_key _public_var _alias_var _public_val _alias_val

# Set default values for postgres connection if not provided
POSTGRES_HOST=${POSTGRES_HOST:-postgres}
POSTGRES_PORT=${POSTGRES_PORT:-5432}
POSTGRES_USER=${POSTGRES_USER:-postgres}

# Wait for PostgreSQL
wait_for_postgres

# Run migrations
run_migrations

# Converge the runtime role (no-op unless the split is configured)
ensure_runtime_role

# Start backend in the background
echo "Starting backend server..."
cd /app/apps/backend
PORT=12009 node dist/index.js &
BACKEND_PID=$!

# Wait a moment for backend to start
sleep 3

# Check if backend is still running
if ! kill -0 $BACKEND_PID 2>/dev/null; then
    echo "❌ Backend server died! Exiting..."
    exit 1
fi
echo "✅ Backend server started successfully (PID: $BACKEND_PID)"

# Start frontend
echo "Starting frontend server..."
cd /app/apps/frontend
PORT=12008 pnpm start &
FRONTEND_PID=$!

# Wait a moment for frontend to start
sleep 3

# Check if frontend is still running
if ! kill -0 $FRONTEND_PID 2>/dev/null; then
    echo "❌ Frontend server died! Exiting..."
    kill $BACKEND_PID 2>/dev/null
    exit 1
fi
echo "✅ Frontend server started successfully (PID: $FRONTEND_PID)"

# Function to cleanup on exit
cleanup() {
    echo "Shutting down services..."
    kill $BACKEND_PID 2>/dev/null || true
    kill $FRONTEND_PID 2>/dev/null || true
    wait $BACKEND_PID 2>/dev/null || true
    wait $FRONTEND_PID 2>/dev/null || true
    echo "Services stopped"
}

# Trap signals for graceful shutdown
trap cleanup TERM INT

echo "Services started successfully!"
echo "Backend running on port 12009"
echo "Frontend running on port 12008"

# Wait for both processes
wait $BACKEND_PID
wait $FRONTEND_PID 