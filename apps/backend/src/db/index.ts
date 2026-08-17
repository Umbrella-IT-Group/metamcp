import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";

import logger from "@/utils/logger";

import { resolveRuntimeConnection } from "./runtime-connection";
import * as schema from "./schema";

const { POSTGRES_CA_CERT } = process.env;

// The RUNTIME connection, which is DATABASE_URL unless the optional
// NOSUPERUSER role split is configured — see ./runtime-connection for why the
// request path and `drizzle-kit migrate` want different privilege levels.
// `drizzle.config.ts` deliberately keeps reading DATABASE_URL: migrations are
// the DDL that needs ownership.
export const runtimeConnection = resolveRuntimeConnection();

// Use an explicit pg Pool so we can attach a global error handler.
// This prevents unhandled 'error' events from bringing down the Node process
// when the database terminates idle connections (e.g., during maintenance).
export const pool = new Pool({
  connectionString: runtimeConnection.connectionString,
  ...(POSTGRES_CA_CERT && {
    ssl: {
      ca: POSTGRES_CA_CERT,
      rejectUnauthorized: true,
    },
  }),
});

pool.on("error", (err) => {
  // Log and continue so the process doesn't crash on idle client errors.
  // pg-pool will create a new client on the next checkout automatically.
  logger.error("PostgreSQL pool error (ignored):", err);
});

export const db = drizzle(pool, { schema });
