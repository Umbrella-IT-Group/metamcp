import {
  DatabaseMcpServer,
  McpServerCreateInput,
  McpServerErrorStatusEnum,
  McpServerUpdateInput,
} from "@repo/zod-types";
import { and, desc, eq, isNotNull, isNull, like, not, or } from "drizzle-orm";
import { DatabaseError } from "pg";
import { z } from "zod";

import {
  BEARER_ENVELOPE_PREFIX,
  encryptServerBearerToken,
} from "@/lib/metamcp/server-bearer-crypto";
import logger from "@/utils/logger";

import { db } from "../index";
import { mcpServersTable } from "../schema";
import type { DbExecutor } from "./db-executor";
import {
  planServerUpdate,
  ServerCredentialRetentionError,
} from "./mcp-server-update-plan";

// Encrypt a bearer token at the CREATE boundary. A
// non-empty value is stored as an `enc:v1:` envelope; empty/undefined is left
// as-is (STDIO servers and credential-less HTTP servers carry no bearer). This
// is the single write choke for both the endpoint auto-mint and the admin
// create paths, so neither caller changes. Throws (fail-closed) when no KEK is
// configured, see encryptServerBearerToken.
function withEncryptedBearerToken<T extends { bearerToken?: string | null }>(
  input: T,
): T {
  if (input.bearerToken) {
    return {
      ...input,
      bearerToken: encryptServerBearerToken(input.bearerToken),
    };
  }
  return input;
}

// Helper function to handle PostgreSQL errors
function handleDatabaseError(
  error: unknown,
  operation: string,
  serverName?: string,
): never {
  logger.error(`Database error in ${operation}:`, error);

  // Extract the actual PostgreSQL error from Drizzle's error structure
  let pgError: DatabaseError | undefined;

  if (
    error instanceof Error &&
    "cause" in error &&
    error.cause instanceof DatabaseError
  ) {
    // Drizzle wraps the PostgreSQL error in the cause property
    pgError = error.cause;
  } else if (error instanceof DatabaseError) {
    // Direct PostgreSQL error
    pgError = error;
  }

  if (pgError) {
    // Handle unique constraint violation for server name
    if (
      pgError.code === "23505" &&
      pgError.constraint === "mcp_servers_name_user_unique_idx"
    ) {
      throw new Error(
        `Server name "${serverName}" already exists. Server names must be unique within your scope.`,
      );
    }

    // Handle regex constraint violation for server name
    if (
      pgError.code === "23514" &&
      pgError.constraint === "mcp_servers_name_regex_check"
    ) {
      throw new Error(
        `Server name "${serverName}" is invalid. Server names must only contain letters, numbers, underscores, and hyphens.`,
      );
    }
  }

  // For any other database errors, throw a generic user-friendly message
  throw new Error(
    `Failed to ${operation} MCP server. Please check your input and try again.`,
  );
}

export class McpServersRepository {
  async create(
    input: McpServerCreateInput,
    // The caller's transaction when it holds one (an admin-plane write records
    // its audit row in the same transaction). Omitted, the pool is used.
    executor?: DbExecutor,
  ): Promise<DatabaseMcpServer> {
    try {
      const [createdServer] = await (executor ?? db)
        .insert(mcpServersTable)
        .values(withEncryptedBearerToken(input))
        .returning();

      return createdServer;
    } catch (error: unknown) {
      handleDatabaseError(error, "create", input.name);
    }
  }

  async findAll(): Promise<DatabaseMcpServer[]> {
    return await db
      .select()
      .from(mcpServersTable)
      .orderBy(desc(mcpServersTable.created_at));
  }

  // Find servers accessible to a specific user (public + user's own servers)
  async findAllAccessibleToUser(userId: string): Promise<DatabaseMcpServer[]> {
    return await db
      .select()
      .from(mcpServersTable)
      .where(
        or(
          isNull(mcpServersTable.user_id), // Public servers
          eq(mcpServersTable.user_id, userId), // User's own servers
        ),
      )
      .orderBy(desc(mcpServersTable.created_at));
  }

  // Find only public servers (no user ownership)
  async findPublicServers(): Promise<DatabaseMcpServer[]> {
    return await db
      .select()
      .from(mcpServersTable)
      .where(isNull(mcpServersTable.user_id))
      .orderBy(desc(mcpServersTable.created_at));
  }

  // Find servers owned by a specific user
  async findByUserId(userId: string): Promise<DatabaseMcpServer[]> {
    return await db
      .select()
      .from(mcpServersTable)
      .where(eq(mcpServersTable.user_id, userId))
      .orderBy(desc(mcpServersTable.created_at));
  }

  async findByUuid(uuid: string): Promise<DatabaseMcpServer | undefined> {
    const [server] = await db
      .select()
      .from(mcpServersTable)
      .where(eq(mcpServersTable.uuid, uuid))
      .limit(1);

    return server;
  }

  async findByName(name: string): Promise<DatabaseMcpServer | undefined> {
    const [server] = await db
      .select()
      .from(mcpServersTable)
      .where(eq(mcpServersTable.name, name))
      .limit(1);

    return server;
  }

  // Find server by name within user scope (for uniqueness checks)
  async findByNameAndUserId(
    name: string,
    userId: string | null,
  ): Promise<DatabaseMcpServer | undefined> {
    const [server] = await db
      .select()
      .from(mcpServersTable)
      .where(
        and(
          eq(mcpServersTable.name, name),
          userId
            ? eq(mcpServersTable.user_id, userId)
            : isNull(mcpServersTable.user_id),
        ),
      )
      .limit(1);

    return server;
  }

  async deleteByUuid(uuid: string): Promise<DatabaseMcpServer | undefined> {
    const [deletedServer] = await db
      .delete(mcpServersTable)
      .where(eq(mcpServersTable.uuid, uuid))
      .returning();

    return deletedServer;
  }

  /**
   * Update a server, judged against the row as it is when the write happens.
   *
   * The current row is read under `FOR UPDATE` in the same transaction as the
   * write, so the URL comparison in planServerUpdate cannot be overtaken by a
   * concurrent update: a second editor whose form still shows the old URL is
   * judged against the URL the first one committed. A refusal throws
   * ServerCredentialRetentionError before anything is written, so the whole
   * row is unchanged; every other database error keeps its generic message.
   */
  async update(
    input: McpServerUpdateInput,
    executor?: DbExecutor,
  ): Promise<DatabaseMcpServer | undefined> {
    return (await this.updateReportingChange(input, executor))?.server;
  }

  /**
   * `update`, also reporting whether the write changed where the gateway
   * connects or what it presents there: the type, the URL, the stored bearer
   * (any replacement or clear) or the stored headers. Compared inside the
   * same transaction, against the locked row, so a concurrent update cannot
   * make the answer stale. The caller uses it to retire pooled connections
   * still built from the old values.
   */
  async updateReportingChange(
    input: McpServerUpdateInput,
    // The caller's transaction when it holds one; the inner transaction is then
    // a savepoint of it, and the row lock below is held until the outer
    // transaction ends.
    executor?: DbExecutor,
  ): Promise<
    | {
        server: DatabaseMcpServer;
        destinationOrCredentialChanged: boolean;
      }
    | undefined
  > {
    const { uuid, ...updateData } = input;

    try {
      return await (executor ?? db).transaction(async (tx) => {
        const [current] = await tx
          .select({
            type: mcpServersTable.type,
            url: mcpServersTable.url,
            bearerToken: mcpServersTable.bearerToken,
            headers: mcpServersTable.headers,
          })
          .from(mcpServersTable)
          .where(eq(mcpServersTable.uuid, uuid))
          .for("update");
        if (!current) return undefined;

        const [updatedServer] = await tx
          .update(mcpServersTable)
          .set(planServerUpdate(current, updateData))
          .where(eq(mcpServersTable.uuid, uuid))
          .returning();
        if (!updatedServer) return undefined;

        return {
          server: updatedServer,
          destinationOrCredentialChanged:
            current.type !== updatedServer.type ||
            (current.url ?? null) !== (updatedServer.url ?? null) ||
            (current.bearerToken ?? null) !==
              (updatedServer.bearerToken ?? null) ||
            JSON.stringify(current.headers ?? {}) !==
              JSON.stringify(updatedServer.headers ?? {}),
        };
      });
    } catch (error: unknown) {
      if (error instanceof ServerCredentialRetentionError) throw error;
      handleDatabaseError(error, "update", input.name);
    }
  }

  async bulkCreate(
    servers: McpServerCreateInput[],
  ): Promise<DatabaseMcpServer[]> {
    try {
      return await db
        .insert(mcpServersTable)
        .values(servers.map(withEncryptedBearerToken))
        .returning();
    } catch (error: unknown) {
      // For bulk operations, we don't have a specific server name to report
      // Extract the actual PostgreSQL error from Drizzle's error structure
      let pgError: DatabaseError | undefined;

      if (
        error instanceof Error &&
        "cause" in error &&
        error.cause instanceof DatabaseError
      ) {
        pgError = error.cause;
      } else if (error instanceof DatabaseError) {
        pgError = error;
      }

      if (pgError) {
        // Handle unique constraint violation for server name
        if (
          pgError.code === "23505" &&
          pgError.constraint === "mcp_servers_name_user_unique_idx"
        ) {
          throw new Error(
            "One or more server names already exist. Server names must be unique within your scope.",
          );
        }

        // Handle regex constraint violation for server name
        if (
          pgError.code === "23514" &&
          pgError.constraint === "mcp_servers_name_regex_check"
        ) {
          throw new Error(
            "One or more server names are invalid. Server names must only contain letters, numbers, underscores, and hyphens.",
          );
        }
      }

      logger.error("Database error in bulk create:", error);
      throw new Error(
        "Failed to bulk create MCP servers. Please check your input and try again.",
      );
    }
  }

  async updateServerErrorStatus(input: {
    serverUuid: string;
    errorStatus: z.infer<typeof McpServerErrorStatusEnum>;
  }) {
    const [updatedServer] = await db
      .update(mcpServersTable)
      .set({
        error_status: input.errorStatus,
      })
      .where(eq(mcpServersTable.uuid, input.serverUuid))
      .returning();

    return updatedServer;
  }

  /**
   * Reset error_status to NONE for all servers that are currently in ERROR state.
   * Used on startup to give servers a fresh chance.
   */
  async resetAllErrorStatuses(): Promise<number> {
    const updated = await db
      .update(mcpServersTable)
      .set({
        error_status: McpServerErrorStatusEnum.enum.NONE,
      })
      .where(
        eq(mcpServersTable.error_status, McpServerErrorStatusEnum.enum.ERROR),
      )
      .returning();

    return updated.length;
  }

  // ===== Bearer-token converge =====

  // Rows whose bearer_token is present but NOT yet an `enc:v1:` envelope, i.e.
  // legacy plaintext the boot converge must encrypt once. Selects only the uuid
  // and the value, and only the rows that need work, so a converged database
  // (the normal steady state) reads nothing.
  async findServersWithPlaintextBearerToken(): Promise<
    { uuid: string; bearerToken: string }[]
  > {
    const rows = await db
      .select({
        uuid: mcpServersTable.uuid,
        bearerToken: mcpServersTable.bearerToken,
      })
      .from(mcpServersTable)
      .where(
        and(
          isNotNull(mcpServersTable.bearerToken),
          not(like(mcpServersTable.bearerToken, `${BEARER_ENVELOPE_PREFIX}%`)),
        ),
      );
    // bearerToken is non-null by the filter; narrow the type for the caller.
    return rows.filter(
      (r): r is { uuid: string; bearerToken: string } => r.bearerToken !== null,
    );
  }

  // Write an already-computed ciphertext for one row. Distinct from update():
  // update() ENCRYPTS its input, so it cannot be used to store a value that is
  // already an envelope without double-wrapping it. The converge computes the
  // envelope and persists it verbatim here.
  async writeBearerTokenCiphertext(
    uuid: string,
    ciphertext: string,
  ): Promise<void> {
    await db
      .update(mcpServersTable)
      .set({ bearerToken: ciphertext })
      .where(eq(mcpServersTable.uuid, uuid));
  }
}

export const mcpServersRepository = new McpServersRepository();
