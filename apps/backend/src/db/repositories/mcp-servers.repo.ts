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

// The UPDATE variant of the choke above, and it differs on one point that is a
// live-outage bug if it is wrong. The serializer redacts bearer_token to null
// on every response, so the edit form cannot see the
// stored value and re-submits an EMPTY bearerToken field on every save that did
// not re-type the secret. Writing that empty value would blank the row's
// credential and break the upstream connection. So a falsy bearerToken here
// means "leave the stored value unchanged": the key is dropped from the SET so
// drizzle never touches the column. A non-empty value replaces it, encrypted at
// rest. This removes no capability the admin had, the value was never
// round-tripped in cleartext for them to deliberately clear by blanking.
function withUpdatedBearerToken<T extends { bearerToken?: string | null }>(
  input: T,
): Omit<T, "bearerToken"> | T {
  if (input.bearerToken) {
    return {
      ...input,
      bearerToken: encryptServerBearerToken(input.bearerToken),
    };
  }
  const { bearerToken: _omitted, ...rest } = input;
  return rest;
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
  async create(input: McpServerCreateInput): Promise<DatabaseMcpServer> {
    try {
      const [createdServer] = await db
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

  async update(
    input: McpServerUpdateInput,
  ): Promise<DatabaseMcpServer | undefined> {
    const { uuid, ...updateData } = input;

    try {
      const [updatedServer] = await db
        .update(mcpServersTable)
        .set(withUpdatedBearerToken(updateData))
        .where(eq(mcpServersTable.uuid, uuid))
        .returning();

      return updatedServer;
    } catch (error: unknown) {
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
      .where(eq(mcpServersTable.error_status, McpServerErrorStatusEnum.enum.ERROR))
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
