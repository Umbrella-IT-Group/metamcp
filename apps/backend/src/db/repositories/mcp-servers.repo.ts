import {
  DatabaseMcpServer,
  McpServerCreateInput,
  McpServerErrorStatusEnum,
  McpServerUpdateInput,
} from "@repo/zod-types";
import {
  and,
  asc,
  desc,
  eq,
  inArray,
  isNotNull,
  isNull,
  like,
  not,
  or,
  sql,
} from "drizzle-orm";
import { DatabaseError } from "pg";
import { z } from "zod";

import { describeDbError } from "@/lib/db-error-summary";
import {
  BEARER_ENVELOPE_PREFIX,
  encryptServerBearerToken,
} from "@/lib/metamcp/server-bearer-crypto";
import logger from "@/utils/logger";

import { db } from "../index";
import { mcpServersTable } from "../schema";
import { lockMcpServerName } from "./admin-plane-locks";
import type { DbExecutor, DbTransaction } from "./db-executor";
import { ServerNameTakenError } from "./mcp-server-name-rule";
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
  logger.error(`Database error in ${operation}:`, describeDbError(error));

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

/**
 * Refuse a name that another server already holds in the owner scope the write
 * leaves. A NULL owner is one scope (IS NOT DISTINCT FROM), which the
 * database's unique rule on (name, owner) does not enforce. Called under the
 * name's lock (`lockMcpServerName`), so a writer queued behind another of the
 * same name judges the rows the first committed. Only a write that puts a
 * server under a name or owner scope it was not under is judged, so the server
 * being written never collides with itself.
 */
async function refuseTakenName(
  tx: DbTransaction,
  next: { name: string; owner: string | null },
): Promise<void> {
  const [holder] = await tx
    .select({ uuid: mcpServersTable.uuid })
    .from(mcpServersTable)
    .where(
      and(
        eq(mcpServersTable.name, next.name),
        sql`${mcpServersTable.user_id} IS NOT DISTINCT FROM ${next.owner}::text`,
      ),
    )
    .limit(1);
  if (holder) throw new ServerNameTakenError();
}

/** A server's name as stored right now, read without a lock. */
async function serverNameOf(
  tx: DbTransaction,
  uuid: string,
): Promise<string | undefined> {
  const [row] = await tx
    .select({ name: mcpServersTable.name })
    .from(mcpServersTable)
    .where(eq(mcpServersTable.uuid, uuid));
  return row?.name;
}

export class McpServersRepository {
  /**
   * Create a server. The name is judged under its lock against every server in
   * the owner scope (NULL is one scope) before the insert, and a name another
   * server holds there throws ServerNameTakenError and writes nothing.
   */
  async create(
    input: McpServerCreateInput,
    // The caller's transaction when it holds one (an admin-plane write records
    // its audit row in the same transaction). Omitted, the pool is used.
    executor?: DbExecutor,
  ): Promise<DatabaseMcpServer> {
    try {
      return await (executor ?? db).transaction(async (tx) => {
        await lockMcpServerName(tx, input.name);
        await refuseTakenName(tx, {
          name: input.name,
          owner: input.user_id ?? null,
        });
        const [createdServer] = await tx
          .insert(mcpServersTable)
          .values(withEncryptedBearerToken(input))
          .returning();

        return createdServer;
      });
    } catch (error: unknown) {
      if (error instanceof ServerNameTakenError) throw error;
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
   *
   * `ownershipChanged` is reported the same way: the owner (`user_id`) the
   * locked row had immediately before this write, against the one written.
   * An owner read before the lock can be overtaken by an update queued ahead
   * of this one, so comparing with that read could miss a change. The caller
   * closes the row's Inspector sessions on it, since the owner decides who
   * may see the row.
   *
   * THE NAME RULE. The write takes the lock of the name it can put the row
   * under before the row's own lock, and when it would put the row under a
   * name or an owner scope it was not under, refuses (ServerNameTakenError,
   * nothing written) if another server holds that name in that scope. A write
   * that leaves both as they are (the sync's routine re-save) is never judged,
   * so a duplicate that already exists is not repaired and does not block the
   * re-save of either row. A write that names no new name but moves the row to
   * another owner is judged under the row's own name, read before the lock is
   * taken and checked again once the row is locked.
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
        /**
         * The row as locked, before the write. Credentials included: it is for
         * the before-state of the audit row (lib/audit/before-state), which
         * records a credential field's change and never its value.
         */
        previous: DatabaseMcpServer;
        destinationOrCredentialChanged: boolean;
        ownershipChanged: boolean;
      }
    | undefined
  > {
    const { uuid, ...updateData } = input;

    try {
      return await (executor ?? db).transaction(async (tx) => {
        // The name this write can put the row under: the one it sets, or, for
        // a write that only moves the row to another owner, the one the row
        // has (read here to take its lock first, and checked once locked).
        const lockedName =
          input.name ??
          (input.user_id !== undefined
            ? await serverNameOf(tx, uuid)
            : undefined);
        if (lockedName !== undefined) await lockMcpServerName(tx, lockedName);
        const [current] = await tx
          .select()
          .from(mcpServersTable)
          .where(eq(mcpServersTable.uuid, uuid))
          .for("update");
        if (!current) return undefined;
        if (
          input.name === undefined &&
          lockedName !== undefined &&
          lockedName !== current.name
        ) {
          throw new Error("The server was renamed while this write waited");
        }

        const planned = planServerUpdate(current, updateData);
        const nextName = input.name ?? current.name;
        const nextOwner =
          planned.user_id !== undefined ? planned.user_id : current.user_id;
        if (
          nextName !== current.name ||
          (nextOwner ?? null) !== (current.user_id ?? null)
        ) {
          await refuseTakenName(tx, {
            name: nextName,
            owner: nextOwner ?? null,
          });
        }

        const [updatedServer] = await tx
          .update(mcpServersTable)
          .set(planned)
          .where(eq(mcpServersTable.uuid, uuid))
          .returning();
        if (!updatedServer) return undefined;

        return {
          server: updatedServer,
          previous: current,
          destinationOrCredentialChanged:
            current.type !== updatedServer.type ||
            (current.url ?? null) !== (updatedServer.url ?? null) ||
            (current.bearerToken ?? null) !==
              (updatedServer.bearerToken ?? null) ||
            JSON.stringify(current.headers ?? {}) !==
              JSON.stringify(updatedServer.headers ?? {}),
          ownershipChanged:
            (current.user_id ?? null) !== (updatedServer.user_id ?? null),
        };
      });
    } catch (error: unknown) {
      if (
        error instanceof ServerCredentialRetentionError ||
        error instanceof ServerNameTakenError
      ) {
        throw error;
      }
      handleDatabaseError(error, "update", input.name);
    }
  }

  /**
   * Rename a server and/or change its description, and nothing else: the
   * write behind the metadata-only variant of `mcpServers.update`. The SET
   * holds only the fields given, so no connection field (type, URL, command,
   * arguments, environment, bearer token, headers, owner) can change here and
   * none is read from the request.
   *
   * The row is locked (FOR UPDATE) first and the owner rule is judged on the
   * locked row, in the same transaction as the write (a savepoint of the
   * caller's when it holds one): a server owned by someone else is refused,
   * judged against the owner as it is now, not as an earlier read saw it. The
   * previous row is returned (credentials included, for the audit row's
   * before-state, which records a credential field's change and never its
   * value); nothing in it reaches a reply.
   *
   * A rename takes the new name's lock before the row's and refuses
   * (ServerNameTakenError, nothing written) when another server holds that
   * name in the row's owner scope, as locked (a NULL owner is one scope). A
   * description-only write, or a rename to the name the row already has, is
   * never judged.
   */
  async updateMetadataReportingChange(
    input: { uuid: string; name?: string; description?: string },
    callerUserId: string,
    executor?: DbExecutor,
  ): Promise<
    | { kind: "not_found" }
    | { kind: "not_owner" }
    | {
        kind: "updated";
        server: DatabaseMcpServer;
        previous: DatabaseMcpServer;
      }
  > {
    try {
      return await (executor ?? db).transaction(async (tx) => {
        if (input.name !== undefined) await lockMcpServerName(tx, input.name);
        const [current] = await tx
          .select()
          .from(mcpServersTable)
          .where(eq(mcpServersTable.uuid, input.uuid))
          .for("update");
        if (!current) return { kind: "not_found" as const };
        if (current.user_id && current.user_id !== callerUserId) {
          return { kind: "not_owner" as const };
        }
        if (input.name !== undefined && input.name !== current.name) {
          await refuseTakenName(tx, {
            name: input.name,
            owner: current.user_id,
          });
        }

        const [server] = await tx
          .update(mcpServersTable)
          .set({
            ...(input.name !== undefined ? { name: input.name } : {}),
            ...(input.description !== undefined
              ? { description: input.description }
              : {}),
          })
          .where(eq(mcpServersTable.uuid, input.uuid))
          .returning();
        if (!server) return { kind: "not_found" as const };
        return { kind: "updated" as const, server, previous: current };
      });
    } catch (error: unknown) {
      if (error instanceof ServerNameTakenError) throw error;
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

      logger.error("Database error in bulk create:", describeDbError(error));
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
   * Clear the ERROR status of one server, or of every server in ERROR, inside
   * the caller's transaction: the write `mcpServers.resetErrors` and the REST
   * reset route share (lib/metamcp/reset-server-errors), so the status change
   * and its audit row commit or roll back together. The rows are read FOR
   * UPDATE first, in uuid order, so two concurrent resets queue on the same
   * row instead of locking a set in different orders. With `serverUuid` an
   * unknown uuid is `not_found`, and a server that is not in ERROR is left
   * alone (an empty `reset`). Returns the servers changed, by name, in a
   * stable order; failures propagate.
   */
  async clearErrorStatus(
    tx: DbTransaction,
    selection: { serverUuid?: string },
  ): Promise<
    | { status: "not_found" }
    | { status: "ok"; reset: Array<{ uuid: string; name: string }> }
  > {
    const ERROR = McpServerErrorStatusEnum.enum.ERROR;
    const locked = await tx
      .select({
        uuid: mcpServersTable.uuid,
        error_status: mcpServersTable.error_status,
      })
      .from(mcpServersTable)
      .where(
        selection.serverUuid !== undefined
          ? eq(mcpServersTable.uuid, selection.serverUuid)
          : eq(mcpServersTable.error_status, ERROR),
      )
      .orderBy(asc(mcpServersTable.uuid))
      .for("update");
    if (selection.serverUuid !== undefined && locked.length === 0) {
      return { status: "not_found" };
    }
    // Judged on the rows as locked: a row another writer moved out of ERROR
    // while this waited is left alone.
    const inError = locked
      .filter((row) => row.error_status === ERROR)
      .map((row) => row.uuid);
    if (inError.length === 0) return { status: "ok", reset: [] };
    const reset = await tx
      .update(mcpServersTable)
      .set({ error_status: McpServerErrorStatusEnum.enum.NONE })
      .where(inArray(mcpServersTable.uuid, inError))
      .returning({ uuid: mcpServersTable.uuid, name: mcpServersTable.name });
    reset.sort(
      (a, b) => a.name.localeCompare(b.name) || a.uuid.localeCompare(b.uuid),
    );
    return { status: "ok", reset };
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
