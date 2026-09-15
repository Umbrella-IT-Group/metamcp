import {
  DatabaseOAuthSession,
  OAuthSessionCreateInput,
  OAuthSessionUpdateInput,
} from "@repo/zod-types";
import { eq, sql } from "drizzle-orm";

import { db } from "../index";
import { oauthSessionsTable } from "../schema";

export class OAuthSessionsRepository {
  async findByMcpServerUuid(
    mcpServerUuid: string,
  ): Promise<DatabaseOAuthSession | undefined> {
    const [session] = await db
      .select()
      .from(oauthSessionsTable)
      .where(eq(oauthSessionsTable.mcp_server_uuid, mcpServerUuid))
      .limit(1);

    return session;
  }

  async create(input: OAuthSessionCreateInput): Promise<DatabaseOAuthSession> {
    const [createdSession] = await db
      .insert(oauthSessionsTable)
      .values({
        mcp_server_uuid: input.mcp_server_uuid,
        ...(input.client_information && {
          client_information: input.client_information,
        }),
        ...(input.tokens && { tokens: input.tokens }),
        ...(input.code_verifier && { code_verifier: input.code_verifier }),
      })
      .returning();

    return createdSession;
  }

  async update(
    input: OAuthSessionUpdateInput,
  ): Promise<DatabaseOAuthSession | undefined> {
    const [updatedSession] = await db
      .update(oauthSessionsTable)
      .set({
        ...(input.client_information && {
          client_information: input.client_information,
        }),
        ...(input.tokens && { tokens: input.tokens }),
        ...(input.code_verifier && { code_verifier: input.code_verifier }),
        updated_at: sql`NOW()`,
      })
      .where(eq(oauthSessionsTable.mcp_server_uuid, input.mcp_server_uuid))
      .returning();

    return updatedSession;
  }

  async upsert(input: OAuthSessionUpdateInput): Promise<DatabaseOAuthSession> {
    // Single-statement atomic upsert. Concurrent callers for the same
    // mcp_server_uuid resolve via ON CONFLICT instead of racing a
    // SELECT-then-INSERT, which previously crashed the loser with a
    // unique-constraint violation. Only fields present on `input` are written
    // so a partial update (e.g. tokens only) does not clear unrelated columns
    // such as code_verifier.
    const [row] = await db
      .insert(oauthSessionsTable)
      .values({
        mcp_server_uuid: input.mcp_server_uuid,
        ...(input.client_information && {
          client_information: input.client_information,
        }),
        ...(input.tokens && { tokens: input.tokens }),
        ...(input.code_verifier && { code_verifier: input.code_verifier }),
      })
      .onConflictDoUpdate({
        target: oauthSessionsTable.mcp_server_uuid,
        set: {
          ...(input.client_information && {
            client_information: input.client_information,
          }),
          ...(input.tokens && { tokens: input.tokens }),
          ...(input.code_verifier && { code_verifier: input.code_verifier }),
          updated_at: sql`NOW()`,
        },
      })
      .returning();

    if (!row) {
      throw new Error("Failed to upsert OAuth session");
    }

    return row;
  }

  async deleteByMcpServerUuid(
    mcpServerUuid: string,
  ): Promise<DatabaseOAuthSession | undefined> {
    const [deletedSession] = await db
      .delete(oauthSessionsTable)
      .where(eq(oauthSessionsTable.mcp_server_uuid, mcpServerUuid))
      .returning();

    return deletedSession;
  }
}

export const oauthSessionsRepository = new OAuthSessionsRepository();
