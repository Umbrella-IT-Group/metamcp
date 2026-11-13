import type { ToolListingMode } from "@repo/zod-types";
import { eq, sql } from "drizzle-orm";

import { db } from "../index";
import { endpointPresentationTable } from "../schema";
import type { DbExecutor } from "./db-executor";

/**
 * Per-endpoint presentation rows (migration 0044), one per endpoint and only
 * while something is non-default.
 *
 * NOT in the repositories barrel (`./index`), deliberately: the gateway's
 * session path reaches this repository through a lazy import inside a
 * try/catch (`endpoint-presentation-resolver`), so suites that load the routers
 * with the database mocked keep a database-free module graph. Import it
 * directly, the way `access-groups.repo` is imported.
 *
 * WHICH POOL: the main pool. A failed read here is survivable (the session is
 * served with the default presentation), but a write is an administrator's
 * act, and neither is telemetry that should shed load with the bounded audit
 * pool.
 */

export interface EndpointPresentationRow {
  endpoint_uuid: string;
  title: string | null;
  instructions: string | null;
  tool_listing: ToolListingMode;
  omit_output_schemas: boolean;
  updated_at: Date;
}

export interface UpsertEndpointPresentationInput {
  endpoint_uuid: string;
  title: string | null;
  instructions: string | null;
  tool_listing: ToolListingMode;
  omit_output_schemas: boolean;
}

export class EndpointPresentationRepository {
  async findByEndpointUuid(
    endpointUuid: string,
  ): Promise<EndpointPresentationRow | undefined> {
    const [row] = await db
      .select()
      .from(endpointPresentationTable)
      .where(eq(endpointPresentationTable.endpoint_uuid, endpointUuid))
      .limit(1);
    return row;
  }

  /**
   * Insert, or replace every setting of the existing row. `updated_at` is set
   * by the database clock on both paths, so it records when the row last
   * changed even if two administrators save at once (last write wins).
   */
  async upsert(
    input: UpsertEndpointPresentationInput,
    executor?: DbExecutor,
  ): Promise<EndpointPresentationRow> {
    const [row] = await (executor ?? db)
      .insert(endpointPresentationTable)
      .values({
        endpoint_uuid: input.endpoint_uuid,
        title: input.title,
        instructions: input.instructions,
        tool_listing: input.tool_listing,
        omit_output_schemas: input.omit_output_schemas,
      })
      .onConflictDoUpdate({
        target: endpointPresentationTable.endpoint_uuid,
        set: {
          title: input.title,
          instructions: input.instructions,
          tool_listing: input.tool_listing,
          omit_output_schemas: input.omit_output_schemas,
          updated_at: sql`now()`,
        },
      })
      .returning();
    return row;
  }

  /** Whether a row existed. Deleting an absent row is not an error. */
  async deleteByEndpointUuid(
    endpointUuid: string,
    executor?: DbExecutor,
  ): Promise<boolean> {
    const deleted = await (executor ?? db)
      .delete(endpointPresentationTable)
      .where(eq(endpointPresentationTable.endpoint_uuid, endpointUuid))
      .returning({ endpoint_uuid: endpointPresentationTable.endpoint_uuid });
    return deleted.length > 0;
  }
}

export const endpointPresentationRepository =
  new EndpointPresentationRepository();
