import {
  CreateToolRequestSchema,
  GetToolsByMcpServerUuidRequestSchema,
} from "@repo/zod-types";

import { adminProcedure, protectedProcedure, router } from "../../trpc";

export const createToolsRouter = <
  TImplementations extends {
    getByMcpServerUuid: (input: any) => Promise<any>;
    create: (input: any) => Promise<any>;
    sync: (input: any) => Promise<any>;
  },
>(
  implementations: TImplementations,
) => {
  return router({
    // Protected: Get tools by MCP server UUID
    getByMcpServerUuid: protectedProcedure
      .input(GetToolsByMcpServerUuidRequestSchema)
      .query(async ({ input }) => {
        return implementations.getByMcpServerUuid(input);
      }),

    // Admin only: Save tools to database (upsert only, no cleanup). Curation
    // class, same rationale as namespaces.updateToolStatus — writes to the
    // shared tools catalog. NOTE: namespaces.refreshTools (member-accessible)
    // does NOT route through this procedure — it calls
    // toolsRepository.bulkUpsert directly from namespaces.impl.ts, bypassing
    // tRPC entirely, so this gate has no effect on that member-facing path.
    create: adminProcedure
      .input(CreateToolRequestSchema)
      .mutation(async ({ input }) => {
        return implementations.create(input);
      }),

    // Admin only: Sync tools with cleanup (removes obsolete tools). Same
    // rationale and refreshTools independence as create() above.
    sync: adminProcedure
      .input(CreateToolRequestSchema)
      .mutation(async ({ input }) => {
        return implementations.sync(input);
      }),
  });
};
