import { GetLogsRequestSchema, GetLogsResponseSchema } from "@repo/zod-types";
import { z } from "zod";

import logger from "@/utils/logger";

import { metamcpLogStore } from "../lib/metamcp/log-store";

// Read-only by design. `clearLogs` was removed with migration 0028's
// audit_log — see the note in packages/trpc/src/routers/frontend/logs.ts.
// The in-memory `clearLogs()` method it called is gone from the log store
// too, so nothing in the process can empty the buffer any more.
export const logsImplementations = {
  getLogs: async (
    input: z.infer<typeof GetLogsRequestSchema>,
  ): Promise<z.infer<typeof GetLogsResponseSchema>> => {
    try {
      const logs = metamcpLogStore.getLogs(input.limit);
      const totalCount = metamcpLogStore.getLogCount();

      return {
        success: true as const,
        data: logs,
        totalCount,
      };
    } catch (error) {
      logger.error("Error getting logs:", error);
      throw new Error("Failed to get logs");
    }
  },
};
