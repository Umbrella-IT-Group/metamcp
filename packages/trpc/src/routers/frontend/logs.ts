import {
  ClearLogsResponseSchema,
  GetLogsRequestSchema,
  GetLogsResponseSchema,
} from "@repo/zod-types";
import { z } from "zod";

import { adminProcedure, router } from "../../trpc";

// Define the logs router with procedure definitions
// The actual implementation will be provided by the backend
export const createLogsRouter = (
  // These are the implementation functions that the backend will provide
  implementations: {
    getLogs: (
      input: z.infer<typeof GetLogsRequestSchema>,
    ) => Promise<z.infer<typeof GetLogsResponseSchema>>;
    clearLogs: () => Promise<z.infer<typeof ClearLogsResponseSchema>>;
  },
) =>
  router({
    // Admin only: read the gateway log buffer. These are process-wide
    // operational logs, not per-user records — they carry upstream MCP
    // connection errors, request paths and internal hostnames for the whole
    // estate, so a member reading them learns about servers and endpoints
    // they have no other visibility into. `clear` was already admin-gated;
    // leaving the read open made that gate cosmetic.
    get: adminProcedure
      .input(GetLogsRequestSchema)
      .output(GetLogsResponseSchema)
      .query(async ({ input }) => {
        return await implementations.getLogs(input);
      }),

    // Admin only: Clear all logs — a destructive, gateway-wide operational
    // action, not a per-user one.
    clear: adminProcedure.output(ClearLogsResponseSchema).mutation(async () => {
      return await implementations.clearLogs();
    }),
  });
