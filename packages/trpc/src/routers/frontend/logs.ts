import { GetLogsRequestSchema, GetLogsResponseSchema } from "@repo/zod-types";
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
  },
) =>
  router({
    // Admin only: read the gateway log buffer. These are process-wide
    // operational logs, not per-user records — they carry upstream MCP
    // connection errors, request paths and internal hostnames for the whole
    // estate, so a member reading them learns about servers and endpoints
    // they have no other visibility into.
    //
    // READ IS THE ENTIRE SURFACE. There was a `clear` mutation here; it was
    // removed with migration 0028's audit_log. It only emptied the in-memory
    // ring buffer, but it was the one admin gesture that erased the live
    // security view mid-investigation, and no system whose promise is an
    // immutable record should offer one. Do not add it back —
    // `admin-gate-sweep.test.ts` asserts the procedure does not exist.
    get: adminProcedure
      .input(GetLogsRequestSchema)
      .output(GetLogsResponseSchema)
      .query(async ({ input }) => {
        return await implementations.getLogs(input);
      }),
  });
