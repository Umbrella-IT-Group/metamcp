import {
  GetGatewayEventsRequestSchema,
  GetGatewayEventsResponseSchema,
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
    getHistory: (
      input: z.infer<typeof GetGatewayEventsRequestSchema>,
    ) => Promise<z.infer<typeof GetGatewayEventsResponseSchema>>;
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

    // Admin only: the DURABLE half of the same view (`gateway_events`,
    // migration 0031). Same gate as `get` above and for the same reason — the
    // rows are the same process-wide operational events, only persisted, so a
    // member reading the history would learn exactly what reading the live tail
    // would tell them. Gating this any lower would make the durable surface a
    // way around the gate on the live one.
    //
    // READ-ONLY, like `get`. There is no clear, no delete and no export
    // mutation here, and there must not be: the table is immutable for 30 days
    // in the database (migration 0031 refuses UPDATE and TRUNCATE outright and
    // DELETE inside the window), and an application path that appeared to empty
    // it would either fail loudly or, worse, look like it worked.
    history: adminProcedure
      .input(GetGatewayEventsRequestSchema)
      .output(GetGatewayEventsResponseSchema)
      .query(async ({ input }) => {
        return await implementations.getHistory(input);
      }),
  });
