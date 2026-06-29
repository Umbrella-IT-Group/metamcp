import { z } from "zod";

export const MetaMcpLogCategorySchema = z.enum([
  "connection",
  "client",
  "tool_call",
  "server",
  "system",
]);

export const MetaMcpLogEntrySchema = z.object({
  id: z.string(),
  timestamp: z.date(),
  category: MetaMcpLogCategorySchema,
  serverName: z.string(),
  serverUuid: z.string().optional(),
  level: z.enum(["error", "info", "warn"]),
  message: z.string(),
  toolName: z.string().optional(),
  durationMs: z.number().optional(),
  clientName: z.string().optional(),
  error: z.string().optional(),
});

export const GetLogsRequestSchema = z.object({
  limit: z.number().int().positive().max(2000).optional(),
});

export const GetLogsResponseSchema = z.object({
  success: z.literal(true),
  data: z.array(MetaMcpLogEntrySchema),
  totalCount: z.number(),
});

export const ClearLogsResponseSchema = z.object({
  success: z.literal(true),
  message: z.string(),
});

export type MetaMcpLogCategory = z.infer<typeof MetaMcpLogCategorySchema>;
export type MetaMcpLogEntry = z.infer<typeof MetaMcpLogEntrySchema>;
export type GetLogsRequest = z.infer<typeof GetLogsRequestSchema>;
export type GetLogsResponse = z.infer<typeof GetLogsResponseSchema>;
export type ClearLogsResponse = z.infer<typeof ClearLogsResponseSchema>;
