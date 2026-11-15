import {
  AuditListRequestSchema,
  AuditListResponseSchema,
} from "@repo/zod-types";
import { z } from "zod";

import { adminProcedure, router } from "../../trpc";

/**
 * The control-plane audit trail, read-only. ADMIN ONLY, and on the operator
 * scope's set so an operator-scope admin-plane key can verify its own changes
 * from their audit rows. There is deliberately no write here: audit_log is
 * append-only (migration 0028) and no procedure may add to it or remove from
 * it. The implementation returns whitelisted fields only.
 */
export const createAuditRouter = (implementations: {
  list: (
    input: z.infer<typeof AuditListRequestSchema>,
  ) => Promise<z.infer<typeof AuditListResponseSchema>>;
}) => {
  return router({
    list: adminProcedure
      .input(AuditListRequestSchema)
      .output(AuditListResponseSchema)
      .query(async ({ input }) => {
        return implementations.list(input);
      }),
  });
};
