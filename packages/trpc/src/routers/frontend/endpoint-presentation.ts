import {
  GetEndpointPresentationRequestSchema,
  GetEndpointPresentationResponseSchema,
  SetEndpointPresentationRequestSchema,
  SetEndpointPresentationResponseSchema,
} from "@repo/zod-types";
import { z } from "zod";

import {
  adminProcedure,
  type AuditActor,
  auditActor,
  router,
} from "../../trpc";

/**
 * Per-endpoint presentation settings (migration 0044): the title and
 * instructions a client receives at connection, the output-schema trim, and the
 * tool listing mode.
 *
 * DELIBERATELY IN NEITHER ADMIN-PLANE PROCEDURE SET
 * (`ADMIN_PLANE_SYNC_PROCEDURES`, `ADMIN_PLANE_OPERATOR_PROCEDURES`). Text that
 * reaches models is a human administrator's act, the same posture as
 * `namespaces.updateToolOverrides`: an admin-plane key of either scope is
 * refused by the scope middleware before any of this runs, and a browser
 * session whose user is not an administrator is refused by `adminProcedure`.
 * Reads are admin-only too, because the settings are as sensitive as the
 * authorship: they say what every client of the endpoint is told.
 *
 * Adding either name to a set would widen what a CI credential can do and needs
 * the review, and the matching change in the consumer repository's pinned copy
 * of those lists, that any other change to those sets needs.
 */
export const createEndpointPresentationRouter = (implementations: {
  get: (
    input: z.infer<typeof GetEndpointPresentationRequestSchema>,
    userId: string,
  ) => Promise<z.infer<typeof GetEndpointPresentationResponseSchema>>;
  set: (
    input: z.infer<typeof SetEndpointPresentationRequestSchema>,
    userId: string,
    actor: AuditActor,
  ) => Promise<z.infer<typeof SetEndpointPresentationResponseSchema>>;
}) => {
  return router({
    get: adminProcedure
      .input(GetEndpointPresentationRequestSchema)
      .output(GetEndpointPresentationResponseSchema)
      .query(async ({ input, ctx }) => {
        return implementations.get(input, ctx.user.id);
      }),

    set: adminProcedure
      .input(SetEndpointPresentationRequestSchema)
      .output(SetEndpointPresentationResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return implementations.set(input, ctx.user.id, auditActor(ctx));
      }),
  });
};
