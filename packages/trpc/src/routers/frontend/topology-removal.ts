import {
  RemoveTopologyRequestSchema,
  RemoveTopologyResponseSchema,
  TopologyRemovalImpactRequestSchema,
  TopologyRemovalImpactResponseSchema,
} from "@repo/zod-types";
import { z } from "zod";

import { adminProcedure, type AuditActor, auditActor } from "../../trpc";

/**
 * The two leaf-only removal procedures shared by `endpoints`, `namespaces` and
 * `mcpServers` (the backend's lib/topology-removal-rules has the rules):
 *
 *  - removalImpact: a read. Whether `remove` would accept the row now (every
 *    rule that stops it), what depends on it and what goes with it, its
 *    snapshot (identifying metadata only) and the fingerprint of its current
 *    state that `remove` must be sent back.
 *  - remove: leaf-only. One row nothing depends on, confirmed by its current
 *    name and the fingerprint read above; the snapshot goes into the audit
 *    row. The broad `delete` of each router stays human-only.
 *
 * Admin only. The verified caller decides which private rows are visible by
 * name, and the audit actor is the caller's own.
 */
export interface TopologyRemovalImplementations {
  removalImpact: (
    input: z.infer<typeof TopologyRemovalImpactRequestSchema>,
    userId: string,
  ) => Promise<z.infer<typeof TopologyRemovalImpactResponseSchema>>;
  remove: (
    input: z.infer<typeof RemoveTopologyRequestSchema>,
    userId: string,
    actor: AuditActor,
  ) => Promise<z.infer<typeof RemoveTopologyResponseSchema>>;
}

export function topologyRemovalProcedures(
  implementations: TopologyRemovalImplementations,
) {
  return {
    removalImpact: adminProcedure
      .input(TopologyRemovalImpactRequestSchema)
      .output(TopologyRemovalImpactResponseSchema)
      .query(async ({ input, ctx }) => {
        return await implementations.removalImpact(input, ctx.user.id);
      }),

    remove: adminProcedure
      .input(RemoveTopologyRequestSchema)
      .output(RemoveTopologyResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return await implementations.remove(
          input,
          ctx.user.id,
          auditActor(ctx),
        );
      }),
  };
}
