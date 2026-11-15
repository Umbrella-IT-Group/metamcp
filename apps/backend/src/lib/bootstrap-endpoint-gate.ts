import { eq } from "drizzle-orm";

import { endpointGateRepository } from "../db/repositories/endpoint-gate.repo";
import { endpointsTable } from "../db/schema";
import {
  type EndpointGateRule,
  judgeEndpointCreate,
  judgeEndpointMove,
} from "./endpoint-namespace-gate";

/** The columns the environment bootstrap writes for one endpoint. */
export interface BootstrapEndpointValues {
  name: string;
  description: string | null;
  namespace_uuid: string;
  enable_api_key_auth: boolean;
  use_query_param_auth: boolean;
  enable_oauth: boolean;
  user_id: string | null;
  updated_at: Date;
}

export type BootstrapEndpointOutcome =
  | { status: "created" | "updated" }
  | { status: "refused"; rule: EndpointGateRule };

/**
 * Write one BOOTSTRAP_ENDPOINTS entry under the endpoint namespace gate
 * (lib/endpoint-namespace-gate), with the same transaction and locks as the
 * tRPC writers: the namespace lock (both namespaces, sorted, for a move), the
 * endpoint row re-read FOR UPDATE, then the judgement, then the write. The
 * bootstrap creates endpoints unrestricted, so a create over a namespace a
 * restricted endpoint guards is refused, as is moving an existing endpoint
 * onto such a namespace. A refused entry is reported and nothing of it is
 * written; the bootstrap carries on with the next one.
 */
export async function applyBootstrapEndpoint(
  values: BootstrapEndpointValues,
  existingUuid: string | null,
): Promise<BootstrapEndpointOutcome> {
  const { db } = await import("../db/index");
  return await db.transaction(async (tx) => {
    if (existingUuid === null) {
      await endpointGateRepository.lockNamespaces(tx, [values.namespace_uuid]);
      const restrictedSibling =
        await endpointGateRepository.restrictedSiblingExists(
          tx,
          values.namespace_uuid,
        );
      const rule = judgeEndpointCreate({
        restricted: false,
        isPublic: values.user_id === null,
        adminPlane: false,
        restrictedSibling,
        gatedSibling: false,
      });
      if (rule) return { status: "refused", rule };
      await tx.insert(endpointsTable).values(values);
      return { status: "created" };
    }

    // The row's namespace as it is now, read before locking only to know
    // which namespace to lock; re-read under the locks below.
    const [current] = await tx
      .select({ namespace_uuid: endpointsTable.namespace_uuid })
      .from(endpointsTable)
      .where(eq(endpointsTable.uuid, existingUuid));
    if (!current) return { status: "refused", rule: "endpoint_changed" };
    await endpointGateRepository.lockNamespaces(tx, [
      current.namespace_uuid,
      values.namespace_uuid,
    ]);
    const locked = await endpointGateRepository.lockEndpoint(tx, existingUuid);
    if (
      !locked ||
      locked.namespace_uuid.toLowerCase() !==
        current.namespace_uuid.toLowerCase()
    ) {
      return { status: "refused", rule: "endpoint_changed" };
    }
    const isMove =
      locked.namespace_uuid.toLowerCase() !==
      values.namespace_uuid.toLowerCase();
    if (isMove) {
      const restrictedSibling =
        await endpointGateRepository.restrictedSiblingExists(
          tx,
          values.namespace_uuid,
          existingUuid,
        );
      const rule = judgeEndpointMove({
        restricted: locked.restricted,
        isPublic: values.user_id === null,
        adminPlane: false,
        restrictedSibling,
        gatedSibling: false,
      });
      if (rule) return { status: "refused", rule };
    }
    await tx
      .update(endpointsTable)
      .set(values)
      .where(eq(endpointsTable.uuid, existingUuid));
    if (isMove) {
      await endpointGateRepository.clearRestrictionKey(tx, existingUuid);
    }
    return { status: "updated" };
  });
}
