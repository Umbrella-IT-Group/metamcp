import logger from "@/utils/logger";

import {
  effectivePresentation,
  presentationEnabled,
  type SessionPresentation,
} from "./endpoint-presentation";

/**
 * The presentation a NEW session on this endpoint is served, read once at
 * `initialize` by the router (the endpoint is known there; the proxy knows only
 * the namespace).
 *
 * Returns `undefined`, the default presentation, when the endpoint is unknown,
 * the kill switch is off (no database read at all in that case), the endpoint
 * has no row, or the row is all-default.
 *
 * NEVER THROWS, and fails open to today's behaviour. Presentation is cosmetic:
 * a title, a paragraph of guidance and a trimmed listing. It must never be the
 * reason an `initialize` fails, so a database error here logs one WARN (which
 * names no setting and carries no administrator text) and the session is served
 * as every session was before the feature existed.
 *
 * The repository is imported lazily, inside the try, the way
 * `auditing.functional.ts` imports its own: this module is on the router's
 * import graph, and the router suites that run with the database mocked must
 * keep a database-free graph. An import failure takes the same fail-open path.
 */
export async function resolveSessionPresentation(
  endpointUuid: string | undefined,
): Promise<SessionPresentation | undefined> {
  if (!endpointUuid || !presentationEnabled()) return undefined;
  try {
    const { endpointPresentationRepository } = await import(
      "../../db/repositories/endpoint-presentation.repo"
    );
    const row =
      await endpointPresentationRepository.findByEndpointUuid(endpointUuid);
    if (!row) return undefined;
    return effectivePresentation({
      ...(row.title !== null ? { title: row.title } : {}),
      ...(row.instructions !== null ? { instructions: row.instructions } : {}),
      toolListing: row.tool_listing,
      omitOutputSchemas: row.omit_output_schemas,
    });
  } catch (error) {
    logger.warn(
      "Endpoint presentation could not be read; serving this session with the default presentation.",
      error,
    );
    return undefined;
  }
}
