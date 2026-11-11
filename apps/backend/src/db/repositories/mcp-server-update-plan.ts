import type { McpServerUpdateInput } from "@repo/zod-types";

import { encryptServerBearerToken } from "@/lib/metamcp/server-bearer-crypto";

/*
 * How a server update treats the stored credentials, kept apart from the
 * repository so the tRPC layer and its tests can use the refusal type without
 * loading the database module.
 */

// The UPDATE counterpart of the repository's CREATE-time encryption
// (withEncryptedBearerToken in mcp-servers.repo.ts), and it differs on one
// point that is a live-outage bug if it is wrong. The serializer redacts
// bearer_token to null on every response, so the edit form cannot see the
// stored value and re-submits an EMPTY bearerToken field on every save that did
// not re-type the secret. Writing that empty value would blank the row's
// credential and break the upstream connection. So a falsy bearerToken here
// means "leave the stored value unchanged": the key is dropped from the SET so
// drizzle never touches the column. A non-empty value replaces it, encrypted at
// rest. Removing the stored value is a separate, explicit request
// (`clearBearerToken`, see planServerUpdate), never a blank field.
function withUpdatedBearerToken<T extends { bearerToken?: string | null }>(
  input: T,
): Omit<T, "bearerToken"> | T {
  if (input.bearerToken) {
    return {
      ...input,
      bearerToken: encryptServerBearerToken(input.bearerToken),
    };
  }
  const { bearerToken: _omitted, ...rest } = input;
  return rest;
}

/**
 * A server update refused because it would carry stored credentials to a new
 * destination. Its message is meant for the administrator and names only
 * which credential needs an explicit decision, never a value.
 */
export class ServerCredentialRetentionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ServerCredentialRetentionError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export const URL_CHANGE_NEEDS_BEARER_DECISION =
  "This update changes the server URL, and the server has a stored bearer token. The stored token is not carried to a new address: enter a new bearer token, or clear the stored one, in the same update.";

export const URL_CHANGE_NEEDS_HEADERS_DECISION =
  "This update changes the server URL, and the server has stored headers. Stored headers are not carried to a new address unseen: send the headers again (an empty set clears them) in the same update.";

export const CLEAR_AND_REPLACE_BEARER_CONFLICT =
  "This update both clears the stored bearer token and sets a new one; send only one of the two.";

/**
 * Whether two stored URL values name the same destination. Compared in their
 * parsed, normalized form, so a re-save of the same address spelled the same
 * way (or differing only in what URL parsing normalizes, such as the case of
 * the host or a default port) is not a change; anything else is. An absent
 * or blank value equals only another absent or blank value.
 */
function sameDestination(
  stored: string | null | undefined,
  next: string | null | undefined,
): boolean {
  const a = stored?.trim() ?? "";
  const b = next?.trim() ?? "";
  if (a === "" || b === "") return a === b;
  try {
    return new URL(a).href === new URL(b).href;
  } catch {
    return a === b;
  }
}

/** The row fields the credential rule reads. */
export interface StoredServerCredentials {
  url: string | null;
  bearerToken: string | null;
  headers: Record<string, string> | null;
}

/**
 * The SET for an update, given the CURRENT row, or a refusal.
 *
 * THE RULE. A stored bearer token or stored headers are credentials for the
 * address they were configured with. An update that changes the URL must say
 * what happens to each of them; it is refused otherwise, and a refused update
 * changes nothing. Without this, an updater who cannot read the bearer (it is
 * never returned) could repoint the row and have the gateway present it to
 * the new address.
 *   - Bearer, URL changed, a bearer stored: a non-empty `bearerToken`
 *     replaces it, `clearBearerToken: true` removes it; blank or omitted is
 *     refused.
 *   - Headers, URL changed, headers stored: `headers` must be present (the
 *     edit form always sends them; `{}` clears them); omitted is refused.
 *   - Same URL (or URL omitted): unchanged contract. A blank or omitted
 *     bearer keeps the stored one, because the edit form cannot see it and
 *     re-submits an empty field on every save (see withUpdatedBearerToken);
 *     omitted headers keep the stored ones.
 *   - `clearBearerToken: true` clears the bearer on any update. Together with
 *     a non-empty `bearerToken` it is contradictory and refused.
 * Nothing stored means nothing to carry, so a URL change on a row with no
 * bearer and no headers needs no decision.
 */
export function planServerUpdate(
  current: StoredServerCredentials,
  input: Omit<McpServerUpdateInput, "uuid">,
): Omit<McpServerUpdateInput, "uuid" | "clearBearerToken"> {
  const { clearBearerToken, ...update } = input;
  const replacing = Boolean(update.bearerToken);
  if (clearBearerToken === true && replacing) {
    throw new ServerCredentialRetentionError(CLEAR_AND_REPLACE_BEARER_CONFLICT);
  }

  const urlChanged =
    update.url !== undefined && !sameDestination(current.url, update.url);
  if (urlChanged) {
    const bearerStored = Boolean(current.bearerToken);
    if (bearerStored && !replacing && clearBearerToken !== true) {
      throw new ServerCredentialRetentionError(
        URL_CHANGE_NEEDS_BEARER_DECISION,
      );
    }
    const headersStored = Object.keys(current.headers ?? {}).length > 0;
    if (headersStored && update.headers === undefined) {
      throw new ServerCredentialRetentionError(
        URL_CHANGE_NEEDS_HEADERS_DECISION,
      );
    }
  }

  if (clearBearerToken === true) {
    return { ...update, bearerToken: null };
  }
  return withUpdatedBearerToken(update);
}
