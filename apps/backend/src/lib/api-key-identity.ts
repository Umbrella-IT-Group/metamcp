/**
 * Acts-as identity resolution for an API key row, shared by both planes.
 *
 * Lives here rather than in api-key-oauth.middleware.ts (its original home,
 * which still re-exports it) because the tRPC `apiKeys.validate` oracle has to
 * resolve the binding exactly as the data plane does, and importing the
 * middleware for it would drag that module's load-time side effects — an
 * ApiKeysRepository construction plus the api-keys / users / oauth repository
 * import chains, all of which reach db/index — into every consumer of the
 * api-keys router. One pure function with no imports, two callers, no
 * second implementation to drift.
 */

/**
 * Runtime re-check of the identity-requires-scope pairing (migration 0024):
 * an acts-as identity is honored ONLY on a row that also carries a single-
 * endpoint scope. Mint-time enforcement (zod + impl) cannot reach rows
 * written outside the app — psql / admin_cli is a routine ops path here, and
 * migration 0024's CHECK constraint could be dropped or predate a row — so
 * without this gate an unscoped-but-bound row would become a GATEWAY-WIDE
 * identity key honored by the streamable-http m365 context gate on every
 * endpoint the key reaches. Fail-closed: no scope → no identity, the key
 * still authenticates but injection stays inert.
 *
 * Production callers: the two authenticateApiKey branches in
 * api-key-oauth.middleware.ts (data plane) and the disabled-identity gate in
 * trpc/api-keys.impl.ts (validate oracle). Covered by
 * middleware/api-key-access.test.ts.
 */
export function resolveActsAsUserId(validation: {
  endpoint_uuid?: string | null;
  acts_as_user_id?: string | null;
}): string | undefined {
  if (
    validation.endpoint_uuid === null ||
    validation.endpoint_uuid === undefined
  ) {
    return undefined;
  }
  return validation.acts_as_user_id || undefined;
}
