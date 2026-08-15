export class ApiKeysSerializer {
  // The one masking rule both list surfaces share, so the two can never
  // drift apart into "one of them still leaks". 10 chars keeps the `sk_mt_`
  // scheme tag plus 4 characters — enough for a human to tell two keys
  // apart in a table, far too little to authenticate with.
  private static keyPrefix(key: string) {
    return `${key.slice(0, 10)}…`;
  }

  static serializeApiKey(dbApiKey: {
    uuid: string;
    name: string;
    key: string;
    created_at: Date;
    is_active: boolean;
  }) {
    return {
      uuid: dbApiKey.uuid,
      name: dbApiKey.name,
      key: dbApiKey.key,
      created_at: dbApiKey.created_at,
      is_active: dbApiKey.is_active,
    };
  }

  // Member-facing list (the caller's own keys PLUS every public/'everyone'
  // key). Drops the full `key` secret for all of them and emits only the
  // non-reversible prefix, same as the admin view below.
  //
  // Security review finding: this used to return `key` raw. Any
  // self-registered member could read every public key — gateway-wide
  // production credentials — in plaintext; three live keys were recovered
  // that way. The reachability is what makes it critical: `list` is a plain
  // protectedProcedure, and public keys are accessible to EVERY member by
  // design, so member enrollment was the whole exploit chain.
  //
  // The field is RENAMED to key_prefix rather than masked under the old name
  // on purpose: a consumer that still needs a usable secret then fails to
  // compile instead of silently shipping a truncated key to a gateway and
  // 401ing in production.
  static serializeApiKeyList(
    dbApiKeys: Array<{
      uuid: string;
      name: string;
      key: string;
      created_at: Date;
      is_active: boolean;
      user_id: string | null;
      endpoint_uuid: string | null;
      acts_as_user_id: string | null;
    }>,
  ) {
    return dbApiKeys.map((apiKey) => ({
      uuid: apiKey.uuid,
      name: apiKey.name,
      key_prefix: ApiKeysSerializer.keyPrefix(apiKey.key),
      created_at: apiKey.created_at,
      is_active: apiKey.is_active,
      user_id: apiKey.user_id,
      endpoint_uuid: apiKey.endpoint_uuid,
      acts_as_user_id: apiKey.acts_as_user_id,
    }));
  }

  static serializeCreateApiKeyResponse(dbApiKey: {
    uuid: string;
    name: string;
    key: string;
    user_id: string | null;
    created_at: Date;
  }) {
    return {
      uuid: dbApiKey.uuid,
      name: dbApiKey.name,
      key: dbApiKey.key,
      created_at: dbApiKey.created_at,
    };
  }

  // Admin cross-user view. Drops the full `key` secret — an admin listing must
  // never hand back every user's raw key — and emits only a non-reversible
  // prefix (scheme tag + first few chars) for identification.
  static serializeAdminApiKeyList(
    dbApiKeys: Array<{
      uuid: string;
      name: string;
      key: string;
      created_at: Date;
      last_used_at: Date | null;
      is_active: boolean;
      user_id: string | null;
      endpoint_uuid: string | null;
      acts_as_user_id: string | null;
      acts_as_email: string | null;
      owner_email: string | null;
    }>,
  ) {
    return dbApiKeys.map((apiKey) => ({
      uuid: apiKey.uuid,
      name: apiKey.name,
      key_prefix: ApiKeysSerializer.keyPrefix(apiKey.key),
      user_id: apiKey.user_id,
      owner_email: apiKey.owner_email,
      endpoint_uuid: apiKey.endpoint_uuid,
      acts_as_user_id: apiKey.acts_as_user_id,
      acts_as_email: apiKey.acts_as_email,
      created_at: apiKey.created_at,
      last_used_at: apiKey.last_used_at,
      is_active: apiKey.is_active,
    }));
  }
}
