export class ApiKeysSerializer {
  // The one display rule every key surface shares, so they can never drift
  // apart into "one of them still leaks". Since migration 0034 the key is not
  // stored at all — only its sha256 and its last 4 characters — so the
  // rendered identifier is built from the scheme tag plus that stored tail:
  // `sk_mt_…abcd`. Enough for a human holding the key to recognise its row,
  // and nothing an attacker can extend into a credential. The elision marker
  // sits in the MIDDLE now rather than at the end, because the visible
  // characters are the key's tail, not its head — a trailing marker would
  // read as "the key starts like this", which is no longer true and would
  // send someone hunting for a prefix that does not exist.
  private static keyPrefix(last4: string) {
    return `sk_mt_…${last4}`;
  }

  // Update readback (rename / activate / revoke). Emits the same
  // non-reversible prefix as the two list surfaces below rather than the raw
  // secret.
  //
  // Security review finding: this used to return `key` raw, so the response
  // to a plain rename handed the caller back a usable credential. `update` is
  // a protectedProcedure any member may call against their OWN keys, so the
  // readback re-disclosed a secret that is meant to be shown exactly once, at
  // mint time (serializeCreateApiKeyResponse). A readback of a mutation the
  // caller already identified by uuid needs no credential material at all.
  //
  // Same rename-don't-mask rule as serializeApiKeyList below, for the same
  // fail-to-compile reason.
  static serializeApiKey(dbApiKey: {
    uuid: string;
    name: string;
    last4: string;
    created_at: Date;
    is_active: boolean;
  }) {
    return {
      uuid: dbApiKey.uuid,
      name: dbApiKey.name,
      key_prefix: ApiKeysSerializer.keyPrefix(dbApiKey.last4),
      created_at: dbApiKey.created_at,
      is_active: dbApiKey.is_active,
    };
  }

  // Member-facing list (the caller's own keys PLUS every public/'everyone'
  // key). Emits only the non-reversible identifier for all of them, same as
  // the admin view below — and since migration 0034 there is no stored key
  // value it could emit instead even if this regressed.
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
      last4: string;
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
      key_prefix: ApiKeysSerializer.keyPrefix(apiKey.last4),
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

  // Admin cross-user view. An admin listing must never hand back every user's
  // raw key; since migration 0034 no key value exists to hand back, and this
  // emits the same scheme-tag + stored-tail identifier as the surfaces above.
  static serializeAdminApiKeyList(
    dbApiKeys: Array<{
      uuid: string;
      name: string;
      last4: string;
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
      key_prefix: ApiKeysSerializer.keyPrefix(apiKey.last4),
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
