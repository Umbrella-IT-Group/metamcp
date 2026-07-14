export class ApiKeysSerializer {
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

  static serializeApiKeyList(
    dbApiKeys: Array<{
      uuid: string;
      name: string;
      key: string;
      created_at: Date;
      is_active: boolean;
      user_id: string | null;
    }>,
  ) {
    return dbApiKeys.map((apiKey) => ({
      uuid: apiKey.uuid,
      name: apiKey.name,
      key: apiKey.key,
      created_at: apiKey.created_at,
      is_active: apiKey.is_active,
      user_id: apiKey.user_id,
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
      owner_email: string | null;
    }>,
  ) {
    return dbApiKeys.map((apiKey) => ({
      uuid: apiKey.uuid,
      name: apiKey.name,
      key_prefix: `${apiKey.key.slice(0, 10)}…`,
      user_id: apiKey.user_id,
      owner_email: apiKey.owner_email,
      created_at: apiKey.created_at,
      last_used_at: apiKey.last_used_at,
      is_active: apiKey.is_active,
    }));
  }
}
