import crypto from "node:crypto";

import { ConfigKeyEnum } from "@repo/zod-types";
import { and, eq, isNull, notInArray, or } from "drizzle-orm";
import { alias } from "drizzle-orm/pg-core";

import { auth } from "../auth";
import { db } from "../db";
import {
  accountsTable,
  apiKeysTable,
  configTable,
  endpointsTable,
  namespacesTable,
  usersTable,
} from "../db/schema";
import { emitAdminEvent } from "./audit/admin-event";

/**
 * Environment-based bootstrap for MetaMCP.
 * Supports arrays of Users, API Keys, Namespaces, and Endpoints via JSON environment variables.
 */

/**
 * Columns preserved when `BOOTSTRAP_RECREATE_USER=true` +
 * `preserveApiKeysOnRecreate` deletes and re-creates the bootstrap user.
 * `endpoint_uuid` marks the key as scoped (migration 0023) — without it a
 * scoped key silently comes back as a NULL / gateway-wide key on the next
 * container recreate, a silent privilege escalation on a supported ops path.
 * `endpoint_name` is equally load-bearing: deleting the user CASCADES away
 * every USER-OWNED endpoint (`endpoints_user_id_users_id_fk` is
 * `ON DELETE cascade`), and `bootstrapEndpoints` later recreates them with
 * FRESH uuids — so the preserved uuid is stale by restore time and the
 * NAME is the only stable handle to re-resolve the scope against. The
 * preserve projection is typed to this shape, so dropping either field
 * from the select is a compile error, not a silent regression.
 *
 * `acts_as_user_id` + `acts_as_email` (migration 0024) are the identity
 * binding's pair of handles, with EXACTLY the endpoint pair's split of
 * roles: the recreate deletes the user row and better-auth sign-up mints a
 * brand-new id, so the preserved user id is stale by restore time and the
 * EMAIL is the only stable handle to re-resolve the binding against.
 * Restoring a bound key WITHOUT its binding would be silent degradation
 * (the key authenticates, m365 injection fail-closes, the log says
 * restored) — a bound key whose identity cannot be re-resolved is SKIPPED
 * loudly instead.
 */
export interface PreservedApiKey {
  name: string;
  key: string;
  is_active: boolean;
  endpoint_uuid: string | null;
  endpoint_name: string | null;
  acts_as_user_id: string | null;
  acts_as_email: string | null;
}

/** One key restore that could not be performed, with why — surfaced loudly. */
export interface SkippedApiKeyRestore {
  keyName: string;
  reason: "endpoint_missing" | "acts_as_unresolvable";
  endpointName: string | null;
  endpointUuid: string | null;
  actsAsEmail: string | null;
}

/**
 * Decide, for a batch of preserved keys, which can be restored onto the
 * recreated user and which must be SKIPPED. Pure so the invariants can be
 * unit-tested without a live DB (`bootstrap.preserve.test.ts`).
 *
 * Rules:
 * - An unscoped key (`endpoint_uuid` NULL) restores as-is: NULL scope is
 *   the deliberately-grandfathered gateway-wide class, not a promotion.
 * - A scoped key restores ONLY by re-resolving its endpoint NAME to the
 *   endpoint's CURRENT uuid (`endpointUuidByName` — the post-
 *   `bootstrapEndpoints` state). The preserved uuid is never inserted:
 *   for user-owned endpoints it dangles (FK violation) after the recreate
 *   cascade.
 * - A scoped key whose endpoint no longer exists (or whose name could not
 *   be captured at preserve time) is SKIPPED — NEVER restored with a NULL
 *   scope, which would silently widen it to gateway-wide.
 * - An identity-bound key (`acts_as_user_id` non-NULL, migration 0024)
 *   restores ONLY by re-resolving its acted-as EMAIL to the user's CURRENT
 *   id (`userIdByEmail` — the post-`bootstrapUsers` state; the recreate
 *   mints a fresh user id, so the preserved id is stale). If the email is
 *   missing or resolves to no current user, the key is SKIPPED — NEVER
 *   restored unbound (silent degradation: the key would authenticate while
 *   m365 injection fail-closes) and never bound to a guessed identity.
 */
export function planPreservedApiKeyRestores(
  keys: PreservedApiKey[],
  userId: string,
  endpointUuidByName: ReadonlyMap<string, string>,
  userIdByEmail: ReadonlyMap<string, string>,
): {
  restores: {
    name: string;
    key: string;
    user_id: string;
    is_active: boolean;
    endpoint_uuid: string | null;
    acts_as_user_id: string | null;
  }[];
  skipped: SkippedApiKeyRestore[];
} {
  const restores: {
    name: string;
    key: string;
    user_id: string;
    is_active: boolean;
    endpoint_uuid: string | null;
    acts_as_user_id: string | null;
  }[] = [];
  const skipped: SkippedApiKeyRestore[] = [];

  for (const k of keys) {
    let resolvedEndpointUuid: string | null = null;
    if (k.endpoint_uuid !== null) {
      const currentUuid =
        k.endpoint_name !== null
          ? endpointUuidByName.get(k.endpoint_name)
          : undefined;
      if (currentUuid === undefined) {
        skipped.push({
          keyName: k.name,
          reason: "endpoint_missing",
          endpointName: k.endpoint_name,
          endpointUuid: k.endpoint_uuid,
          actsAsEmail: k.acts_as_email,
        });
        continue;
      }
      resolvedEndpointUuid = currentUuid;
    }

    let resolvedActsAsUserId: string | null = null;
    if (k.acts_as_user_id !== null) {
      const currentId =
        k.acts_as_email !== null
          ? userIdByEmail.get(k.acts_as_email)
          : undefined;
      if (currentId === undefined) {
        skipped.push({
          keyName: k.name,
          reason: "acts_as_unresolvable",
          endpointName: k.endpoint_name,
          endpointUuid: k.endpoint_uuid,
          actsAsEmail: k.acts_as_email,
        });
        continue;
      }
      resolvedActsAsUserId = currentId;
    }

    restores.push({
      name: k.name,
      key: k.key,
      user_id: userId,
      is_active: k.is_active,
      endpoint_uuid: resolvedEndpointUuid,
      acts_as_user_id: resolvedActsAsUserId,
    });
  }

  return { restores, skipped };
}

type UserConfig = {
  email: string;
  password: string;
  name?: string;
};

type ApiKeyConfig = {
  name: string;
  is_public?: boolean;
  user_email?: string; // Email of user who owns this key (for private keys)
  owner?: string; // Alias for user_email
};

type NamespaceConfig = {
  name: string;
  description?: string;
  is_public?: boolean;
  user_email?: string; // Email of user who owns this namespace (for private namespaces)
  owner?: string; // Alias for user_email
  update?: boolean;
};

type EndpointConfig = {
  name: string;
  description?: string;
  enable_auth?: boolean;
  enable_auth_query?: boolean;
  enable_auth_oauth?: boolean;
  is_public?: boolean;
  user_email?: string; // Email of user who owns this endpoint (for private endpoints)
  owner?: string; // Alias for user_email
  namespace?: string; // Name of namespace where endpoint should be created (optional, defaults to first available)
  update?: boolean;
};

type EnvConfig = {
  // Single user (legacy support)
  defaultUserEmail?: string;
  defaultUserPassword?: string;
  defaultUserName: string;

  // Multiple users (new)
  users: UserConfig[];

  // User management
  deleteOtherUsers: boolean;

  // User lifecycle / safety
  recreateDefaultUser: boolean;
  preserveApiKeysOnRecreate: boolean;
  warnOnPasswordChange: boolean;
  bootstrapOnlyOnFirstRun: boolean;

  // Registration controls
  disableUiRegistration: boolean;
  disableSsoRegistration: boolean;

  // Array configurations
  apiKeys: ApiKeyConfig[];
  namespaces: NamespaceConfig[];
  endpoints: EndpointConfig[];
};

const BOOTSTRAP_COMPLETE_KEY = "BOOTSTRAP_COMPLETE";
const BOOTSTRAP_USER_PASSWORD_FP_PREFIX =
  "BOOTSTRAP_USER_PASSWORD_FINGERPRINT_";

function parseBool(value: string | undefined, def: boolean): boolean {
  if (value === undefined) return def;
  const v = value.trim().toLowerCase();
  if (["1", "true", "yes", "y", "on"].includes(v)) return true;
  if (["0", "false", "no", "n", "off"].includes(v)) return false;
  return def;
}

function nonEmpty(value: string | undefined): string | undefined {
  const v = value?.trim();
  return v ? v : undefined;
}

function generateApiKey(): string {
  return `sk_mt_${crypto.randomBytes(32).toString("hex")}`; // 64 hex chars
}

function maskKey(key: string): string {
  if (!key) return "";
  if (key.length <= 14) return `${key.slice(0, 6)}…`;
  return `${key.slice(0, 10)}…${key.slice(-4)}`;
}

function sha256Hex(input: string): string {
  return crypto.createHash("sha256").update(input, "utf8").digest("hex");
}

function parseJsonArray<T>(envVar: string | undefined, defaultValue: T[]): T[] {
  if (!envVar) return defaultValue;

  try {
    const parsed = JSON.parse(envVar);
    if (!Array.isArray(parsed)) {
      console.warn(
        `⚠️ Environment variable is not an array, using default: ${envVar.slice(0, 50)}...`,
      );
      return defaultValue;
    }
    return parsed as T[];
  } catch (err) {
    console.warn(
      `⚠️ Failed to parse JSON array from environment variable: ${err}`,
    );
    return defaultValue;
  }
}

/**
 * Get owner email from config object. Supports both "user_email" and "owner" field names.
 * Returns user_email if present, otherwise returns owner, otherwise returns undefined.
 */
function getOwnerEmail(config: {
  user_email?: string;
  owner?: string;
}): string | undefined {
  return config.user_email ?? config.owner;
}

function parseEnvConfig(): EnvConfig {
  // Parse users array
  const usersArray = parseJsonArray<UserConfig>(
    process.env.BOOTSTRAP_USERS,
    [],
  );

  // If single user config exists and users array is empty, add it to array
  const singleUserEmail = nonEmpty(process.env.BOOTSTRAP_USER_EMAIL);
  const singleUserPassword = nonEmpty(process.env.BOOTSTRAP_USER_PASSWORD);

  if (singleUserEmail && singleUserPassword && usersArray.length === 0) {
    usersArray.push({
      email: singleUserEmail,
      password: singleUserPassword,
      name: nonEmpty(process.env.BOOTSTRAP_USER_NAME) ?? "Administrator",
    });
  }

  return {
    // Single user (legacy - for backwards compatibility in some contexts)
    defaultUserEmail: singleUserEmail,
    defaultUserPassword: singleUserPassword,
    defaultUserName:
      nonEmpty(process.env.BOOTSTRAP_USER_NAME) ?? "Administrator",

    // Multiple users
    users: usersArray,

    deleteOtherUsers: parseBool(
      process.env.BOOTSTRAP_DELETE_OTHER_USERS,
      false,
    ),

    recreateDefaultUser: parseBool(process.env.BOOTSTRAP_RECREATE_USER, false),
    preserveApiKeysOnRecreate: parseBool(
      process.env.BOOTSTRAP_PRESERVE_API_KEYS,
      true,
    ),
    warnOnPasswordChange: parseBool(
      process.env.BOOTSTRAP_WARN_PASSWORD_CHANGE,
      true,
    ),
    bootstrapOnlyOnFirstRun: parseBool(
      process.env.BOOTSTRAP_ONLY_FIRST_RUN,
      false,
    ),

    // Registration controls. Upstream defaults BOTH of these OPEN, so an
    // unset variable on a template-derived deploy silently re-opens
    // self-registration, an unauthenticated account-creation exposure on a
    // gateway whose whole access model assumes accounts are provisioned.
    // Absence is therefore read as DISABLED here, and `parseBool` returns the
    // default for an unparseable value as well as an undefined one, so a typo
    // (`BOOTSTRAP_DISABLE_REGISTRATION_UI=flase`) also fails closed rather
    // than opening the door.
    //
    // What keeps a fresh install from locking ITSELF out is ORDERING, not a
    // warning: `applyRegistrationControls` runs AFTER `bootstrapUsers`, so
    // `BOOTSTRAP_USERS` onboards the first administrator through the signup
    // route while it is still open and the lock lands behind it. See that
    // function's comment for why the reverse order self-locks.
    // (`validateConfig`'s lockout warning does NOT cover this case: it only
    // fires when `config.users.length === 0`, and the dangerous combination
    // is disabled-WITH-users-configured, where the users exist to be created
    // and the refusal would be silent.)
    //
    // The lock is structural for a BOOTSTRAP-ENABLED deploy only. A
    // `BOOTSTRAP_ENABLE=false` deploy never reaches this entrypoint at all
    // (`startup.ts`), writes no config row, and `configService`'s readers
    // treat a missing row as `false`, so such a deploy keeps upstream's
    // open-by-absent-row behaviour and has to close registration by hand in
    // the admin UI.
    disableUiRegistration: parseBool(
      process.env.BOOTSTRAP_DISABLE_REGISTRATION_UI,
      true,
    ),
    disableSsoRegistration: parseBool(
      process.env.BOOTSTRAP_DISABLE_REGISTRATION_SSO,
      true,
    ),

    // Array configurations
    apiKeys: parseJsonArray<ApiKeyConfig>(process.env.BOOTSTRAP_API_KEYS, []),
    namespaces: parseJsonArray<NamespaceConfig>(
      process.env.BOOTSTRAP_NAMESPACES,
      [],
    ),
    endpoints: parseJsonArray<EndpointConfig>(
      process.env.BOOTSTRAP_ENDPOINTS,
      [],
    ),
  };
}

async function upsertConfig(key: string, value: string, description?: string) {
  await db
    .insert(configTable)
    .values({
      id: key,
      value,
      description,
      updated_at: new Date(),
    })
    .onConflictDoUpdate({
      target: [configTable.id],
      set: { value, description, updated_at: new Date() },
    });
}

async function getConfigValue(key: string): Promise<string | null> {
  const row = await db.query.configTable.findFirst({
    where: eq(configTable.id, key),
  });
  return row?.value ?? null;
}

/**
 * Read a registration-control flag for the `old_value` half of an audit row,
 * in the SAME shape the UI setter records it (`trpc/config.impl.ts` ->
 * `previousValue`), so a bootstrap row and an administrator's row are
 * comparable in the ledger rather than two different encodings of the same
 * fact.
 *
 * A missing row is `false`, not `null`: that is exactly what
 * `configService.isSignupDisabled()` reports for it, and it is the honest
 * reading — no row means the control was never engaged. `null` is reserved
 * for a read that FAILED, which then compares unequal to any boolean and so
 * makes the change-detection assume-changed. Over-reporting one redundant row
 * after a database blip is the cheap failure; losing the row that says
 * registration was reopened at boot is not.
 */
async function readRegistrationFlag(key: string): Promise<boolean | null> {
  try {
    return (await getConfigValue(key)) === "true";
  } catch (err) {
    // Said out loud, because the resulting audit row is degraded: it will
    // carry `old_value: null` and be emitted even if nothing moved, so the
    // log line is what tells an investigator the null is a failed read rather
    // than a state the flag was ever in.
    console.warn(
      `⚠️ Failed to read current ${key} for the registration-control audit; assuming changed:`,
      err,
    );
    return null;
  }
}

/**
 * Apply the two registration controls (applied every run), leaving an audit
 * row for any flag this boot actually moved.
 *
 * CALL THIS AFTER `bootstrapUsers`, NEVER BEFORE. The ordering is
 * load-bearing, not cosmetic. `ensureUser` creates its accounts by POSTing to
 * Better Auth's own `/api/auth/sign-up/email` through `auth.handler`, which
 * runs the `databaseHooks.user.create.before` hook in `auth.ts`, and that hook
 * THROWS once `DISABLE_SIGNUP` is `true`. Writing the lock first therefore
 * locks bootstrap out of its own onboarding path: with the fail-closed
 * defaults a fresh database would come up with NO administrator at all, and a
 * `BOOTSTRAP_RECREATE_USER=true` run would delete the existing administrator
 * and then fail to recreate it. Creating the configured users first and
 * locking behind them is what makes the fail-closed default safe on a first
 * boot.
 *
 * The gap this opens is not reachable: the whole sequence runs inside
 * `initializeOnStartup()`, which `index.ts` awaits BEFORE `app.listen()`, so
 * no request can arrive while signup is briefly still open.
 *
 * These two writes are the same authority as the admin UI's signup toggles,
 * exercised by the environment instead of by a person: a container restart
 * carrying a changed (or newly absent) BOOTSTRAP_DISABLE_REGISTRATION_* can
 * flip who may create an account, and until now it did so with no durable
 * evidence at all, the only trace being the config row's `updated_at`. They
 * therefore emit the SAME per-key `config.*.set` actions the UI setters emit
 * (`trpc/config.impl.ts`), so an investigation reads one timeline instead of
 * correlating audit rows against container logs. `source: "bootstrap_env"` is
 * what separates the two origins; the absent actor is what makes the row
 * `actor_type: "system"` rather than a phantom administrator.
 *
 * Only a genuine CHANGE is recorded. Bootstrap re-asserts both flags on EVERY
 * start, so emitting unconditionally would bury the one restart that moved a
 * flag under a row per restart that did not.
 */
async function applyRegistrationControls(config: EnvConfig): Promise<void> {
  console.log("🔧 Setting registration controls...");
  try {
    const key = ConfigKeyEnum.enum.DISABLE_SIGNUP;
    const next = config.disableUiRegistration;
    const previous = await readRegistrationFlag(key);
    await upsertConfig(
      key,
      next.toString(),
      "Whether new user signup is disabled",
    );
    // After the write, never before: a row claiming signup was reopened by a
    // call that then threw would be worse than no row at all.
    if (previous !== next) {
      emitAdminEvent(undefined, {
        action: "config.signup_disabled.set",
        target_type: "config_key",
        target_id: key,
        detail: {
          old_value: previous,
          new_value: next,
          source: "bootstrap_env",
        },
      });
    }
  } catch (err) {
    console.warn("⚠️ Failed to set UI registration control:", err);
  }

  try {
    const key = ConfigKeyEnum.enum.DISABLE_SSO_SIGNUP;
    const next = config.disableSsoRegistration;
    const previous = await readRegistrationFlag(key);
    await upsertConfig(
      key,
      next.toString(),
      "Whether new user signup via SSO/OAuth is disabled",
    );
    if (previous !== next) {
      emitAdminEvent(undefined, {
        action: "config.sso_signup_disabled.set",
        target_type: "config_key",
        target_id: key,
        detail: {
          old_value: previous,
          new_value: next,
          source: "bootstrap_env",
        },
      });
    }
  } catch (err) {
    console.warn("⚠️ Failed to set SSO registration control:", err);
  }

  console.log(
    `✓ Registration controls set: UI=${!config.disableUiRegistration}, SSO=${!config.disableSsoRegistration}`,
  );
}

async function shouldSkipBootstrap(config: EnvConfig): Promise<boolean> {
  if (!config.bootstrapOnlyOnFirstRun) return false;

  try {
    const v = await getConfigValue(BOOTSTRAP_COMPLETE_KEY);
    if (v === "true") {
      console.log(
        "✓ Bootstrap already completed; BOOTSTRAP_ONLY_FIRST_RUN=true (skipping one-time bootstrap steps)",
      );
      return true;
    }
  } catch (err) {
    console.warn(
      "⚠️ Failed to read BOOTSTRAP_COMPLETE marker; proceeding with bootstrap.",
      err,
    );
  }

  return false;
}

async function markBootstrapComplete(): Promise<void> {
  try {
    await upsertConfig(
      BOOTSTRAP_COMPLETE_KEY,
      "true",
      "One-time bootstrap completion marker",
    );
  } catch (err) {
    console.warn("⚠️ Failed to write BOOTSTRAP_COMPLETE marker:", err);
  }
}

async function warnIfPasswordChanged(
  email: string,
  password: string,
  warnOnChange: boolean,
  hasExistingUser: boolean,
  recreateUser: boolean,
): Promise<void> {
  if (!warnOnChange) return;
  if (!hasExistingUser) return;

  try {
    const currentFp = sha256Hex(password);
    const fpKey = `${BOOTSTRAP_USER_PASSWORD_FP_PREFIX}${email}`;
    const previousFp = await getConfigValue(fpKey);

    if (previousFp && previousFp !== currentFp && !recreateUser) {
      console.warn(
        `⚠️ Password for ${email} appears to have changed since last applied.`,
      );
      console.warn(
        "⚠️ BOOTSTRAP_RECREATE_USER=false so the existing user's password will NOT be updated.",
      );
      console.warn(
        "⚠️ To force the environment password to apply, set BOOTSTRAP_RECREATE_USER=true.",
      );
    }
  } catch (err) {
    console.warn(
      `⚠️ Failed password-change detection for ${email} (ignored):`,
      err,
    );
  }
}

async function recordPasswordFingerprint(
  email: string,
  password: string,
): Promise<void> {
  try {
    const fpKey = `${BOOTSTRAP_USER_PASSWORD_FP_PREFIX}${email}`;
    await upsertConfig(
      fpKey,
      sha256Hex(password),
      `Fingerprint of last-applied password for ${email}`,
    );
  } catch (err) {
    console.warn(`⚠️ Failed to store password fingerprint for ${email}:`, err);
  }
}

/**
 * Loud notice for the worst recreate outcome: the user's API keys were
 * already DELETED (the recreate path removes them before sign-up) but the
 * user never came back, so the deferred restore will never run for them —
 * N credentials died behind an otherwise generic sign-up warning. Key
 * NAMES only, never values: the values are secrets and are gone anyway.
 */
function warnPreservedKeysUnrestorable(
  email: string,
  preservedKeys: PreservedApiKey[] | undefined,
): void {
  if (!preservedKeys || preservedKeys.length === 0) return;
  console.warn(
    `⚠️ ${preservedKeys.length} preserved API key(s) for ${email} were deleted by the recreate but CANNOT be restored because the user was not recreated: ${preservedKeys
      .map((k) => k.name)
      .join(", ")}. Re-mint them once the user exists again.`,
  );
}

/**
 * Ensure a single user exists.
 */
async function ensureUser(
  userConfig: UserConfig,
  config: EnvConfig,
): Promise<{
  userId?: string;
  email: string;
  recreated: boolean;
  /**
   * Keys captured before the recreate delete. Restoring them is DEFERRED to
   * `restorePreservedApiKeys`, which the bootstrap entrypoint runs AFTER
   * `bootstrapEndpoints`: the user delete cascades user-owned endpoints
   * away and they come back with fresh uuids, so a scoped key can only be
   * restored once the endpoints exist again (re-resolved by name).
   */
  preservedApiKeys?: PreservedApiKey[];
}> {
  const email = userConfig.email;
  const password = userConfig.password;
  const name = userConfig.name ?? "User";

  console.log(`🔧 Initializing user: ${email}`);

  const existing = await db.query.usersTable.findFirst({
    where: eq(usersTable.email, email),
  });

  await warnIfPasswordChanged(
    email,
    password,
    config.warnOnPasswordChange,
    !!existing,
    config.recreateDefaultUser,
  );

  let preservedUserApiKeys: PreservedApiKey[] | undefined;

  let recreated = false;

  if (existing && config.recreateDefaultUser) {
    recreated = true;
    console.warn(
      `⚠️ BOOTSTRAP_RECREATE_USER=true — deleting existing user ${email} to reapply password via Better Auth`,
    );

    if (config.preserveApiKeysOnRecreate) {
      try {
        // Second users join, aliased: acts_as_user_id → the acted-as user's
        // CURRENT email — the stable handle the deferred restore re-resolves
        // the binding against (the user id minted by the recreate's sign-up
        // is different, so the preserved id is stale by restore time).
        const actsAsUsers = alias(usersTable, "acts_as_users");
        // The capture must cover BOTH edges into the doomed user row:
        // keys the user OWNS (user_id) — the restorable set — and keys that
        // merely ACT AS them (acts_as_user_id, migration 0024) while being
        // owned elsewhere (public or another user). The latter die via the
        // acts_as FK's ON DELETE CASCADE when the user row is deleted below;
        // they cannot be restored (an identity-bound key must be owned by
        // the identity it exercises — post-round-2 rule; such rows predate
        // it), but their destruction must be LOUD, never silent.
        const capturedRows = await db
          .select({
            name: apiKeysTable.name,
            key: apiKeysTable.key,
            is_active: apiKeysTable.is_active,
            user_id: apiKeysTable.user_id,
            // Load-bearing pair: `endpoint_uuid` marks the key as scoped and
            // `endpoint_name` (left join — NULL for unscoped keys) is the
            // stable handle the deferred restore re-resolves the scope
            // against, because this uuid goes stale the moment the user
            // delete below cascades user-owned endpoints away.
            endpoint_uuid: apiKeysTable.endpoint_uuid,
            endpoint_name: endpointsTable.name,
            // Same split of roles for the identity binding (see the
            // PreservedApiKey doc comment).
            acts_as_user_id: apiKeysTable.acts_as_user_id,
            acts_as_email: actsAsUsers.email,
          })
          .from(apiKeysTable)
          .leftJoin(
            endpointsTable,
            eq(apiKeysTable.endpoint_uuid, endpointsTable.uuid),
          )
          .leftJoin(
            actsAsUsers,
            eq(apiKeysTable.acts_as_user_id, actsAsUsers.id),
          )
          .where(
            or(
              eq(apiKeysTable.user_id, existing.id),
              eq(apiKeysTable.acts_as_user_id, existing.id),
            ),
          );

        const ownedKeys: PreservedApiKey[] = [];
        const foreignBoundKeyNames: string[] = [];
        for (const row of capturedRows) {
          if (row.user_id === existing.id) {
            ownedKeys.push({
              name: row.name,
              key: row.key,
              is_active: row.is_active,
              endpoint_uuid: row.endpoint_uuid ?? null,
              endpoint_name: row.endpoint_name ?? null,
              acts_as_user_id: row.acts_as_user_id ?? null,
              acts_as_email: row.acts_as_email ?? null,
            });
          } else {
            foreignBoundKeyNames.push(row.name);
          }
        }
        preservedUserApiKeys = ownedKeys;

        if (foreignBoundKeyNames.length > 0) {
          console.warn(
            `⚠️ ${foreignBoundKeyNames.length} API key(s) bound to ${email}'s identity but NOT owned by them (public or another user's) will be DELETED by the recreate cascade and CANNOT be restored — an identity-bound key must be owned by the identity it exercises: ${foreignBoundKeyNames.join(", ")}. Re-mint compliant keys if still needed.`,
          );
        }
      } catch (err) {
        console.warn(`⚠️ Failed to preserve API keys for ${email}:`, err);
      }
    }

    try {
      await db
        .delete(accountsTable)
        .where(eq(accountsTable.userId, existing.id));
    } catch (err) {
      console.warn(`⚠️ Failed to delete accounts for ${email}:`, err);
    }

    try {
      await db
        .delete(apiKeysTable)
        .where(eq(apiKeysTable.user_id, existing.id));
    } catch (err) {
      console.warn(
        `⚠️ Failed to delete user-scoped API keys for ${email}:`,
        err,
      );
    }

    try {
      await db.delete(usersTable).where(eq(usersTable.id, existing.id));
    } catch (err) {
      console.warn(`⚠️ Failed to delete existing user ${email}:`, err);
    }
  }

  if (!existing || recreated) {
    // Create via Better Auth
    const request = new Request("http://internal/api/auth/sign-up/email", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email,
        password,
        name,
      }),
    });

    const response = await auth.handler(request);
    if (!response.ok) {
      const body = await response.text().catch(() => "");
      console.warn(
        `⚠️ Better Auth sign-up failed for ${email} (${response.status}). Continuing startup. ${
          body ? `Response: ${body}` : ""
        }`,
      );
      // The keys were deleted above; without a user there is no restore.
      warnPreservedKeysUnrestorable(email, preservedUserApiKeys);
      return { email, recreated };
    }
  }

  const user = await db.query.usersTable.findFirst({
    where: eq(usersTable.email, email),
  });

  if (!user) {
    console.warn(`⚠️ User ${email} not found after signup; skipping.`);
    // Same credential-loss case as the sign-up failure above.
    warnPreservedKeysUnrestorable(email, preservedUserApiKeys);
    return { email, recreated };
  }

  // Keep metadata consistent
  try {
    await db
      .update(usersTable)
      .set({
        name,
        emailVerified: true,
        updatedAt: new Date(),
      })
      .where(eq(usersTable.id, user.id));
  } catch (err) {
    console.warn(`⚠️ Failed to update user metadata for ${email}:`, err);
  }

  // NOTE: preserved keys are deliberately NOT restored here. The restore
  // must run AFTER `bootstrapEndpoints` (see `restorePreservedApiKeys`):
  // inserting the preserved `endpoint_uuid` at this point violates the
  // `api_keys.endpoint_uuid → endpoints.uuid` FK for any key scoped to a
  // user-owned endpoint (cascaded away by the user delete above), which is
  // exactly the silent-loss-reported-as-success bug this ordering fixes.

  // Record fingerprint when we actually create/recreate
  if (!existing || recreated) {
    await recordPasswordFingerprint(email, password);
  }

  console.log(`✓ User ready: ${email}`);
  return {
    userId: user.id,
    email,
    recreated,
    preservedApiKeys:
      recreated && config.preserveApiKeysOnRecreate
        ? preservedUserApiKeys
        : undefined,
  };
}

/** Preserved keys awaiting the post-`bootstrapEndpoints` restore pass. */
type PendingApiKeyRestore = {
  userId: string;
  email: string;
  keys: PreservedApiKey[];
};

/**
 * Bootstrap all users from configuration.
 */
async function bootstrapUsers(config: EnvConfig): Promise<{
  userMap: Map<string, string>;
  pendingApiKeyRestores: PendingApiKeyRestore[];
}> {
  const userMap = new Map<string, string>(); // email -> userId
  const pendingApiKeyRestores: PendingApiKeyRestore[] = [];

  if (!config.users || config.users.length === 0) {
    console.warn(
      "⚠️ No users configured for bootstrap (BOOTSTRAP_USERS is empty and no single user config found)",
    );
    return { userMap, pendingApiKeyRestores };
  }

  console.log(`👥 Bootstrapping ${config.users.length} user(s)...`);

  for (const userConfig of config.users) {
    try {
      if (!userConfig.email || !userConfig.password) {
        console.warn("⚠️ User config missing email or password; skipping");
        continue;
      }

      const result = await ensureUser(userConfig, config);
      if (result.userId) {
        userMap.set(result.email, result.userId);
        if (result.preservedApiKeys && result.preservedApiKeys.length > 0) {
          pendingApiKeyRestores.push({
            userId: result.userId,
            email: result.email,
            keys: result.preservedApiKeys,
          });
        }
      }
    } catch (err) {
      console.warn(`⚠️ Failed to bootstrap user ${userConfig.email}:`, err);
    }
  }

  return { userMap, pendingApiKeyRestores };
}

/**
 * Restore the API keys preserved across a `BOOTSTRAP_RECREATE_USER` delete.
 * MUST run after `bootstrapEndpoints`: the user delete cascades user-owned
 * endpoints away and `bootstrapEndpoints` recreates them with FRESH uuids,
 * so each scoped key's endpoint NAME is re-resolved against the CURRENT
 * endpoint set here. A scoped key whose endpoint no longer exists is
 * skipped LOUDLY — never restored gateway-wide, never reported as restored.
 *
 * Ordering note: `bootstrapApiKeys` (config-declared keys) has already run
 * by now. On a name collision the preserved key wins via
 * `onConflictDoUpdate` — the same net result as the pre-fix order, where
 * the restore ran first and `bootstrapApiKeys` skipped the existing name.
 */
async function restorePreservedApiKeys(
  pending: PendingApiKeyRestore[],
): Promise<void> {
  if (pending.length === 0) return;

  let endpointUuidByName: Map<string, string>;
  try {
    const endpointRows = await db
      .select({ uuid: endpointsTable.uuid, name: endpointsTable.name })
      .from(endpointsTable);
    endpointUuidByName = new Map(
      endpointRows.map((row) => [row.name, row.uuid]),
    );
  } catch (err) {
    const total = pending.reduce((sum, p) => sum + p.keys.length, 0);
    console.warn(
      `⚠️ Failed to load endpoints for API key restore — ${total} preserved key(s) NOT restored (restoring blind could widen a scoped key to gateway-wide):`,
      err,
    );
    return;
  }

  // The acted-as email → CURRENT user id map, for re-binding identity-bound
  // keys (migration 0024). Loaded only when some preserved key actually
  // carries a binding — and, symmetrically with the endpoints load above,
  // a failed load aborts the restore LOUDLY rather than restoring blind
  // (an unbound restore of a bound key is silent degradation; a guessed
  // binding is worse).
  let userIdByEmail: Map<string, string> = new Map();
  const anyBound = pending.some((p) =>
    p.keys.some((k) => k.acts_as_user_id !== null),
  );
  if (anyBound) {
    try {
      const userRows = await db
        .select({ id: usersTable.id, email: usersTable.email })
        .from(usersTable);
      userIdByEmail = new Map(userRows.map((row) => [row.email, row.id]));
    } catch (err) {
      const total = pending.reduce((sum, p) => sum + p.keys.length, 0);
      console.warn(
        `⚠️ Failed to load users for API key restore — ${total} preserved key(s) NOT restored (identity-bound keys cannot be re-bound without the email → user map):`,
        err,
      );
      return;
    }
  }

  for (const { userId, email, keys } of pending) {
    const plan = planPreservedApiKeyRestores(
      keys,
      userId,
      endpointUuidByName,
      userIdByEmail,
    );

    let restored = 0;
    let failed = 0;
    for (const values of plan.restores) {
      try {
        await db
          .insert(apiKeysTable)
          .values(values)
          .onConflictDoUpdate({
            target: [apiKeysTable.user_id, apiKeysTable.name],
            set: {
              key: values.key,
              is_active: values.is_active,
              // Restore the scope on conflict too, otherwise a pre-existing
              // row could keep a stale (or NULL) scope.
              endpoint_uuid: values.endpoint_uuid,
              // Same for the identity binding — a conflicting row must not
              // keep a stale (or NULL) acts-as identity.
              acts_as_user_id: values.acts_as_user_id,
            },
          });
        restored++;
      } catch (err) {
        failed++;
        console.warn(
          `⚠️ Failed to restore preserved API key "${values.name}" for ${email}:`,
          err,
        );
      }
    }

    for (const skip of plan.skipped) {
      if (skip.reason === "acts_as_unresolvable") {
        console.warn(
          `⚠️ Preserved API key "${skip.keyName}" for ${email} was bound to acts-as identity "${skip.actsAsEmail ?? "unknown (email not captured)"}", which cannot be resolved to a current user after the recreate — key NOT restored (restoring it unbound would silently degrade an identity key; restoring with a guessed identity is worse). Re-mint it against the intended user.`,
        );
      } else {
        console.warn(
          `⚠️ Preserved API key "${skip.keyName}" for ${email} was scoped to endpoint "${skip.endpointName ?? `uuid ${skip.endpointUuid}`}", which no longer exists after the recreate — key NOT restored (a NULL-scope restore would widen it to gateway-wide). Re-mint it against the intended endpoint.`,
        );
      }
    }

    console.log(
      `✓ API key restore for recreated user ${email}: ${restored} restored, ${plan.skipped.length} skipped${failed > 0 ? `, ${failed} FAILED` : ""} (of ${keys.length} preserved)`,
    );
  }
}

async function maybeDeleteOtherUsers(
  config: EnvConfig,
  bootstrappedEmails: string[],
): Promise<void> {
  if (!config.deleteOtherUsers) return;
  if (bootstrappedEmails.length === 0) {
    console.warn(
      "⚠️ BOOTSTRAP_DELETE_OTHER_USERS=true but no bootstrapped users found; skipping to avoid lockout.",
    );
    return;
  }

  console.warn(
    `⚠️ BOOTSTRAP_DELETE_OTHER_USERS=true — deleting all users except bootstrapped users`,
  );

  try {
    await db
      .delete(usersTable)
      .where(notInArray(usersTable.email, bootstrappedEmails));
    console.log("✓ Deleted other users");
  } catch (err) {
    console.warn("⚠️ Failed to delete other users:", err);
  }
}

/**
 * Identity of a key a deferred preserved-key restore will overwrite:
 * restores upsert on the (user_id, name) unique pair, so that pair is the
 * collision key. NUL separator — it cannot appear in either component.
 */
function pendingRestoreKeyId(userId: string, name: string): string {
  return `${userId}\u0000${name}`;
}

/**
 * Bootstrap API keys from configuration array.
 *
 * `pendingRestoreKeyIds` names the (user_id, name) pairs that
 * `restorePreservedApiKeys` will upsert LATER in the run (it runs after
 * `bootstrapEndpoints`; this runs before). A config-declared key that
 * collides with a pending restore is still minted — if the restore then
 * fails, a working key beats none — but its log line must not present the
 * fresh masked value as the live credential, because the restore's
 * `onConflictDoUpdate` replaces it moments later. Without the amendment
 * the log said "Created ... : <mask>" and the mask was never the value
 * that survives startup.
 */
async function bootstrapApiKeys(
  config: EnvConfig,
  userMap: Map<string, string>,
  pendingRestoreKeyIds: ReadonlySet<string> = new Set(),
): Promise<void> {
  if (!config.apiKeys || config.apiKeys.length === 0) {
    console.log(
      "ℹ️ No API keys configured for bootstrap (BOOTSTRAP_API_KEYS is empty)",
    );
    return;
  }

  console.log(`🔑 Bootstrapping ${config.apiKeys.length} API key(s)...`);

  for (const apiKeyConfig of config.apiKeys) {
    try {
      const name = apiKeyConfig.name;
      const isPublic = apiKeyConfig.is_public ?? false;
      const ownerEmail = getOwnerEmail(apiKeyConfig);

      let userId: string | null = null;

      if (!isPublic) {
        // For private keys, determine the owner
        if (ownerEmail) {
          userId = userMap.get(ownerEmail) ?? null;
          if (!userId) {
            console.warn(
              `⚠️ Skipping API key "${name}" because user "${ownerEmail}" was not found`,
            );
            continue;
          }
        } else {
          // No user specified, use first user
          const firstUserId = Array.from(userMap.values())[0];
          if (!firstUserId) {
            console.warn(
              `⚠️ Skipping private API key "${name}" because no users are available`,
            );
            continue;
          }
          userId = firstUserId;
        }
      }

      // Check if key already exists
      const whereCondition = userId
        ? and(eq(apiKeysTable.user_id, userId), eq(apiKeysTable.name, name))
        : and(isNull(apiKeysTable.user_id), eq(apiKeysTable.name, name));

      const existing = await db.query.apiKeysTable.findFirst({
        where: whereCondition,
      });

      if (!existing) {
        const key = generateApiKey();
        await db.insert(apiKeysTable).values({
          name,
          key,
          user_id: userId,
          is_active: true,
        });

        const ownerInfo = userId
          ? `for user ${ownerEmail ?? Array.from(userMap.keys())[0]}`
          : "(public)";
        const restorePending =
          userId !== null &&
          pendingRestoreKeyIds.has(pendingRestoreKeyId(userId, name));
        if (restorePending) {
          // Log truth: the value minted here is NOT the one that survives
          // startup — the deferred restore overwrites it. Never print this
          // mask as if it were the live credential.
          console.log(
            `✓ Created ${isPublic ? "public" : "private"} API key "${name}" ${ownerInfo} (placeholder — a preserved-key restore for this name is pending and will overwrite it; the restored value is the live one)`,
          );
        } else {
          console.log(
            `✓ Created ${isPublic ? "public" : "private"} API key "${name}" ${ownerInfo}: ${maskKey(key)}`,
          );
        }
      } else {
        const ownerInfo = userId
          ? `for user ${ownerEmail ?? Array.from(userMap.keys())[0]}`
          : "(public)";
        console.log(
          `✓ ${isPublic ? "Public" : "Private"} API key "${name}" ${ownerInfo} already exists: ${maskKey(existing.key)}`,
        );
      }
    } catch (err) {
      console.warn(
        `⚠️ Failed to bootstrap API key "${apiKeyConfig.name}":`,
        err,
      );
    }
  }
}

/**
 * Bootstrap namespaces from configuration array.
 */
async function bootstrapNamespaces(
  config: EnvConfig,
  userMap: Map<string, string>,
): Promise<Map<string, string>> {
  const namespaceMap = new Map<string, string>(); // name -> uuid

  if (!config.namespaces || config.namespaces.length === 0) {
    console.log(
      "ℹ️ No namespaces configured for bootstrap (BOOTSTRAP_NAMESPACES is empty)",
    );
    return namespaceMap;
  }

  console.log(`🔧 Bootstrapping ${config.namespaces.length} namespace(s)...`);

  for (const nsConfig of config.namespaces) {
    try {
      const name = nsConfig.name;
      const description = nsConfig.description ?? null;
      const isPublic = nsConfig.is_public ?? false;
      const shouldUpdate = nsConfig.update ?? true;
      const ownerEmail = getOwnerEmail(nsConfig);

      let ownerUserId: string | null = null;

      if (!isPublic) {
        // For private namespaces, determine the owner
        if (ownerEmail) {
          ownerUserId = userMap.get(ownerEmail) ?? null;
          if (!ownerUserId) {
            console.warn(
              `⚠️ Skipping namespace "${name}" because user "${ownerEmail}" was not found`,
            );
            continue;
          }
        } else {
          // No user specified, use first user
          const firstUserId = Array.from(userMap.values())[0];
          if (!firstUserId) {
            console.warn(
              `⚠️ Skipping private namespace "${name}" because no users are available`,
            );
            continue;
          }
          ownerUserId = firstUserId;
        }
      }

      // Look for existing namespace
      const whereCondition = ownerUserId
        ? and(
            eq(namespacesTable.name, name),
            eq(namespacesTable.user_id, ownerUserId),
          )
        : and(eq(namespacesTable.name, name), isNull(namespacesTable.user_id));

      const existing = await db.query.namespacesTable.findFirst({
        where: whereCondition,
      });

      if (!existing) {
        const inserted = await db
          .insert(namespacesTable)
          .values({
            name,
            description,
            user_id: ownerUserId,
          })
          .returning({ uuid: namespacesTable.uuid });

        const uuid = inserted?.[0]?.uuid;
        if (uuid) {
          namespaceMap.set(name, uuid);
          const ownerInfo = ownerUserId
            ? `for user ${ownerEmail ?? Array.from(userMap.keys())[0]}`
            : "(public)";
          console.log(
            `✓ Created ${isPublic ? "public" : "private"} namespace "${name}" ${ownerInfo}`,
          );
        } else {
          console.warn(`⚠️ Namespace insert for "${name}" did not return uuid`);
        }
      } else {
        namespaceMap.set(name, existing.uuid);

        if (shouldUpdate) {
          await db
            .update(namespacesTable)
            .set({
              description: description ?? existing.description,
              updated_at: new Date(),
              user_id: ownerUserId,
            })
            .where(eq(namespacesTable.uuid, existing.uuid));

          console.log(`✓ Updated namespace "${name}"`);
        } else {
          console.log(`✓ Namespace "${name}" already exists (no update)`);
        }
      }
    } catch (err) {
      console.warn(`⚠️ Failed to bootstrap namespace "${nsConfig.name}":`, err);
    }
  }

  return namespaceMap;
}

/**
 * Bootstrap endpoints from configuration array.
 */
async function bootstrapEndpoints(
  config: EnvConfig,
  namespaceMap: Map<string, string>,
  userMap: Map<string, string>,
): Promise<void> {
  if (!config.endpoints || config.endpoints.length === 0) {
    console.log(
      "ℹ️ No endpoints configured for bootstrap (BOOTSTRAP_ENDPOINTS is empty)",
    );
    return;
  }

  console.log(`🔧 Bootstrapping ${config.endpoints.length} endpoint(s)...`);

  for (const epConfig of config.endpoints) {
    try {
      const name = epConfig.name;
      const description = epConfig.description ?? null;
      const enableAuth = epConfig.enable_auth ?? true;
      const enableAuthQuery = epConfig.enable_auth_query ?? false;
      const enableAuthOauth = epConfig.enable_auth_oauth ?? false;
      const isPublic = epConfig.is_public ?? true;
      const shouldUpdate = epConfig.update ?? true;
      const ownerEmail = getOwnerEmail(epConfig);

      let ownerUserId: string | null = null;

      if (!isPublic) {
        // For private endpoints, determine the owner
        if (ownerEmail) {
          ownerUserId = userMap.get(ownerEmail) ?? null;
          if (!ownerUserId) {
            console.warn(
              `⚠️ Skipping endpoint "${name}" because user "${ownerEmail}" was not found`,
            );
            continue;
          }
        } else {
          // No user specified, use first user
          const firstUserId = Array.from(userMap.values())[0];
          if (!firstUserId) {
            console.warn(
              `⚠️ Skipping private endpoint "${name}" because no users are available`,
            );
            continue;
          }
          ownerUserId = firstUserId;
        }
      }

      // Find the namespace UUID
      let namespaceUuid: string | undefined;
      let namespaceName: string | undefined;

      if (epConfig.namespace) {
        // Specific namespace requested
        namespaceUuid = namespaceMap.get(epConfig.namespace);
        namespaceName = epConfig.namespace;

        if (!namespaceUuid) {
          console.warn(
            `⚠️ Skipping endpoint "${name}" because specified namespace "${epConfig.namespace}" was not found. Available namespaces: ${Array.from(namespaceMap.keys()).join(", ")}`,
          );
          continue;
        }
      } else {
        // No namespace specified, use first available
        if (namespaceMap.size > 0) {
          namespaceUuid = Array.from(namespaceMap.values())[0];
          namespaceName = Array.from(namespaceMap.keys())[0];
        }
      }

      if (!namespaceUuid) {
        console.warn(
          `⚠️ Skipping endpoint "${name}" because no namespace is available. Bootstrap at least one namespace first.`,
        );
        continue;
      }

      // Look for existing endpoint
      const existing = await db.query.endpointsTable.findFirst({
        where: eq(endpointsTable.name, name),
      });

      const values = {
        name,
        description,
        namespace_uuid: namespaceUuid,
        enable_api_key_auth: enableAuth,
        use_query_param_auth: enableAuthQuery,
        enable_oauth: enableAuthOauth,
        user_id: ownerUserId,
        updated_at: new Date(),
      };

      if (!existing) {
        await db.insert(endpointsTable).values(values);
        const ownerInfo = ownerUserId
          ? `for user ${ownerEmail ?? Array.from(userMap.keys())[0]}`
          : "(public)";
        const namespaceInfo = namespaceName
          ? ` in namespace "${namespaceName}"`
          : "";
        console.log(
          `✓ Created ${isPublic ? "public" : "private"} endpoint "${name}" ${ownerInfo}${namespaceInfo}`,
        );
      } else {
        if (shouldUpdate) {
          await db
            .update(endpointsTable)
            .set(values)
            .where(eq(endpointsTable.uuid, existing.uuid));
          const namespaceInfo = namespaceName
            ? ` in namespace "${namespaceName}"`
            : "";
          console.log(`✓ Updated endpoint "${name}"${namespaceInfo}`);
        } else {
          console.log(`✓ Endpoint "${name}" already exists (no update)`);
        }
      }
    } catch (err) {
      console.warn(`⚠️ Failed to bootstrap endpoint "${epConfig.name}":`, err);
    }
  }
}

function validateConfig(config: EnvConfig): void {
  if (
    config.disableUiRegistration &&
    config.disableSsoRegistration &&
    config.users.length === 0
  ) {
    console.warn(
      "⚠️ Both UI and SSO registration are disabled, but no users are configured. This may lock you out.",
    );
  }

  if (config.recreateDefaultUser && config.users.length === 0) {
    console.warn(
      "⚠️ BOOTSTRAP_RECREATE_USER=true but no users are configured; recreation cannot run.",
    );
  }

  // Validate users
  for (const user of config.users) {
    if (!user.email || user.email.trim() === "") {
      console.warn("⚠️ User configuration is missing 'email' field");
    }
    if (!user.password || user.password.trim() === "") {
      console.warn(`⚠️ User ${user.email} is missing 'password' field`);
    }
    if (user.password && user.password.length < 8) {
      console.warn(
        `⚠️ Password for ${user.email} is less than 8 characters. Consider using a stronger password.`,
      );
    }
  }

  if (config.recreateDefaultUser && !config.preserveApiKeysOnRecreate) {
    console.warn(
      "⚠️ BOOTSTRAP_RECREATE_USER=true and BOOTSTRAP_PRESERVE_API_KEYS=false",
    );
    console.warn("     This will delete all API keys for the users!");
  }

  if (config.deleteOtherUsers && config.users.length === 0) {
    console.warn(
      "⚠️ BOOTSTRAP_DELETE_OTHER_USERS=true without any users configured",
    );
    console.warn("     This could lock you out of the system!");
  }

  // Validate API keys configuration
  for (const apiKey of config.apiKeys) {
    if (!apiKey.name || apiKey.name.trim() === "") {
      console.warn("⚠️ API key configuration is missing 'name' field");
    }
    const ownerEmail = getOwnerEmail(apiKey);
    if (!apiKey.is_public && ownerEmail && config.users.length === 0) {
      console.warn(
        `⚠️ API key "${apiKey.name}" references user "${ownerEmail}" but no users are configured`,
      );
    }
  }

  // Validate namespaces configuration
  for (const ns of config.namespaces) {
    if (!ns.name || ns.name.trim() === "") {
      console.warn("⚠️ Namespace configuration is missing 'name' field");
    }
    const ownerEmail = getOwnerEmail(ns);
    if (!ns.is_public && ownerEmail && config.users.length === 0) {
      console.warn(
        `⚠️ Namespace "${ns.name}" references user "${ownerEmail}" but no users are configured`,
      );
    }
  }

  // Validate endpoints configuration
  for (const ep of config.endpoints) {
    if (!ep.name || ep.name.trim() === "") {
      console.warn("⚠️ Endpoint configuration is missing 'name' field");
    }
    const ownerEmail = getOwnerEmail(ep);
    if (!ep.is_public && ownerEmail && config.users.length === 0) {
      console.warn(
        `⚠️ Endpoint "${ep.name}" references user "${ownerEmail}" but no users are configured`,
      );
    }
  }

  if (config.endpoints.length > 0 && config.namespaces.length === 0) {
    console.warn("⚠️ Endpoints are configured but no namespaces are defined.");
    console.warn(
      "     Endpoints require at least one namespace to be created!",
    );
  }
}

export async function initializeEnvironmentConfiguration(): Promise<void> {
  console.log("🚀 Initializing environment-based configuration...");
  const config = parseEnvConfig();

  // Log configuration summary for debugging
  if (process.env.BOOTSTRAP_DEBUG === "true") {
    console.log("📋 Bootstrap Configuration:");
    console.log(`   Users: ${config.users.length} configured`);
    console.log(`   API Keys: ${config.apiKeys.length} configured`);
    console.log(`   Namespaces: ${config.namespaces.length} configured`);
    console.log(`   Endpoints: ${config.endpoints.length} configured`);
    console.log(`   Recreate User: ${config.recreateDefaultUser}`);
    console.log(`   First Run Only: ${config.bootstrapOnlyOnFirstRun}`);
    console.log(`   Delete Others: ${config.deleteOtherUsers}`);
  }

  validateConfig(config);

  // One-time bootstrap guard
  const skipBootstrap = await shouldSkipBootstrap(config);
  if (skipBootstrap) {
    // A guarded boot creates no users, so there is no create-before-lock
    // ordering to honour here; the flags are still asserted because they are
    // "applied every run" controls, and skipping them would leave a
    // BOOTSTRAP_ONLY_FIRST_RUN deploy's registration state wherever the last
    // unguarded boot (or an administrator) happened to leave it.
    await applyRegistrationControls(config);
    console.log("✅ Environment-based configuration initialized (guarded)");
    return;
  }

  // Bootstrap all users
  let userMap: Map<string, string>;
  let pendingApiKeyRestores: PendingApiKeyRestore[];
  try {
    ({ userMap, pendingApiKeyRestores } = await bootstrapUsers(config));
  } catch (err) {
    console.warn("⚠️ Users bootstrap failed:", err);
    userMap = new Map();
    pendingApiKeyRestores = [];
  }

  // Delete other users after bootstrapping configured users
  try {
    const bootstrappedEmails = Array.from(userMap.keys());
    await maybeDeleteOtherUsers(config, bootstrappedEmails);
  } catch (err) {
    console.warn("⚠️ User cleanup step failed:", err);
  }

  // Registration controls, HERE and not earlier: every account this boot
  // creates goes through the signup route these controls close (see
  // applyRegistrationControls). Nothing below this line signs a user up, so
  // this is the earliest safe point rather than the end of the run.
  await applyRegistrationControls(config);

  // Bootstrap API keys. The pending-restore pairs let the log stay truthful
  // for a config-declared key the deferred restore will overwrite (see
  // bootstrapApiKeys' doc comment).
  try {
    const pendingRestoreIds = new Set(
      pendingApiKeyRestores.flatMap((pending) =>
        pending.keys.map((k) => pendingRestoreKeyId(pending.userId, k.name)),
      ),
    );
    await bootstrapApiKeys(config, userMap, pendingRestoreIds);
  } catch (err) {
    console.warn("⚠️ API keys bootstrap failed:", err);
  }

  // Bootstrap namespaces and collect UUID mappings
  let namespaceMap: Map<string, string>;
  try {
    namespaceMap = await bootstrapNamespaces(config, userMap);
  } catch (err) {
    console.warn("⚠️ Namespaces bootstrap failed:", err);
    namespaceMap = new Map();
  }

  // Bootstrap endpoints
  try {
    await bootstrapEndpoints(config, namespaceMap, userMap);
  } catch (err) {
    console.warn("⚠️ Endpoints bootstrap failed:", err);
  }

  // Restore API keys preserved across a user recreate — AFTER endpoints, so
  // scoped keys re-resolve their endpoint name to the freshly-created uuid
  // (see restorePreservedApiKeys' doc comment for why this ordering is
  // load-bearing).
  try {
    await restorePreservedApiKeys(pendingApiKeyRestores);
  } catch (err) {
    console.warn("⚠️ Preserved API key restore failed:", err);
  }

  // Mark one-time bootstrap complete
  if (config.bootstrapOnlyOnFirstRun) {
    if (userMap.size > 0 || namespaceMap.size > 0) {
      await markBootstrapComplete();
    }
  }

  console.log("✅ Environment-based configuration initialized successfully");
}
