/**
 * Per-user Graph access-token mint service for the M365 broker.
 *
 * Per-call path: `injected-fetch.ts` asks for the calling user's access
 * token, only for a request that can execute a tool (a tools/call; the
 * handshake, listings, GET stream and session DELETE never ask); this
 * service answers from a per-user in-memory cache (60s expiry buffer) or
 * mints a fresh one via the Entra v2 refresh grant.
 *
 * Hard requirements (design doc §5.3):
 *  - Per-user SINGLE-FLIGHT: Entra rotates the refresh token on every
 *    redemption, so two concurrent mints for one user would race — the
 *    loser redeems an already-consumed RT and kills the grant. One
 *    in-process mutex per user (single-container deployment; documented
 *    multi-instance follow-up: pg advisory lock).
 *  - ATOMIC ROTATE-AND-PERSIST: the rotated RT is encrypted + persisted
 *    BEFORE the mint resolves. If the persist write fails, the fresh RT
 *    is held in memory (`pendingRotations`) and re-persisted on the next
 *    mint — losing it would strand the user into re-enrollment because
 *    the pre-rotation RT is already invalid.
 *  - COMPARE-AND-SWAP PERSIST: the rotation and the reauth mark only apply to
 *    the row state the mint READ (the stored ciphertext is both the grant's
 *    generation and its rotation version), so a re-enrollment, disconnect,
 *    revoke or boot rewrap that lands while a mint is in flight wins instead of
 *    being overwritten by the old grant's token. A miss is reconciled against a
 *    fresh read (see `reconcileMiss`), never blindly retried.
 *  - GENERATION-GUARDED STATE: `invalidateUser` bumps a per-user generation.
 *    Every asynchronous change to the access-token cache, the held rotation or
 *    the in-flight table is made only while the mint's generation is still the
 *    current one, for deletion as well as insertion, so an old mint finishing
 *    late (or failing late) cannot erase or recreate state that belongs to a
 *    newer enrollment.
 *  - AUDIT: one structured JSON line per mint attempt
 *    (user_id, outcome, scopes, duration) — stdout → Loki. Token
 *    material NEVER appears in logs.
 *  - TYPED FAILURES: every failure maps to `M365BrokerError` so the
 *    proxy layer can answer the consumer with an actionable, typed tool
 *    error (+ enrollment elicitation) instead of an opaque 500.
 */
import logger from "@/utils/logger";

// TYPE-ONLY import: the drizzle client behind the repository throws at
// module load when DATABASE_URL is unset. `client.ts` (and its tests)
// import this module transitively via `injected-fetch.ts`, so the
// runtime repo is resolved lazily at first mint — the module graph
// stays DB-free (same doctrine as `consumer-identity-resolver.ts`).
import type {
  M365TokensRepository,
  M365UserTokenRow,
} from "../../db/repositories/m365-tokens.repo";
import {
  entraTokenUrl,
  getM365BrokerConfig,
  isM365BrokerConfigured,
  M365BrokerConfig,
  m365EnrollUrl,
} from "./config";
import {
  openUserRefreshToken,
  peekEnvelopeVersion,
  sealUserRefreshToken,
} from "./envelope";
import { M365BrokerError } from "./errors";

/** Milliseconds of remaining lifetime below which a cached AT is stale. */
const EXPIRY_BUFFER_MS = 60_000;

interface CachedAccessToken {
  accessToken: string;
  /** Epoch ms at which Entra says the token expires. */
  expiresAt: number;
}

/**
 * A rotated refresh token whose persist has not landed.
 *
 * `anchor` is the plaintext of the STORED refresh token this chain descends
 * from, validated against the database row at the mint that created or extended
 * the chain, NOT the token that was redeemed to produce `refreshToken`. The
 * distinction is what keeps the chain usable across more than one failed
 * persist: stored A, redeem A to B and fail to persist, redeem B to C and fail
 * again, and the database still opens to A, so the anchor is still A and C is
 * kept. Anchoring to the redeemed token (B) would no longer match the stored A
 * and C would be discarded. A held token is used only while the row still opens
 * to its anchor; a real re-enrollment opens to a different grant and drops it.
 * In memory only, like the pending token itself.
 */
interface PendingRotation {
  refreshToken: string;
  anchor: string;
}

interface InflightMint {
  promise: Promise<string>;
  /** The user's generation when the mint started. */
  generation: number;
}

/** What one mint knows about the row state it started from. */
interface MintContext {
  userId: string;
  generation: number;
  /** The ciphertext this mint READ; every conditional write is against it. */
  stored: string;
}

/**
 * `applied`: the rotated token is what the row now holds. `skipped`: the stored
 * credential changed or was removed during the mint, so the rotation was
 * deliberately not applied. `failed`: the outcome is unknown, hold the token.
 */
type RotationResult = "applied" | "skipped" | "failed";

interface EntraTokenResponse {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  error?: string;
  error_description?: string;
  error_codes?: number[];
  suberror?: string;
}

/**
 * Entra error_codes that signal an MFA / Conditional Access claims
 * challenge on the refresh grant — interactive re-auth resolves them.
 */
const MFA_ERROR_CODES = new Set([
  50074, 50076, 50079, 53000, 53001, 530032, 530033,
]);
/** Entra error_codes that signal explicit revocation. */
const REVOKED_ERROR_CODES = new Set([50173, 70043, 700084]);

export class M365MintService {
  private cache = new Map<string, CachedAccessToken>();
  private inflight = new Map<string, InflightMint>();
  /**
   * Rotated RTs whose DB persist failed — kept (plaintext, in-process
   * memory only) so the next mint can use them and retry the persist
   * instead of redeeming the already-invalidated stored RT. See
   * `PendingRotation` for how the chain stays anchored to the stored grant.
   */
  private pendingRotations = new Map<string, PendingRotation>();
  /**
   * Per-user counter bumped by `invalidateUser`. A mint remembers the value it
   * started under and may change the cache, the held rotation or the in-flight
   * table only while it is still current. Bounded by the number of users.
   */
  private generations = new Map<string, number>();

  private repoPromise?: Promise<M365TokensRepository>;

  constructor(
    private readonly injectedRepo?: M365TokensRepository,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  /** Lazy default-repo resolution — see the type-only import note above. */
  private getRepo(): Promise<M365TokensRepository> {
    if (this.injectedRepo) return Promise.resolve(this.injectedRepo);
    if (!this.repoPromise) {
      this.repoPromise = import("../../db/repositories/m365-tokens.repo").then(
        (module) => module.m365TokensRepository,
      );
    }
    return this.repoPromise;
  }

  /**
   * Access token for `userId`, from cache or a fresh mint.
   * Throws `M365BrokerError` on every failure path.
   */
  async getAccessToken(userId: string): Promise<string> {
    if (!isM365BrokerConfigured()) {
      throw new M365BrokerError(
        "not_configured",
        "M365 broker is not configured on this gateway (missing metamcp-m365 env)",
      );
    }

    const cached = this.cache.get(userId);
    if (cached && cached.expiresAt - EXPIRY_BUFFER_MS > Date.now()) {
      return cached.accessToken;
    }

    // Single-flight: concurrent callers for the same user await the
    // same mint, but only a mint of the user's CURRENT generation. After an
    // invalidation (re-enrollment, disconnect) a mint that was already running
    // belongs to the old grant, and joining it would hand the new caller the
    // old account's access token, so such a caller starts a fresh mint instead.
    //
    // IN-PROCESS ONLY, and sufficient only because exactly one gateway process
    // serves M365 mints for a database: the deployment is one container with a
    // fixed name, so a recreate stops the old container before the new one
    // starts and two never mint at once, in steady state or across a deploy.
    // MORE THAN ONE REPLICA REOPENS THIS. Two processes holding the same stored
    // refresh token would both redeem it, Entra would accept the first and
    // reject the second with invalid_grant, and the loser's conditional reauth
    // mark could land before the winner's rotation and strand the user. A
    // cross-process lock (a Postgres advisory lock held on one dedicated
    // connection across the read, the redemption and the write) must land
    // before a second replica is planned.
    const generation = this.generationOf(userId);
    const existing = this.inflight.get(userId);
    if (existing && existing.generation === generation) {
      return existing.promise;
    }

    // The entry is removed in a finally BEFORE resolution is observed by
    // awaiters, and only if it is still this mint's own: an old mint finishing
    // after a newer one replaced its entry must not delete the newer one.
    const entry = { generation } as InflightMint;
    entry.promise = this.mint(userId, generation).finally(() => {
      if (this.inflight.get(userId) === entry) {
        this.inflight.delete(userId);
      }
    });
    this.inflight.set(userId, entry);
    return entry.promise;
  }

  /**
   * Drop cached state for a user (disconnect / re-enroll) and retire every mint
   * that is currently running for them: bumping the generation is what stops
   * those mints from caching, holding or deleting anything afterwards.
   */
  invalidateUser(userId: string): void {
    this.generations.set(userId, this.generationOf(userId) + 1);
    this.cache.delete(userId);
    this.pendingRotations.delete(userId);
  }

  private generationOf(userId: string): number {
    return this.generations.get(userId) ?? 0;
  }

  /** True while no invalidation has happened since `generation` was read. */
  private isCurrent(userId: string, generation: number): boolean {
    return this.generationOf(userId) === generation;
  }

  private async mint(userId: string, generation: number): Promise<string> {
    const startedAt = Date.now();
    const config = getM365BrokerConfig();

    const repo = await this.getRepo();
    const row = await repo.findByUserId(userId);
    if (!row || row.status !== "active") {
      this.audit(userId, "credential_missing", startedAt, {
        row_status: row?.status ?? "none",
      });
      throw new M365BrokerError(
        "credential_missing",
        row
          ? "Your Microsoft 365 connection needs to be re-authorized."
          : "No Microsoft 365 account is connected for your user yet.",
        m365EnrollUrl(),
      );
    }

    // What this mint read. Every conditional write below is against it.
    const stored = row.rt_ciphertext;
    const storedVersion = peekEnvelopeVersion(stored);
    const ctx: MintContext = { userId, generation, stored };

    // Always decrypt the stored envelope, even when a rotation is held: a held
    // token is only valid while the row still opens to the grant it descends
    // from, and that is only knowable by opening the row.
    let storedPlaintext: string;
    try {
      storedPlaintext = openUserRefreshToken(
        stored,
        config.kek,
        userId,
      ).plaintext;
    } catch (error) {
      this.audit(userId, "decrypt_failed", startedAt, {
        kek_id: row.kek_id,
        envelope: storedVersion,
      });
      logger.error(
        `M365 broker: refresh-token decrypt failed for user ${userId} (kek_id=${row.kek_id}, envelope=${storedVersion ?? "unknown"}) — KEK mismatch, corrupted or foreign envelope, or a v1 envelope under M365_ENVELOPE_STRICT`,
        error,
      );
      throw new M365BrokerError(
        "credential_missing",
        "Your stored Microsoft 365 credential could not be read — please re-connect.",
        m365EnrollUrl(),
      );
    }

    // Prefer a held (persist-failed) rotation over the stored RT, because the
    // stored one may already be consumed, but only while the row still opens to
    // the grant the held chain descends from. A mint of an older generation
    // never reads another generation's held token.
    let redeemFrom = storedPlaintext;
    const pending = this.isCurrent(userId, generation)
      ? this.pendingRotations.get(userId)
      : undefined;
    if (pending) {
      if (pending.refreshToken === storedPlaintext) {
        // A persist that was reported as failed had in fact committed: the row
        // already holds the chain head, so the stored RT IS the held one.
        this.pendingRotations.delete(userId);
      } else if (pending.anchor === storedPlaintext) {
        redeemFrom = pending.refreshToken;
      } else {
        logger.warn(
          `M365 broker: discarding a held refresh-token rotation for user ${userId}: the stored credential is a different grant (re-enrollment or another writer)`,
        );
        this.pendingRotations.delete(userId);
      }
    }

    const outcome = await this.redeemRefreshToken(config, ctx, redeemFrom);

    // Rotate-and-persist BEFORE resolving. Entra has already
    // invalidated the RT we just redeemed.
    let rotation: "applied" | "skipped" | "held" | "none" = "none";
    if (outcome.refreshToken) {
      const result = await this.persistRotation({
        config,
        ctx,
        anchor: storedPlaintext,
        redeemedRt: redeemFrom,
        rotatedRt: outcome.refreshToken,
      });
      // Every change to the held rotation below is made only while this mint's
      // generation is current. After an invalidation the state belongs to the
      // newer enrollment, which a late `applied`, `skipped` or `failed` of this
      // mint must neither erase nor recreate.
      const current = this.isCurrent(userId, generation);
      if (result === "failed") {
        if (current) {
          // Keep the fresh RT in memory and retry persistence on the next
          // mint. Losing it = forced re-enrollment. The anchor is the stored
          // grant this mint validated, so the chain survives further failed
          // persists (see PendingRotation).
          this.pendingRotations.set(userId, {
            refreshToken: outcome.refreshToken,
            anchor: storedPlaintext,
          });
          rotation = "held";
          logger.error(
            `M365 broker: rotated refresh token persist FAILED for user ${userId} — holding rotation in memory and retrying next mint. A gateway restart before a successful persist forces re-enrollment for this user.`,
          );
        } else {
          rotation = "skipped";
          logger.warn(
            `M365 broker: rotated refresh token for user ${userId} not held: the connection was replaced or removed while the mint was running`,
          );
        }
      } else {
        if (current) {
          this.pendingRotations.delete(userId);
        }
        rotation = result;
      }
    }

    // The access token is returned to this caller regardless (it was
    // legitimately issued before any change and cannot be recalled, and a
    // replaced or revoked grant cannot mint again), but it is cached only while
    // its grant is still the live one.
    if (this.isCurrent(userId, generation) && rotation !== "skipped") {
      this.cache.set(userId, {
        accessToken: outcome.accessToken,
        expiresAt: outcome.expiresAt,
      });
    }
    this.audit(userId, "minted", startedAt, {
      scopes: outcome.scope,
      rotated: Boolean(outcome.refreshToken),
      envelope: storedVersion,
      rotation,
    });
    return outcome.accessToken;
  }

  private async redeemRefreshToken(
    config: M365BrokerConfig,
    ctx: MintContext,
    refreshToken: string,
  ): Promise<{
    accessToken: string;
    refreshToken?: string;
    expiresAt: number;
    scope?: string;
  }> {
    const { userId } = ctx;
    const startedAt = Date.now();
    let response: Response;
    try {
      response = await this.fetchImpl(entraTokenUrl(config.tenantId), {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: config.clientId,
          client_secret: config.clientSecret,
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          scope: config.scopes,
        }).toString(),
      });
    } catch (error) {
      this.audit(userId, "mint_network_error", startedAt, {});
      logger.error(
        `M365 broker: token endpoint unreachable for user ${userId}:`,
        error,
      );
      throw new M365BrokerError(
        "mint_failed",
        "Could not reach the Microsoft identity platform — try again shortly.",
      );
    }

    let body: EntraTokenResponse;
    try {
      body = (await response.json()) as EntraTokenResponse;
    } catch {
      body = {};
    }

    if (!response.ok || !body.access_token) {
      throw this.classifyRefreshFailure(ctx, response.status, body);
    }

    return {
      accessToken: body.access_token,
      refreshToken: body.refresh_token,
      expiresAt: Date.now() + (body.expires_in ?? 3600) * 1000,
      scope: body.scope,
    };
  }

  /**
   * Map an Entra refresh-grant rejection to a typed broker error and
   * update row state where the failure is credential-terminal.
   */
  private classifyRefreshFailure(
    ctx: MintContext,
    httpStatus: number,
    body: EntraTokenResponse,
  ): M365BrokerError {
    const { userId } = ctx;
    const errorCodes = body.error_codes ?? [];
    const description = body.error_description?.split("\n")[0] ?? "";

    // Transient platform trouble — never burn the grant for it.
    if (httpStatus >= 500 || !body.error) {
      this.audit(userId, "mint_failed", Date.now(), {
        http_status: httpStatus,
        entra_error: body.error ?? "none",
      });
      return new M365BrokerError(
        "mint_failed",
        `Microsoft identity platform returned ${httpStatus} — try again shortly.`,
      );
    }

    const isInteraction =
      body.error === "interaction_required" ||
      errorCodes.some((c) => MFA_ERROR_CODES.has(c));
    const isRevoked = errorCodes.some((c) => REVOKED_ERROR_CODES.has(c));
    const isInvalidGrant = body.error === "invalid_grant";

    if (isInteraction || isRevoked || isInvalidGrant) {
      // Credential-terminal: mark the row, drop caches, hand the user
      // the re-enrollment path. Both halves are scoped to the state this mint
      // read: the caches are cleared only while this mint's generation is
      // current (a rejection arriving after a re-enrollment concerns the OLD
      // grant and must not erase the new enrollment's cache or held rotation),
      // and the mark applies only while the row still holds the rejected
      // ciphertext (so it cannot mark the re-enrolled row).
      if (this.isCurrent(userId, ctx.generation)) {
        this.cache.delete(userId);
        this.pendingRotations.delete(userId);
      }
      this.getRepo()
        .then((repo) => repo.markReauthRequired(userId, ctx.stored))
        .catch((persistError) => {
          logger.warn(
            `M365 broker: failed to mark reauth_required for user ${userId}:`,
            persistError,
          );
        });

      const code = isRevoked
        ? "credential_revoked"
        : isInteraction
          ? "mfa_required"
          : "credential_expired";
      this.audit(userId, code, Date.now(), {
        entra_error: body.error,
        entra_error_codes: errorCodes,
      });
      logger.info(
        `M365 broker: refresh grant rejected for user ${userId}: ${body.error} (${errorCodes.join(",")}) ${description}`,
      );
      return new M365BrokerError(
        code,
        code === "mfa_required"
          ? "Microsoft requires re-authentication (MFA/Conditional Access) for your account."
          : "Your Microsoft 365 connection has expired or been revoked.",
        m365EnrollUrl(),
      );
    }

    // invalid_client / invalid_request etc. — deployment configuration
    // problem, not a user problem. Loud log, generic error.
    this.audit(userId, "mint_failed", Date.now(), {
      http_status: httpStatus,
      entra_error: body.error,
      entra_error_codes: errorCodes,
    });
    logger.error(
      `M365 broker: refresh grant failed with non-grant error for user ${userId}: ${body.error} (${errorCodes.join(",")}) ${description}`,
    );
    return new M365BrokerError(
      "mint_failed",
      "The gateway could not obtain a Microsoft 365 token (configuration error — the operator has been signaled in logs).",
    );
  }

  /**
   * Persist a rotation as a compare-and-swap against the ciphertext this mint
   * read, with up to two attempts for a THROWN error. A returned `false` is a
   * definite answer ("the row is no longer in the state this mint read") and is
   * reconciled, never blindly retried.
   *
   * `anchor` is the stored grant the mint validated and `redeemedRt` the token
   * it redeemed (they differ when a held rotation was redeemed); both identify
   * "the same grant" during reconciliation.
   */
  private async persistRotation(args: {
    config: M365BrokerConfig;
    ctx: MintContext;
    anchor: string;
    redeemedRt: string;
    rotatedRt: string;
  }): Promise<RotationResult> {
    const { config, ctx, anchor, redeemedRt, rotatedRt } = args;
    const { userId, stored } = ctx;

    // Sealing is inside the guarded section: the redeemed token is already
    // consumed, so a seal failure must fall into the held-in-memory path
    // rather than reject the mint and lose it.
    let repo: M365TokensRepository;
    let envelope: string;
    try {
      repo = await this.getRepo();
      envelope = sealUserRefreshToken(
        rotatedRt,
        config.kek,
        config.kekId,
        userId,
        peekEnvelopeVersion(stored),
      );
    } catch (error) {
      logger.error(
        `M365 broker: could not seal the rotated refresh token for user ${userId}:`,
        error,
      );
      return "failed";
    }

    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const updated = await repo.rotateRefreshToken(
          userId,
          envelope,
          config.kekId,
          stored,
        );
        if (updated) return "applied";
        return await this.reconcileMiss(repo, config, {
          userId,
          anchor,
          redeemedRt,
          rotatedRt,
        });
      } catch (error) {
        logger.warn(
          `M365 broker: rotation persist attempt ${attempt + 1}/2 failed for user ${userId}:`,
          error,
        );
      }
    }
    return "failed";
  }

  /**
   * The CAS matched no row. That is benign in three ways, and a real loss in
   * one, which only a fresh read can tell apart:
   *
   *  - an earlier attempt committed and then threw, so the row already holds
   *    the rotated token (`applied`);
   *  - another writer rewrapped the same grant into a different envelope (the
   *    boot converge of a newly started process, a rolling deploy), so the row
   *    still opens to the grant this mint descends from: re-seal against the
   *    row's CURRENT version and retry the swap once against its CURRENT
   *    ciphertext (`applied`, or `failed` and held if that misses too);
   *  - the row was re-enrolled, disconnected, revoked or is unreadable, so the
   *    stored state is not this grant's to overwrite (`skipped`).
   *
   * "The same grant" is the stored grant the mint validated (`anchor`) or the
   * token it redeemed, never the redeemed token alone: after several failed
   * persists the database still opens to the anchor, and comparing only
   * against the redeemed token would mistake a rewrap for a re-enrollment and
   * discard the freshest token. Never throws: a failed read is `failed`.
   * Nothing here relies on Entra rejecting or still accepting an older token.
   */
  private async reconcileMiss(
    repo: M365TokensRepository,
    config: M365BrokerConfig,
    args: {
      userId: string;
      anchor: string;
      redeemedRt: string;
      rotatedRt: string;
    },
  ): Promise<RotationResult> {
    const { userId, anchor, redeemedRt, rotatedRt } = args;
    const skipped = (): RotationResult => {
      logger.warn(
        `M365 broker: rotation not applied for user ${userId}: the stored credential changed or was removed during the mint (re-enrollment, disconnect, revoke or another instance's refresh); the stored state was kept`,
      );
      return "skipped";
    };

    let current: M365UserTokenRow | undefined;
    try {
      current = await repo.findByUserId(userId);
    } catch (error) {
      logger.warn(
        `M365 broker: could not re-read the row for user ${userId} to reconcile a rotation:`,
        error,
      );
      return "failed";
    }
    if (!current || current.status !== "active") return skipped();

    let currentPlaintext: string;
    try {
      // v1 is allowed here even under strict: this read only decides whether
      // the row is still the same grant, and the write below re-seals it.
      currentPlaintext = openUserRefreshToken(
        current.rt_ciphertext,
        config.kek,
        userId,
        { allowV1: true },
      ).plaintext;
    } catch {
      return skipped();
    }

    if (currentPlaintext === rotatedRt) return "applied";
    if (currentPlaintext !== anchor && currentPlaintext !== redeemedRt) {
      return skipped();
    }

    try {
      const resealed = sealUserRefreshToken(
        rotatedRt,
        config.kek,
        config.kekId,
        userId,
        peekEnvelopeVersion(current.rt_ciphertext),
      );
      const swapped = await repo.rotateRefreshToken(
        userId,
        resealed,
        config.kekId,
        current.rt_ciphertext,
      );
      return swapped ? "applied" : "failed";
    } catch (error) {
      logger.warn(
        `M365 broker: reconcile re-seal for user ${userId} failed:`,
        error,
      );
      return "failed";
    }
  }

  /** One structured JSON audit line per mint attempt — stdout → Loki. */
  private audit(
    userId: string,
    outcome: string,
    startedAt: number,
    extra: Record<string, unknown>,
  ): void {
    logger.info(
      JSON.stringify({
        event: "m365_mint",
        user_id: userId,
        outcome,
        duration_ms: Date.now() - startedAt,
        ...extra,
      }),
    );
  }
}

export const m365MintService = new M365MintService();
