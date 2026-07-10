/**
 * Per-user Graph access-token mint service for the M365 broker.
 *
 * Per-call path: `injected-fetch.ts` asks for the calling user's access
 * token; this service answers from a per-user in-memory cache (60s
 * expiry buffer) or mints a fresh one via the Entra v2 refresh grant.
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
import type { M365TokensRepository } from "../../db/repositories/m365-tokens.repo";
import {
  entraTokenUrl,
  getM365BrokerConfig,
  isM365BrokerConfigured,
  M365BrokerConfig,
  m365EnrollUrl,
} from "./config";
import { decryptRefreshToken, encryptRefreshToken } from "./crypto";
import { M365BrokerError } from "./errors";

/** Milliseconds of remaining lifetime below which a cached AT is stale. */
const EXPIRY_BUFFER_MS = 60_000;

interface CachedAccessToken {
  accessToken: string;
  /** Epoch ms at which Entra says the token expires. */
  expiresAt: number;
}

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
  private inflight = new Map<string, Promise<string>>();
  /**
   * Rotated RTs whose DB persist failed — kept (plaintext, in-process
   * memory only) so the next mint can use them and retry the persist
   * instead of redeeming the already-invalidated stored RT.
   */
  private pendingRotations = new Map<string, string>();

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
    // same mint. The promise is removed in a finally BEFORE resolution
    // is observed by awaiters (safe: Map holds the same promise).
    const existing = this.inflight.get(userId);
    if (existing) {
      return existing;
    }

    const mintPromise = this.mint(userId).finally(() => {
      this.inflight.delete(userId);
    });
    this.inflight.set(userId, mintPromise);
    return mintPromise;
  }

  /** Drop cached state for a user (disconnect / re-enroll). */
  invalidateUser(userId: string): void {
    this.cache.delete(userId);
    this.pendingRotations.delete(userId);
  }

  private async mint(userId: string): Promise<string> {
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

    // Prefer a pending (persist-failed) rotation over the stored RT —
    // the stored one may already be consumed.
    let refreshToken = this.pendingRotations.get(userId);
    if (!refreshToken) {
      try {
        refreshToken = decryptRefreshToken(row.rt_ciphertext, config.kek);
      } catch (error) {
        this.audit(userId, "decrypt_failed", startedAt, {
          kek_id: row.kek_id,
        });
        logger.error(
          `M365 broker: refresh-token decrypt failed for user ${userId} (kek_id=${row.kek_id}) — KEK mismatch or corrupted envelope`,
          error,
        );
        throw new M365BrokerError(
          "credential_missing",
          "Your stored Microsoft 365 credential could not be read — please re-connect.",
          m365EnrollUrl(),
        );
      }
    }

    const outcome = await this.redeemRefreshToken(config, userId, refreshToken);

    // Rotate-and-persist BEFORE resolving. Entra has already
    // invalidated the RT we just redeemed.
    if (outcome.refreshToken) {
      const envelope = encryptRefreshToken(
        outcome.refreshToken,
        config.kek,
        config.kekId,
      );
      const persisted = await this.persistRotation(userId, envelope, config);
      if (persisted) {
        this.pendingRotations.delete(userId);
      } else {
        // Keep the fresh RT in memory and retry persistence on the
        // next mint. Losing it = forced re-enrollment.
        this.pendingRotations.set(userId, outcome.refreshToken);
        logger.error(
          `M365 broker: rotated refresh token persist FAILED for user ${userId} — holding rotation in memory and retrying next mint. A gateway restart before a successful persist forces re-enrollment for this user.`,
        );
      }
    }

    this.cache.set(userId, {
      accessToken: outcome.accessToken,
      expiresAt: outcome.expiresAt,
    });
    this.audit(userId, "minted", startedAt, {
      scopes: outcome.scope,
      rotated: Boolean(outcome.refreshToken),
    });
    return outcome.accessToken;
  }

  private async redeemRefreshToken(
    config: M365BrokerConfig,
    userId: string,
    refreshToken: string,
  ): Promise<{
    accessToken: string;
    refreshToken?: string;
    expiresAt: number;
    scope?: string;
  }> {
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
      throw this.classifyRefreshFailure(userId, response.status, body);
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
    userId: string,
    httpStatus: number,
    body: EntraTokenResponse,
  ): M365BrokerError {
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
      // the re-enrollment path.
      this.cache.delete(userId);
      this.pendingRotations.delete(userId);
      this.getRepo()
        .then((repo) => repo.markReauthRequired(userId))
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

  /** Persist a rotation, retrying once on failure. */
  private async persistRotation(
    userId: string,
    envelope: string,
    config: M365BrokerConfig,
  ): Promise<boolean> {
    const repo = await this.getRepo();
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const updated = await repo.rotateRefreshToken(
          userId,
          envelope,
          config.kekId,
        );
        if (updated) return true;
        // Row vanished mid-mint (concurrent disconnect). Don't hold the
        // rotation — the user explicitly disconnected.
        logger.warn(
          `M365 broker: rotation persist found no row for user ${userId} (disconnected mid-mint?)`,
        );
        this.pendingRotations.delete(userId);
        return true;
      } catch (error) {
        logger.warn(
          `M365 broker: rotation persist attempt ${attempt + 1}/2 failed for user ${userId}:`,
          error,
        );
      }
    }
    return false;
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
