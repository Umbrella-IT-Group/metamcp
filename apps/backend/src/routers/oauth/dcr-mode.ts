import logger from "@/utils/logger";

/**
 * How `POST /oauth/register` (anonymous RFC 7591 registration) behaves.
 *
 *   pending  (unset default) A self-registered client is stored as "pending"
 *            and cannot be authorized until an administrator approves it on
 *            the OAuth Clients page.
 *   off      Registration is refused before anything is minted or stored, with
 *            REGISTRATION_DISABLED_BODY. Discovery stops advertising the
 *            endpoint. Existing clients, approvals and grants are untouched,
 *            and administrators can still create clients. This is the switch
 *            a pre-provisioned shared client is meant to let a deployment
 *            flip.
 *   open     Local development only: a new self-registration is stored
 *            already approved. Startup refuses this value unless NODE_ENV is
 *            "development" or "test".
 *
 * In EVERY mode registration accepts only plain-http loopback callbacks
 * (isDcrLoopbackRedirectUri); `open` does not restore hosted callbacks and
 * does not promote clients that are already pending or rejected.
 *
 * Strict values, no trimming or case folding. An unknown or empty value
 * resolves to `off`, not to the default, with a boot warning: once a
 * deployment has turned registration off, a typo must not reopen it.
 */
export const OAUTH_DCR_MODE_ENV = "OAUTH_DCR_MODE";

export type OAuthDcrMode = "pending" | "off" | "open";

/** NODE_ENV values under which `open` is permitted. */
const OPEN_MODE_ENVIRONMENTS: ReadonlySet<string> = new Set([
  "development",
  "test",
]);

export interface OAuthDcrModeResolution {
  mode: OAuthDcrMode;
  /** Logged once at startup when set. */
  warning: string | null;
  /** Set when startup must refuse to continue; `mode` is then `off`. */
  error: string | null;
}

/** Pure resolution from an environment, for startup and for tests. */
export function resolveOAuthDcrMode(
  env: NodeJS.ProcessEnv = process.env,
): OAuthDcrModeResolution {
  const raw = env[OAUTH_DCR_MODE_ENV];

  if (raw === undefined) {
    return { mode: "pending", warning: null, error: null };
  }

  if (raw === "pending" || raw === "off") {
    return { mode: raw, warning: null, error: null };
  }

  if (raw === "open") {
    const nodeEnv = env.NODE_ENV ?? "";
    if (!OPEN_MODE_ENVIRONMENTS.has(nodeEnv)) {
      return {
        mode: "off",
        warning: null,
        error:
          `${OAUTH_DCR_MODE_ENV}=open approves self-registered OAuth clients automatically ` +
          `and is permitted only when NODE_ENV is "development" or "test" ` +
          `(NODE_ENV is ${JSON.stringify(nodeEnv.slice(0, 40))}). Unset it, or set pending or off.`,
      };
    }
    return {
      mode: "open",
      warning:
        `[oauth] ${OAUTH_DCR_MODE_ENV}=open: new self-registered OAuth clients are approved ` +
        `automatically. Local development only.`,
      error: null,
    };
  }

  return {
    mode: "off",
    warning:
      `[oauth] ${OAUTH_DCR_MODE_ENV}=${JSON.stringify(raw.slice(0, 40))} is not pending, off or open; ` +
      `self-registration is OFF until it is corrected.`,
    error: null,
  };
}

let latched: OAuthDcrMode | null = null;

/**
 * Resolve, log and latch the mode. Called at module scope in
 * apps/backend/src/index.ts, before any route is registered, so a bad value
 * stops the process with its reason at boot rather than on the first
 * registration request. Throws when the resolution carries an error.
 */
export function initOAuthDcrMode(
  env: NodeJS.ProcessEnv = process.env,
): OAuthDcrMode {
  const resolution = resolveOAuthDcrMode(env);
  if (resolution.error) {
    throw new Error(resolution.error);
  }
  if (resolution.warning) {
    logger.warn(resolution.warning);
  }
  logger.info(
    `[oauth] client self-registration: ${OAUTH_DCR_MODE_ENV}=${resolution.mode}`,
  );
  latched = resolution.mode;
  return resolution.mode;
}

/**
 * The effective mode for a request.
 *
 * Normally the value latched at startup. A process that never ran
 * initOAuthDcrMode (a unit test importing a router directly) resolves here
 * once instead; a resolution that would have stopped startup gives `off`, the
 * closed direction, and logs why.
 */
export function getOAuthDcrMode(): OAuthDcrMode {
  if (latched !== null) {
    return latched;
  }
  const resolution = resolveOAuthDcrMode();
  if (resolution.error) {
    logger.error(`[oauth] ${resolution.error}`);
  } else if (resolution.warning) {
    logger.warn(resolution.warning);
  }
  latched = resolution.mode;
  return latched;
}

/** Drop the latched mode so a test can resolve a different environment. */
export function resetOAuthDcrModeForTests(): void {
  latched = null;
}

/**
 * The 400 body `POST /oauth/register` answers in `off` mode.
 *
 * Deliberately NOT an RFC 7591 error code: RFC 7591 has no code for
 * "registration is disabled", and reusing one of its codes would tell a
 * client its metadata was wrong. `registration_disabled` is this gateway's own
 * value, documented in README-oauth.md.
 */
export const REGISTRATION_DISABLED_BODY = Object.freeze({
  error: "registration_disabled",
  error_description:
    "This gateway does not accept automatic client registration. Ask an administrator for a client.",
});
