import { env } from "next-runtime-env";

/**
 * White-label branding config (Umbrella IT Group fork — see UMBRELLA_FORK.md).
 *
 * Three surfaces are deployment-configurable: the browser-tab title, the org
 * name rendered next to the sidebar logo, and the logo image itself.
 *
 * Read through `next-runtime-env`, which the fork already mounts in the root
 * layout (`<PublicEnvScript />`). That matters: every route in this app is
 * dynamically rendered, and next-runtime-env re-reads `process.env` per
 * request on the server and republishes it to `window.__ENV` on the client.
 * So changing a branding var is a container restart, NOT an image rebuild.
 *
 * Only `NEXT_PUBLIC_`-prefixed vars can cross to the browser (next-runtime-env
 * filters on that prefix), and the sidebar brand is a client component, so the
 * canonical names carry the prefix. `docker-entrypoint.sh` promotes the
 * friendlier unprefixed `BRANDING_*` aliases into the canonical names at
 * container start — before either server process boots, so the server render
 * and the client hydration can never disagree about the brand.
 */

/**
 * The defaults ARE the current Umbrella branding. A deployment that sets none
 * of the branding vars must render exactly what it rendered before this
 * feature existed — that zero-config parity is the whole contract, and it is
 * what lets the Umbrella prod instance take this change with no config edit.
 * Editing a default here rebrands every existing deployment; set the env var
 * instead.
 */
export const DEFAULT_PRODUCT_NAME = "Umbrella MCP Gateway";
export const DEFAULT_ORG_NAME = "Umbrella IT";
export const DEFAULT_LOGO_PATH = "/umbrella-bug.png";
export const DEFAULT_DESCRIPTION =
  "Umbrella IT Group's MCP gateway — aggregates Autotask, IT Glue, CIPP, registry and more into curated namespaces for AI tooling.";

export interface Branding {
  /** Browser-tab title. */
  productName: string;
  /** Brand name rendered next to the sidebar logo, and the logo's alt text. */
  orgName: string;
  /** App-served path to the logo image. */
  logoPath: string;
  /** `<meta name="description">` for the app shell. */
  description: string;
}

/**
 * An env var set to an empty (or whitespace-only) string is the easy accident
 * — `BRANDING_ORG_NAME=` in a .env file, or a compose interpolation of an
 * unset variable. Nobody wants a blank brand, so treat empty as unset.
 */
export function resolveBrandText(
  raw: string | undefined | null,
  fallback: string,
): string {
  const trimmed = (raw ?? "").trim();
  return trimmed === "" ? fallback : trimmed;
}

/**
 * The accepted contract is narrow: an app-served absolute path only (leading
 * "/", and not the protocol-relative "//host/..." form). Anything else falls
 * back to the bundled default and says so on stderr rather than degrading
 * silently.
 *
 * Why reject a remote URL rather than pass it through: `next/image` only
 * accepts a host declared in `next.config.js` `images.remotePatterns`, and its
 * two failure modes are both bad. In `next dev` it THROWS (the check in
 * `next/dist/shared/lib/image-loader.js` is wrapped in
 * `NODE_ENV !== 'production'` — Next's own comment there reads "this should
 * only error in development") and this component sits in the layout wrapping
 * every authenticated page, so a typo'd env var crashes the dev UI outright.
 * In production that check is compiled out, so instead the optimizer answers
 * `400 "url" parameter is not allowed` and the operator gets a silently broken
 * logo behind an opaque status code. A working default plus a loud warning
 * beats both. (Declaring a remote host would also mean editing
 * `next.config.js` — i.e. an image rebuild, which is exactly what this feature
 * exists to avoid.)
 *
 * This validates the SHAPE, it does not sanitize: `/a/../b` and backslash
 * forms pass. That is fine — the value is operator-supplied container config,
 * and any `/`-leading url is served internally by the image optimizer (no
 * outbound fetch, no filesystem escape), so a malformed one yields an internal
 * 400/404 rather than reaching anything.
 *
 * Serving a custom image: mount it into the container under
 * `apps/frontend/public/` (a subdirectory such as `/branding` keeps the
 * bundled assets intact) and point this var at the resulting path. Next
 * enumerates `public/` once at server start, so the file must be present
 * before the container starts — a restart, never a rebuild.
 */
export function resolveLogoPath(raw: string | undefined | null): string {
  const trimmed = (raw ?? "").trim();
  if (trimmed === "") return DEFAULT_LOGO_PATH;

  if (!trimmed.startsWith("/") || trimmed.startsWith("//")) {
    console.warn(
      `[branding] NEXT_PUBLIC_BRANDING_LOGO_PATH must be an app-served absolute path ` +
        `beginning with "/" (got ${JSON.stringify(trimmed)}); falling back to ${DEFAULT_LOGO_PATH}.`,
    );
    return DEFAULT_LOGO_PATH;
  }

  return trimmed;
}

/**
 * Resolve the active branding. Safe to call from a server component (reads
 * `process.env`) or a client component (reads the runtime-published
 * `window.__ENV`) — `env()` handles both, so both renders see one value.
 */
export function getBranding(): Branding {
  return {
    productName: resolveBrandText(
      env("NEXT_PUBLIC_BRANDING_PRODUCT_NAME"),
      DEFAULT_PRODUCT_NAME,
    ),
    orgName: resolveBrandText(
      env("NEXT_PUBLIC_BRANDING_ORG_NAME"),
      DEFAULT_ORG_NAME,
    ),
    logoPath: resolveLogoPath(env("NEXT_PUBLIC_BRANDING_LOGO_PATH")),
    description: resolveBrandText(
      env("NEXT_PUBLIC_BRANDING_DESCRIPTION"),
      DEFAULT_DESCRIPTION,
    ),
  };
}
