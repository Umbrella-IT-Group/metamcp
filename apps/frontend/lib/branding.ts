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
 * The logo is rendered with `next/image`, which THROWS on a src whose host is
 * not declared in `next.config.js` `images.remotePatterns`. That component
 * sits in the sidebar layout wrapping every authenticated page, so a typo'd
 * env var pointing at an external URL would take the entire UI down. A
 * cosmetic setting must not be able to do that, so the accepted contract is
 * narrow: an app-served absolute path only (leading "/", and not the
 * protocol-relative "//host/..." form). Anything else falls back to the
 * bundled default and says so on stderr rather than degrading silently.
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
