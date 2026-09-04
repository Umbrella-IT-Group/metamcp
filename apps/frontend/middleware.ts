import { betterFetch } from "@better-fetch/fetch";
import { NextRequest, NextResponse } from "next/server";

import { shouldBypassMiddleware } from "./lib/middleware-bypass";
import {
  buildContentSecurityPolicy,
  NONCE_HEADER,
} from "./lib/security-headers";

const locales = ["en", "zh", "ko"];
const defaultLocale = "en";

// Get the preferred locale from the request
function getLocale(request: NextRequest): string {
  // Check if there's a locale in the pathname
  const pathname = request.nextUrl.pathname;
  const pathnameHasLocale = locales.some(
    (locale) => pathname.startsWith(`/${locale}/`) || pathname === `/${locale}`,
  );

  if (pathnameHasLocale) {
    return pathname.split("/")[1] || defaultLocale;
  }

  // Check cookies for saved preference first (user's explicit choice)
  const savedLocale = request.cookies.get("preferred-language")?.value;
  if (savedLocale && locales.includes(savedLocale)) {
    return savedLocale;
  }

  // Check Accept-Language header as fallback
  const acceptLanguage = request.headers.get("accept-language");
  if (acceptLanguage) {
    // Simple language detection - look for zh in accept-language
    if (acceptLanguage.includes("zh")) {
      return "zh";
    }

    // Look for ko in accept-language
    if (acceptLanguage.includes("ko")) {
      return "ko";
    }
  }

  return defaultLocale;
}

/**
 * Where to send an unauthenticated request, preserving the QUERY STRING.
 *
 * The query is not decoration on every route: the OAuth consent screen carries
 * its whole authorization request in `?areq=`, so dropping the search string
 * here meant a session that lapsed mid-consent sent the user back to a bare
 * /consent with nothing to approve, and the connection had to be restarted
 * from the client.
 */
function loginRedirect(
  request: NextRequest,
  locale: string,
  pathnameWithoutLocale: string,
): URL {
  const loginUrl = new URL(`/${locale}/login`, request.url);
  loginUrl.searchParams.set(
    "callbackUrl",
    `${pathnameWithoutLocale}${request.nextUrl.search}`,
  );
  return loginUrl;
}

export async function middleware(request: NextRequest) {
  const pathname = request.nextUrl.pathname;

  // Skip middleware for static files and the backend/framework routes. The
  // bypass set and its segment-boundary matching live in ./lib/middleware-bypass
  // so the config.matcher below stays in lockstep with it (see that module for
  // why bare-prefix matching swallowed the same-prefix /oauth-clients page).
  if (shouldBypassMiddleware(pathname)) {
    return NextResponse.next();
  }

  // Per-request CSP nonce. The policy bans inline script except by nonce, and a
  // nonce cannot be a static next.config value, so it is minted here, the only
  // layer that runs before the document is rendered. It is stamped on the
  // request's CSP header (Next reads it there to nonce the framework hydration
  // scripts) and on `x-nonce` (the root layout reads it there to nonce the
  // third-party inline scripts Next does not own: the runtime-env script and
  // the theme anti-flash script). See ./lib/security-headers.
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const csp = buildContentSecurityPolicy(nonce);
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set(NONCE_HEADER, nonce);
  requestHeaders.set("Content-Security-Policy", csp);

  // A document render: carry the nonce forward to the renderer via the request
  // headers, and the policy back to the browser on the response. Only the
  // page-rendering branches below use this; the redirect branches return a
  // bodyless 307 whose destination gets its own pass through this middleware.
  const renderDocument = () => {
    const response = NextResponse.next({
      request: { headers: requestHeaders },
    });
    response.headers.set("Content-Security-Policy", csp);
    return response;
  };

  // Handle i18n routing first
  const pathnameHasLocale = locales.some(
    (locale) => pathname.startsWith(`/${locale}/`) || pathname === `/${locale}`,
  );

  let locale = defaultLocale;
  let pathnameWithoutLocale = pathname;

  if (pathnameHasLocale) {
    locale = pathname.split("/")[1] || defaultLocale;
    pathnameWithoutLocale = pathname.slice(locale.length + 1) || "/";
  } else {
    // Redirect to the appropriate locale
    locale = getLocale(request);
    const newUrl = new URL(`/${locale}${pathname}`, request.url);
    // Preserve query parameters during redirect
    newUrl.search = request.nextUrl.search;
    return NextResponse.redirect(newUrl);
  }

  // Now handle authentication for the pathname without locale.
  // "/" is deliberately NOT public: an unauthenticated visitor to the root
  // should be redirected to /login rather than served the dashboard shell,
  // which then fires a 401 on every data query. Leaving it out routes the root
  // through the session check below like any other protected page, so an
  // authenticated user still gets the dashboard and everyone else gets login.
  const publicRoutes = ["/login", "/register", "/cors-error"];
  if (publicRoutes.includes(pathnameWithoutLocale)) {
    return renderDocument();
  }

  try {
    // Get the original host for nginx compatibility
    const originalHost =
      request.headers.get("x-forwarded-host") ||
      request.headers.get("host") ||
      "";

    // Check if user is authenticated by calling the session endpoint
    const { data: session } = await betterFetch("/api/auth/get-session", {
      // this hardcoded is correct, because in same container, we should use localhost, outside url won't work
      baseURL: "http://localhost:12009",
      headers: {
        cookie: request.headers.get("cookie") || "",
        // Pass nginx-forwarded host headers for better-auth baseURL resolution
        host: originalHost,
        // Include nginx forwarding headers if present
        "x-forwarded-host": request.headers.get("x-forwarded-host") || "",
        "x-forwarded-proto": request.headers.get("x-forwarded-proto") || "",
        "x-forwarded-for": request.headers.get("x-forwarded-for") || "",
      },
    });

    if (!session) {
      // Redirect to login if not authenticated (with locale)
      return NextResponse.redirect(
        loginRedirect(request, locale, pathnameWithoutLocale),
      );
    }

    return renderDocument();
  } catch (error) {
    console.error("Auth middleware error:", error);
    // On error, redirect to login (with locale)
    return NextResponse.redirect(
      loginRedirect(request, locale, pathnameWithoutLocale),
    );
  }
}

export const config = {
  matcher: [
    // Skip all internal paths (_next, etc.). Each prefix is matched on a segment
    // boundary ((?:/|$)) so a page whose route merely shares a prefix (e.g.
    // /oauth-clients vs the bypassed /oauth) is NOT skipped. Keep this in
    // lockstep with shouldBypassMiddleware in ./lib/middleware-bypass. Next
    // requires config.matcher to be a statically-analyzable literal, so it
    // cannot import that list; middleware-bypass.test.ts cross-checks the two.
    "/((?!_next(?:/|$)|api/|trpc(?:/|$)|mcp-proxy(?:/|$)|metamcp(?:/|$)|oauth(?:/|$)|fe-oauth(?:/|$)|\\.well-known(?:/|$)|service(?:/|$)|health(?:/|$)|m365(?:/|$)|.*\\..*).*)",
  ],
};
