import { createAuthClient } from "better-auth/react";

import { getAppUrl } from "./env";

// No client plugin for OIDC. better-auth 1.7 serves generic OAuth providers
// through the core `signIn.social({ provider })` call and `/callback/:id`
// route, and removed `genericOAuthClient()` along with `signIn.oauth2`.
export const authClient = createAuthClient({
  baseURL: getAppUrl(),
}) as ReturnType<typeof createAuthClient>;
