import cors from "cors";
import express from "express";

import logger from "@/utils/logger";

import {
  oauthRepository,
  toolCallAuditRepository,
} from "../../db/repositories";
import authorizationRouter from "./authorization";
import metadataRouter from "./metadata";
import registrationRouter from "./registration";
import tokenRouter from "./token";
import userinfoRouter from "./userinfo";
import {
  jsonParsingMiddleware,
  securityHeaders,
  urlencodedParsingMiddleware,
} from "./utils";

const oauthRouter = express.Router();

// Tool-call audit retention (days). The prune rides the same cleanup
// interval below; <=0 disables pruning (retain forever).
const TOOL_AUDIT_RETENTION_DAYS = (() => {
  const raw = Number.parseInt(
    process.env.TOOL_AUDIT_RETENTION_DAYS || "90",
    10,
  );
  return Number.isFinite(raw) ? raw : 90;
})();

// Cleanup expired entries every 5 minutes
setInterval(
  async () => {
    try {
      await oauthRepository.cleanupExpired();
      logger.info("Cleaned up expired OAuth codes and tokens");
    } catch (error) {
      logger.error("Error cleaning up expired OAuth entries:", error);
    }
    if (TOOL_AUDIT_RETENTION_DAYS > 0) {
      try {
        await toolCallAuditRepository.pruneOlderThan(TOOL_AUDIT_RETENTION_DAYS);
      } catch (error) {
        logger.error("Error pruning tool_call_audit:", error);
      }
    }
  },
  5 * 60 * 1000,
);

/**
 * Path prefixes this router actually serves, matched whole-segment so
 * `/oauthsomething` is not mistaken for one of ours. Kept in sync with the
 * sub-router route tables below: every route they register begins with
 * `/oauth/` or `/.well-known/`.
 */
const OAUTH_SERVED_PREFIXES = ["/oauth", "/.well-known"] as const;

// OAuth discovery, registration and token exchange are consumed by arbitrary
// MCP clients that this gateway has never seen before, so these paths answer
// any origin. `credentials` is deliberately NOT set: a wildcard
// `Access-Control-Allow-Origin` is refused by browsers the moment credentials
// are involved, so the pairing granted nothing and only obscured the fact that
// no deliberate policy had been chosen. Every browser-driven leg of this flow
// (the consent screen's `/oauth/consent/info` read, the decision POST) reaches
// the backend same-origin through the frontend's rewrites, and non-browser MCP
// clients authenticate with an `Authorization` header rather than a cookie —
// so nothing needs cookies carried here cross-origin.
const oauthCors = cors({
  origin: "*",
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
});

// This router is mounted UNPREFIXED (`app.use(oauthRouter)` in ../../index) so
// that `/.well-known/*` lands at the root, where RFC 8414 discovery requires
// it. Router-level middleware on an unprefixed router runs for EVERY request
// the app receives, so applying `oauthCors` directly put an anonymous-OAuth
// policy on paths this router does not serve: `/api/auth/*` responses carried
// it, and because the cors package answers preflights itself, so did the
// OPTIONS leg of every other route in the app. The guard keeps the policy on
// the paths it was written for.
oauthRouter.use((req, res, next) => {
  const served = OAUTH_SERVED_PREFIXES.some(
    (prefix) => req.path === prefix || req.path.startsWith(`${prefix}/`),
  );
  return served ? oauthCors(req, res, next) : next();
});

// Apply middleware for OAuth-specific routes.
//
// `securityHeaders` is deliberately NOT put behind the guard above. It has the
// same unprefixed reach — it lands on every route in the app — but what it
// lands is hardening (`X-Frame-Options: DENY`, `nosniff`, a referrer policy, a
// CSP), so the spread is wanted. Scoping it would REMOVE those headers from
// every non-OAuth route, which is the wrong direction. Only the CORS policy
// needed scoping, because CORS is the one that grants rather than restricts.
oauthRouter.use(securityHeaders);
oauthRouter.use(jsonParsingMiddleware);
oauthRouter.use(urlencodedParsingMiddleware);

// Mount all OAuth sub-routers
oauthRouter.use(metadataRouter);
oauthRouter.use(authorizationRouter);
oauthRouter.use(tokenRouter);
oauthRouter.use(registrationRouter);
oauthRouter.use(userinfoRouter);

export default oauthRouter;
