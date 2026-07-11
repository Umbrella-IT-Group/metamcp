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
        await toolCallAuditRepository.pruneOlderThan(
          TOOL_AUDIT_RETENTION_DAYS,
        );
      } catch (error) {
        logger.error("Error pruning tool_call_audit:", error);
      }
    }
  },
  5 * 60 * 1000,
);

// Enable CORS for all OAuth endpoints with wildcard origin
oauthRouter.use(
  cors({
    origin: "*", // Allow all origins for OAuth endpoints
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  }),
);

// Apply middleware for OAuth-specific routes
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
