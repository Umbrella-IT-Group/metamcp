import express from "express";

import logger from "@/utils/logger";

import { oauthRepository, usersRepository } from "../../db/repositories";

const userinfoRouter = express.Router();

/**
 * OAuth 2.0 UserInfo Endpoint
 * Returns information about the authenticated user
 */
userinfoRouter.get("/oauth/userinfo", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Missing or invalid authorization header",
      });
    }

    const token = authHeader.substring(7); // Remove "Bearer " prefix

    // Validate MCP token format
    if (!token.startsWith("mcp_token_")) {
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Invalid access token format",
      });
    }

    // Look up token data (in production, this should validate signature and lookup in database)
    const tokenData = await oauthRepository.getAccessToken(token);
    if (!tokenData) {
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Token not found or expired",
      });
    }

    // Check if token has expired
    if (Date.now() > tokenData.expires_at.getTime()) {
      await oauthRepository.deleteAccessToken(token);
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Access token has expired",
      });
    }

    // `users.disabled` enforcement (migration 0027), same reasoning as the
    // introspect endpoint next door in token.ts. Access tokens live 24h in
    // this fork and this handler reads the token row alone, so a locked-out
    // account's outstanding token would otherwise keep answering with its
    // identity claims — `sub`, email, username and granted scope — to anyone
    // holding it.
    //
    // Answered with this handler's existing invalid-token 401 rather than a
    // new "account disabled" error: the token genuinely is invalid for this
    // account now, OAuth clients already treat 401 here as "re-authorize"
    // (where the authorize handler refuses them again), and reusing the
    // unknown-token wording keeps a disabled account indistinguishable on the
    // wire from a token that never existed. The row is not deleted — disable
    // is reversible; Revoke is what deletes.
    if (await usersRepository.isDisabled(tokenData.user_id)) {
      logger.warn(
        `[oauth] userinfo rejected reason=disabled user=${tokenData.user_id}`,
      );
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Token not found or expired",
      });
    }

    // For MCP tokens, return basic user info based on the user_id stored with the token
    // In a real implementation, you would fetch actual user data from the database
    res.json({
      sub: tokenData.user_id,
      email: `user-${tokenData.user_id}@metamcp.local`,
      name: `MetaMCP User ${tokenData.user_id}`,
      preferred_username: `user_${tokenData.user_id}`,
      scope: tokenData.scope,
    });
  } catch (error) {
    logger.error("Error in OAuth userinfo endpoint:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Internal server error",
    });
  }
});

export default userinfoRouter;
