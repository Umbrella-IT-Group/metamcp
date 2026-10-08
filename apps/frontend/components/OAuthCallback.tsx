"use client";

import { useEffect, useRef } from "react";

import { useTranslations } from "@/hooks/useTranslations";

import { completeOAuthCallback } from "../lib/oauth-callback";

const OAuthCallback = () => {
  const { t } = useTranslations();
  const hasProcessedRef = useRef(false);

  useEffect(() => {
    const handleCallback = async () => {
      // Skip if we've already processed this callback
      if (hasProcessedRef.current) {
        return;
      }
      hasProcessedRef.current = true;

      try {
        // The exchange and the session write live in lib/oauth-callback so
        // they can be tested; this component only navigates.
        window.location.href = await completeOAuthCallback(
          window.location.search,
        );
      } catch (error) {
        console.error("OAuth callback error:", error);
        window.location.href = "/mcp-servers";
      }
    };

    void handleCallback();
  }, []);

  return (
    <div className="flex items-center justify-center h-screen">
      <p className="text-lg text-gray-500">
        {t("common:oauth.processingCallback")}
      </p>
    </div>
  );
};

export default OAuthCallback;
