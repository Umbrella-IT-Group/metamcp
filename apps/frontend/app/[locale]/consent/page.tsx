"use client";

import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";

import { LanguageSwitcher } from "@/components/language-switcher";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/ui/theme-toggle";
import { useTranslations } from "@/hooks/useTranslations";

/**
 * OAuth consent screen.
 *
 * Lives at /consent rather than /oauth/consent on purpose: next.config.js
 * rewrites /oauth/:path* to the backend, so a page under that prefix would be
 * proxied away and never render. Outside the prefix it also gets the normal
 * middleware session check, which is a second gate on top of the backend's.
 *
 * The Approve/Deny controls are a plain HTML form, not a fetch. The backend
 * answers with a 302 to the client's redirect_uri, and only a real top-level
 * form submission lets the browser follow that redirect out to the client the
 * way an OAuth flow expects. It also means the double-submit cookie rides
 * along on a same-site POST, which is exactly the request SameSite=Lax permits
 * and a cross-site attacker cannot reproduce.
 */

interface ConsentInfo {
  client_id: string;
  client_name: string;
  redirect_uri: string;
  scope: string;
}

function ConsentPrompt() {
  const { t } = useTranslations();
  const searchParams = useSearchParams();
  const areq = searchParams.get("areq") ?? "";

  const [info, setInfo] = useState<ConsentInfo | null>(null);
  // An error is held as a translation key, not a rendered string, so the
  // effect below never has to depend on `t` (which changes identity on every
  // render and would re-fire the fetch forever).
  const [errorKey, setErrorKey] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    if (!areq) {
      setErrorKey("auth:consentRequestMissing");
      setIsLoading(false);
      return;
    }

    let cancelled = false;

    const loadConsentInfo = async () => {
      try {
        const response = await fetch(
          `/oauth/consent/info?areq=${encodeURIComponent(areq)}`,
          { credentials: "same-origin" },
        );

        if (!response.ok) {
          throw new Error(`consent info request failed: ${response.status}`);
        }

        const data = (await response.json()) as ConsentInfo;
        if (!cancelled) setInfo(data);
      } catch {
        if (!cancelled) setErrorKey("auth:consentRequestInvalid");
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    };

    loadConsentInfo();

    return () => {
      cancelled = true;
    };
  }, [areq]);

  if (isLoading) {
    return (
      <p className="text-center text-sm text-muted-foreground">
        {t("common:loading")}
      </p>
    );
  }

  if (errorKey || !info) {
    return (
      <div className="space-y-4">
        <h1 className="text-center text-2xl font-semibold tracking-tight">
          {t("auth:consentTitle")}
        </h1>
        <div className="rounded-md bg-destructive/15 p-3 text-sm text-destructive">
          {t(errorKey ?? "auth:consentRequestInvalid")}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="space-y-2 text-center">
        <h1 className="text-2xl font-semibold tracking-tight">
          {t("auth:consentTitle")}
        </h1>
        <p className="text-sm text-muted-foreground">
          {t("auth:consentIntro")}
        </p>
      </div>

      <div className="space-y-3 rounded-md border p-4 text-sm">
        <div className="space-y-1">
          <p className="text-base font-medium break-words">
            {info.client_name}
          </p>
          {/*
            client_name is whatever the application asked to be called during
            anonymous registration — nothing verifies it. Saying so, and
            showing the full destination below rather than a bare host, is what
            lets someone notice a "Claude" that sends codes somewhere else.
          */}
          <p className="text-xs text-muted-foreground">
            {t("auth:consentClientNameNote")}
          </p>
        </div>
        <div className="space-y-1">
          <span className="text-muted-foreground">
            {t("auth:consentRedirectLabel")}
          </span>
          <p className="font-mono text-xs break-all">{info.redirect_uri}</p>
        </div>
        <div className="flex justify-between gap-4">
          <span className="text-muted-foreground">
            {t("auth:consentScopeLabel")}
          </span>
          <span className="font-mono">{info.scope}</span>
        </div>
      </div>

      <div className="rounded-md bg-muted/50 p-3 text-sm text-muted-foreground">
        {t("auth:consentWarning")}
      </div>

      <form
        method="POST"
        action="/oauth/authorize/decision"
        className="space-y-3"
      >
        <input type="hidden" name="areq" value={areq} />
        <Button
          type="submit"
          name="decision"
          value="approve"
          className="w-full"
        >
          {t("auth:consentApprove")}
        </Button>
        <Button
          type="submit"
          name="decision"
          value="deny"
          variant="outline"
          className="w-full"
        >
          {t("auth:consentDeny")}
        </Button>
      </form>
    </div>
  );
}

export default function ConsentPage() {
  return (
    <div className="relative min-h-screen flex items-center justify-center px-4">
      <div className="absolute top-4 right-4 flex items-center gap-2">
        <ThemeToggle />
        <LanguageSwitcher />
      </div>
      <div className="w-full max-w-sm mx-auto flex flex-col justify-center space-y-6">
        <Suspense fallback={<div>Loading...</div>}>
          <ConsentPrompt />
        </Suspense>
      </div>
    </div>
  );
}
