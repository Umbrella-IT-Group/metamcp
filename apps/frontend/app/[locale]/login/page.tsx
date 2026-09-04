"use client";

import Image from "next/image";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";

import { DomainWarningBanner } from "@/components/domain-warning-banner";
import { LanguageSwitcher } from "@/components/language-switcher";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ThemeToggle } from "@/components/ui/theme-toggle";
import { useTranslations } from "@/hooks/useTranslations";
import { authClient } from "@/lib/auth-client";
import { getBranding } from "@/lib/branding";
import { toSafeInternalPath } from "@/lib/safe-redirect";
import { vanillaTrpcClient } from "@/lib/trpc";

function LoginForm() {
  const { t } = useTranslations();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [isSignupDisabled, setIsSignupDisabled] = useState(false);
  const [isBasicAuthDisabled, setIsBasicAuthDisabled] = useState(false);
  const [isOidcLoading, setIsOidcLoading] = useState(false);
  const [isOidcEnabled, setIsOidcEnabled] = useState(false);
  const [authProvidersLoading, setAuthProvidersLoading] = useState(true);

  const router = useRouter();
  const searchParams = useSearchParams();
  // Sanitize once at the source: callbackUrl is attacker-controlled and flows
  // into both router.push and better-auth's callbackURL below. Reduced to a
  // safe same-origin path so neither leg can redirect off-site.
  const callbackUrl = toSafeInternalPath(searchParams.get("callbackUrl"));

  // Check if signup is disabled
  useEffect(() => {
    const checkSignupStatus = async () => {
      try {
        const isDisabled =
          await vanillaTrpcClient.frontend.config.getSignupDisabled.query();
        setIsSignupDisabled(isDisabled);
      } catch (error) {
        console.error("Failed to fetch signup status:", error);
      }
    };

    checkSignupStatus();
  }, []);

  // Check if basic auth is disabled
  useEffect(() => {
    const checkBasicAuthStatus = async () => {
      try {
        const isDisabled =
          await vanillaTrpcClient.frontend.config.getBasicAuthDisabled.query();
        setIsBasicAuthDisabled(isDisabled);
      } catch (error) {
        console.error("Failed to fetch basic auth config:", error);
      }
    };

    checkBasicAuthStatus();
  }, []);

  // Check if OIDC is enabled
  useEffect(() => {
    const checkOidcStatus = async () => {
      try {
        const providers =
          await vanillaTrpcClient.frontend.config.getAuthProviders.query();
        const oidcProvider = providers.find(
          (provider) => provider.id === "oidc" && provider.enabled,
        );
        setIsOidcEnabled(!!oidcProvider);
      } catch (error) {
        console.error("Failed to fetch OIDC config:", error);
      } finally {
        setAuthProvidersLoading(false);
      }
    };

    checkOidcStatus();
  }, []);

  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError("");

    try {
      const { error } = await authClient.signIn.email({
        email,
        password,
        callbackURL: callbackUrl,
      });

      if (error) {
        setError(error.message || t("auth:signInError"));
      } else {
        router.push(callbackUrl);
      }
    } catch (_err) {
      setError(t("auth:signInError"));
    } finally {
      setIsLoading(false);
    }
  };

  const handleOidcSignIn = async () => {
    setIsOidcLoading(true);
    try {
      await authClient.signIn.social({
        provider: "oidc",
        callbackURL: callbackUrl,
      });
    } catch (error) {
      console.error("OIDC sign in failed:", error);
      setError(t("auth:oidcSignInError"));
    } finally {
      setIsOidcLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="space-y-2 text-center">
        <h1 className="text-2xl font-semibold tracking-tight">
          {t("auth:signInToAccount")}
        </h1>
        {/* The subtitle must match what the form actually offers. When basic
            auth is disabled the email/password fields do not render, so the
            "enter your email and password" copy contradicted the UI; show the
            single-sign-on line instead. When basic auth is off AND OIDC is not
            enabled, the disabled-auth notice below carries the explanation, so
            no subtitle is shown here. */}
        {!isBasicAuthDisabled ? (
          <p className="text-sm text-muted-foreground">
            {t("auth:enterCredentials")}
          </p>
        ) : isOidcEnabled ? (
          <p className="text-sm text-muted-foreground">
            {t("auth:oidcOnlySubtitle")}
          </p>
        ) : null}
      </div>

      {error && (
        <div className="rounded-md bg-destructive/15 p-3 text-sm text-destructive">
          {error}
        </div>
      )}

      {!isBasicAuthDisabled && (
        <form onSubmit={handleSignIn} className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="email" className="text-sm font-medium">
              {t("auth:email")}
            </label>
            <Input
              id="email"
              type="email"
              placeholder={t("auth:emailPlaceholder")}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              disabled={isLoading}
            />
          </div>

          <div className="space-y-2">
            <label htmlFor="password" className="text-sm font-medium">
              {t("auth:password")}
            </label>
            <Input
              id="password"
              type="password"
              placeholder={t("auth:passwordPlaceholder")}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              disabled={isLoading}
            />
          </div>

          <Button type="submit" className="w-full" disabled={isLoading}>
            {isLoading ? t("auth:signingIn") : t("auth:signIn")}
          </Button>
        </form>
      )}

      {isBasicAuthDisabled && !isOidcEnabled && (
        <div className="rounded-md bg-muted/50 p-4 text-center text-sm text-muted-foreground">
          {t("auth:basicAuthDisabledMessage")}
        </div>
      )}

      {!authProvidersLoading && isOidcEnabled && (
        <>
          {!isBasicAuthDisabled && (
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <span className="w-full border-t" />
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-background px-2 text-muted-foreground">
                  {t("auth:orContinueWith")}
                </span>
              </div>
            </div>
          )}

          <Button
            variant="outline"
            className="w-full"
            onClick={handleOidcSignIn}
            disabled={isOidcLoading}
          >
            {isOidcLoading ? t("auth:signingIn") : t("auth:signInWithOidc")}
          </Button>
        </>
      )}

      {!isSignupDisabled && (
        <div className="text-center text-sm">
          <span className="text-muted-foreground">{t("auth:noAccount")} </span>
          <Link href="/register" className="underline underline-offset-4">
            {t("auth:signUp")}
          </Link>
        </div>
      )}
    </div>
  );
}

export default function LoginPage() {
  // Brand the sign-in surface like the rest of the app (logo + org name over a
  // card), instead of the bare centered text it used to be. getBranding() is
  // isomorphic and defaults to the Umbrella marks when no branding vars are set.
  const { orgName, logoPath } = getBranding();

  return (
    <div className="relative min-h-screen flex items-center justify-center px-4">
      <div className="absolute top-4 right-4 flex items-center gap-2">
        <ThemeToggle />
        <LanguageSwitcher />
      </div>
      <div className="w-full max-w-sm mx-auto flex flex-col justify-center space-y-6">
        <DomainWarningBanner />
        <div className="flex flex-col items-center gap-3">
          <Image
            src={logoPath}
            alt={orgName}
            width={256}
            height={256}
            priority
            className="h-12 w-auto"
          />
          <span className="text-lg font-semibold">{orgName}</span>
        </div>
        <Card>
          <CardContent>
            <Suspense fallback={<div>Loading...</div>}>
              <LoginForm />
            </Suspense>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
