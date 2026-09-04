"use client";

import {
  FileTerminal,
  Key,
  KeyRound,
  Link as LinkIcon,
  Package,
  Search,
  SearchCode,
  Server,
  Settings,
  ShieldCheck,
  Users,
} from "lucide-react";
import Image from "next/image";
import Link from "next/link";
import { useEffect, useState } from "react";

import { LanguageSwitcher } from "@/components/language-switcher";
import { LogsStatusIndicator } from "@/components/logs-status-indicator";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar";
import { ThemeToggle } from "@/components/ui/theme-toggle";
import { useTranslations } from "@/hooks/useTranslations";
import { authClient } from "@/lib/auth-client";
import { getBranding } from "@/lib/branding";
import { getLocalizedPath, SupportedLocale } from "@/lib/i18n";

// Menu items function - now takes locale parameter
const getMenuItems = (t: (key: string) => string, locale: SupportedLocale) => [
  {
    title: t("navigation:exploreMcpServers"),
    url: getLocalizedPath("/search", locale),
    icon: Search,
  },
  {
    title: t("navigation:mcpServers"),
    url: getLocalizedPath("/mcp-servers", locale),
    icon: Server,
  },
  {
    title: t("navigation:metamcpNamespaces"),
    url: getLocalizedPath("/namespaces", locale),
    icon: Package,
  },
  {
    title: t("navigation:metamcpEndpoints"),
    url: getLocalizedPath("/endpoints", locale),
    icon: LinkIcon,
  },
  {
    title: t("navigation:mcpInspector"),
    url: getLocalizedPath("/mcp-inspector", locale),
    icon: SearchCode,
  },
  {
    title: t("navigation:apiKeys"),
    url: getLocalizedPath("/api-keys", locale),
    icon: Key,
  },
  {
    title: t("navigation:oauthClients"),
    url: getLocalizedPath("/oauth-clients", locale),
    icon: KeyRound,
  },
  {
    title: t("navigation:settings"),
    url: getLocalizedPath("/settings", locale),
    icon: Settings,
  },
];

/**
 * The admin-only sidebar links: the Access dashboard and Access Groups.
 *
 * Every other item in this sidebar is ungated because every page behind them
 * has a member-usable view. These two do not: every one of their queries is
 * adminProcedure, so a member who followed either link would get an empty page
 * and an "administrators only" notice.
 *
 * BOTH live in one component so the session is read ONCE. Two components would
 * mean two `getSession()` round trips on every page load to answer the same
 * question, and could render inconsistently if one resolved and the other
 * failed.
 *
 * This is presentation, NOT the security boundary — the backend gate is. A
 * member who types either URL still reaches the route and still sees nothing,
 * because the pages themselves fail closed on the same session role. Hiding the
 * links only keeps the nav honest about what the member can do.
 */
function AdminMenuItems() {
  const { t, locale } = useTranslations();
  const [isAdmin, setIsAdmin] = useState(false);

  useEffect(() => {
    // Fail closed: isAdmin starts false and a failed session lookup leaves it
    // false, so an error hides the link rather than showing a dead one.
    authClient
      .getSession()
      .then((session) => {
        const role = (session?.data?.user as { role?: string } | undefined)
          ?.role;
        setIsAdmin(role === "admin");
      })
      .catch(() => {
        setIsAdmin(false);
      });
  }, []);

  if (!isAdmin) return null;

  return (
    <>
      <SidebarMenuItem>
        <SidebarMenuButton asChild>
          <Link href={getLocalizedPath("/access", locale)}>
            <ShieldCheck />
            <span>{t("navigation:access")}</span>
          </Link>
        </SidebarMenuButton>
      </SidebarMenuItem>
      <SidebarMenuItem>
        <SidebarMenuButton asChild>
          <Link href={getLocalizedPath("/access-groups", locale)}>
            <Users />
            <span>{t("navigation:accessGroups")}</span>
          </Link>
        </SidebarMenuButton>
      </SidebarMenuItem>
    </>
  );
}

function LiveLogsMenuItem() {
  const { t, locale } = useTranslations();

  return (
    <SidebarMenuItem>
      <SidebarMenuButton asChild>
        <Link href={getLocalizedPath("/live-logs", locale)}>
          <FileTerminal />
          <span>{t("navigation:liveLogs")}</span>
          <LogsStatusIndicator />
        </Link>
      </SidebarMenuButton>
    </SidebarMenuItem>
  );
}

function UserInfoFooter() {
  const { t } = useTranslations();
  // Only the display name and email are read below; type it to just those so
  // the footer does not lean on `any`.
  const [user, setUser] = useState<{
    name?: string | null;
    email?: string | null;
  } | null>(null);

  // Get user info
  useEffect(() => {
    authClient.getSession().then((session) => {
      if (session?.data?.user) {
        setUser(session.data.user);
      }
    });
  }, []);

  const handleSignOut = async () => {
    await authClient.signOut();
    window.location.href = "/login";
  };

  return (
    <SidebarFooter>
      <div className="flex flex-col gap-4 p-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <LanguageSwitcher />
            <ThemeToggle />
          </div>
          <p className="text-xs text-muted-foreground">v2.4.22</p>
        </div>
        <Separator />
        {user && (
          <div className="flex flex-col gap-3">
            <div className="flex flex-col gap-1">
              <span className="text-sm font-medium">
                {user.name || user.email}
              </span>
              <span className="text-xs text-muted-foreground">
                {user.email}
              </span>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={handleSignOut}
              className="w-full"
            >
              {t("auth:signOut")}
            </Button>
          </div>
        )}
      </div>
    </SidebarFooter>
  );
}

export default function SidebarLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const { t, locale } = useTranslations();
  const items = getMenuItems(t, locale);
  const { orgName, logoPath } = getBranding();

  return (
    <SidebarProvider>
      <Sidebar>
        {/* Umbrella IT Group fork — see UMBRELLA_FORK.md. Sidebar brand
            uses the square color "Umbrella Bug" brandmark + the
            "Umbrella IT" text. Square asset renders crisply in the
            sidebar at any size; the previous wordmark-only attempt
            relied on a 3:1 aspect ratio that didn't fit.

            Both the mark and the text are deployment-configurable (see
            lib/branding.ts); the defaults are those same Umbrella assets.
            Width is `w-auto` rather than a fixed `w-10` so a non-square
            replacement logo scales on its own aspect ratio instead of being
            squashed into a square box — for the square default the rendered
            box is 40x40 either way. */}
        <SidebarHeader className="flex flex-col justify-center items-center px-2 py-4">
          <div className="flex items-center justify-center w-full mb-2 gap-3">
            <Image
              src={logoPath}
              alt={orgName}
              width={256}
              height={256}
              priority
              className="h-10 w-auto"
            />
            <h2 className="text-xl font-semibold leading-tight">{orgName}</h2>
          </div>
        </SidebarHeader>

        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupLabel>{t("navigation:application")}</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {items.map((item) => (
                  <SidebarMenuItem key={item.title}>
                    <SidebarMenuButton asChild>
                      <Link href={item.url}>
                        <item.icon />
                        <span>{item.title}</span>
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
                <AdminMenuItems />
                <LiveLogsMenuItem />
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        </SidebarContent>

        <UserInfoFooter />
      </Sidebar>
      <SidebarInset>
        <header className="flex h-16 shrink-0 items-center gap-2 transition-[width,height] ease-linear group-has-[[data-collapsible=icon]]/sidebar-wrapper:h-12">
          <div className="flex items-center gap-2 px-4">
            <SidebarTrigger className="ml-1 cursor-pointer" />
            <Separator orientation="vertical" className="mr-2 h-4" />
          </div>
        </header>
        {/* min-w-0 so a wide page (e.g. a data table) shrinks to the inset
            width and scrolls inside its own wrapper rather than widening the
            whole column past the viewport. */}
        <div className="flex min-w-0 flex-1 flex-col gap-4 p-4 pt-0">
          {children}
        </div>
      </SidebarInset>
    </SidebarProvider>
  );
}
