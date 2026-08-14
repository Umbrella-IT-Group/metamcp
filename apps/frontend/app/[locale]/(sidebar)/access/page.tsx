"use client";

import { format } from "date-fns";
import {
  ExternalLink,
  RefreshCw,
  ShieldCheck,
  ShieldOff,
  Trash2,
} from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useTranslations } from "@/hooks/useTranslations";
import { authClient } from "@/lib/auth-client";
import { getLocalizedPath } from "@/lib/i18n";
import { trpc } from "@/lib/trpc";

/**
 * The Access dashboard — one admin surface listing EVERY way into this
 * gateway.
 *
 * Built after the 2026-08-13 incident, where an attacker's self-registered
 * member accounts went unnoticed because MetaMCP has no users page at all:
 * API keys, OAuth clients and endpoints each had an admin view, but the
 * accounts those grants belong to were visible only in psql. An access path
 * that is not on a screen does not get audited.
 *
 * Users and OAuth tokens are new surfaces and live here in full. API keys and
 * OAuth clients REUSE the existing admin queries and are shown read-only,
 * with a link to their own management pages — this page is the inventory, not
 * a second place to mint credentials.
 */

// Dates arrive as Date or as an ISO string depending on the transport; every
// other page in this app re-wraps defensively, so this does too. Written once
// here rather than inline six times.
function formatDate(value: Date | string, withTime = false) {
  return format(
    new Date(value),
    withTime ? "MMM d, yyyy HH:mm" : "MMM d, yyyy",
  );
}

export default function AccessPage() {
  const { t, locale } = useTranslations();

  // Session role, read exactly as the OAuth-clients and API-keys pages read
  // it. EVERY query and mutation on this page is adminProcedure, so this is
  // presentation only — the backend is the boundary. roleLoaded prevents the
  // false "administrators only" flash while the session request is in flight;
  // a failed fetch offers a retry rather than pinning the neutral state.
  // Fail-closed throughout.
  const [isAdmin, setIsAdmin] = useState(false);
  const [roleLoaded, setRoleLoaded] = useState(false);
  const [roleError, setRoleError] = useState(false);
  const [currentUserId, setCurrentUserId] = useState<string | null>(null);

  const loadRole = useCallback(() => {
    setRoleError(false);
    authClient
      .getSession()
      .then((session) => {
        const sessionUser = session?.data?.user as
          | { role?: string; id?: string }
          | undefined;
        setIsAdmin(sessionUser?.role === "admin");
        setCurrentUserId(sessionUser?.id ?? null);
        setRoleLoaded(true);
      })
      .catch(() => {
        setRoleError(true);
      });
  }, []);

  useEffect(() => {
    loadRole();
  }, [loadRole]);

  const utils = trpc.useUtils();

  // `enabled: isAdmin` keeps a member from firing four adminProcedure queries
  // that could only ever return FORBIDDEN.
  const { data: usersResponse, isLoading: usersLoading } =
    trpc.frontend.users.list.useQuery(undefined, { enabled: isAdmin });
  const { data: tokensResponse, isLoading: tokensLoading } =
    trpc.frontend.oauthTokens.list.useQuery(undefined, { enabled: isAdmin });
  const { data: apiKeysResponse, isLoading: apiKeysLoading } =
    trpc.frontend.apiKeys.listAll.useQuery(undefined, { enabled: isAdmin });
  const { data: clientsResponse, isLoading: clientsLoading } =
    trpc.frontend.oauthClients.list.useQuery(undefined, { enabled: isAdmin });

  const users = usersResponse?.users ?? [];
  const tokens = tokensResponse?.tokens ?? [];
  const apiKeys = apiKeysResponse?.apiKeys ?? [];
  const clients = clientsResponse?.clients ?? [];

  const [revokeTarget, setRevokeTarget] = useState<{
    id: string;
    email: string;
  } | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<{
    id: string;
    email: string;
  } | null>(null);

  // Revoking or deleting a user changes the token list, the key list and the
  // user list at once, so all three are invalidated — showing a stale "1
  // active session" next to an account that was just cut off is exactly the
  // wrong answer during an incident.
  const invalidateAccessViews = () => {
    utils.frontend.users.list.invalidate();
    utils.frontend.oauthTokens.list.invalidate();
    utils.frontend.apiKeys.listAll.invalidate();
  };

  const revokeMutation = trpc.frontend.users.revokeAccess.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        invalidateAccessViews();
        toast.success(
          t("access:revokeSuccess", {
            sessions: data.sessions_deleted,
            tokens: data.oauth_tokens_deleted,
            codes: data.authorization_codes_deleted,
            keys: data.api_keys_deactivated,
          }),
        );
      } else {
        // A revoke that matched nothing resolves fine at the transport layer
        // and severed nothing. Say so instead of showing a green toast.
        toast.error(data.message || t("access:revokeError"));
      }
      setRevokeTarget(null);
    },
    onError: (error) => {
      toast.error(t("access:revokeError") + ": " + error.message);
    },
  });

  const deleteMutation = trpc.frontend.users.delete.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        invalidateAccessViews();
        toast.success(t("access:userDeleted"));
      } else {
        toast.error(data.message || t("access:deleteError"));
      }
      setDeleteTarget(null);
    },
    onError: (error) => {
      toast.error(t("access:deleteError") + ": " + error.message);
    },
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldCheck className="h-8 w-8 text-primary" />
          <div>
            <h1 className="text-3xl font-bold tracking-tight">
              {t("access:title")}
            </h1>
            <p className="text-muted-foreground">{t("access:description")}</p>
          </div>
        </div>

        {!roleLoaded && roleError && (
          <div className="flex flex-col items-end gap-1">
            <Button variant="outline" onClick={loadRole}>
              <RefreshCw className="h-4 w-4 mr-2" />
              {t("common:refresh")}
            </Button>
            <p className="text-xs text-destructive">{t("access:loadError")}</p>
          </div>
        )}
      </div>

      {roleLoaded && !isAdmin ? (
        <p className="text-sm text-muted-foreground">{t("access:adminOnly")}</p>
      ) : (
        <Tabs defaultValue="users" className="space-y-4">
          <TabsList>
            <TabsTrigger value="users">{t("access:tabUsers")}</TabsTrigger>
            <TabsTrigger value="tokens">
              {t("access:tabOauthTokens")}
            </TabsTrigger>
            <TabsTrigger value="keys">{t("access:tabApiKeys")}</TabsTrigger>
            <TabsTrigger value="clients">
              {t("access:tabOauthClients")}
            </TabsTrigger>
          </TabsList>

          {/* ---- Users: the surface that did not exist before ---- */}
          <TabsContent value="users" className="space-y-2">
            <SectionHeading
              title={t("access:usersHeading")}
              description={t("access:usersDescription")}
            />
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("access:columnEmail")}</TableHead>
                    <TableHead>{t("access:columnName")}</TableHead>
                    <TableHead>{t("access:columnRole")}</TableHead>
                    <TableHead>{t("access:columnVerified")}</TableHead>
                    <TableHead>{t("access:columnAccessPaths")}</TableHead>
                    <TableHead>{t("access:columnLastActive")}</TableHead>
                    <TableHead>{t("access:columnCreated")}</TableHead>
                    <TableHead className="w-[140px]">
                      {t("access:columnActions")}
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {usersLoading ? (
                    <EmptyRow colSpan={8} text={t("access:loading")} />
                  ) : users.length === 0 ? (
                    <EmptyRow colSpan={8} text={t("access:noUsers")} />
                  ) : (
                    users.map((user) => {
                      const isSelf = user.id === currentUserId;
                      return (
                        <TableRow key={user.id}>
                          <TableCell className="font-medium break-all">
                            {user.email}
                            {isSelf && (
                              <Badge variant="outline" className="ml-2">
                                {t("access:you")}
                              </Badge>
                            )}
                          </TableCell>
                          <TableCell>{user.name}</TableCell>
                          <TableCell>
                            <Badge
                              variant={
                                user.role === "admin" ? "default" : "outline"
                              }
                            >
                              {user.role}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant={
                                user.emailVerified ? "default" : "outline"
                              }
                            >
                              {user.emailVerified
                                ? t("access:verified")
                                : t("access:unverified")}
                            </Badge>
                          </TableCell>
                          <TableCell className="whitespace-nowrap text-xs">
                            {/* Three independent access paths, shown side by
                                side rather than summed: an account with zero
                                sessions can still be reaching MCP through a
                                token or a key. */}
                            {user.active_session_count}{" "}
                            {t("access:sessionsLabel")}
                            {" · "}
                            {user.active_oauth_token_count}{" "}
                            {t("access:tokensLabel")}
                            {" · "}
                            {user.active_api_key_count} {t("access:keysLabel")}
                          </TableCell>
                          <TableCell className="whitespace-nowrap">
                            {user.last_active_at
                              ? formatDate(user.last_active_at, true)
                              : t("access:never")}
                          </TableCell>
                          <TableCell className="whitespace-nowrap">
                            {formatDate(user.created_at)}
                          </TableCell>
                          <TableCell>
                            {/* Both actions are disabled on the caller's own
                                row: the server refuses self-revoke and
                                self-delete outright (BAD_REQUEST), and a
                                button that can only produce an error is worse
                                than no button. */}
                            <div className="flex items-center gap-1">
                              <Button
                                size="sm"
                                variant="ghost"
                                disabled={isSelf}
                                title={t("access:revokeAccess")}
                                onClick={() =>
                                  setRevokeTarget({
                                    id: user.id,
                                    email: user.email,
                                  })
                                }
                              >
                                <ShieldOff className="h-4 w-4" />
                              </Button>
                              <Button
                                size="sm"
                                variant="ghost"
                                disabled={isSelf}
                                title={t("access:deleteUser")}
                                onClick={() =>
                                  setDeleteTarget({
                                    id: user.id,
                                    email: user.email,
                                  })
                                }
                              >
                                <Trash2 className="h-4 w-4 text-destructive" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </div>
          </TabsContent>

          {/* ---- Active OAuth tokens ---- */}
          <TabsContent value="tokens" className="space-y-2">
            <SectionHeading
              title={t("access:tokensHeading")}
              description={t("access:tokensDescription")}
            />
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("access:columnUser")}</TableHead>
                    <TableHead>{t("access:columnClient")}</TableHead>
                    <TableHead>{t("access:columnScope")}</TableHead>
                    <TableHead>{t("access:columnCreated")}</TableHead>
                    <TableHead>{t("access:columnExpires")}</TableHead>
                    <TableHead>{t("access:columnRefresh")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {tokensLoading ? (
                    <EmptyRow colSpan={6} text={t("access:loading")} />
                  ) : tokens.length === 0 ? (
                    <EmptyRow colSpan={6} text={t("access:noTokens")} />
                  ) : (
                    tokens.map((token) => (
                      // The token value is not part of the response, so there
                      // is no natural unique key; user+client+issue-time is
                      // unique in practice and carries no secret.
                      <TableRow
                        key={`${token.user_id}:${token.client_id}:${new Date(
                          token.created_at,
                        ).toISOString()}`}
                      >
                        <TableCell className="font-medium break-all">
                          {token.user_email ?? (
                            <span className="text-muted-foreground italic">
                              {t("access:unknownUser")}
                            </span>
                          )}
                        </TableCell>
                        <TableCell>
                          {token.client_name ?? (
                            <span className="text-muted-foreground italic">
                              {t("access:unknownClient")}
                            </span>
                          )}
                          <div className="text-xs text-muted-foreground font-mono break-all">
                            {token.client_id}
                          </div>
                        </TableCell>
                        <TableCell>
                          <code className="text-xs font-mono">
                            {token.scope}
                          </code>
                        </TableCell>
                        <TableCell className="whitespace-nowrap">
                          {formatDate(token.created_at, true)}
                        </TableCell>
                        <TableCell className="whitespace-nowrap">
                          {formatDate(token.expires_at, true)}
                        </TableCell>
                        <TableCell>
                          {/* Presence only — a refresh token is a long-lived
                              credential and is never sent to the browser. */}
                          <Badge
                            variant={
                              token.has_refresh_token ? "default" : "outline"
                            }
                          >
                            {token.has_refresh_token
                              ? t("access:hasRefresh")
                              : t("access:noRefresh")}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
          </TabsContent>

          {/* ---- API keys (existing admin query, read-only here) ---- */}
          <TabsContent value="keys" className="space-y-2">
            <SectionHeading
              title={t("access:apiKeysHeading")}
              description={t("access:apiKeysDescription")}
              action={
                <Button variant="outline" size="sm" asChild>
                  <Link href={getLocalizedPath("/api-keys", locale)}>
                    <ExternalLink className="h-4 w-4 mr-2" />
                    {t("access:manageApiKeys")}
                  </Link>
                </Button>
              }
            />
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("access:columnKeyName")}</TableHead>
                    <TableHead>{t("access:columnKeyPrefix")}</TableHead>
                    <TableHead>{t("access:columnOwner")}</TableHead>
                    <TableHead>{t("access:columnStatus")}</TableHead>
                    <TableHead>{t("access:columnLastUsed")}</TableHead>
                    <TableHead>{t("access:columnCreated")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {apiKeysLoading ? (
                    <EmptyRow colSpan={6} text={t("access:loading")} />
                  ) : apiKeys.length === 0 ? (
                    <EmptyRow colSpan={6} text={t("access:noApiKeys")} />
                  ) : (
                    apiKeys.map((apiKey) => (
                      <TableRow key={apiKey.uuid}>
                        <TableCell className="font-medium">
                          {apiKey.name}
                        </TableCell>
                        <TableCell>
                          {/* Non-reversible prefix only, as the admin key
                              serializer emits it. */}
                          <code className="text-xs font-mono">
                            {apiKey.key_prefix}
                          </code>
                        </TableCell>
                        <TableCell className="break-all">
                          {apiKey.owner_email ?? (
                            <span className="text-muted-foreground italic">
                              {t("access:everyone")}
                            </span>
                          )}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={apiKey.is_active ? "default" : "outline"}
                          >
                            {apiKey.is_active
                              ? t("access:active")
                              : t("access:inactive")}
                          </Badge>
                        </TableCell>
                        <TableCell className="whitespace-nowrap">
                          {apiKey.last_used_at
                            ? formatDate(apiKey.last_used_at, true)
                            : t("access:never")}
                        </TableCell>
                        <TableCell className="whitespace-nowrap">
                          {formatDate(apiKey.created_at)}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
          </TabsContent>

          {/* ---- OAuth clients (existing admin query, read-only here) ---- */}
          <TabsContent value="clients" className="space-y-2">
            <SectionHeading
              title={t("access:clientsHeading")}
              description={t("access:clientsDescription")}
              action={
                <Button variant="outline" size="sm" asChild>
                  <Link href={getLocalizedPath("/oauth-clients", locale)}>
                    <ExternalLink className="h-4 w-4 mr-2" />
                    {t("access:manageClients")}
                  </Link>
                </Button>
              }
            />
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("access:columnClientName")}</TableHead>
                    <TableHead>{t("access:columnClientId")}</TableHead>
                    <TableHead>{t("access:columnRedirectUris")}</TableHead>
                    <TableHead>{t("access:columnSecret")}</TableHead>
                    <TableHead>{t("access:columnCreated")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {clientsLoading ? (
                    <EmptyRow colSpan={5} text={t("access:loading")} />
                  ) : clients.length === 0 ? (
                    <EmptyRow colSpan={5} text={t("access:noClients")} />
                  ) : (
                    clients.map((client) => (
                      <TableRow key={client.client_id}>
                        <TableCell className="font-medium">
                          {client.client_name}
                        </TableCell>
                        <TableCell>
                          <code className="text-xs font-mono break-all">
                            {client.client_id}
                          </code>
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-col gap-1">
                            {client.redirect_uris.map((uri) => (
                              <code
                                key={uri}
                                className="text-xs font-mono break-all"
                              >
                                {uri}
                              </code>
                            ))}
                          </div>
                        </TableCell>
                        <TableCell>
                          {/* Presence only — the stored secret is disclosed
                              once at creation and never listed. */}
                          <Badge
                            variant={
                              client.has_client_secret ? "default" : "outline"
                            }
                          >
                            {client.has_client_secret
                              ? t("access:hasSecret")
                              : t("access:noSecret")}
                          </Badge>
                        </TableCell>
                        <TableCell className="whitespace-nowrap">
                          {formatDate(client.created_at)}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
          </TabsContent>
        </Tabs>
      )}

      {/* Revoke confirmation. Wording states plainly that the account survives
          and can sign in again — a revoke mistaken for a ban is a live
          attacker nobody is watching. */}
      <AlertDialog
        open={revokeTarget !== null}
        onOpenChange={(open) => {
          if (!open) setRevokeTarget(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("access:revokeConfirmTitle", {
                email: revokeTarget?.email ?? "",
              })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t("access:revokeConfirmDescription")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("common:cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (!revokeTarget) return;
                revokeMutation.mutate({ user_id: revokeTarget.id });
              }}
              disabled={revokeMutation.isPending}
            >
              {revokeMutation.isPending
                ? t("access:revoking")
                : t("access:revokeConfirmAction")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete confirmation. The cascade reaches the user's private MCP
          servers, namespaces and endpoints, so the dialog names them rather
          than letting an operator discover it afterwards. */}
      <AlertDialog
        open={deleteTarget !== null}
        onOpenChange={(open) => {
          if (!open) setDeleteTarget(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("access:deleteConfirmTitle", {
                email: deleteTarget?.email ?? "",
              })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t("access:deleteConfirmDescription")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("common:cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (!deleteTarget) return;
                deleteMutation.mutate({ user_id: deleteTarget.id });
              }}
              disabled={deleteMutation.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteMutation.isPending
                ? t("common:deleting")
                : t("access:deleteConfirmAction")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function SectionHeading({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div className="space-y-1">
        <div className="flex items-center gap-2">
          <h2 className="text-xl font-semibold tracking-tight">{title}</h2>
          <Badge variant="outline">Admin</Badge>
        </div>
        <p className="text-sm text-muted-foreground">{description}</p>
      </div>
      {action}
    </div>
  );
}

function EmptyRow({ colSpan, text }: { colSpan: number; text: string }) {
  return (
    <TableRow>
      <TableCell colSpan={colSpan} className="text-center py-12">
        <p className="text-muted-foreground">{text}</p>
      </TableCell>
    </TableRow>
  );
}
