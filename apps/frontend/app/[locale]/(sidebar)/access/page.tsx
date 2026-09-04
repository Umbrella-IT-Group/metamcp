"use client";

import { format } from "date-fns";
import {
  AlertTriangle,
  ExternalLink,
  Lock,
  RefreshCw,
  ShieldCheck,
  ShieldOff,
  Trash2,
  Unlock,
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
import { PageHeader } from "@/components/ui/page-header";
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
import { pluralize } from "@/lib/pluralize";
import { trpc } from "@/lib/trpc";

/**
 * The Access dashboard — one admin surface listing EVERY way into this
 * gateway.
 *
 * Built after self-registration abuse, where an attacker's self-registered
 * member accounts went unnoticed because MetaMCP has no users page at all:
 * API keys, OAuth clients and endpoints each had an admin view, but the
 * accounts those grants belong to were visible only in psql. An access path
 * that is not on a screen does not get audited.
 *
 * Users and OAuth tokens are new surfaces and live here in full. API keys and
 * OAuth clients REUSE the existing admin queries and are shown read-only,
 * with a link to their own management pages — this page is the inventory, not
 * a second place to mint credentials.
 *
 * EVERY list on this page distinguishes "empty" from "failed". That is not
 * polish: rendering a failed query as "No accounts found" would reproduce the
 * exact false negative this page exists to prevent, on the screen built to
 * prevent it.
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
  const usersQuery = trpc.frontend.users.list.useQuery(undefined, {
    enabled: isAdmin,
  });
  const tokensQuery = trpc.frontend.oauthTokens.list.useQuery(undefined, {
    enabled: isAdmin,
  });
  const apiKeysQuery = trpc.frontend.apiKeys.listAll.useQuery(undefined, {
    enabled: isAdmin,
  });
  const clientsQuery = trpc.frontend.oauthClients.list.useQuery(undefined, {
    enabled: isAdmin,
  });

  const users = usersQuery.data?.users ?? [];
  const userTotal = usersQuery.data?.total ?? users.length;
  const tokens = tokensQuery.data?.tokens ?? [];
  const apiKeys = apiKeysQuery.data?.apiKeys ?? [];
  const clients = clientsQuery.data?.clients ?? [];

  const [revokeTarget, setRevokeTarget] = useState<{
    id: string;
    email: string;
  } | null>(null);
  const [disableTarget, setDisableTarget] = useState<{
    id: string;
    email: string;
    disabled: boolean;
  } | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<{
    id: string;
    email: string;
  } | null>(null);

  // The blast-radius preview for the delete dialog. Fetched only while a
  // delete is actually being considered — it is several counting queries, and
  // running them for every row on every render would be wasteful.
  const deleteImpactQuery = trpc.frontend.users.previewDelete.useQuery(
    { user_id: deleteTarget?.id ?? "" },
    { enabled: deleteTarget !== null },
  );
  const impact = deleteImpactQuery.data?.impact;
  const crossUserTotal =
    (impact?.other_users_endpoints ?? 0) + (impact?.other_users_api_keys ?? 0);

  // Revoking, disabling or deleting a user changes the token list, the key
  // list and the user list at once, so all three are invalidated — showing a
  // stale "1 active session" next to an account that was just cut off is
  // exactly the wrong answer during a live response.
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
            m365: data.m365_tokens_revoked,
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

  const disableMutation = trpc.frontend.users.setDisabled.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        invalidateAccessViews();
        toast.success(
          data.disabled
            ? t("access:disableSuccess")
            : t("access:enableSuccess"),
        );
      } else {
        toast.error(data.message || t("access:disableError"));
      }
      setDisableTarget(null);
    },
    onError: (error) => {
      toast.error(t("access:disableError") + ": " + error.message);
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
    <div className="space-y-6 min-w-0">
      <PageHeader
        icon={<ShieldCheck className="h-8 w-8 text-primary" />}
        title={t("access:title")}
        description={t("access:description")}
        actions={
          !roleLoaded &&
          roleError && (
            <div className="flex flex-col items-end gap-1">
              <Button variant="outline" onClick={loadRole}>
                <RefreshCw className="h-4 w-4 mr-2" />
                {t("common:refresh")}
              </Button>
              <p className="text-xs text-destructive">
                {t("access:loadError")}
              </p>
            </div>
          )
        }
      />

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
                    <TableHead>{t("access:columnStatus")}</TableHead>
                    <TableHead>{t("access:columnAccessPaths")}</TableHead>
                    <TableHead title={t("access:sessionRefreshedHelp")}>
                      {t("access:columnSessionRefreshed")}
                    </TableHead>
                    <TableHead>{t("access:columnCreated")}</TableHead>
                    <TableHead className="w-[160px]">
                      {t("access:columnActions")}
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  <ListStateRow
                    colSpan={8}
                    isLoading={usersQuery.isLoading}
                    isError={usersQuery.isError}
                    isEmpty={users.length === 0}
                    onRetry={() => usersQuery.refetch()}
                    t={t}
                    emptyText={t("access:noUsers")}
                  />
                  {!usersQuery.isLoading &&
                    !usersQuery.isError &&
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
                            <div className="flex flex-col gap-1 items-start">
                              {user.disabled && (
                                <Badge variant="destructive">
                                  {t("access:disabledBadge")}
                                </Badge>
                              )}
                              <Badge
                                variant={
                                  user.emailVerified ? "default" : "outline"
                                }
                              >
                                {user.emailVerified
                                  ? t("access:verified")
                                  : t("access:unverified")}
                              </Badge>
                            </div>
                          </TableCell>
                          <TableCell className="whitespace-nowrap text-xs">
                            {/* Three independent access paths, shown side by
                                side rather than summed: an account with zero
                                sessions can still be reaching MCP through a
                                token or a key. */}
                            {user.active_session_count}{" "}
                            {pluralize(
                              user.active_session_count,
                              t("access:sessionLabel"),
                              t("access:sessionsLabel"),
                            )}
                            {" · "}
                            {user.active_oauth_token_count}{" "}
                            {t("access:tokensLabel")}
                            {" · "}
                            {user.active_api_key_count}{" "}
                            {pluralize(
                              user.active_api_key_count,
                              t("access:keyLabel"),
                              t("access:keysLabel"),
                            )}
                          </TableCell>
                          <TableCell
                            className="whitespace-nowrap"
                            title={t("access:sessionRefreshedHelp")}
                          >
                            {user.last_session_refresh_at
                              ? formatDate(user.last_session_refresh_at, true)
                              : t("access:never")}
                          </TableCell>
                          <TableCell className="whitespace-nowrap">
                            {formatDate(user.created_at)}
                          </TableCell>
                          <TableCell>
                            {/* Every action is disabled on the caller's own
                                row: the server refuses self-revoke,
                                self-disable and self-delete outright
                                (BAD_REQUEST), and a button that can only
                                produce an error is worse than no button. */}
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
                                title={
                                  user.disabled
                                    ? t("access:enableUser")
                                    : t("access:disableUser")
                                }
                                onClick={() =>
                                  setDisableTarget({
                                    id: user.id,
                                    email: user.email,
                                    disabled: user.disabled,
                                  })
                                }
                              >
                                {user.disabled ? (
                                  <Unlock className="h-4 w-4 text-primary" />
                                ) : (
                                  <Lock className="h-4 w-4" />
                                )}
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
                    })}
                </TableBody>
              </Table>
            </div>
            {/* The cap is stated, never silent: an account missing from this
                screen is the failure repeating itself. */}
            {!usersQuery.isError && users.length > 0 && (
              <p className="text-xs text-muted-foreground">
                {t("access:showingCount", {
                  shown: users.length,
                  total: userTotal,
                })}
              </p>
            )}
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
                  <ListStateRow
                    colSpan={6}
                    isLoading={tokensQuery.isLoading}
                    isError={tokensQuery.isError}
                    isEmpty={tokens.length === 0}
                    onRetry={() => tokensQuery.refetch()}
                    t={t}
                    emptyText={t("access:noTokens")}
                  />
                  {!tokensQuery.isLoading &&
                    !tokensQuery.isError &&
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
                    ))}
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
                    <TableHead>{t("access:columnKeyStatus")}</TableHead>
                    <TableHead>{t("access:columnLastUsed")}</TableHead>
                    <TableHead>{t("access:columnCreated")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  <ListStateRow
                    colSpan={6}
                    isLoading={apiKeysQuery.isLoading}
                    isError={apiKeysQuery.isError}
                    isEmpty={apiKeys.length === 0}
                    onRetry={() => apiKeysQuery.refetch()}
                    t={t}
                    emptyText={t("access:noApiKeys")}
                  />
                  {!apiKeysQuery.isLoading &&
                    !apiKeysQuery.isError &&
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
                    ))}
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
                  <ListStateRow
                    colSpan={5}
                    isLoading={clientsQuery.isLoading}
                    isError={clientsQuery.isError}
                    isEmpty={clients.length === 0}
                    onRetry={() => clientsQuery.refetch()}
                    t={t}
                    emptyText={t("access:noClients")}
                  />
                  {!clientsQuery.isLoading &&
                    !clientsQuery.isError &&
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
                    ))}
                </TableBody>
              </Table>
            </div>
          </TabsContent>
        </Tabs>
      )}

      {/* Revoke confirmation. Wording states plainly that the account survives
          and can sign in again, and points at Disable — a revoke mistaken for
          a lock is a live attacker nobody is watching. */}
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

      {/* Disable / enable confirmation. */}
      <AlertDialog
        open={disableTarget !== null}
        onOpenChange={(open) => {
          if (!open) setDisableTarget(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {disableTarget?.disabled
                ? t("access:enableConfirmTitle", {
                    email: disableTarget?.email ?? "",
                  })
                : t("access:disableConfirmTitle", {
                    email: disableTarget?.email ?? "",
                  })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {disableTarget?.disabled
                ? t("access:enableConfirmDescription")
                : t("access:disableConfirmDescription")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("common:cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (!disableTarget) return;
                disableMutation.mutate({
                  user_id: disableTarget.id,
                  disabled: !disableTarget.disabled,
                });
              }}
              disabled={disableMutation.isPending}
            >
              {disableMutation.isPending
                ? disableTarget?.disabled
                  ? t("access:enabling")
                  : t("access:disabling")
                : disableTarget?.disabled
                  ? t("access:enableConfirmAction")
                  : t("access:disableConfirmAction")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete confirmation, with the measured blast radius.
          The cascade is NOT limited to this account — it reaches endpoints and
          API keys owned by OTHER users — so the dialog shows counts read from
          the database before the click rather than a prose promise that a live
          postgres disproved. The confirm button stays disabled until those
          counts have loaded: nobody should approve a destruction whose size is
          still unknown. */}
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
              {t("access:deleteConfirmLead")}
            </AlertDialogDescription>
          </AlertDialogHeader>

          {deleteImpactQuery.isLoading ? (
            <p className="text-sm text-muted-foreground">
              {t("access:deleteImpactLoading")}
            </p>
          ) : deleteImpactQuery.isError || !impact ? (
            <p className="text-sm text-destructive">
              {t("access:deleteImpactFailed")}
            </p>
          ) : (
            <div className="space-y-3 text-sm">
              <div className="rounded-md border p-3 space-y-1">
                <p className="font-medium">{t("access:deleteImpactOwn")}</p>
                <ImpactRow
                  label={t("access:deleteImpactNamespaces")}
                  value={impact.own_namespaces}
                />
                <ImpactRow
                  label={t("access:deleteImpactEndpoints")}
                  value={impact.own_endpoints}
                />
                <ImpactRow
                  label={t("access:deleteImpactServers")}
                  value={impact.own_mcp_servers}
                />
                <ImpactRow
                  label={t("access:deleteImpactApiKeys")}
                  value={impact.own_api_keys}
                />
                <ImpactRow
                  label={t("access:deleteImpactSessions")}
                  value={impact.sessions}
                />
                <ImpactRow
                  label={t("access:deleteImpactTokens")}
                  value={impact.oauth_tokens}
                />
                <ImpactRow
                  label={t("access:deleteImpactM365")}
                  value={impact.m365_tokens}
                />
              </div>

              {crossUserTotal > 0 ? (
                <div className="rounded-md border border-destructive p-3 space-y-2">
                  <p className="font-medium flex items-center gap-2 text-destructive">
                    <AlertTriangle className="h-4 w-4" />
                    {t("access:deleteImpactOther")}
                  </p>
                  <ImpactRow
                    label={t("access:deleteImpactEndpoints")}
                    value={impact.other_users_endpoints}
                  />
                  <ImpactRow
                    label={t("access:deleteImpactApiKeys")}
                    value={impact.other_users_api_keys}
                  />
                  <p className="text-xs text-destructive">
                    {t("access:deleteCrossUserWarning")}
                  </p>
                </div>
              ) : (
                <p className="text-xs text-muted-foreground">
                  {t("access:deleteCrossUserNone")}
                </p>
              )}

              <p className="text-xs text-muted-foreground">
                {t("access:deleteConsiderDisable")}
              </p>
            </div>
          )}

          <AlertDialogFooter>
            <AlertDialogCancel>{t("common:cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (!deleteTarget) return;
                deleteMutation.mutate({ user_id: deleteTarget.id });
              }}
              disabled={
                deleteMutation.isPending ||
                deleteImpactQuery.isLoading ||
                deleteImpactQuery.isError ||
                !impact
              }
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

function ImpactRow({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-mono">{value}</span>
    </div>
  );
}

/**
 * The loading / failed / empty state for every table on this page.
 *
 * Factored out because the distinction it draws is the whole point of the
 * page: a query that FAILED must never render as "nothing here". On a
 * security inventory, "no accounts found" and "we could not ask" are opposite
 * answers, and conflating them is exactly the false negative that let a
 * self-registered attacker go unnoticed in the first place. The error state
 * says so and offers a retry; only a genuinely successful empty result gets
 * the empty copy.
 *
 * Returns null when there are rows to draw, so the caller can render them.
 */
function ListStateRow({
  colSpan,
  isLoading,
  isError,
  isEmpty,
  onRetry,
  emptyText,
  t,
}: {
  colSpan: number;
  isLoading: boolean;
  isError: boolean;
  isEmpty: boolean;
  onRetry: () => void;
  emptyText: string;
  t: (key: string, params?: Record<string, string | number>) => string;
}) {
  if (isLoading) {
    return (
      <TableRow>
        <TableCell colSpan={colSpan} className="text-center py-12">
          <p className="text-muted-foreground">{t("access:loading")}</p>
        </TableCell>
      </TableRow>
    );
  }

  if (isError) {
    return (
      <TableRow>
        <TableCell colSpan={colSpan} className="py-12">
          <div className="flex flex-col items-center gap-2">
            <p className="flex items-center gap-2 font-medium text-destructive">
              <AlertTriangle className="h-4 w-4" />
              {t("access:errorTitle")}
            </p>
            <p className="text-sm text-muted-foreground max-w-md text-center">
              {t("access:errorBody")}
            </p>
            <Button variant="outline" size="sm" onClick={onRetry}>
              <RefreshCw className="h-4 w-4 mr-2" />
              {t("access:retry")}
            </Button>
          </div>
        </TableCell>
      </TableRow>
    );
  }

  if (isEmpty) {
    return (
      <TableRow>
        <TableCell colSpan={colSpan} className="text-center py-12">
          <p className="text-muted-foreground">{emptyText}</p>
        </TableCell>
      </TableRow>
    );
  }

  return null;
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
