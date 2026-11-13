"use client";

import { McpServer } from "@repo/zod-types";
import { useDebounce, useMemoizedFn } from "ahooks";
import { ChevronDown, Edit, Eye, SearchCode, Server } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import React, { Suspense, useEffect, useMemo, useState } from "react";

import { EditMcpServer } from "@/components/edit-mcp-server";
import { InspectorSkeleton } from "@/components/skeletons/inspector-skeleton";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Separator } from "@/components/ui/separator";
import { useConnection } from "@/hooks/useConnection";
import { useTranslations } from "@/hooks/useTranslations";
import { authClient } from "@/lib/auth-client";
import {
  buildInspectorTargetKey,
  describeTarget,
  inspectorConnectionOptions,
  resolveInspectorTarget,
} from "@/lib/inspector/inspector-target";
import { inspectorConnectAction } from "@/lib/inspector-connection-key";
import { Notification } from "@/lib/notificationTypes";
import { trpc } from "@/lib/trpc";

import { Inspector } from "./components/inspector";
import { InspectorTargetNotice } from "./components/inspector-target-notice";
import { NotificationsPanel } from "./components/notifications-panel";
import { RpcTrafficPanel } from "./components/rpc-traffic-panel";

interface NotificationEntry {
  id: string;
  notification: Notification;
  timestamp: Date;
  type: "notification" | "stderr";
}

type TargetParam = "server" | "namespace" | "endpoint";

function McpInspectorContent() {
  const { t } = useTranslations();
  const [editDialogOpen, setEditDialogOpen] = useState<boolean>(false);
  const [notifications, setNotifications] = useState<NotificationEntry[]>([]);
  const [includeInactive, setIncludeInactive] = useState(false);
  const searchParams = useSearchParams();
  const router = useRouter();

  // Fail closed: isAdmin starts false, and a failed session lookup leaves it
  // false, so a namespace or endpoint can never be reached without a confirmed
  // administrator role (the backend refuses a member anyway: the whole
  // /mcp-proxy route is admin only). roleLoaded is true once the lookup has
  // answered either way, so a failed lookup still lets servers be inspected.
  const [isAdmin, setIsAdmin] = useState(false);
  const [roleLoaded, setRoleLoaded] = useState(false);
  useEffect(() => {
    let cancelled = false;
    authClient
      .getSession()
      .then((session) => {
        if (cancelled) return;
        const role = (session?.data?.user as { role?: string } | undefined)
          ?.role;
        setIsAdmin(role === "admin");
        setRoleLoaded(true);
      })
      .catch(() => {
        if (cancelled) return;
        setIsAdmin(false);
        setRoleLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Fetch MCP servers list
  const { data: serversResponse, isLoading: serversLoading } =
    trpc.frontend.mcpServers.list.useQuery();

  // `list` returns public rows plus the caller's own, even for an
  // administrator. `listAll` returns every row with its owner in `user_id`;
  // it is admin only, so it is not even asked for by anyone else.
  const { data: namespacesResponse, isLoading: namespacesLoading } =
    trpc.frontend.namespaces.listAll.useQuery(undefined, {
      enabled: isAdmin,
    });
  const { data: endpointsResponse, isLoading: endpointsLoading } =
    trpc.frontend.endpoints.listAll.useQuery(undefined, {
      enabled: isAdmin,
    });

  // Memoize the arrays to prevent unnecessary re-renders
  const servers: McpServer[] = useMemo(() => {
    return serversResponse?.success ? serversResponse.data : [];
  }, [serversResponse]);
  const namespaces = useMemo(
    () => (namespacesResponse?.success ? namespacesResponse.data : []),
    [namespacesResponse],
  );
  const endpoints = useMemo(
    () => (endpointsResponse?.success ? endpointsResponse.data : []),
    [endpointsResponse],
  );

  const listsLoading =
    serversLoading ||
    !roleLoaded ||
    (isAdmin && (namespacesLoading || endpointsLoading));

  // The page is pointed at a server, or (administrators only) a namespace or
  // an endpoint. Each parameter is looked up, as an exact uuid, in the lists
  // above; nothing from the URL is ever used to build a request address.
  const serverParam = searchParams.get("server");
  const namespaceParam = searchParams.get("namespace");
  const endpointParam = searchParams.get("endpoint");
  const target = useMemo(
    () =>
      resolveInspectorTarget(
        {
          server: serverParam,
          namespace: namespaceParam,
          endpoint: endpointParam,
        },
        { servers, namespaces, endpoints },
        { isAdmin },
      ),
    [
      serverParam,
      namespaceParam,
      endpointParam,
      servers,
      namespaces,
      endpoints,
      isAdmin,
    ],
  );
  const isGatewayTarget =
    target.kind === "namespace" || target.kind === "endpoint";

  // Each gateway connection opens one pooled session per backend in the
  // namespace, so a flurry of toggles must not reconnect each time: the
  // connection sees the value only once it has settled. A server target does
  // not use it.
  const settledIncludeInactive = useDebounce(includeInactive, { wait: 400 });
  const connectionIncludeInactive = isGatewayTarget && settledIncludeInactive;

  // Notification management functions using useMemoizedFn
  const addNotification = useMemoizedFn(
    (notification: Notification, type: "notification" | "stderr") => {
      const entry: NotificationEntry = {
        id: `${Date.now()}-${Math.random()}`,
        notification,
        timestamp: new Date(),
        type,
      };
      setNotifications((prev) => [entry, ...prev]);
    },
  );

  const clearNotifications = useMemoizedFn(() => {
    setNotifications([]);
  });

  const removeNotification = useMemoizedFn((id: string) => {
    setNotifications((prev) =>
      prev.filter((notification) => notification.id !== id),
    );
  });

  // Memoized notification callbacks for useConnection
  const onNotification = useMemoizedFn((notification: Notification) => {
    addNotification(notification, "notification");
  });

  const onStdErrNotification = useMemoizedFn((notification: Notification) => {
    addNotification(notification, "stderr");
  });

  // MCP Connection setup - only enable when the target is resolved and the
  // lists it came from are loaded
  const { targetEnabled, ...connectionOptions } = inspectorConnectionOptions(
    target,
    connectionIncludeInactive,
  );
  const connection = useConnection({
    ...connectionOptions,
    onNotification,
    onStdErrNotification,
    captureTraffic: true,
    enabled: targetEnabled && !listsLoading,
  });

  // Reconnect only when the target, or a setting its connection uses,
  // changes. The list queries return a new array whenever ANY row in the list
  // changes (another server's status, an edit, an add, a delete; the cache
  // keeps an unchanged row's object, so a server target is new only when its
  // own row changes). An effect that depends on the arrays therefore tears
  // down and re-spawns a healthy connection, and wipes the notification and
  // stderr panel, on every unrelated update. The key is a string, so React
  // compares it by value; see lib/inspector-connection-key.ts (servers) and
  // lib/inspector/inspector-target.ts (gateway targets) for what it holds.
  const connectionKey = buildInspectorTargetKey(
    target,
    connectionIncludeInactive,
  );

  // Handle target connection logic and notifications
  React.useEffect(() => {
    // Clear notifications when switching targets or changing their settings
    clearNotifications();

    if (!connection || target.kind === "none" || listsLoading) {
      return;
    }

    // What each status means, and why the error states connect, is documented
    // on inspectorConnectAction (and unit tested there).
    const action = inspectorConnectAction(connection.connectionStatus);
    if (action === "reconnect") {
      connection.disconnect().then(() => {
        connection.connect();
      });
    } else if (action === "connect") {
      connection.connect();
    }
    // The key stands in for `target` on purpose; see above.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [connectionKey, listsLoading]);

  const handleConnectionToggle = useMemoizedFn(() => {
    if (connection.connectionStatus === "connected") {
      connection.disconnect().then(() => {
        connection.connect();
      });
    } else {
      connection.connect();
    }
  });

  // Handle successful edit
  const handleEditSuccess = useMemoizedFn(() => {
    setEditDialogOpen(false);
  });

  // Get connection status display info
  const getConnectionStatusInfo = useMemoizedFn(() => {
    switch (connection.connectionStatus) {
      case "connected":
        return {
          text: t("inspector:connected"),
          color: "text-green-600 dark:text-green-400",
        };
      case "disconnected":
        return {
          text: t("inspector:disconnected"),
          color: "text-gray-500 dark:text-gray-400",
        };
      case "error":
      case "error-connecting-to-proxy":
        return {
          text: t("inspector:connectionError"),
          color: "text-red-600 dark:text-red-400",
        };
      default:
        return {
          text: t("inspector:connecting"),
          color: "text-yellow-600 dark:text-yellow-400",
        };
    }
  });

  const connectionInfo = getConnectionStatusInfo();

  // Function to handle target selection and update URL. Exactly one of the
  // three parameters is set; the other two are removed.
  const handleTargetSelect = useMemoizedFn(
    (param: TargetParam, uuid: string) => {
      const params = new URLSearchParams(searchParams.toString());
      params.delete("server");
      params.delete("namespace");
      params.delete("endpoint");
      if (uuid) {
        params.set(param, uuid);
      }
      router.replace(`/mcp-inspector?${params.toString()}`);
    },
  );

  const privateSuffix = (userId: string | null | undefined) =>
    userId ? ` (${t("inspector:inspectorTarget.private")})` : "";

  const selectedLabel =
    target.kind === "none"
      ? isAdmin
        ? t("inspector:inspectorTarget.select")
        : t("inspector:selectServerDropdown")
      : describeTarget(target, t);

  const noTargetsAvailable =
    servers.length === 0 && namespaces.length === 0 && endpoints.length === 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="space-y-4">
        <div className="flex items-center gap-3">
          <SearchCode className="h-8 w-8 text-primary" />
          <div>
            <h1 className="text-3xl font-bold tracking-tight">
              {t("inspector:title")}
            </h1>
            <p className="text-muted-foreground">{t("inspector:subtitle")}</p>
          </div>
        </div>

        <Separator />

        {/* Target Selection */}
        <div className="flex flex-wrap items-center gap-4">
          <span className="text-sm font-medium">
            {isAdmin
              ? t("inspector:inspectorTarget.label")
              : t("inspector:serverSelection")}
          </span>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="outline"
                className="justify-between min-w-[300px]"
              >
                <span className="truncate">{selectedLabel}</span>
                <ChevronDown className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent className="max-h-[70vh] w-[360px] overflow-y-auto">
              {listsLoading ? (
                <DropdownMenuItem disabled>
                  {t("inspector:loadingServers")}
                </DropdownMenuItem>
              ) : noTargetsAvailable ? (
                <DropdownMenuItem disabled>
                  {t("inspector:noServersAvailable")}
                </DropdownMenuItem>
              ) : (
                <>
                  {isAdmin && servers.length > 0 && (
                    <DropdownMenuLabel>
                      {t("inspector:inspectorTarget.groupServers")}
                    </DropdownMenuLabel>
                  )}
                  {servers.map((server) => (
                    <DropdownMenuItem
                      key={server.uuid}
                      onClick={() => handleTargetSelect("server", server.uuid)}
                      className="flex flex-col items-start gap-1"
                    >
                      <div className="font-medium">{server.name}</div>
                      {server.description && (
                        <div className="text-xs text-muted-foreground">
                          {server.description}
                        </div>
                      )}
                    </DropdownMenuItem>
                  ))}

                  {isAdmin && namespaces.length > 0 && (
                    <>
                      <DropdownMenuSeparator />
                      <DropdownMenuLabel>
                        {t("inspector:inspectorTarget.groupNamespaces")}
                      </DropdownMenuLabel>
                      {namespaces.map((namespace) => (
                        <DropdownMenuItem
                          key={namespace.uuid}
                          onClick={() =>
                            handleTargetSelect("namespace", namespace.uuid)
                          }
                          className="flex flex-col items-start gap-1"
                        >
                          <div className="font-medium">
                            {namespace.name}
                            {privateSuffix(namespace.user_id)}
                          </div>
                          {namespace.description && (
                            <div className="text-xs text-muted-foreground">
                              {namespace.description}
                            </div>
                          )}
                        </DropdownMenuItem>
                      ))}
                    </>
                  )}

                  {isAdmin && endpoints.length > 0 && (
                    <>
                      <DropdownMenuSeparator />
                      <DropdownMenuLabel>
                        {t("inspector:inspectorTarget.groupEndpoints")}
                      </DropdownMenuLabel>
                      {endpoints.map((endpoint) => (
                        <DropdownMenuItem
                          key={endpoint.uuid}
                          onClick={() =>
                            handleTargetSelect("endpoint", endpoint.uuid)
                          }
                          className="flex flex-col items-start gap-1"
                        >
                          <div className="font-medium">
                            {t("inspector:inspectorTarget.endpointLabel", {
                              endpoint: endpoint.name,
                              namespace: endpoint.namespace.name,
                            })}
                            {privateSuffix(endpoint.user_id)}
                          </div>
                        </DropdownMenuItem>
                      ))}
                    </>
                  )}
                </>
              )}
            </DropdownMenuContent>
          </DropdownMenu>

          {/* Connection Status and Controls */}
          {target.kind !== "none" && (
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm text-muted-foreground">
                {t("inspector:connectionStatus")}
              </span>
              <span className={`text-sm font-medium ${connectionInfo.color}`}>
                {connectionInfo.text}
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={handleConnectionToggle}
                disabled={
                  connection.connectionStatus === "connecting" || listsLoading
                }
              >
                {connection.connectionStatus === "connected"
                  ? t("inspector:reconnectButton")
                  : t("inspector:connectButton")}
              </Button>
              {target.kind === "server" ? (
                <>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      router.push(`/mcp-servers/${target.server.uuid}`)
                    }
                  >
                    <Eye className="h-4 w-4 mr-2" />
                    {t("mcp-servers:list.viewDetails")}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setEditDialogOpen(true)}
                  >
                    <Edit className="h-4 w-4 mr-2" />
                    {t("inspector:editServerButton")}
                  </Button>
                </>
              ) : (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    router.push(
                      `/namespaces/${encodeURIComponent(target.namespaceUuid)}`,
                    )
                  }
                >
                  <Eye className="h-4 w-4 mr-2" />
                  {t("inspector:inspectorTarget.viewNamespace")}
                </Button>
              )}
            </div>
          )}
        </div>

        <InspectorTargetNotice
          target={target}
          includeInactive={includeInactive}
          onIncludeInactiveChange={setIncludeInactive}
          t={t}
        />
      </div>

      {/* Edit Server Dialog */}
      {target.kind === "server" && (
        <EditMcpServer
          server={target.server}
          isOpen={editDialogOpen}
          onClose={() => setEditDialogOpen(false)}
          onSuccess={handleEditSuccess}
        />
      )}

      {/* Inspector Content */}
      <div className="rounded-lg border p-6">
        {target.kind !== "none" ? (
          connection.connectionStatus === "connected" ? (
            <Inspector
              mcpServerUuid={connectionOptions.mcpServerUuid}
              makeRequest={connection.makeRequest}
              serverCapabilities={connection.serverCapabilities}
              targetKind={target.kind}
              serverInfo={connection.serverInfo}
            />
          ) : (
            <div className="space-y-4">
              <InspectorSkeleton />
              <div className="flex justify-center">
                <div className="text-sm text-muted-foreground">
                  {connection.connectionStatus === "connecting"
                    ? t("inspector:connectingToServer")
                    : t("inspector:connectToStart")}
                </div>
              </div>
            </div>
          )
        ) : (
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <Server className="h-12 w-12 text-muted-foreground/50 mb-4" />
            <h3 className="text-lg font-semibold mb-2">
              {t("inspector:noServerSelected")}
            </h3>
            <p className="text-sm text-muted-foreground max-w-md">
              {t("inspector:noServerSelectedDesc")}
            </p>
          </div>
        )}
      </div>

      {/* Notifications Panel */}
      <NotificationsPanel
        notifications={notifications}
        onClearNotifications={clearNotifications}
        onRemoveNotification={removeNotification}
      />

      {/* Traffic log. Outside the connected block on purpose: a connection
          that failed to start is what this panel is most useful for. */}
      {target.kind !== "none" && (
        <RpcTrafficPanel store={connection.rpcTraffic} target={target} t={t} />
      )}
    </div>
  );
}

export default function McpInspectorPage() {
  return (
    <Suspense fallback={<InspectorSkeleton />}>
      <McpInspectorContent />
    </Suspense>
  );
}
