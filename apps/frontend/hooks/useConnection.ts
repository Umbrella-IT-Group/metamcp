import { auth } from "@modelcontextprotocol/sdk/client/auth.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  SSEClientTransport,
  SSEClientTransportOptions,
  SseError,
} from "@modelcontextprotocol/sdk/client/sse.js";
import {
  StreamableHTTPClientTransport,
  StreamableHTTPClientTransportOptions,
} from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { RequestOptions } from "@modelcontextprotocol/sdk/shared/protocol.js";
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  CancelledNotificationSchema,
  ClientNotification,
  ClientRequest,
  CompleteResultSchema,
  CreateMessageRequestSchema,
  ErrorCode,
  ListRootsRequestSchema,
  LoggingMessageNotificationSchema,
  McpError,
  Progress,
  PromptListChangedNotificationSchema,
  PromptReference,
  Request,
  ResourceListChangedNotificationSchema,
  ResourceReference,
  ResourceUpdatedNotificationSchema,
  Result,
  ServerCapabilities,
  ToolListChangedNotificationSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { McpServerType, McpServerTypeEnum } from "@repo/zod-types";
import { useMemoizedFn } from "ahooks";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { z } from "zod";

import { SESSION_KEYS } from "@/lib/constants";

import { ConnectionStatus } from "../lib/constants";
import { getAppUrl } from "../lib/env";
import {
  reuseOrCreateStore,
  RpcTrafficStore,
} from "../lib/inspector/rpc-traffic/store";
import {
  connectWithTraffic,
  type TrafficSink,
} from "../lib/inspector/rpc-traffic/transport-tap";
import type { InspectorServerInfo } from "../lib/inspector/server-info";
import { resolveRequestTimeouts } from "../lib/mcp-request-options";
import {
  Notification,
  StdErrNotificationSchema,
} from "../lib/notificationTypes";
import { createAuthProvider } from "../lib/oauth-provider";
import { trpc } from "../lib/trpc";

interface UseConnectionOptions {
  mcpServerUuid: string;
  transportType: McpServerType;
  command: string;
  args: string;
  url: string;
  bearerToken?: string;
  headerName?: string;
  onNotification?: (notification: Notification) => void;
  onStdErrNotification?: (notification: Notification) => void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onPendingRequest?: (request: any, resolve: any, reject: any) => void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  getRoots?: () => any[];
  isMetaMCP?: boolean;
  includeInactiveServers?: boolean;
  enabled?: boolean; // Skip hook execution when false
  // Keep an in-memory JSON-RPC traffic log for this connection (the Inspector
  // page shows it). Off for the detail pages, which do not.
  captureTraffic?: boolean;
}

// A transport belongs to the connection that created it, not to the current
// target's options. End Streamable HTTP sessions before close() aborts their
// controller, and still close the client if ending its session fails.
async function closeConnection(client: Client, transport?: Transport) {
  try {
    if (transport instanceof StreamableHTTPClientTransport) {
      await transport.terminateSession();
    }
  } catch (error) {
    console.error("Error ending MCP session:", error);
  }
  try {
    await client.close();
  } catch (error) {
    console.error("Error closing MCP connection:", error);
  }
}

export function useConnection({
  mcpServerUuid,
  transportType,
  command,
  args,
  url,
  bearerToken,
  headerName,
  onNotification,
  onStdErrNotification,
  onPendingRequest,
  getRoots,
  isMetaMCP = false,
  includeInactiveServers = false,
  enabled = true,
  captureTraffic = false,
}: UseConnectionOptions) {
  const authProvider = createAuthProvider(mcpServerUuid, url);
  const [connectionStatus, setConnectionStatus] =
    useState<ConnectionStatus>("disconnected");
  const [serverCapabilities, setServerCapabilities] =
    useState<ServerCapabilities | null>(null);
  const [mcpClient, setMcpClient] = useState<Client | null>(null);
  // Detach ownership synchronously before an asynchronous close. A newer
  // connect must neither close this pair again nor inherit the old client.
  const activeConnectionRef = useRef<{
    client: Client;
    transport: Transport;
  } | null>(null);
  const mountedRef = useRef(true);
  const [serverInfo, setServerInfo] = useState<InspectorServerInfo | null>(
    null,
  );
  // The log belongs to the connection chain, not to a render: the ref lets a
  // retry inside one connect() reach the store the failed attempt wrote to,
  // and the state hands the same object to the page.
  const rpcTrafficRef = useRef<RpcTrafficStore | null>(null);
  const [rpcTraffic, setRpcTraffic] = useState<RpcTrafficStore | null>(null);
  const [completionsSupported, setCompletionsSupported] = useState(true);
  // Every connect() is an attempt, numbered from this counter, and an attempt
  // is current only while the counter still holds its number. A newer
  // connect(), a disconnect(), a change of what the hook connects to and an
  // unmount each move the counter on. An attempt that was waiting (on the
  // proxy health check, the handshake or a sign-in) finds out it was
  // superseded when it resumes, closes what it opened, and leaves the state,
  // the traffic log and the hook's sign-in flow alone. Without this the attempt
  // that finishes last decides which connection the page holds, and a slow connect
  // to the target the person just left replaces the one they selected.
  const attemptRef = useRef(0);

  // Fetch timeout configurations from the database
  const { data: mcpTimeout } = trpc.frontend.config.getMcpTimeout.useQuery(
    undefined,
    { enabled: enabled },
  );
  const { data: mcpMaxTotalTimeout } =
    trpc.frontend.config.getMcpMaxTotalTimeout.useQuery(undefined, {
      enabled: enabled,
    });
  const { data: mcpResetTimeoutOnProgress } =
    trpc.frontend.config.getMcpResetTimeoutOnProgress.useQuery(undefined, {
      enabled: enabled,
    });

  // useMemoizedFn (ahooks) erases the generic <T> from the wrapped function's
  // type, collapsing makeRequest's return to Promise<unknown> and breaking
  // schema-inferred call sites (zod 4 tightened output<T> from any to
  // unknown). The memoized function's runtime behavior is unchanged, so we
  // cast back to the real generic signature it implements.
  const makeRequest = useMemoizedFn(
    async <T extends z.ZodType>(
      request: ClientRequest,
      schema: T,
      options?: RequestOptions & { suppressToast?: boolean },
    ): Promise<z.output<T>> => {
      // State can still expose the previous client while its close awaits a
      // server response. Only the pair that still owns the connection may send.
      const client = activeConnectionRef.current?.client;
      if (!client) {
        throw new Error("MCP client not connected");
      }
      try {
        const abortController = new AbortController();

        // Get configurable timeout values from database, similar to backend metamcp-proxy.ts.
        // The fallbacks apply only while a setting has not loaded; a stored
        // value is used as stored (see lib/mcp-request-options.ts).
        const mcpRequestOptions: RequestOptions = {
          signal: options?.signal ?? abortController.signal,
          ...resolveRequestTimeouts(
            {
              resetTimeoutOnProgress: mcpResetTimeoutOnProgress,
              timeout: mcpTimeout,
              maxTotalTimeout: mcpMaxTotalTimeout,
            },
            {
              resetTimeoutOnProgress: options?.resetTimeoutOnProgress,
              timeout: options?.timeout,
              maxTotalTimeout: options?.maxTotalTimeout,
            },
          ),
        };

        // If progress notifications are enabled, add an onprogress hook to the MCP Client request options
        // This is required by SDK to reset the timeout on progress notifications
        if (mcpRequestOptions.resetTimeoutOnProgress) {
          mcpRequestOptions.onprogress = (params: Progress) => {
            // Add progress notification to `Server Notification` window in the UI
            if (
              onNotification &&
              activeConnectionRef.current?.client === client
            ) {
              onNotification({
                method: "notification/progress",
                params,
              });
            }
          };
        }

        return await client.request(request, schema, mcpRequestOptions);
      } catch (e: unknown) {
        if (!options?.suppressToast) {
          const errorString = (e as Error).message ?? String(e);
          toast.error(errorString);
        }
        throw e;
      }
    },
  ) as <T extends z.ZodType>(
    request: ClientRequest,
    schema: T,
    options?: RequestOptions & { suppressToast?: boolean },
  ) => Promise<z.output<T>>;

  const handleCompletion = useMemoizedFn(
    async (
      ref: ResourceReference | PromptReference,
      argName: string,
      value: string,
      signal?: AbortSignal,
    ): Promise<string[]> => {
      if (!mcpClient || !completionsSupported) {
        return [];
      }

      const request: ClientRequest = {
        method: "completion/complete",
        params: {
          argument: {
            name: argName,
            value,
          },
          ref,
        },
      };

      try {
        const response = await makeRequest(request, CompleteResultSchema, {
          signal,
          suppressToast: true,
        });
        return response?.completion.values || [];
      } catch (e: unknown) {
        // Disable completions silently if the server doesn't support them.
        // See https://github.com/modelcontextprotocol/specification/discussions/122
        if (e instanceof McpError && e.code === ErrorCode.MethodNotFound) {
          setCompletionsSupported(false);
          return [];
        }

        // Unexpected errors - show toast and rethrow
        toast.error(e instanceof Error ? e.message : String(e));
        throw e;
      }
    },
  );

  const sendNotification = useMemoizedFn(
    async (notification: ClientNotification) => {
      const client = activeConnectionRef.current?.client;
      if (!client) {
        const error = new Error("MCP client not connected");
        toast.error(error.message);
        throw error;
      }

      try {
        await client.notification(notification);
      } catch (e: unknown) {
        toast.error(e instanceof Error ? e.message : String(e));
        throw e;
      }
    },
  );

  const checkProxyHealth = useMemoizedFn(async () => {
    try {
      const proxyHealthUrl = new URL(`/mcp-proxy/server/health`, getAppUrl());

      // Cookies will be sent automatically by the browser
      const proxyHealthResponse = await fetch(proxyHealthUrl, {
        credentials: "include", // Ensure cookies are sent
      });
      const proxyHealth = await proxyHealthResponse.json();
      if (proxyHealth?.status !== "ok") {
        throw new Error("MCP Proxy Server is not healthy");
      }
    } catch (e) {
      console.error("Couldn't connect to MCP Proxy Server", e);
      throw e;
    }
  });

  const is401Error = useMemoizedFn((error: unknown): boolean => {
    return Boolean(
      (error instanceof SseError && error.code === 401) ||
        (error instanceof Error && error.message.includes("401")) ||
        (error instanceof Error && error.message.includes("Unauthorized")) ||
        // Handle fetch errors that might come from streamable HTTP
        (error instanceof TypeError && error.message.includes("401")) ||
        // Handle response errors
        (error &&
          typeof error === "object" &&
          "status" in error &&
          (error as { status: number }).status === 401),
    );
  });

  const isProxyAuthError = useMemoizedFn((error: unknown): boolean => {
    return (
      error instanceof Error &&
      error.message.includes("Authentication required. Use the session token")
    );
  });

  const handleAuthError = useMemoizedFn(async (error: unknown) => {
    if (is401Error(error)) {
      sessionStorage.setItem(SESSION_KEYS.SERVER_URL, url || "");
      sessionStorage.setItem(SESSION_KEYS.MCP_SERVER_UUID, mcpServerUuid);

      const result = await auth(authProvider, {
        serverUrl: url || "",
      });
      return result === "AUTHORIZED";
    }
    return false;
  });

  const connect = useMemoizedFn(
    async (_e?: unknown, retryCount: number = 0): Promise<void> => {
      // A page can have queued disconnect().then(connect) before it unmounts.
      // Invalidation alone cannot stop that later call taking a fresh token.
      if (!mountedRef.current) return;

      // Taking the next number supersedes every earlier attempt, the ones
      // still in flight included, even when this call returns early below.
      attemptRef.current += 1;
      const attempt = attemptRef.current;
      const isCurrent = () => attemptRef.current === attempt;

      // Skip connection if hook is disabled
      if (!enabled) {
        console.warn("Cannot connect: useConnection hook is disabled");
        setConnectionStatus("disconnected");
        return;
      }

      // For MetaMCP connections, we don't need server data
      if (!isMetaMCP) {
        // Ensure transportType is defined
        if (!transportType) {
          console.error(
            "Cannot connect: Transport type not defined or not fetched",
          );
          setConnectionStatus("error");
          return;
        }
      }

      // The page reads this to show progress and to know a connect is under
      // way, so a second connect is not started for the same target.
      setConnectionStatus("connecting");
      const previous = activeConnectionRef.current;
      activeConnectionRef.current = null;
      setMcpClient(null);
      setServerCapabilities(null);
      setServerInfo(null);
      setCompletionsSupported(false);

      const client = new Client<Request, Notification, Result>(
        {
          name: "metamcp-proxy",
          version: "2.0.0",
        },
        {
          capabilities: {
            sampling: {},
            roots: {
              listChanged: true,
            },
          },
        },
      );

      // Which log this attempt writes to. A retry inside this connect() call
      // keeps the log the failed attempt wrote; a new connect starts an empty
      // one, so a log never outlives the target it was recorded against.
      const store = reuseOrCreateStore({
        capture: captureTraffic,
        previous: rpcTrafficRef.current,
        retryCount,
        create: () => new RpcTrafficStore(),
      });
      rpcTrafficRef.current = store;
      setRpcTraffic(store);

      // What this attempt has opened, so it can close it when it turns out to
      // be superseded. Ending the session comes first for the same reason as
      // in disconnect(): close() aborts the transport, after which the DELETE
      // could not be sent. Neither step sends a cancellation, and neither may
      // throw into the caller; a failure is reported and the attempt ends.
      let transport: Transport | undefined;

      // The log an attempt writes to may still be the one the page shows (a
      // disconnect leaves it in place). Until its connection is published, an
      // attempt writes to it only while it is the current one: once superseded,
      // a late handshake answer, or the close that abandon() causes, would be
      // added as if that connection were live. A published connection owns its
      // log until it is closed, so its own close is recorded.
      let published = false;
      const mayWriteToLog = () => published || isCurrent();
      const sink: TrafficSink | null = store
        ? {
            message: (direction, message) => {
              if (mayWriteToLog()) store.sink.message(direction, message);
            },
            transport: (event, error) => {
              if (mayWriteToLog()) store.sink.transport(event, error);
            },
          }
        : null;

      const abandon = () => closeConnection(client, transport);

      // Direct connect() calls can replace an already published connection.
      // Close it before opening another, including when the new attempt fails
      // or the page unmounts while that attempt is still connecting.
      if (previous) {
        await closeConnection(previous.client, previous.transport);
        if (!isCurrent()) {
          await abandon();
          return;
        }
      }

      try {
        await checkProxyHealth();
      } catch (error) {
        if (!isCurrent()) {
          await abandon();
          return;
        }
        // The health check runs before a transport exists, so the tap cannot
        // report this failed connection attempt for us.
        store?.publishTransportError(error);
        setConnectionStatus("error-connecting-to-proxy");
        return;
      }
      if (!isCurrent()) {
        await abandon();
        return;
      }

      try {
        // Inject auth manually instead of using SSEClientTransport, because we're
        // proxying through the inspector server first.
        const headers: HeadersInit = {};

        // Use manually provided bearer token if available, otherwise use OAuth tokens
        const token =
          bearerToken || (await authProvider.tokens())?.access_token;
        if (!isCurrent()) {
          await abandon();
          return;
        }
        if (token) {
          const authHeaderName = headerName || "Authorization";

          // Add custom header name as a special request header to let the server know which header to pass through
          if (authHeaderName.toLowerCase() !== "authorization") {
            headers[authHeaderName] = token;
            headers["x-custom-auth-header"] = authHeaderName;
          } else {
            headers[authHeaderName] = `Bearer ${token}`;
          }
        }

        // Create appropriate transport
        let transportOptions:
          | StreamableHTTPClientTransportOptions
          | SSEClientTransportOptions;

        let mcpProxyServerUrl: URL;

        // Handle MetaMCP connections
        if (isMetaMCP) {
          // For MetaMCP, we use SSE connection to the metamcp proxy endpoint
          mcpProxyServerUrl = new URL(url, getAppUrl());
          // Add includeInactiveServers as a query parameter
          if (includeInactiveServers) {
            mcpProxyServerUrl.searchParams.append(
              "includeInactiveServers",
              "true",
            );
          }
          transportOptions = {
            eventSourceInit: {
              fetch: (
                url: string | URL | globalThis.Request,
                init?: RequestInit,
              ) =>
                fetch(url, {
                  ...init,
                  headers,
                  credentials: "include",
                }),
            },
            requestInit: {
              headers,
              credentials: "include",
            },
          };
        } else {
          switch (transportType) {
            case McpServerTypeEnum.enum.STDIO:
              mcpProxyServerUrl = new URL(
                `/mcp-proxy/server/stdio`,
                getAppUrl(),
              );
              // The proxy spawns what the `mcp_servers` row says and nothing
              // else, so the uuid is the only parameter it needs. `command`
              // and `args` are still sent because the backend falls back to
              // matching them against a registered row when no uuid arrives
              // (an older bundle in a still-open tab). `env` is deliberately
              // NOT sent: it is ignored on arrival and it carries this
              // server's secrets through a query string.
              mcpProxyServerUrl.searchParams.append(
                "mcpServerUuid",
                mcpServerUuid,
              );
              mcpProxyServerUrl.searchParams.append("command", command);
              mcpProxyServerUrl.searchParams.append("args", args);
              transportOptions = {
                authProvider: authProvider,
                eventSourceInit: {
                  fetch: (
                    url: string | URL | globalThis.Request,
                    init?: RequestInit,
                  ) =>
                    fetch(url, {
                      ...init,
                      headers,
                      credentials: "include",
                    }),
                },
                requestInit: {
                  headers,
                  credentials: "include",
                },
                // Use maxTotalTimeout from database for reconnection delay, with fallback to 30s
                reconnectionOptions: {
                  maxReconnectionDelay: mcpMaxTotalTimeout ?? 30000,
                  initialReconnectionDelay: 1000,
                  reconnectionDelayGrowFactor: 1.5,
                  maxRetries: 2,
                },
              };
              break;

            case McpServerTypeEnum.enum.SSE:
              mcpProxyServerUrl = new URL(`/mcp-proxy/server/sse`, getAppUrl());
              mcpProxyServerUrl.searchParams.append("url", url);
              transportOptions = {
                eventSourceInit: {
                  fetch: (
                    url: string | URL | globalThis.Request,
                    init?: RequestInit,
                  ) =>
                    fetch(url, {
                      ...init,
                      headers,
                      credentials: "include",
                    }),
                },
                requestInit: {
                  headers,
                  credentials: "include",
                },
                // Use maxTotalTimeout from database for reconnection delay, with fallback to 30s
                reconnectionOptions: {
                  maxReconnectionDelay: mcpMaxTotalTimeout ?? 30000,
                  initialReconnectionDelay: 1000,
                  reconnectionDelayGrowFactor: 1.5,
                  maxRetries: 2,
                },
              };
              break;

            case McpServerTypeEnum.enum.STREAMABLE_HTTP:
              mcpProxyServerUrl = new URL(`/mcp-proxy/server/mcp`, getAppUrl());
              mcpProxyServerUrl.searchParams.append("url", url);
              transportOptions = {
                authProvider: authProvider,
                eventSourceInit: {
                  fetch: (
                    url: string | URL | globalThis.Request,
                    init?: RequestInit,
                  ) =>
                    fetch(url, {
                      ...init,
                      headers,
                      credentials: "include",
                    }),
                },
                requestInit: {
                  headers,
                  credentials: "include",
                },
                // Use maxTotalTimeout from database for reconnection delay, with fallback to 30s
                reconnectionOptions: {
                  maxReconnectionDelay: mcpMaxTotalTimeout ?? 30000,
                  initialReconnectionDelay: 1000,
                  reconnectionDelayGrowFactor: 1.5,
                  maxRetries: 2,
                },
              };
              break;

            default:
              console.error(`Unsupported transport type: ${transportType}`);
              setConnectionStatus("error");
              return;
          }

          mcpProxyServerUrl.searchParams.append("transportType", transportType);
        }

        if (onNotification) {
          [
            CancelledNotificationSchema,
            LoggingMessageNotificationSchema,
            ResourceUpdatedNotificationSchema,
            ResourceListChangedNotificationSchema,
            ToolListChangedNotificationSchema,
            PromptListChangedNotificationSchema,
          ].forEach((notificationSchema) => {
            client.setNotificationHandler(
              notificationSchema,
              (notification) => {
                // The SDK can deliver notifications before connect() resolves.
                // A stale handshake must not write into the new target's panel.
                if (isCurrent()) onNotification(notification);
              },
            );
          });

          client.fallbackNotificationHandler = (
            notification: Notification,
          ): Promise<void> => {
            if (isCurrent()) onNotification(notification);
            return Promise.resolve();
          };
        }

        if (onStdErrNotification) {
          client.setNotificationHandler(
            StdErrNotificationSchema,
            (notification) => {
              if (isCurrent()) onStdErrNotification(notification);
            },
          );
        }

        let capabilities;
        try {
          const created = isMetaMCP
            ? new SSEClientTransport(mcpProxyServerUrl, transportOptions)
            : transportType === McpServerTypeEnum.enum.STREAMABLE_HTTP
              ? new StreamableHTTPClientTransport(mcpProxyServerUrl, {
                  sessionId: undefined,
                  ...transportOptions,
                })
              : new SSEClientTransport(mcpProxyServerUrl, transportOptions);
          transport = created;

          // The only place this hook connects: the traffic tap has to be on
          // the transport before the SDK starts it (see transport-tap.ts).
          await connectWithTraffic(client, created as Transport, sink);

          // Nothing below may run for a superseded attempt: it would publish
          // a connection to a target the page has left over the one it holds.
          if (!isCurrent()) {
            await abandon();
            return;
          }
          published = true;

          // The tap decorates this same object, so it is still the transport.
          activeConnectionRef.current = { client, transport: created };

          capabilities = client.getServerCapabilities();
          // The protocol version comes from the captured initialize result:
          // the SSE transport has no getter for it.
          const protocolVersion = store?.initializeResult()?.protocolVersion;
          setServerInfo({
            implementation: client.getServerVersion(),
            capabilities,
            instructions: client.getInstructions(),
            protocolVersion:
              typeof protocolVersion === "string" ? protocolVersion : undefined,
          });
        } catch (error) {
          // A superseded attempt that failed has nothing to report: the log
          // and the status belong to the attempt that replaced it.
          if (!isCurrent()) {
            await abandon();
            return;
          }

          // A failed handshake is the case the log exists for. The same error
          // can already be in it (the transport reports it and rejects with
          // it); the store records one object once.
          store?.publishTransportError(error);

          console.error(
            `Failed to connect to MCP Server via the MCP Inspector Proxy: ${mcpProxyServerUrl}:`,
            error,
          );

          // Check if it's a proxy auth error
          if (isProxyAuthError(error)) {
            toast.error(
              "Please enter the session token from the proxy server console in the Configuration settings.",
            );
            setConnectionStatus("error");
            return;
          }

          const shouldRetry = await handleAuthError(error);
          // Superseded while signing in: no retry, which would also reuse the
          // newer attempt's traffic log (see reuseOrCreateStore).
          if (!isCurrent()) {
            await abandon();
            return;
          }
          if (shouldRetry) {
            return connect(undefined, retryCount + 1);
          }
          if (is401Error(error)) {
            // Don't set error state if we're about to redirect for auth, but
            // do leave "connecting": nothing is connecting any more.
            setConnectionStatus("disconnected");
            return;
          }
          throw error;
        }
        setServerCapabilities(capabilities ?? null);
        setCompletionsSupported(true); // Reset completions support on new connection

        if (onPendingRequest) {
          client.setRequestHandler(CreateMessageRequestSchema, (request) => {
            return new Promise((resolve, reject) => {
              onPendingRequest(request, resolve, reject);
            });
          });
        }

        if (getRoots) {
          client.setRequestHandler(ListRootsRequestSchema, async () => {
            return { roots: getRoots() };
          });
        }

        setMcpClient(client);
        setConnectionStatus("connected");
      } catch (e) {
        if (!isCurrent()) {
          await abandon();
          return;
        }
        console.error(e);
        setConnectionStatus("error");
      }
    },
  );

  const disconnect = useMemoizedFn(async () => {
    // An attempt still in flight must not finish into a hook that was told to
    // disconnect. A slow close owns only the connection it detached here.
    const attempt = ++attemptRef.current;
    const active = activeConnectionRef.current;
    activeConnectionRef.current = null;
    try {
      if (active) {
        await closeConnection(active.client, active.transport);
      }
      if (enabled && attemptRef.current === attempt) {
        // A stale disconnect must not clear a newer attempt's credentials.
        authProvider.clear();
      }
    } catch (error) {
      console.error("Error during disconnect:", error);
    } finally {
      // A new connect can publish while the old transport is closing.
      if (mountedRef.current && attemptRef.current === attempt) {
        setMcpClient(null);
        setConnectionStatus("disconnected");
        setCompletionsSupported(false);
        setServerCapabilities(null);
        setServerInfo(null);
      }
    }
  });

  // Handle enabled/disabled state changes
  useEffect(() => {
    if (!enabled && connectionStatus === "connected") {
      // Disconnect when hook becomes disabled
      disconnect();
    }
  }, [enabled, connectionStatus, disconnect]);

  // What the hook connects to. When any of it changes, or the page unmounts,
  // an attempt still in flight is for a target the page has left: it is
  // superseded, and a status that says "connecting" for it is put back, so a
  // page that does not connect to the new target does not show a connect that
  // will never finish. A page that does connect starts a new attempt after
  // this runs (a cleanup runs before the effects of the same commit).
  useEffect(() => {
    return () => {
      attemptRef.current += 1;
      setConnectionStatus((status) =>
        status === "connecting" ? "disconnected" : status,
      );
    };
  }, [
    mcpServerUuid,
    transportType,
    command,
    args,
    url,
    bearerToken,
    headerName,
    isMetaMCP,
    includeInactiveServers,
    enabled,
  ]);

  // Register once: status changes must not disconnect a reconnect that has
  // just started. Unload also invalidates a handshake that is still pending.
  useEffect(() => {
    mountedRef.current = true;
    const handleDisconnect = () => {
      if (activeConnectionRef.current) {
        void disconnect();
        return;
      }
      // OAuth can unload the page before a connection is published. Invalidate
      // that attempt without clearing the code verifier its callback needs.
      attemptRef.current += 1;
      if (mountedRef.current) {
        setMcpClient(null);
        setConnectionStatus("disconnected");
        setCompletionsSupported(false);
        setServerCapabilities(null);
        setServerInfo(null);
      }
    };

    window.addEventListener("beforeunload", handleDisconnect);
    window.addEventListener("unload", handleDisconnect);

    return () => {
      mountedRef.current = false;
      window.removeEventListener("beforeunload", handleDisconnect);
      window.removeEventListener("unload", handleDisconnect);
      handleDisconnect();
    };
  }, [disconnect]);

  return {
    connectionStatus,
    serverCapabilities,
    serverInfo,
    mcpClient,
    rpcTraffic,
    makeRequest,
    sendNotification,
    handleCompletion,
    completionsSupported,
    connect,
    disconnect,
  };
}
