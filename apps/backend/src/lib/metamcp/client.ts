import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StdioServerParameters } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { ToolListChangedNotificationSchema } from "@modelcontextprotocol/sdk/types.js";
import { ServerParameters } from "@repo/zod-types";

import logger from "@/utils/logger";

import {
  isM365BrokerError,
  M365BrokerError,
  M365BrokerErrorCode,
} from "../m365/errors";
import { getInjectedFetchForServer } from "../m365/injected-fetch";
import { recordConnectBrokerFailure } from "../m365/request-context";
import { ProcessManagedStdioTransport } from "../stdio-transport/process-managed-transport";
import { describeConnectError, formatConnectionAge } from "./connect-error";
import { metamcpLogStore } from "./log-store";
import { serverErrorTracker } from "./server-error-tracker";
import { resolveEnvVariables } from "./utils";

const sleep = (time: number) =>
  new Promise<void>((resolve) => setTimeout(() => resolve(), time));

/**
 * Reason that a remote transport drop fired the `onTransportDrop`
 * callback. `close` means the SDK's `Transport.onclose` fired (the
 * remote dropped us cleanly or the socket EOF'd); `error` means the
 * SDK's `Transport.onerror` fired (network-layer failure surfaced
 * out-of-band, not necessarily fatal but treated as a drop signal).
 *
 * Mirrors the STDIO `onProcessCrash` callback shape so the pool layer
 * can pivot on a single recovery path regardless of transport kind.
 */
export type TransportDropReason = "close" | "error";

/**
 * Callback fired when an HTTP/SSE transport drops asynchronously.
 * Sibling to `onProcessCrash` (which covers STDIO). The pool wires
 * this to its `invalidateServerConnection` cascade so a watchtower
 * restart on a backend MCP container can be detected and recovered
 * BEFORE the next request hits the dead pool entry.
 *
 * Will NOT fire during a normal `cleanup()` shutdown — `cleanup()`
 * sets a `closing` flag that suppresses the callback so caller-driven
 * teardown is distinguishable from remote drops.
 */
export type TransportDropCallback = (
  reason: TransportDropReason,
  error?: Error,
) => void;

/**
 * Exponential-backoff schedule for reconnect attempts in
 * `connectMetaMcpClient`. Replaces the pre-PR #20 fixed `waitFor = 5000`
 * sleep which was too slow for fast watchtower bounces (3-8s) and
 * unnecessarily fast for cold-start cycles (the backend container
 * takes 20-30s to be ready to accept SSE). The schedule starts at
 * 1s, doubles each attempt, and caps at 30s.
 *
 * Default schedule (attempts 0..6): 1s, 2s, 4s, 8s, 16s, 30s, 30s ...
 * Plus a small ±250ms uniform jitter to avoid synchronized retry
 * thundering when multiple servers bounce at once (watchtower
 * batches updates across a docker-compose project).
 *
 * Tunable via env: `MCP_RECONNECT_BACKOFF_INITIAL_MS`,
 * `MCP_RECONNECT_BACKOFF_MAX_MS`, `MCP_RECONNECT_BACKOFF_MULTIPLIER`.
 */
const RECONNECT_BACKOFF_INITIAL_MS = parseInt(
  process.env.MCP_RECONNECT_BACKOFF_INITIAL_MS || "1000",
  10,
);
const RECONNECT_BACKOFF_MAX_MS = parseInt(
  process.env.MCP_RECONNECT_BACKOFF_MAX_MS || "30000",
  10,
);
const RECONNECT_BACKOFF_MULTIPLIER = parseFloat(
  process.env.MCP_RECONNECT_BACKOFF_MULTIPLIER || "2",
);

/**
 * Compute the backoff delay (ms) for a given zero-indexed attempt
 * number using the configured exponential schedule + uniform jitter.
 * Exported for unit tests; not part of the public API.
 */
export const computeReconnectBackoffMs = (attempt: number): number => {
  const base = Math.min(
    RECONNECT_BACKOFF_MAX_MS,
    RECONNECT_BACKOFF_INITIAL_MS *
      Math.pow(RECONNECT_BACKOFF_MULTIPLIER, attempt),
  );
  return base + Math.random() * 250;
};

/**
 * A subscriber invoked when the backend MCP server emits
 * `notifications/tools/list_changed`. The proxy layer (and the pool
 * invalidation path) attach subscribers here to fan that signal out to
 * upstream MetaMCP `Server` instances.
 *
 * Subscribers MUST be tolerant of being called multiple times (Set
 * semantics on the field already dedupe identical references; idempotent
 * subscriber bodies handle the over-fire case from pool invalidation).
 */
export type ListChangedSubscriber = () => Promise<void> | void;

export interface ConnectedClient {
  client: Client;
  cleanup: () => Promise<void>;
  onProcessCrash?: (exitCode: number | null, signal: string | null) => void;
  /**
   * Sibling to `onProcessCrash` for HTTP/SSE backends. Fired when the
   * SDK transport reports an async drop (`onclose` or `onerror`) that
   * we did NOT initiate via `cleanup()`. The pool layer wires this to
   * `invalidateServerConnection` to detect watchtower-driven container
   * restarts BEFORE the next request hits the dead pool entry.
   */
  onTransportDrop?: TransportDropCallback;
  /**
   * Set of fan-out subscribers for upstream `tools/list_changed` propagation.
   * Populated by the proxy layer (one per upstream `Server` that this
   * backend client is feeding). Cleared by `cleanup`. The pool's
   * `invalidateServerConnection` fires every subscriber here once before
   * dropping the client, so that consumers see a `list_changed` signal
   * on the watchtower-restart cycle even when the backend doesn't emit
   * one itself.
   */
  listChangedSubscribers: Set<ListChangedSubscriber>;
}

/**
 * Transforms localhost URLs to use host.docker.internal when running inside Docker
 */
export const transformDockerUrl = (url: string): string => {
  if (process.env.TRANSFORM_LOCALHOST_TO_DOCKER_INTERNAL === "true") {
    const transformed = url.replace(
      /localhost|127\.0\.0\.1/g,
      "host.docker.internal",
    );
    return transformed;
  }
  return url;
};

export const createMetaMcpClient = (
  serverParams: ServerParameters,
): { client: Client | undefined; transport: Transport | undefined } => {
  let transport: Transport | undefined;

  // Create the appropriate transport based on server type
  // Default to "STDIO" if type is undefined
  if (!serverParams.type || serverParams.type === "STDIO") {
    // Resolve environment variable placeholders
    const resolvedEnv = serverParams.env
      ? resolveEnvVariables(serverParams.env)
      : undefined;

    const stdioParams: StdioServerParameters = {
      command: serverParams.command || "",
      args: serverParams.args || undefined,
      env: resolvedEnv,
      stderr: "pipe",
    };
    transport = new ProcessManagedStdioTransport(stdioParams);

    // Handle stderr stream when set to "pipe"
    if ((transport as ProcessManagedStdioTransport).stderr) {
      const stderrStream = (transport as ProcessManagedStdioTransport).stderr;

      stderrStream?.on("data", (chunk: Buffer) => {
        metamcpLogStore.addLog(
          serverParams.name,
          "error",
          chunk.toString().trim(),
        );
      });

      stderrStream?.on("error", (error: Error) => {
        metamcpLogStore.addLog(
          serverParams.name,
          "error",
          "stderr error",
          error,
        );
      });
    }
  } else if (serverParams.type === "SSE" && serverParams.url) {
    // Transform the URL if TRANSFORM_LOCALHOST_TO_DOCKER_INTERNAL is set to "true"
    const transformedUrl = transformDockerUrl(serverParams.url);

    // Build headers: start with custom headers, then add auth header
    const headers: Record<string, string> = {
      ...(serverParams.headers || {}),
    };

    // Check for authentication - prioritize OAuth tokens, fallback to bearerToken
    const authToken =
      serverParams.oauth_tokens?.access_token || serverParams.bearerToken;
    if (authToken) {
      headers["Authorization"] = `Bearer ${authToken}`;
    }

    const hasHeaders = Object.keys(headers).length > 0;

    if (!hasHeaders) {
      transport = new SSEClientTransport(new URL(transformedUrl));
    } else {
      transport = new SSEClientTransport(new URL(transformedUrl), {
        requestInit: {
          headers,
        },
        eventSourceInit: {
          fetch: (url, init) => fetch(url, { ...init, headers }),
        },
      });
    }
  } else if (serverParams.type === "STREAMABLE_HTTP" && serverParams.url) {
    // Transform the URL if TRANSFORM_LOCALHOST_TO_DOCKER_INTERNAL is set to "true"
    const transformedUrl = transformDockerUrl(serverParams.url);

    // Build headers: start with custom headers, then add auth header
    const headers: Record<string, string> = {
      ...(serverParams.headers || {}),
    };

    // Check for authentication - prioritize OAuth tokens, fallback to bearerToken
    const authToken =
      serverParams.oauth_tokens?.access_token || serverParams.bearerToken;
    if (authToken) {
      headers["Authorization"] = `Bearer ${authToken}`;
    }

    const hasHeaders = Object.keys(headers).length > 0;

    // M365 delegated broker: servers configured for per-user Graph
    // token injection get a custom fetch that stamps a freshly minted
    // per-user Authorization onto EVERY outgoing request (and strips
    // any connection-level credential). Request-scoped — survives pool
    // idle-handoff/cap-reuse without cross-user token leakage. See
    // `lib/m365/injected-fetch.ts` for the invariant.
    const injectedFetch = getInjectedFetchForServer(serverParams.name);

    if (!hasHeaders && !injectedFetch) {
      transport = new StreamableHTTPClientTransport(new URL(transformedUrl));
    } else {
      transport = new StreamableHTTPClientTransport(new URL(transformedUrl), {
        ...(hasHeaders ? { requestInit: { headers } } : {}),
        ...(injectedFetch ? { fetch: injectedFetch } : {}),
      });
    }
  } else {
    metamcpLogStore.addLog(
      serverParams.name,
      "error",
      `Unsupported server type: ${serverParams.type}`,
    );
    return { client: undefined, transport: undefined };
  }

  const client = new Client(
    {
      name: "metamcp-client",
      version: "2.0.0",
    },
    {
      // prompts/resources/tools are SERVER capabilities; they were never
      // valid on a client. SDK <=1.16 tolerated them, but SDK 1.29's
      // ClientCapabilities schema strips unknown keys, so advertising them
      // was always inert. An empty object is the exact wire-equivalent and
      // keeps metamcp's downstream client advertising no client-side
      // capabilities, as before.
      capabilities: {},
    },
  );
  return { client, transport };
};

/**
 * Test-only injection seam. Production callers (the pool) omit `deps` and
 * get the real transport factory; unit tests supply a fake `createClient`
 * so the retry loop, the `closing` guard and the M365 broker
 * short-circuit are exercisable without live network I/O or a real SDK
 * transport. Mirrors the injectable-deps convention already used by
 * `makeM365InjectedFetch` and `buildM365BrokerErrorResult`.
 */
export interface ConnectMetaMcpClientDeps {
  createClient?: typeof createMetaMcpClient;
}

/**
 * M365 broker codes that represent a DETERMINISTIC per-user identity
 * rejection on the connect-time mint — retrying can never change this
 * user's outcome, so a connect that hits one of these short-circuits to a
 * single attempt (see the catch block below). Deliberately every code
 * EXCEPT `mint_failed`: mint-service throws `mint_failed` for TRANSIENT
 * operational failures — the token-endpoint being unreachable
 * (mint-service.ts's network-error catch) or answering 5xx / a
 * non-grant error (mint-service.ts's `classifyRefreshFailure`, the
 * ">=500 || !body.error" and "invalid_client/invalid_request" branches).
 * Pre-Track-A5 those retried with the normal backoff schedule — free
 * resilience against a brief Entra blip — and that must be preserved, not
 * collapsed into the same one-attempt short-circuit as the deterministic
 * codes.
 */
const NON_RETRYABLE_M365_BROKER_CODES: ReadonlySet<M365BrokerErrorCode> =
  new Set([
    "credential_missing",
    "credential_expired",
    "credential_revoked",
    "mfa_required",
    "not_configured",
  ]);

export const connectMetaMcpClient = async (
  serverParams: ServerParameters,
  onProcessCrash?: (exitCode: number | null, signal: string | null) => void,
  onTransportDrop?: TransportDropCallback,
  deps: ConnectMetaMcpClientDeps = {},
): Promise<ConnectedClient | undefined> => {
  const createClient = deps.createClient ?? createMetaMcpClient;
  // Get max attempts from server error tracker instead of hardcoding
  const maxAttempts = await serverErrorTracker.getServerMaxAttempts(
    serverParams.uuid,
  );
  let count = 0;
  let retry = true;

  logger.info(
    `Connecting to server ${serverParams.name} (${serverParams.uuid}) with max attempts: ${maxAttempts}`,
  );

  while (retry) {
    let transport: Transport | undefined;
    let client: Client | undefined;
    // Hoisted to loop scope (was declared inside the try) so the catch
    // block can set it before its cleanup `transport.close()` — that
    // intentional teardown must not masquerade as an unexpected backend
    // drop (see the catch below). Reset each attempt: a fresh transport
    // starts un-closing.
    let closing = false;
    // When the `initialize` handshake completed. `undefined` = never
    // established, which lets the drop handlers tell an established-then-
    // dropped socket (container replace) from a connect-time failure
    // (backend down) that the connect-attempt log already covers.
    let connectedAt: number | undefined;

    try {
      // Check if server is already in error state before attempting connection
      const isInErrorState = await serverErrorTracker.isServerInErrorState(
        serverParams.uuid,
      );
      if (isInErrorState) {
        logger.info(
          `Server ${serverParams.name} (${serverParams.uuid}) is already in ERROR state, skipping connection attempt`,
        );
        return undefined;
      }

      // Create fresh client and transport for each attempt
      const result = createClient(serverParams);
      client = result.client;
      transport = result.transport;

      if (!client || !transport) {
        return undefined;
      }

      // Set up process crash detection for STDIO transports BEFORE connecting
      if (transport instanceof ProcessManagedStdioTransport) {
        logger.info(
          `Setting up crash handler for server ${serverParams.name} (${serverParams.uuid})`,
        );
        transport.onprocesscrash = (exitCode, signal) => {
          logger.info(
            `Process crashed for server ${serverParams.name} (${serverParams.uuid}): code=${exitCode}, signal=${signal}`,
          );

          // Notify the pool about the crash
          if (onProcessCrash) {
            logger.info(
              `Calling onProcessCrash callback for server ${serverParams.name} (${serverParams.uuid})`,
            );
            onProcessCrash(exitCode, signal);
          } else {
            logger.info(
              `No onProcessCrash callback provided for server ${serverParams.name} (${serverParams.uuid})`,
            );
          }
        };
      }

      // HTTP/SSE parity with STDIO's `onprocesscrash`: wire `onclose` +
      // `onerror` on the SDK Transport so we detect watchtower-driven
      // backend restarts BEFORE the next request trips PR #13/#16's
      // recovery cascade. Idle pool entries that sit dead because no
      // request hit them are the failure mode this closes.
      //
      // Two guards keep these handlers from firing spurious "backend
      // drop" noise:
      //   - `closing`: the SDK may invoke `onclose` after WE tore the
      //     transport down (normal `cleanup()`, or the connect-failure
      //     cleanup in the catch below). An intentional close is not a
      //     drop, so suppress it.
      //   - `connectedAt === undefined`: a transport that never finished
      //     `initialize` isn't an established connection that "dropped" —
      //     it's a connect-time failure, already surfaced by the
      //     connect-attempt log in the catch (with the unwrapped cause).
      //     Firing the drop path here would double-log it and invalidate
      //     a pool entry that doesn't exist yet.
      const isHttpTransport =
        transport instanceof SSEClientTransport ||
        transport instanceof StreamableHTTPClientTransport;
      if (isHttpTransport) {
        const previousOnClose = transport.onclose;
        transport.onclose = () => {
          // Chain to any SDK-internal handler first so the SDK can do
          // its own bookkeeping (Client.connect() may register one).
          try {
            previousOnClose?.();
          } catch (chainError) {
            logger.warn(
              `Chained onclose handler threw for server ${serverParams.name} (${serverParams.uuid}):`,
              chainError,
            );
          }
          if (closing || connectedAt === undefined) {
            return;
          }
          const age = formatConnectionAge(connectedAt);
          logger.info(
            `Transport closed unexpectedly for server ${serverParams.name} (${serverParams.uuid}) — ${age}`,
          );
          metamcpLogStore.record({
            category: "connection",
            serverName: serverParams.name,
            serverUuid: serverParams.uuid,
            level: "warn",
            message: `Transport closed unexpectedly (backend drop, ${age})`,
          });
          if (onTransportDrop) {
            try {
              onTransportDrop("close");
            } catch (cbError) {
              logger.warn(
                `onTransportDrop(close) threw for server ${serverParams.name} (${serverParams.uuid}):`,
                cbError,
              );
            }
          }
        };

        const previousOnError = transport.onerror;
        transport.onerror = (transportError: Error) => {
          try {
            previousOnError?.(transportError);
          } catch (chainError) {
            logger.warn(
              `Chained onerror handler threw for server ${serverParams.name} (${serverParams.uuid}):`,
              chainError,
            );
          }
          if (closing || connectedAt === undefined) {
            return;
          }
          const age = formatConnectionAge(connectedAt);
          const detail = describeConnectError(transportError);
          logger.warn(
            `Transport error for server ${serverParams.name} (${serverParams.uuid}) — ${detail} (${age}):`,
            transportError,
          );
          metamcpLogStore.record({
            category: "connection",
            serverName: serverParams.name,
            serverUuid: serverParams.uuid,
            level: "warn",
            message: `Transport error (backend drop, ${detail}, ${age})`,
            error: transportError,
          });
          if (onTransportDrop) {
            try {
              onTransportDrop("error", transportError);
            } catch (cbError) {
              logger.warn(
                `onTransportDrop(error) threw for server ${serverParams.name} (${serverParams.uuid}):`,
                cbError,
              );
            }
          }
        };
      }

      await client.connect(transport);
      // Handshake complete — from here a transport close/error is a real
      // drop of an established connection, not a connect-time failure.
      connectedAt = Date.now();

      metamcpLogStore.record({
        category: "connection",
        serverName: serverParams.name,
        serverUuid: serverParams.uuid,
        level: "info",
        message:
          count > 0 ? `Connected after ${count + 1} attempts` : "Connected",
      });

      // Subscriber set for upstream `tools/list_changed` fan-out. Created
      // BEFORE the notification handler is registered so the handler can
      // close over a stable reference without TDZ risk.
      const listChangedSubscribers = new Set<ListChangedSubscriber>();

      // Register a notification handler that fans `notifications/tools/list_changed`
      // out to every subscriber attached by the proxy/pool layer. Subscribers
      // that throw must NOT prevent siblings from running — they're independent
      // upstream `Server` instances and one rejection shouldn't strand the others.
      client.setNotificationHandler(
        ToolListChangedNotificationSchema,
        async () => {
          for (const subscriber of listChangedSubscribers) {
            try {
              await subscriber();
            } catch (subscriberError) {
              logger.warn(
                `list_changed subscriber threw for server ${serverParams.name} (${serverParams.uuid}):`,
                subscriberError,
              );
            }
          }
        },
      );

      const capturedTransport = transport;
      const capturedClient = client;
      return {
        client,
        cleanup: async () => {
          // Mark closing BEFORE we tear the transport down so any
          // `onclose` the SDK fires synchronously during `transport.close()`
          // sees the flag and suppresses the drop callback. Without this,
          // every normal session shutdown would spuriously trigger the
          // recovery cascade.
          closing = true;
          // Clear subscribers first so any late `list_changed` arrival
          // during transport teardown can't trigger fan-out against a
          // half-closed proxy server.
          listChangedSubscribers.clear();
          await capturedTransport.close();
          await capturedClient.close();
        },
        onProcessCrash: (exitCode, signal) => {
          logger.warn(
            `Process crash detected for server ${serverParams.name} (${serverParams.uuid}): code=${exitCode}, signal=${signal}`,
          );

          // Notify the pool about the crash
          if (onProcessCrash) {
            onProcessCrash(exitCode, signal);
          }
        },
        onTransportDrop: (reason, dropError) => {
          logger.warn(
            `Transport drop detected for server ${serverParams.name} (${serverParams.uuid}): reason=${reason}`,
            dropError,
          );
          if (onTransportDrop) {
            onTransportDrop(reason, dropError);
          }
        },
        listChangedSubscribers,
      };
    } catch (error) {
      // Set the closing guard BEFORE the cleanup close below so an
      // intentional teardown of a transport that DID establish (a throw
      // after `connectedAt` was set) isn't logged as an unexpected drop.
      // The connectedAt guard on the handlers covers the more common
      // never-established case. Fixes the connect-failure cleanup that
      // used to close without any guard and logged its own close as a
      // "backend drop" twice per attempt.
      closing = true;

      const brokerError = isM365BrokerError(error) ? error : undefined;
      const nonRetryableBroker =
        brokerError !== undefined &&
        NON_RETRYABLE_M365_BROKER_CODES.has(brokerError.code);

      if (nonRetryableBroker) {
        // brokerError is narrowed non-undefined by nonRetryableBroker.
        const deterministicError = brokerError as M365BrokerError;
        // A DETERMINISTIC per-user identity state, not a backend fault.
        // Retrying can never resolve it and only produces the
        // "Connect attempt N/N failed" storm the operator saw, so
        // short-circuit after one attempt. Latch the error into the
        // request-scoped sink: the outer tools/call handler drains it and
        // answers the consumer with the enrollment prompt — the same
        // surface the warm tool-call path already presents. See
        // recordConnectBrokerFailure + m365/broker-error-result.ts.
        recordConnectBrokerFailure({
          serverName: serverParams.name,
          error: deterministicError,
        });
        metamcpLogStore.record({
          category: "connection",
          serverName: serverParams.name,
          serverUuid: serverParams.uuid,
          level: "info",
          message: `M365 enrollment required for the connecting user (${deterministicError.code}) — non-retryable; delivering enrollment prompt to caller`,
        });
      } else if (brokerError) {
        // mint_failed: a TRANSIENT operational failure inside mint-service
        // (network error reaching the token endpoint, or a 5xx / non-grant
        // response). Falls through to the normal retry-with-backoff below
        // like any other connect failure — see
        // NON_RETRYABLE_M365_BROKER_CODES's doc comment for why this code
        // is excluded from the short-circuit. Logged with the typed
        // message (not describeConnectError, which is for untyped
        // network/undici throws) so an operator sees the actionable
        // "try again shortly" text, not a bare stack.
        metamcpLogStore.record({
          category: "connection",
          serverName: serverParams.name,
          serverUuid: serverParams.uuid,
          level: "error",
          message: `Connect attempt ${count + 1}/${maxAttempts} failed — M365 token mint failed (mint_failed): ${brokerError.message}`,
          error: brokerError,
        });
      } else {
        // Unwrap undici's nested `.cause` so the log names the actionable
        // leaf (connect ECONNREFUSED 172.18.0.13:3000) rather than the
        // generic "fetch failed" / "terminated" wrapper.
        metamcpLogStore.record({
          category: "connection",
          serverName: serverParams.name,
          serverUuid: serverParams.uuid,
          level: "error",
          message: `Connect attempt ${count + 1}/${maxAttempts} failed — ${describeConnectError(error)}`,
          error,
        });
      }

      // CRITICAL FIX: Clean up transport/process on connection failure
      // This prevents orphaned processes from accumulating
      if (transport) {
        try {
          await transport.close();
          console.log(
            `Cleaned up transport for failed connection to ${serverParams.name} (${serverParams.uuid})`,
          );
        } catch (cleanupError) {
          console.error(
            `Error cleaning up transport for ${serverParams.name} (${serverParams.uuid}):`,
            cleanupError,
          );
        }
      }
      if (client) {
        try {
          await client.close();
        } catch {
          // Client may not be fully initialized, ignore.
        }
      }

      // Non-retryable: one attempt only. The pool sees `undefined`
      // exactly as it does for any failed connect (unchanged contract);
      // the latched enrollment prompt is what reaches the consumer.
      if (nonRetryableBroker) {
        return undefined;
      }

      count++;
      retry = count < maxAttempts;

      if (brokerError && !retry) {
        // mint_failed exhausted every retry. Latch it (same sink the
        // non-retryable branch uses) so the consumer still gets the typed
        // "try again shortly" enrollment-adjacent message via
        // buildM365BrokerErrorResult instead of a generic connect
        // failure / "Unknown tool" — the informative payload shouldn't be
        // thrown away just because this code happened to be retryable.
        recordConnectBrokerFailure({
          serverName: serverParams.name,
          error: brokerError,
        });
      }

      if (retry) {
        // Exponential backoff with jitter. See
        // `computeReconnectBackoffMs` doc comment for the schedule.
        // `count - 1` because `count` was just incremented past the
        // failed attempt — the next sleep should reflect the NEXT
        // attempt's index (0-based: first retry waits 1s, not 2s).
        const delay = computeReconnectBackoffMs(count - 1);
        logger.info(
          `Reconnect attempt ${count + 1}/${maxAttempts} for server ${serverParams.name} (${serverParams.uuid}) in ${Math.round(delay)}ms`,
        );
        await sleep(delay);
      }
    }
  }

  return undefined;
};
