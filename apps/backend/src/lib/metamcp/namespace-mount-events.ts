import logger from "@/utils/logger";

/**
 * In-process signal that a server's mount status changed in a namespace, from
 * the admin write (`namespaces.updateServerStatus`) to every live proxy of
 * that namespace (`metamcp-proxy.ts` `createServer`).
 *
 * WHAT IT IS FOR. Enforcement does not depend on it: the tool filter reads the
 * mount status on every call (namespace-server-lookup.ts), so a call to a
 * server whose mount was just switched INACTIVE is refused whether or not a
 * proxy heard about it. This signal does the client-facing part. Each live
 * proxy drops the routes it holds to that server, so nothing keeps pointing at
 * a disabled mount, and tells its client `notifications/tools/list_changed`,
 * so the client re-lists instead of offering tools that are now refused (or,
 * after a switch back to ACTIVE, missing tools that are served again).
 *
 * WHAT IT DOES NOT DO. It never tears down a backend connection: a pooled
 * upstream client can serve the same server in another namespace, where its
 * mount may still be ACTIVE. It only reaches proxies in this process; the
 * gateway runs one backend process, and the per-call read above is what holds
 * for anything this signal misses.
 *
 * Synchronous on purpose: `updateServerStatus` calls it after its write
 * commits and before it returns success, so by the time the admin sees the
 * change confirmed every live proxy has dropped its routes. A listener that
 * throws is logged and does not stop the others.
 */
export type NamespaceMountListener = (serverUuid: string) => void;

const listeners = new Map<string, Set<NamespaceMountListener>>();

/**
 * Register a live proxy's listener for one namespace. Returns the function
 * that removes it; the proxy calls that when its session closes.
 */
export function onNamespaceMountChange(
  namespaceUuid: string,
  listener: NamespaceMountListener,
): () => void {
  let set = listeners.get(namespaceUuid);
  if (!set) {
    set = new Set();
    listeners.set(namespaceUuid, set);
  }
  set.add(listener);
  return () => {
    const current = listeners.get(namespaceUuid);
    if (!current) return;
    current.delete(listener);
    if (current.size === 0) listeners.delete(namespaceUuid);
  };
}

/**
 * Tell every live proxy of `namespaceUuid` that `serverUuid`'s mount status
 * changed. Returns how many proxies were told.
 */
export function notifyNamespaceMountChange(
  namespaceUuid: string,
  serverUuid: string,
): number {
  const set = listeners.get(namespaceUuid);
  if (!set) return 0;
  let told = 0;
  // Copy first: a listener may close its proxy and unregister while we walk.
  for (const listener of Array.from(set)) {
    try {
      listener(serverUuid);
      told += 1;
    } catch (error) {
      logger.error(
        `A live session of namespace ${namespaceUuid} failed to drop its routes to server ${serverUuid} after a mount status change; the per-call mount check still refuses that server:`,
        error,
      );
    }
  }
  return told;
}

/** Test seam: how many listeners a namespace holds. */
export function namespaceMountListenerCount(namespaceUuid: string): number {
  return listeners.get(namespaceUuid)?.size ?? 0;
}
