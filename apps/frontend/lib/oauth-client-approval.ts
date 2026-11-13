/**
 * Presentation rules for OAuth client approval (backend migration 0042),
 * shared by the OAuth Clients page and the read-only Access dashboard so the
 * two never disagree about what a status means.
 *
 * The backend is the boundary: these helpers only decide what to show and
 * which buttons to offer. The server re-checks every decision.
 */

export type BadgeVariant = "default" | "secondary" | "destructive" | "outline";

/** Translation key for a stored approval status; anything unexpected is "unknown". */
export function approvalStatusKey(status: string | null | undefined): string {
  switch (status) {
    case "approved":
      return "oauth-clients:statusApproved";
    case "pending":
      return "oauth-clients:statusPending";
    case "rejected":
      return "oauth-clients:statusRejected";
    default:
      return "oauth-clients:statusUnknown";
  }
}

/**
 * Badge style for a status. Pending is the state that needs an administrator,
 * so it is the prominent one; rejected and unknown read as refusals.
 */
export function approvalStatusVariant(
  status: string | null | undefined,
): BadgeVariant {
  switch (status) {
    case "approved":
      return "secondary";
    case "pending":
      return "default";
    default:
      return "destructive";
  }
}

/** Translation key for a client's provenance (`registration_source`). */
export function registrationSourceKey(
  source: string | null | undefined,
): string {
  switch (source) {
    case "dcr":
      return "oauth-clients:sourceDcr";
    case "admin":
      return "oauth-clients:sourceAdmin";
    case "cimd":
      return "oauth-clients:sourceCimd";
    default:
      return "oauth-clients:sourceLegacy";
  }
}

/**
 * Whether the page offers Approve and Reject for a row: only a self-registered
 * client that is still pending. The server enforces the same rule with a
 * conditional update, so a stale list can at worst offer a button that
 * answers "no longer pending".
 */
export function isDecidableClient(client: {
  registration_source?: string | null;
  approval_status?: string | null;
}): boolean {
  return (
    client.registration_source === "dcr" && client.approval_status === "pending"
  );
}

/**
 * Whether a failed decision means the list was out of date (the row is gone
 * or was already decided), as opposed to a fault worth reporting as such.
 */
export function isStaleDecisionError(error: unknown): boolean {
  const code = (error as { data?: { code?: unknown } } | null)?.data?.code;
  return code === "CONFLICT" || code === "NOT_FOUND";
}

export type DecisionKind = "approve" | "reject";

/**
 * Re-fetch both views that show client approval: the OAuth Clients page's
 * inventory and the Access dashboard's token list (whose rows carry the
 * issuing client's status). The Access dashboard's own client tab reads the
 * same `oauthClients.list` query, so one invalidation covers it.
 */
export function refreshClientInventories(utils: {
  frontend: {
    oauthClients: { list: { invalidate: () => unknown } };
    oauthTokens: { list: { invalidate: () => unknown } };
  };
}): void {
  void utils.frontend.oauthClients.list.invalidate();
  void utils.frontend.oauthTokens.list.invalidate();
}

/**
 * The callbacks for an approve or reject mutation, built outside React so
 * they can be tested directly. Every outcome refreshes the client inventories
 * (a success changed a row; a stale result means the list was wrong), and
 * `done` always runs so the buttons are re-enabled.
 */
export function decisionCallbacks(params: {
  kind: DecisionKind;
  t: (key: string, params?: Record<string, string | number>) => string;
  notifySuccess: (message: string) => void;
  notifyError: (message: string) => void;
  refresh: () => void;
  done: () => void;
}) {
  const { kind, t, notifySuccess, notifyError, refresh, done } = params;
  return {
    onSuccess: () => {
      notifySuccess(
        t(
          kind === "approve"
            ? "oauth-clients:clientApproved"
            : "oauth-clients:clientRejected",
        ),
      );
      refresh();
    },
    onError: (error: { message?: string; data?: unknown }) => {
      if (isStaleDecisionError(error)) {
        notifyError(
          `${t("oauth-clients:decisionStale")} ${error.message ?? ""}`.trim(),
        );
      } else {
        notifyError(
          `${t("oauth-clients:decisionError")}: ${error.message ?? ""}`,
        );
      }
      refresh();
    },
    onSettled: () => {
      done();
    },
  };
}
