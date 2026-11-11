import { Check, RefreshCw, X } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { TableCell, TableRow } from "@/components/ui/table";
import {
  approvalStatusKey,
  approvalStatusVariant,
  isDecidableClient,
  registrationSourceKey,
} from "@/lib/oauth-client-approval";

type Translate = (
  key: string,
  params?: Record<string, string | number>,
) => string;

/**
 * A client's approval status (migration 0042), with its provenance beneath it
 * when known. Shared by the OAuth Clients page and the Access dashboard, so a
 * pending or rejected client never reads as ordinary approved access.
 */
export function OAuthClientStatusBadge({
  status,
  source,
  t,
}: {
  status: string | null | undefined;
  /** Omit to show the status alone (the Access token list has no provenance). */
  source?: string | null;
  t: Translate;
}) {
  return (
    <div className="flex flex-col gap-1">
      <Badge
        variant={approvalStatusVariant(status)}
        data-status={status ?? "missing"}
      >
        {t(approvalStatusKey(status))}
      </Badge>
      {source !== undefined ? (
        <span className="text-xs text-muted-foreground">
          {t(registrationSourceKey(source))}
        </span>
      ) : null}
    </div>
  );
}

/**
 * The address a self-registration came from, or "unavailable" when there is
 * none (admin-created and legacy rows, or an audit write that did not land).
 * Labelled as an observed address: it identifies no person and says nothing
 * about whether the client is safe.
 */
export function RegisteredFrom({
  ip,
  t,
}: {
  ip: string | null | undefined;
  t: Translate;
}) {
  if (!ip) {
    return (
      <span className="text-xs text-muted-foreground italic">
        {t("oauth-clients:registeredFromUnavailable")}
      </span>
    );
  }
  return (
    <code
      className="text-xs font-mono break-all"
      title={t("oauth-clients:registeredFromHelp")}
    >
      {ip}
    </code>
  );
}

/**
 * Approve and Reject for a pending self-registered client; nothing for any
 * other row. Both buttons are disabled while any decision on the page is in
 * flight, and the one running says so.
 */
export function OAuthClientDecisionActions({
  client,
  deciding,
  onApprove,
  onReject,
  t,
}: {
  client: {
    client_id: string;
    registration_source?: string | null;
    approval_status?: string | null;
  };
  /** The decision in flight on this page, if any. */
  deciding: { clientId: string; kind: "approve" | "reject" } | null;
  onApprove: (clientId: string) => void;
  onReject: (clientId: string) => void;
  t: Translate;
}) {
  if (!isDecidableClient(client)) return null;
  const busy = deciding !== null;
  const here = deciding?.clientId === client.client_id ? deciding.kind : null;
  return (
    <div className="flex gap-1">
      <Button
        size="sm"
        variant="outline"
        disabled={busy}
        aria-busy={here === "approve"}
        onClick={() => onApprove(client.client_id)}
      >
        <Check className="h-4 w-4 mr-1" />
        {here === "approve"
          ? t("oauth-clients:approving")
          : t("oauth-clients:approve")}
      </Button>
      <Button
        size="sm"
        variant="outline"
        disabled={busy}
        aria-busy={here === "reject"}
        onClick={() => onReject(client.client_id)}
      >
        <X className="h-4 w-4 mr-1" />
        {here === "reject"
          ? t("oauth-clients:rejecting")
          : t("oauth-clients:reject")}
      </Button>
    </div>
  );
}

/**
 * The list's loading, failure and empty states as a single table row. A
 * failed load says so and offers a retry, rather than looking like an empty
 * inventory.
 */
export function OAuthClientsListState({
  colSpan,
  isLoading,
  isError,
  errorMessage,
  isEmpty,
  onRetry,
  t,
}: {
  colSpan: number;
  isLoading: boolean;
  isError: boolean;
  errorMessage?: string | null;
  isEmpty: boolean;
  onRetry: () => void;
  t: Translate;
}) {
  if (isLoading) {
    return (
      <TableRow>
        <TableCell colSpan={colSpan} className="text-center py-12">
          <p className="text-muted-foreground">{t("oauth-clients:loading")}</p>
        </TableCell>
      </TableRow>
    );
  }
  if (isError) {
    return (
      <TableRow>
        <TableCell colSpan={colSpan} className="text-center py-12 space-y-2">
          <p className="text-destructive" role="alert">
            {t("oauth-clients:listLoadError")}
            {errorMessage ? `: ${errorMessage}` : ""}
          </p>
          <Button variant="outline" size="sm" onClick={onRetry}>
            <RefreshCw className="h-4 w-4 mr-2" />
            {t("common:refresh")}
          </Button>
        </TableCell>
      </TableRow>
    );
  }
  if (isEmpty) {
    return (
      <TableRow>
        <TableCell colSpan={colSpan} className="text-center py-12">
          <p className="text-muted-foreground">
            {t("oauth-clients:noClients")}
          </p>
          <p className="text-sm text-muted-foreground">
            {t("oauth-clients:noClientsDescription")}
          </p>
        </TableCell>
      </TableRow>
    );
  }
  return null;
}
