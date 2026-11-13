"use client";

import { EndpointWithNamespace } from "@repo/zod-types";
import { useMemo, useState } from "react";
import { toast } from "sonner";

import { InstallSnippetPanel } from "@/components/install-snippet-panel";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useTranslations } from "@/hooks/useTranslations";
import { getAppUrl } from "@/lib/env";
import { buildInstallSnippets } from "@/lib/install-snippets";

type Translate = (
  key: string,
  params?: Record<string, string | number>,
) => string;

// The clipboard is missing outside a secure context and can be refused by
// the browser, so a failed copy says so instead of failing in silence.
function copyToClipboard(text: string, t: Translate) {
  if (!navigator.clipboard) {
    toast.error(t("inspector:installClient.copyFailed"));
    return;
  }
  navigator.clipboard.writeText(text).then(
    () => toast.success(t("inspector:installClient.copied")),
    () => toast.error(t("inspector:installClient.copyFailed")),
  );
}

function InstallClientBody({
  endpoint,
  t,
}: {
  endpoint: EndpointWithNamespace;
  t: Translate;
}) {
  const [nameText, setNameText] = useState(endpoint.name);
  // A cleared name falls back to the endpoint's own rather than to "mcp".
  const serverName = nameText.trim() === "" ? undefined : nameText;

  const result = useMemo(
    () =>
      buildInstallSnippets({
        appUrl: getAppUrl(),
        endpointName: endpoint.name,
        serverName,
        enableApiKeyAuth: endpoint.enable_api_key_auth,
        enableOauth: endpoint.enable_oauth,
        requireScopedApiKey: endpoint.require_scoped_api_key,
      }),
    [
      endpoint.name,
      endpoint.enable_api_key_auth,
      endpoint.enable_oauth,
      endpoint.require_scoped_api_key,
      serverName,
    ],
  );

  return (
    <>
      <DialogHeader>
        <DialogTitle>
          {t("inspector:installClient.title", { name: endpoint.name })}
        </DialogTitle>
        <DialogDescription>
          {t("inspector:installClient.description")}
        </DialogDescription>
      </DialogHeader>
      <div className="space-y-4 min-w-0">
        <div className="space-y-1">
          <Label htmlFor="install-client-name">
            {t("inspector:installClient.nameLabel")}
          </Label>
          <Input
            id="install-client-name"
            value={nameText}
            onChange={(event) => setNameText(event.target.value)}
            autoComplete="off"
            spellCheck={false}
          />
          {result.ok && result.serverName !== nameText ? (
            <p className="text-xs text-muted-foreground">
              {t("inspector:installClient.nameUsedAs", {
                name: result.serverName,
              })}
            </p>
          ) : null}
        </div>
        {result.ok ? (
          <InstallSnippetPanel
            snippets={result}
            t={t}
            onCopy={(text) => copyToClipboard(text, t)}
          />
        ) : (
          <p className="text-sm text-destructive">
            {t("inspector:installClient.invalidUrl")}
          </p>
        )}
      </div>
    </>
  );
}

/**
 * "Add to client" for one endpoint. Radix unmounts the content when the
 * dialog closes, so the body's state (the editable server name) starts fresh
 * on every open. The parent keeps the last endpoint after a close so the
 * content does not lose its title mid-animation.
 */
export function InstallClientDialog({
  endpoint,
  isOpen,
  onClose,
}: {
  endpoint: EndpointWithNamespace | null;
  isOpen: boolean;
  onClose: () => void;
}) {
  const { t } = useTranslations();
  if (!endpoint) return null;
  return (
    <Dialog
      open={isOpen}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-3xl">
        <InstallClientBody endpoint={endpoint} t={t} />
      </DialogContent>
    </Dialog>
  );
}
