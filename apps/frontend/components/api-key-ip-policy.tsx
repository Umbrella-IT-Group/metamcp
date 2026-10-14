"use client";

import { Globe } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import {
  cidrsToText,
  describeKeyPolicy,
  type IpPolicyMode,
  keyPolicyRequest,
  type KeyPolicySelection,
  parseCidrText,
  selectionForKey,
} from "@/lib/api-key-ip-policy-form";
import { trpc } from "@/lib/trpc";

/**
 * API-key IP allowlist controls for the API keys admin section (migration
 * 0040). Rendered only inside the page's `isAdmin` block, and every read and
 * write behind them is `adminProcedure`, so this is presentation, not the
 * boundary. English copy, like the rest of that admin section.
 *
 * Saving is explicit (a Save button), never on change: a policy decides which
 * networks may use a credential, and a half-typed list must not become one.
 * The server validates every entry and refuses enforce with an empty list; its
 * message is shown as the error toast.
 */

const MODE_HELP: Record<IpPolicyMode, string> = {
  off: "Off: nothing is checked.",
  audit:
    "Audit: requests are served; addresses outside the list are recorded as would-deny.",
  enforce:
    "Enforce: requests from addresses outside the list are refused with 403.",
};

/** The policy cell in the admin key list: badge plus last-used address. */
export function ApiKeyIpPolicyCell({
  allowedCidrs,
  mode,
  lastUsedIp,
}: {
  allowedCidrs: string[] | null;
  mode: IpPolicyMode;
  lastUsedIp: string | null;
}) {
  const { label, tone } = describeKeyPolicy(allowedCidrs, mode);
  return (
    <div className="flex flex-col gap-1">
      <Badge variant={tone}>{label}</Badge>
      <span className="text-xs text-muted-foreground font-mono">
        {lastUsedIp ?? "no address yet"}
      </span>
    </div>
  );
}

/** The global policy, applied to every key with no list of its own. */
export function GlobalIpPolicyCard() {
  const utils = trpc.useUtils();
  const { data } = trpc.frontend.apiKeys.getGlobalIpPolicy.useQuery();
  const [mode, setMode] = useState<IpPolicyMode>("off");
  const [text, setText] = useState("");

  useEffect(() => {
    if (data) {
      setMode(data.mode);
      setText(cidrsToText(data.allowed_cidrs));
    }
  }, [data]);

  const saveMutation = trpc.frontend.apiKeys.setGlobalIpPolicy.useMutation({
    onSuccess: (saved) => {
      setMode(saved.mode);
      setText(cidrsToText(saved.allowed_cidrs));
      utils.frontend.apiKeys.getGlobalIpPolicy.invalidate();
      toast.success("Global IP policy saved");
    },
    onError: (error) => {
      toast.error(error.message);
    },
  });

  return (
    <div className="rounded-md border p-4 space-y-3">
      <div className="flex items-center gap-2">
        <Globe className="h-4 w-4 text-primary" />
        <h3 className="font-medium">Global IP policy</h3>
        <Badge variant="outline">{data?.mode ?? "off"}</Badge>
      </div>
      <p className="text-sm text-muted-foreground">
        Applies to every API key that has no list of its own. OAuth sign-ins are
        never affected. {MODE_HELP[mode]}
      </p>
      {data?.kill_switch_active && (
        <p className="text-sm text-destructive">
          API_KEY_IP_POLICY_DISABLED is set on the gateway: no IP policy is
          evaluated until it is unset.
        </p>
      )}
      {data?.problems?.map((problem) => (
        <p key={problem} className="text-sm text-destructive">
          {problem}
        </p>
      ))}
      <div className="grid gap-3 md:grid-cols-[1fr_200px]">
        <div className="space-y-1">
          <Label htmlFor="global-ip-cidrs">Allowed CIDRs, one per line</Label>
          <Textarea
            id="global-ip-cidrs"
            value={text}
            onChange={(event) => setText(event.target.value)}
            placeholder="203.0.113.0/24"
            className="font-mono"
          />
        </div>
        <div className="space-y-1">
          <Label>Mode</Label>
          <Select
            value={mode}
            onValueChange={(value) => setMode(value as IpPolicyMode)}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="off">Off</SelectItem>
              <SelectItem value="audit">Audit</SelectItem>
              <SelectItem value="enforce">Enforce</SelectItem>
            </SelectContent>
          </Select>
          <Button
            className="w-full mt-2"
            disabled={saveMutation.isPending}
            onClick={() =>
              saveMutation.mutate({ mode, allowed_cidrs: parseCidrText(text) })
            }
          >
            Save
          </Button>
        </div>
      </div>
    </div>
  );
}

/** Per-key editor: an icon button that opens a dialog. */
export function ApiKeyIpPolicyButton({
  apiKey,
  onSaved,
}: {
  apiKey: {
    uuid: string;
    name: string;
    allowed_cidrs: string[] | null;
    ip_policy_mode: IpPolicyMode;
    last_used_ip: string | null;
  };
  onSaved: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [selection, setSelection] = useState<KeyPolicySelection>("global");
  const [text, setText] = useState("");

  const openDialog = () => {
    setSelection(selectionForKey(apiKey.allowed_cidrs, apiKey.ip_policy_mode));
    setText(cidrsToText(apiKey.allowed_cidrs));
    setOpen(true);
  };

  const saveMutation = trpc.frontend.apiKeys.setIpPolicy.useMutation({
    onSuccess: () => {
      toast.success(`IP policy saved for ${apiKey.name}`);
      setOpen(false);
      onSaved();
    },
    onError: (error) => {
      toast.error(error.message);
    },
  });

  return (
    <>
      <Button
        size="sm"
        variant="ghost"
        onClick={openDialog}
        title="IP policy"
        aria-label={`IP policy for ${apiKey.name}`}
      >
        <Globe className="h-4 w-4" />
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>IP policy: {apiKey.name}</DialogTitle>
            <DialogDescription>
              Last used from{" "}
              <span className="font-mono">
                {apiKey.last_used_ip ?? "no address yet"}
              </span>
              . To exempt a caller with no fixed address, such as CI runners,
              list both 0.0.0.0/0 and ::/0.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label>Policy</Label>
              <Select
                value={selection}
                onValueChange={(value) =>
                  setSelection(value as KeyPolicySelection)
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="global">
                    Follow the global policy
                  </SelectItem>
                  <SelectItem value="off">Own list, off</SelectItem>
                  <SelectItem value="audit">Own list, audit</SelectItem>
                  <SelectItem value="enforce">Own list, enforce</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {selection === "global"
                  ? "This key uses the global list and mode."
                  : MODE_HELP[selection]}
              </p>
            </div>
            {selection !== "global" && (
              <div className="space-y-1">
                <Label htmlFor={`ip-cidrs-${apiKey.uuid}`}>
                  Allowed CIDRs, one per line
                </Label>
                <Textarea
                  id={`ip-cidrs-${apiKey.uuid}`}
                  value={text}
                  onChange={(event) => setText(event.target.value)}
                  placeholder="203.0.113.0/24"
                  className="font-mono"
                />
              </div>
            )}
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button
                disabled={saveMutation.isPending}
                onClick={() =>
                  saveMutation.mutate(
                    keyPolicyRequest(apiKey.uuid, selection, text),
                  )
                }
              >
                Save
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
