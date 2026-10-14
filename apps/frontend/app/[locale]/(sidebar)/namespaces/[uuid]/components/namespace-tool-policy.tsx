"use client";

import type { NamespaceToolPolicy } from "@repo/zod-types";
import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Switch } from "@/components/ui/switch";
import { useTranslations } from "@/hooks/useTranslations";
import { authClient } from "@/lib/auth-client";
import { trpc } from "@/lib/trpc";

/**
 * The namespace's tool policy (migration 0040), shown to everyone who can see
 * the namespace and switchable by an administrator.
 *
 * `allow_all` serves every tool that has no row in Tools Management (the
 * original behaviour); `allowlist` serves only the tools switched on there.
 *
 * NOT A FORM FIELD, for the reason the endpoint Access panel gives: changing
 * which tools a namespace serves is a security act with its own admin-gated
 * procedure and audit event (`namespace.tool_policy`), so it must not ride
 * along in the Edit dialog's Save. Turning the allowlist ON asks first,
 * because it hides tools from live consumers at once; turning it off (the
 * rollback) does not.
 *
 * The switch renders only for an administrator. That is presentation only;
 * `namespaces.setToolPolicy` is adminProcedure, and the backend is the
 * boundary.
 */
export function NamespaceToolPolicyRow({
  namespaceUuid,
  namespaceName,
  toolPolicy,
}: {
  namespaceUuid: string;
  namespaceName: string;
  toolPolicy: NamespaceToolPolicy;
}) {
  const { t } = useTranslations();
  const utils = trpc.useUtils();
  const [confirmOpen, setConfirmOpen] = useState(false);

  // Fail closed: isAdmin starts false and a failed session lookup leaves it
  // false, so an error hides the switch rather than showing a dead one. Same
  // idiom as the endpoint Access panel.
  const [isAdmin, setIsAdmin] = useState(false);
  const loadRole = useCallback(() => {
    authClient
      .getSession()
      .then((session) => {
        const role = (session?.data?.user as { role?: string } | undefined)
          ?.role;
        setIsAdmin(role === "admin");
      })
      .catch(() => {
        setIsAdmin(false);
      });
  }, []);
  useEffect(() => {
    loadRole();
  }, [loadRole]);

  const setToolPolicyMutation =
    trpc.frontend.namespaces.setToolPolicy.useMutation({
      onSuccess: (data) => {
        if (data.success) {
          utils.frontend.namespaces.get.invalidate({ uuid: namespaceUuid });
          utils.frontend.namespaces.list.invalidate();
          toast.success(t("namespaces:detail.toolPolicyUpdated"), {
            description: data.message,
          });
          setConfirmOpen(false);
        } else {
          toast.error(t("namespaces:detail.toolPolicyUpdateFailed"), {
            description: data.message,
          });
        }
      },
      onError: (error) => {
        toast.error(t("namespaces:detail.toolPolicyUpdateFailed"), {
          description: error.message,
        });
      },
    });

  const isAllowlist = toolPolicy === "allowlist";

  return (
    <div className="space-y-1">
      <div className="flex justify-between items-center">
        <span className="text-sm font-medium text-muted-foreground">
          {t("namespaces:detail.toolPolicy")}:
        </span>
        <div className="flex items-center gap-3 flex-1 ml-6 justify-end">
          <Badge variant={isAllowlist ? "info" : "neutral"}>
            {isAllowlist
              ? t("namespaces:detail.toolPolicyAllowlist")
              : t("namespaces:detail.toolPolicyAllowAll")}
          </Badge>
          {isAdmin && (
            <Switch
              aria-label={t("namespaces:detail.toolPolicySwitchLabel")}
              checked={isAllowlist}
              disabled={setToolPolicyMutation.isPending}
              onCheckedChange={(checked) => {
                if (checked) {
                  setConfirmOpen(true);
                } else {
                  setToolPolicyMutation.mutate({
                    namespaceUuid,
                    toolPolicy: "allow_all",
                  });
                }
              }}
            />
          )}
        </div>
      </div>
      <p className="text-xs text-muted-foreground text-right">
        {isAllowlist
          ? t("namespaces:detail.toolPolicyAllowlistHelp")
          : t("namespaces:detail.toolPolicyAllowAllHelp")}
      </p>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {t("namespaces:detail.toolPolicyConfirmTitle")}
            </DialogTitle>
            <DialogDescription>
              {t("namespaces:detail.toolPolicyConfirmDescription", {
                name: namespaceName,
              })}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setConfirmOpen(false)}
              disabled={setToolPolicyMutation.isPending}
            >
              {t("namespaces:cancel")}
            </Button>
            <Button
              onClick={() =>
                setToolPolicyMutation.mutate({
                  namespaceUuid,
                  toolPolicy: "allowlist",
                })
              }
              disabled={setToolPolicyMutation.isPending}
            >
              {t("namespaces:detail.toolPolicyConfirm")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
