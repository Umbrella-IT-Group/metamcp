"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { useTranslations } from "@/hooks/useTranslations";
import { authClient } from "@/lib/auth-client";
import { getLocalizedPath } from "@/lib/i18n";
import { trpc } from "@/lib/trpc";

/**
 * The Access panel on the endpoint edit dialog (migration 0033).
 *
 * NOT A FORM FIELD, deliberately. Every other control in that dialog writes
 * into `editEndpointFormSchema` and lands on Save; this one calls
 * `accessGroups.setEndpointRestricted` the moment it is flipped. The reason is
 * the same one that gave the gate its own tRPC procedure and its own audit
 * event: turning an endpoint's authorization gate on is a security act, and it
 * should not be able to ride along in a Save that the operator thought was a
 * rename — nor be silently discarded when they hit Cancel.
 *
 * Read AND write here are `adminProcedure`, so this renders nothing at all for
 * a member. That is presentation only; the backend is the boundary.
 */
export function EndpointAccessSection({
  endpointUuid,
}: {
  endpointUuid: string;
}) {
  const { t, locale } = useTranslations();
  const utils = trpc.useUtils();

  // Fail closed: isAdmin starts false and a failed session lookup leaves it
  // false, so an error hides the control rather than showing a dead one. Same
  // idiom as the sidebar's admin-only entries and the OAuth clients page.
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

  const { data: accessResponse, isLoading } =
    trpc.frontend.accessGroups.getEndpointAccess.useQuery(
      { endpoint_uuid: endpointUuid },
      { enabled: isAdmin && Boolean(endpointUuid) },
    );

  const setRestrictedMutation =
    trpc.frontend.accessGroups.setEndpointRestricted.useMutation({
      onSuccess: (data) => {
        if (data.success) {
          utils.frontend.accessGroups.getEndpointAccess.invalidate({
            endpoint_uuid: endpointUuid,
          });
          // `endpoints.list` is deliberately NOT invalidated: it is
          // member-visible and no longer carries `restricted` at all, so it
          // cannot go stale on this flip. The two admin reads that do carry the
          // bit are the ones refreshed here and above.
          utils.frontend.accessGroups.listEndpoints.invalidate();
          utils.frontend.accessGroups.get.invalidate();
          toast.success(t("access:groups.restrictedUpdated"));
        } else {
          toast.error(
            data.message || t("access:groups.restrictedUpdateFailed"),
          );
        }
      },
      onError: (error) => {
        toast.error(
          t("access:groups.restrictedUpdateFailed") + ": " + error.message,
        );
      },
    });

  if (!isAdmin) return null;

  const access = accessResponse?.success ? accessResponse.data : undefined;
  const restricted = access?.restricted ?? false;
  const groups = access?.groups ?? [];

  // What the switch ACTUALLY does on this endpoint, which `restricted` alone
  // cannot say. The gate governs OAuth callers only:
  //
  //   enable_oauth off        -> the switch is inert; no caller reaches this
  //                             endpoint through the gate at all.
  //   + enable_api_key_auth   -> it narrows the OAuth half only; every API-key
  //                             holder still passes, by design.
  //
  // Reporting "only administrators can reach it" in either case would be
  // false, and false in the reassuring direction, which is the worst kind on a
  // security panel.
  const gateIsInert =
    restricted && access !== undefined && !access.enable_oauth;
  const apiKeysStillPass =
    restricted && access !== undefined && access.enable_api_key_auth;
  const gateFullyGoverns =
    restricted &&
    access !== undefined &&
    access.enable_oauth &&
    !access.enable_api_key_auth;

  return (
    <div className="space-y-4 border-t pt-4">
      <h4 className="text-sm font-medium">{t("access:groups.sectionTitle")}</h4>

      <div className="flex items-center justify-between">
        <div className="space-y-0.5">
          <label className="text-sm font-medium">
            {t("access:groups.restrictedLabel")}
          </label>
          <p className="text-xs text-muted-foreground">
            {t("access:groups.restrictedDescription")}
          </p>
        </div>
        <Switch
          checked={restricted}
          onCheckedChange={(checked) =>
            setRestrictedMutation.mutate({
              endpoint_uuid: endpointUuid,
              restricted: checked,
            })
          }
          disabled={isLoading || setRestrictedMutation.isPending}
        />
      </div>

      {gateIsInert && (
        // The switch is on but this endpoint accepts no OAuth callers, so it
        // gates nobody. Said outright, because a switch that reads as "on" and
        // does nothing is the most misleading state this panel can render.
        <div className="p-3 bg-yellow-50 dark:bg-yellow-950/20 border border-yellow-200 dark:border-yellow-800/30 rounded-md">
          <p className="text-sm text-yellow-800 dark:text-yellow-200">
            {t("access:groups.noOauthWarning")}
          </p>
        </div>
      )}

      {gateFullyGoverns && groups.length === 0 && (
        // The lockout warning, now correctly narrowed. It only holds when OAuth
        // is the ONLY way in: a restricted endpoint with no group mapped then
        // admits administrators and nobody else, which is legitimate but almost
        // never intended, and the person who set it is usually an administrator
        // so they will not notice by using it.
        <div className="p-3 bg-yellow-50 dark:bg-yellow-950/20 border border-yellow-200 dark:border-yellow-800/30 rounded-md">
          <p className="text-sm text-yellow-800 dark:text-yellow-200">
            {t("access:groups.noGroupsWarning")}
          </p>
        </div>
      )}

      {apiKeysStillPass && access?.enable_oauth && (
        // Not a warning: this is the designed scope boundary. But an operator
        // reading "restricted" on an endpoint that also accepts API keys should
        // not have to infer that every key holder still gets in.
        <p className="text-xs text-muted-foreground">
          {t("access:groups.apiKeysStillPass")}
        </p>
      )}

      <div className="space-y-2">
        <p className="text-xs text-muted-foreground">
          {t("access:groups.mappedGroupsLabel")}
        </p>
        {groups.length === 0 ? (
          <p className="text-xs text-muted-foreground">
            {t("access:groups.noMappedGroups")}
          </p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {groups.map((group) => (
              <Badge key={group.uuid} variant="outline">
                {group.name}
                <span className="ml-1 text-muted-foreground">
                  {t("access:groups.memberCount", {
                    count: group.member_count,
                  })}
                </span>
              </Badge>
            ))}
          </div>
        )}
        <p className="text-xs text-muted-foreground">
          {/* Mapping is done on the groups screen, not here: a group spans
              several endpoints, so editing the membership from one endpoint's
              dialog would hide what else the change affects. */}
          <Link
            href={getLocalizedPath("/access-groups", locale)}
            className="underline"
          >
            {t("access:groups.manageLink")}
          </Link>
        </p>
      </div>

      <p className="text-xs text-muted-foreground">
        {t("access:groups.apiKeyNote")}
      </p>
    </div>
  );
}
