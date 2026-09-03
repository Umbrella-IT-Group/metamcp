"use client";

import { CreateApiKeyFormSchema } from "@repo/zod-types";
import { format } from "date-fns";
import {
  Ban,
  Copy,
  Key,
  Plus,
  RefreshCw,
  RotateCcw,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useTranslations } from "@/hooks/useTranslations";
import { authClient } from "@/lib/auth-client";
import { trpc } from "@/lib/trpc";
import { createTranslatedZodResolver } from "@/lib/zod-resolver";

type CreateApiKeyFormData = z.infer<typeof CreateApiKeyFormSchema>;

export default function ApiKeysPage() {
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  // The mint-time one-time reveal. This is the ONLY place a full key value
  // is ever rendered — `list` returns prefixes only (see the key column
  // below), so a key not copied here is gone and must be re-minted.
  const [newApiKey, setNewApiKey] = useState<string | null>(null);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [apiKeyToDelete, setApiKeyToDelete] = useState<{
    uuid: string;
    name: string;
  } | null>(null);
  const { t } = useTranslations();

  // Current session role. Read from the better-auth session (role is surfaced
  // via user.additionalFields — see apps/backend/src/auth.ts). Members never
  // see the admin cross-user section or the 'everyone' mint option; the
  // backend enforces the same boundary regardless of the UI.
  //
  // roleLoaded gates the create-button header: isAdmin starts false, so
  // without it every ADMIN saw a flash of the false "Only administrators
  // can create API keys." claim while the session fetch was in flight.
  // Until the role genuinely resolves, the header renders a neutral
  // disabled button that claims nothing about the viewer. A FAILED fetch
  // no longer pins that state forever: roleError swaps the neutral
  // spinner-button for an explicit error line + retry, so a transient
  // auth-endpoint blip doesn't leave an admin staring at a permanently
  // "loading" create button. Still fail-closed throughout — no admin
  // surface renders until the role actually resolves, and the backend
  // enforces the boundary regardless.
  const [isAdmin, setIsAdmin] = useState(false);
  const [roleLoaded, setRoleLoaded] = useState(false);
  const [roleError, setRoleError] = useState(false);
  const loadRole = useCallback(() => {
    setRoleError(false);
    authClient
      .getSession()
      .then((session) => {
        const role = (session?.data?.user as { role?: string } | undefined)
          ?.role;
        setIsAdmin(role === "admin");
        setRoleLoaded(true);
      })
      .catch(() => {
        // Role unknown — surface it and offer a retry (see comment above).
        setRoleError(true);
      });
  }, []);
  useEffect(() => {
    loadRole();
  }, [loadRole]);

  const { data: apiKeys, refetch } = trpc.frontend.apiKeys.list.useQuery();
  // Admin-only cross-user listing. `enabled: isAdmin` keeps members from ever
  // firing the adminProcedure query (which would FORBIDDEN anyway).
  const { data: allApiKeys, refetch: refetchAll } =
    trpc.frontend.apiKeys.listAll.useQuery(undefined, { enabled: isAdmin });
  // Endpoints, for the required scope picker in the create dialog and to
  // render each key's scope by endpoint name in the lists.
  const { data: endpointsResponse } = trpc.frontend.endpoints.list.useQuery();
  const availableEndpoints = endpointsResponse?.success
    ? endpointsResponse.data
    : [];
  const endpointNameByUuid = new Map(
    availableEndpoints.map((endpoint) => [endpoint.uuid, endpoint.name]),
  );
  const createMutation = trpc.frontend.apiKeys.create.useMutation({
    onSuccess: (data) => {
      setNewApiKey(data.key);
      refetch();
      if (isAdmin) refetchAll();
      toast.success(t("api-keys:apiKeyCreated"));
    },
    onError: (error) => {
      toast.error(error.message);
    },
  });

  const deleteMutation = trpc.frontend.apiKeys.delete.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        refetch();
        if (isAdmin) refetchAll();
        toast.success(t("api-keys:apiKeyDeleted"));
        setDeleteDialogOpen(false);
        setApiKeyToDelete(null);
      } else {
        // Handle backend error response
        toast.error(data.message || t("api-keys:apiKeyDeleted"));
      }
    },
    onError: (error) => {
      toast.error(error.message);
    },
  });

  // Deactivate / reactivate is the doctrine-compliant kill: it expires the key
  // through the existing update path (is_active toggle) while PRESERVING the
  // ownership and last-used audit row, unlike DELETE which destroys the only
  // record of who held the credential. The backend audits is_active=false
  // under its own apikey.revoke verb, so an incident review can answer "which
  // keys were killed, by whom, when" from the action column.
  const updateMutation = trpc.frontend.apiKeys.update.useMutation({
    onSuccess: (data) => {
      refetch();
      if (isAdmin) refetchAll();
      toast.success(
        data.is_active
          ? t("api-keys:apiKeyReactivated")
          : t("api-keys:apiKeyDeactivated"),
      );
    },
    onError: (error) => {
      toast.error(error.message);
    },
  });

  const form = useForm<CreateApiKeyFormData>({
    resolver: createTranslatedZodResolver(CreateApiKeyFormSchema, t),
    defaultValues: {
      name: "",
      user_id: undefined, // Will be set based on ownership selection
      // Scope is REQUIRED and has no default: the caller must pick the one
      // endpoint the key works on, or (admin) the explicit all-endpoints
      // escape hatch. The zod schema rejects an unset scope.
      endpoint_uuid: undefined,
      all_endpoints: undefined,
      // Acts-as identity (migration 0024) is OPTIONAL and defaults to none:
      // an unbound key stays fail-closed for m365 delegated injection.
      acts_as_user_id: undefined,
    },
  });

  const onSubmit = (data: CreateApiKeyFormData) => {
    createMutation.mutate(data);
  };

  const handleCreateSuccess = () => {
    form.reset();
    setCreateDialogOpen(false);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success(t("api-keys:copyToClipboard"));
  };

  const handleDeleteClick = (apiKey: { uuid: string; name: string }) => {
    setApiKeyToDelete(apiKey);
    setDeleteDialogOpen(true);
  };

  // Toggle sends the OPPOSITE of the current state so one button serves both
  // directions. No confirm dialog: deactivate is reversible (reactivate is
  // the same control), unlike the destructive DELETE which stays confirm-gated.
  const handleToggleActive = (apiKey: { uuid: string; is_active: boolean }) => {
    updateMutation.mutate({ uuid: apiKey.uuid, is_active: !apiKey.is_active });
  };

  // Scope cell: NULL endpoint_uuid = legacy/gateway-wide key ("All
  // endpoints", visually marked as global); otherwise the bound endpoint's
  // name (uuid prefix fallback if the endpoint isn't visible to the caller).
  const renderScopeBadge = (endpointUuid: string | null) =>
    endpointUuid === null ? (
      <Badge
        variant="outline"
        className="bg-amber-50 dark:bg-amber-950/20 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-800"
      >
        {t("api-keys:allEndpointsBadge")}
      </Badge>
    ) : (
      <Badge variant="outline">
        {endpointNameByUuid.get(endpointUuid) ?? endpointUuid.slice(0, 8)}
      </Badge>
    );

  // Identity badge (migration 0024): a key with an admin-bound acts-as
  // identity exercises that user's delegated m365 identity on its endpoint.
  // Surfaced next to the scope badge in every key list so an identity-bound
  // key can never be mistaken for a plain (fail-closed) one. `label` is the
  // acted-as user's email where available (admin list) or their id
  // shortened (member list, via shortUserId); null renders nothing.
  const renderIdentityBadge = (label: string | null) =>
    label === null ? null : (
      <Badge
        variant="outline"
        className="bg-purple-50 dark:bg-purple-950/20 text-purple-700 dark:text-purple-300 border-purple-200 dark:border-purple-800"
      >
        {`${t("api-keys:actsAsBadge")} ${label}`}
      </Badge>
    );

  // Better-auth ids are opaque ~32-char strings — shorten for badge display.
  // Emails are shown in full (admin list only).
  const shortUserId = (id: string | null) =>
    id === null ? null : id.length > 8 ? `${id.slice(0, 8)}…` : id;

  const handleDeleteConfirm = () => {
    if (apiKeyToDelete) {
      deleteMutation.mutate({ uuid: apiKeyToDelete.uuid });
    }
  };

  const handleDeleteCancel = () => {
    setDeleteDialogOpen(false);
    setApiKeyToDelete(null);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Key className="h-8 w-8 text-primary" />
          <div>
            <h1 className="text-3xl font-bold tracking-tight">
              {t("api-keys:title")}
            </h1>
            <p className="text-muted-foreground">{t("api-keys:description")}</p>
          </div>
        </div>
        {/* Minting is admin-only since the migration 0023 scope rules: every
            new key must carry an (admin-gated) endpoint scope, so a member
            create always fails server-side. Rather than show a dialog that
            can only error, non-admins get a disabled button + an explanatory
            line. The backend enforces this regardless of the UI. While the
            role is still resolving, the button is neutrally disabled with
            NO admin-only claim (see the roleLoaded comment above). */}
        {!roleLoaded ? (
          roleError ? (
            <div className="flex flex-col items-end gap-1">
              <Button variant="outline" onClick={loadRole}>
                <RefreshCw className="h-4 w-4 mr-2" />
                {t("api-keys:retryRoleLoad")}
              </Button>
              <p className="text-xs text-destructive">
                {t("api-keys:roleLoadError")}
              </p>
            </div>
          ) : (
            <Button disabled aria-busy="true">
              <Plus className="h-4 w-4 mr-2" />
              {t("api-keys:createApiKey")}
            </Button>
          )
        ) : !isAdmin ? (
          <div className="flex flex-col items-end gap-1">
            <Button disabled title={t("api-keys:createAdminOnly")}>
              <Plus className="h-4 w-4 mr-2" />
              {t("api-keys:createApiKey")}
            </Button>
            <p className="text-xs text-muted-foreground">
              {t("api-keys:createAdminOnly")}
            </p>
          </div>
        ) : (
          <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="h-4 w-4 mr-2" />
                {t("api-keys:createApiKey")}
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>{t("api-keys:createApiKey")}</DialogTitle>
                <DialogDescription>
                  {t("api-keys:createApiKeyDescription")}
                </DialogDescription>
              </DialogHeader>
              {newApiKey ? (
                <div className="space-y-4">
                  <div className="p-4 bg-muted rounded-lg">
                    <p className="text-sm font-medium mb-2">
                      {t("api-keys:newApiKey")}
                    </p>
                    <div className="flex items-center gap-2">
                      <code className="flex-1 p-2 bg-background rounded border text-sm font-mono break-all">
                        {newApiKey}
                      </code>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => copyToClipboard(newApiKey)}
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                  <Button
                    onClick={() => {
                      setNewApiKey(null);
                      handleCreateSuccess();
                    }}
                    className="w-full"
                  >
                    {t("api-keys:done")}
                  </Button>
                </div>
              ) : (
                <form
                  onSubmit={form.handleSubmit(onSubmit)}
                  className="space-y-4"
                >
                  <div>
                    <label className="text-sm font-medium">
                      {t("api-keys:name")}
                    </label>
                    <Input
                      {...form.register("name")}
                      placeholder={t("api-keys:namePlaceholder")}
                    />
                    {form.formState.errors.name && (
                      <p className="text-sm text-destructive mt-1">
                        {form.formState.errors.name.message}
                      </p>
                    )}
                  </div>
                  <div>
                    <Label htmlFor="ownership" className="text-sm font-medium">
                      {t("api-keys:ownership")}
                    </Label>
                    <Select
                      value={
                        form.watch("user_id") === null ? "public" : "private"
                      }
                      onValueChange={(value) => {
                        form.setValue(
                          "user_id",
                          value === "public" ? null : undefined,
                        );
                        if (value === "public") {
                          // An identity binding requires the key to be OWNED
                          // by the acted-as user — a public ('everyone') key
                          // has no owner, so switching to it clears the
                          // acts-as field (same pattern as the all-endpoints
                          // switch in the scope select below) and the input
                          // is disabled while 'everyone' is selected.
                          form.setValue("acts_as_user_id", undefined);
                          form.clearErrors("acts_as_user_id");
                        }
                      }}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder={t("api-keys:ownership")} />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="private">
                          {t("api-keys:forMyself")}
                        </SelectItem>
                        {/* Minting a public ('everyone') key is admin-only —
                          the backend rejects it for members regardless, so
                          the option is simply hidden for non-admins. */}
                        {isAdmin && (
                          <SelectItem value="public">
                            {t("api-keys:everyone")}
                          </SelectItem>
                        )}
                      </SelectContent>
                    </Select>
                    <p className="text-xs text-muted-foreground mt-1">
                      {t("api-keys:ownershipDescription")}
                    </p>
                  </div>
                  <div>
                    <Label htmlFor="scope" className="text-sm font-medium">
                      {t("api-keys:scope")}
                    </Label>
                    <Select
                      value={
                        form.watch("all_endpoints") === true
                          ? "__all__"
                          : (form.watch("endpoint_uuid") ?? "")
                      }
                      onValueChange={(value) => {
                        if (value === "__all__") {
                          form.setValue("all_endpoints", true);
                          form.setValue("endpoint_uuid", undefined);
                          // An identity binding requires a single-endpoint
                          // scope — switching to gateway-wide clears it so
                          // the form can never submit the rejected pairing.
                          form.setValue("acts_as_user_id", undefined);
                          form.clearErrors("acts_as_user_id");
                        } else {
                          form.setValue("endpoint_uuid", value);
                          form.setValue("all_endpoints", undefined);
                        }
                        form.clearErrors("endpoint_uuid");
                      }}
                    >
                      <SelectTrigger>
                        <SelectValue
                          placeholder={t("api-keys:selectEndpoint")}
                        />
                      </SelectTrigger>
                      <SelectContent>
                        {availableEndpoints.map((endpoint) => (
                          <SelectItem key={endpoint.uuid} value={endpoint.uuid}>
                            {endpoint.name}
                          </SelectItem>
                        ))}
                        {/* Gateway-wide keys are the explicit escape hatch and
                          admin-only — the backend rejects the flag for
                          members regardless, so the option is hidden. */}
                        {isAdmin && (
                          <SelectItem value="__all__">
                            {t("api-keys:allEndpoints")}
                          </SelectItem>
                        )}
                      </SelectContent>
                    </Select>
                    {form.formState.errors.endpoint_uuid && (
                      <p className="text-sm text-destructive mt-1">
                        {form.formState.errors.endpoint_uuid.message}
                      </p>
                    )}
                    <p className="text-xs text-muted-foreground mt-1">
                      {t("api-keys:scopeDescription")}
                    </p>
                  </div>
                  {/* Acts-as identity binding (migration 0024) — this whole
                      dialog is admin-only (see the create-button gate above),
                      and the backend re-enforces admin-only regardless. Free
                      text for the better-auth user id: the ownership select
                      above carries no concrete user ids ('private' = the
                      current admin implicitly, 'everyone' = null) and there
                      is deliberately no list-users tRPC to feed a picker, so
                      the id cannot be auto-filled/locked from an owner
                      select. Enabled ONLY when a specific endpoint is
                      selected AND ownership is a specific user — an
                      identity-bound key must be endpoint-scoped and OWNED by
                      the identity it exercises, so the field is inert (and
                      cleared, see both onValueChange handlers) under the
                      all-endpoints escape hatch or 'everyone' ownership. The
                      backend rejects any owner ≠ acted-as divergence
                      (FORBIDDEN + zod ownerMismatch) regardless of the UI. */}
                  <div>
                    <Label
                      htmlFor="acts-as-user"
                      className="text-sm font-medium"
                    >
                      {t("api-keys:actsAsUser")}
                    </Label>
                    <Input
                      id="acts-as-user"
                      {...form.register("acts_as_user_id", {
                        // Empty / whitespace input means "no binding" — the
                        // schema field is optional, never an empty string.
                        setValueAs: (value: unknown) =>
                          typeof value === "string" && value.trim() !== ""
                            ? value.trim()
                            : undefined,
                      })}
                      placeholder={t("api-keys:actsAsUserPlaceholder")}
                      disabled={
                        !form.watch("endpoint_uuid") ||
                        form.watch("user_id") === null
                      }
                    />
                    {form.formState.errors.acts_as_user_id && (
                      <p className="text-sm text-destructive mt-1">
                        {form.formState.errors.acts_as_user_id.message}
                      </p>
                    )}
                    <p className="text-xs text-muted-foreground mt-1">
                      {t("api-keys:actsAsUserDescription")}
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => setCreateDialogOpen(false)}
                      className="flex-1"
                    >
                      {t("api-keys:cancel")}
                    </Button>
                    <Button
                      type="submit"
                      disabled={createMutation.isPending}
                      className="flex-1"
                    >
                      {createMutation.isPending
                        ? t("common:creating")
                        : t("common:create")}
                    </Button>
                  </div>
                </form>
              )}
            </DialogContent>
          </Dialog>
        )}
      </div>

      <Separator />

      {/* Fork-added: says out loud why the key column stopped being
          copyable, so the removal reads as a deliberate control rather
          than a broken table, and points at the supported replacement. */}
      <p className="text-sm text-muted-foreground">
        Key values are shown as a prefix only. A key&apos;s full value is
        displayed once, when it is created, and is never retrievable afterwards.
        If you need gateway access, ask an administrator to mint a key scoped to
        the endpoint you need rather than reusing a shared one.
      </p>

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("common:name")}</TableHead>
              <TableHead>Key</TableHead>
              <TableHead>{t("api-keys:created")}</TableHead>
              <TableHead>{t("common:status")}</TableHead>
              <TableHead>{t("api-keys:ownership")}</TableHead>
              <TableHead>{t("api-keys:scope")}</TableHead>
              <TableHead className="w-[100px]">{t("common:actions")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {apiKeys?.apiKeys?.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center py-12">
                  <div className="flex flex-col items-center gap-2">
                    <Key className="h-8 w-8 text-muted-foreground" />
                    <p className="text-muted-foreground">
                      {t("api-keys:noApiKeys")}
                    </p>
                    <p className="text-sm text-muted-foreground">
                      {t("api-keys:createFirstApiKey")}
                    </p>
                  </div>
                </TableCell>
              </TableRow>
            ) : (
              apiKeys?.apiKeys?.map((apiKey) => (
                <TableRow key={apiKey.uuid}>
                  <TableCell className="font-medium">{apiKey.name}</TableCell>
                  {/* Prefix only — the server no longer sends a usable
                      secret here (see serializeApiKeyList). The reveal and
                      copy-full controls that used to live in this cell are
                      gone with it: there is nothing left to reveal, and a
                      button that copies a truncated key would only produce
                      401s. Full values exist exactly once, in the mint
                      dialog above. */}
                  <TableCell>
                    <code className="text-sm font-mono break-all">
                      {apiKey.key_prefix}
                    </code>
                  </TableCell>
                  <TableCell>
                    {format(new Date(apiKey.created_at), "MMM d, yyyy")}
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={apiKey.is_active ? "default" : "secondary"}
                      className={
                        apiKey.is_active
                          ? "bg-green-100 dark:bg-green-900/20 text-green-800 dark:text-green-200 border-green-200 dark:border-green-800"
                          : "bg-red-100 dark:bg-red-900/20 text-red-800 dark:text-red-200 border-red-200 dark:border-red-800"
                      }
                    >
                      {apiKey.is_active
                        ? t("common:active")
                        : t("common:inactive")}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant="outline"
                      className={
                        apiKey.user_id === null
                          ? "bg-green-50 dark:bg-green-950/20 text-green-700 dark:text-green-300 border-green-200 dark:border-green-800"
                          : "bg-gray-50 dark:bg-gray-950/20 text-gray-700 dark:text-gray-300 border-gray-200 dark:border-gray-800"
                      }
                    >
                      {apiKey.user_id === null
                        ? t("api-keys:public")
                        : t("api-keys:private")}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1 flex-wrap">
                      {renderScopeBadge(apiKey.endpoint_uuid)}
                      {renderIdentityBadge(shortUserId(apiKey.acts_as_user_id))}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() =>
                          handleToggleActive({
                            uuid: apiKey.uuid,
                            is_active: apiKey.is_active,
                          })
                        }
                        disabled={updateMutation.isPending}
                        title={
                          apiKey.is_active
                            ? t("api-keys:deactivate")
                            : t("api-keys:reactivate")
                        }
                      >
                        {apiKey.is_active ? (
                          <Ban className="h-4 w-4" />
                        ) : (
                          <RotateCcw className="h-4 w-4" />
                        )}
                      </Button>
                      {/* Delete stays confirm-gated (AlertDialog below) and is
                          visually demoted with destructive color: deactivate is
                          the preferred, reversible, record-preserving kill. */}
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() =>
                          handleDeleteClick({
                            uuid: apiKey.uuid,
                            name: apiKey.name,
                          })
                        }
                        disabled={deleteMutation.isPending}
                        title={t("api-keys:delete")}
                        className="text-destructive hover:text-destructive"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {/* Admin-only: every API key across all users. Rendered only for
          admins (the listAll query is adminProcedure-gated; members never
          fetch it). This is the "admin section" — there is no separate admin
          nav route, so hiding it here is what keeps admin surfaces out of a
          member's view. */}
      {isAdmin && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-primary" />
            <h2 className="text-xl font-semibold tracking-tight">
              All API Keys
            </h2>
            <Badge variant="outline">Admin</Badge>
          </div>
          <p className="text-sm text-muted-foreground">
            Every API key across all users, including keys you do not own. Only
            administrators can see and revoke these.
          </p>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("common:name")}</TableHead>
                  <TableHead>Key</TableHead>
                  <TableHead>Owner</TableHead>
                  <TableHead>{t("api-keys:scope")}</TableHead>
                  <TableHead>{t("api-keys:created")}</TableHead>
                  <TableHead>Last used</TableHead>
                  <TableHead>{t("common:status")}</TableHead>
                  <TableHead className="w-[100px]">
                    {t("common:actions")}
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {allApiKeys?.apiKeys?.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-center py-12">
                      <p className="text-muted-foreground">
                        {t("api-keys:noApiKeys")}
                      </p>
                    </TableCell>
                  </TableRow>
                ) : (
                  allApiKeys?.apiKeys?.map((apiKey) => (
                    <TableRow key={apiKey.uuid}>
                      <TableCell className="font-medium">
                        {apiKey.name}
                      </TableCell>
                      <TableCell>
                        <code className="text-sm font-mono break-all">
                          {apiKey.key_prefix}
                        </code>
                      </TableCell>
                      <TableCell>
                        {apiKey.owner_email ?? (
                          <Badge
                            variant="outline"
                            className="bg-green-50 dark:bg-green-950/20 text-green-700 dark:text-green-300 border-green-200 dark:border-green-800"
                          >
                            {t("api-keys:public")}
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1 flex-wrap">
                          {renderScopeBadge(apiKey.endpoint_uuid)}
                          {renderIdentityBadge(
                            apiKey.acts_as_email ??
                              shortUserId(apiKey.acts_as_user_id),
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        {format(new Date(apiKey.created_at), "MMM d, yyyy")}
                      </TableCell>
                      <TableCell>
                        {apiKey.last_used_at ? (
                          format(
                            new Date(apiKey.last_used_at),
                            "MMM d, yyyy HH:mm",
                          )
                        ) : (
                          <span className="text-muted-foreground">Never</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={apiKey.is_active ? "default" : "secondary"}
                          className={
                            apiKey.is_active
                              ? "bg-green-100 dark:bg-green-900/20 text-green-800 dark:text-green-200 border-green-200 dark:border-green-800"
                              : "bg-red-100 dark:bg-red-900/20 text-red-800 dark:text-red-200 border-red-200 dark:border-red-800"
                          }
                        >
                          {apiKey.is_active
                            ? t("common:active")
                            : t("common:inactive")}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1">
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() =>
                              handleToggleActive({
                                uuid: apiKey.uuid,
                                is_active: apiKey.is_active,
                              })
                            }
                            disabled={updateMutation.isPending}
                            title={
                              apiKey.is_active
                                ? t("api-keys:deactivate")
                                : t("api-keys:reactivate")
                            }
                          >
                            {apiKey.is_active ? (
                              <Ban className="h-4 w-4" />
                            ) : (
                              <RotateCcw className="h-4 w-4" />
                            )}
                          </Button>
                          {/* Delete stays confirm-gated (AlertDialog below) and
                              is visually demoted with destructive color:
                              deactivate is the preferred, reversible,
                              record-preserving kill. */}
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() =>
                              handleDeleteClick({
                                uuid: apiKey.uuid,
                                name: apiKey.name,
                              })
                            }
                            disabled={deleteMutation.isPending}
                            title={t("api-keys:delete")}
                            className="text-destructive hover:text-destructive"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </div>
      )}

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("api-keys:confirmDelete")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t("api-keys:deleteConfirmation")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={handleDeleteCancel}>
              {t("api-keys:cancel")}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDeleteConfirm}
              disabled={deleteMutation.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteMutation.isPending
                ? t("common:deleting")
                : t("api-keys:delete")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
