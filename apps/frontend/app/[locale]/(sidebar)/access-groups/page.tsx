"use client";

import { CreateAccessGroupRequestSchema } from "@repo/zod-types";
import { Plus, RefreshCw, Trash2, Users } from "lucide-react";
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
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
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
import { endpointGateState } from "@/lib/endpoint-gate-state";
import { trpc } from "@/lib/trpc";
import { createTranslatedZodResolver } from "@/lib/zod-resolver";

type CreateAccessGroupFormData = z.infer<typeof CreateAccessGroupRequestSchema>;

/**
 * Access groups: which OAuth users may reach which endpoints (migration 0033).
 *
 * DISTINCT FROM `/access`, which is the read-only inventory of every way into
 * this gateway (accounts, tokens, keys, clients). That page answers "who can
 * get in at all"; this one answers "and once in, which connectors are theirs".
 *
 * Modelled on the OAuth clients page: one self-contained file, a table plus an
 * inline create dialog, and the same fail-closed role read. Every procedure it
 * calls is `adminProcedure`, so the role check here is presentation only — it
 * keeps a member from being shown controls that could only ever FORBIDDEN.
 *
 * TOOL-LEVEL SCOPING IS NOT WHAT THIS IS. A group grants or denies a WHOLE
 * endpoint. To give an audience a narrower tool set, curate a second namespace
 * and publish a second endpoint over it, then map the group to that one.
 */
export default function AccessGroupsPage() {
  const { t } = useTranslations();
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [selectedGroupUuid, setSelectedGroupUuid] = useState<string | null>(
    null,
  );
  const [groupToDelete, setGroupToDelete] = useState<{
    uuid: string;
    name: string;
  } | null>(null);
  const [memberToAdd, setMemberToAdd] = useState("");
  const [endpointToAdd, setEndpointToAdd] = useState("");

  // Fail-closed role read, identical to the OAuth clients page. `roleLoaded`
  // exists so an admin does not see a flash of the false "administrators only"
  // claim while the session request is in flight; `roleError` surfaces a retry
  // rather than pinning the neutral state forever.
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
        setRoleError(true);
      });
  }, []);
  useEffect(() => {
    loadRole();
  }, [loadRole]);

  const utils = trpc.useUtils();

  const { data: groupsResponse, isLoading } =
    trpc.frontend.accessGroups.list.useQuery(undefined, { enabled: isAdmin });
  const groups = groupsResponse?.success ? groupsResponse.data : [];

  const { data: detailResponse } = trpc.frontend.accessGroups.get.useQuery(
    { uuid: selectedGroupUuid ?? "" },
    { enabled: isAdmin && Boolean(selectedGroupUuid) },
  );
  const detail = detailResponse?.success ? detailResponse.data : undefined;

  // The member picker's source. `users.list` is already adminProcedure and is
  // what the Access dashboard uses.
  const { data: usersResponse } = trpc.frontend.users.list.useQuery(undefined, {
    enabled: isAdmin && Boolean(selectedGroupUuid),
  });
  // `users.list` returns the array directly, with no success envelope — unlike
  // the access-group queries on this page.
  const users = usersResponse?.users ?? [];

  // The endpoint picker's source. Deliberately NOT `endpoints.list`, which is
  // scoped to the caller and would silently omit an endpoint owned by someone
  // else — exactly the one an administrator is most likely to be gating.
  const { data: endpointsResponse } =
    trpc.frontend.accessGroups.listEndpoints.useQuery(undefined, {
      enabled: isAdmin && Boolean(selectedGroupUuid),
    });
  const endpoints = endpointsResponse?.success ? endpointsResponse.data : [];

  const refreshAll = () => {
    utils.frontend.accessGroups.list.invalidate();
    if (selectedGroupUuid) {
      utils.frontend.accessGroups.get.invalidate({ uuid: selectedGroupUuid });
    }
    // The endpoint-detail Access panel reads the same grants.
    utils.frontend.accessGroups.getEndpointAccess.invalidate();
  };

  /** Every mutation on this page reports its own `success: false` message. */
  const mutationHandlers = (successKey: string, failureKey: string) => ({
    onSuccess: (data: { success: boolean; message?: string }) => {
      if (data.success) {
        refreshAll();
        toast.success(data.message ?? t(successKey));
      } else {
        toast.error(data.message || t(failureKey));
      }
    },
    onError: (error: { message: string }) => {
      toast.error(t(failureKey) + ": " + error.message);
    },
  });

  const form = useForm<CreateAccessGroupFormData>({
    resolver: createTranslatedZodResolver(CreateAccessGroupRequestSchema, t),
    defaultValues: { name: "", description: "" },
  });

  const createMutation = trpc.frontend.accessGroups.create.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        utils.frontend.accessGroups.list.invalidate();
        toast.success(t("access:groups.created"));
        setCreateDialogOpen(false);
        form.reset();
      } else {
        toast.error(data.message || t("access:groups.createFailed"));
      }
    },
    onError: (error) => {
      toast.error(t("access:groups.createFailed") + ": " + error.message);
    },
  });

  const deleteMutation = trpc.frontend.accessGroups.delete.useMutation({
    ...mutationHandlers("access:groups.deleted", "access:groups.deleteFailed"),
    onSettled: () => {
      setGroupToDelete(null);
      if (groupToDelete?.uuid === selectedGroupUuid) setSelectedGroupUuid(null);
    },
  });

  const addMemberMutation = trpc.frontend.accessGroups.addMember.useMutation(
    mutationHandlers("access:groups.memberAdded", "access:groups.memberFailed"),
  );
  const removeMemberMutation =
    trpc.frontend.accessGroups.removeMember.useMutation(
      mutationHandlers(
        "access:groups.memberRemoved",
        "access:groups.memberFailed",
      ),
    );
  const addEndpointMutation =
    trpc.frontend.accessGroups.addEndpoint.useMutation(
      mutationHandlers(
        "access:groups.endpointAdded",
        "access:groups.endpointFailed",
      ),
    );
  const removeEndpointMutation =
    trpc.frontend.accessGroups.removeEndpoint.useMutation(
      mutationHandlers(
        "access:groups.endpointRemoved",
        "access:groups.endpointFailed",
      ),
    );

  const memberIds = new Set(detail?.members.map((m) => m.user_id) ?? []);
  const mappedEndpointIds = new Set(
    detail?.endpoints.map((e) => e.endpoint_uuid) ?? [],
  );
  const addableUsers = users.filter((user) => !memberIds.has(user.id));
  const addableEndpoints = endpoints.filter(
    (endpoint) => !mappedEndpointIds.has(endpoint.uuid),
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Users className="h-8 w-8 text-primary" />
          <div>
            <h1 className="text-3xl font-bold tracking-tight">
              {t("access:groups.title")}
            </h1>
            <p className="text-muted-foreground">
              {t("access:groups.description")}
            </p>
          </div>
        </div>

        {!roleLoaded ? (
          roleError ? (
            <div className="flex flex-col items-end gap-1">
              <Button variant="outline" onClick={loadRole}>
                <RefreshCw className="h-4 w-4 mr-2" />
                {t("common:refresh")}
              </Button>
              <p className="text-xs text-destructive">
                {t("access:loadError")}
              </p>
            </div>
          ) : (
            <Button disabled aria-busy="true">
              <Plus className="h-4 w-4 mr-2" />
              {t("access:groups.createGroup")}
            </Button>
          )
        ) : !isAdmin ? (
          <div className="flex flex-col items-end gap-1">
            <Button disabled title={t("access:adminOnly")}>
              <Plus className="h-4 w-4 mr-2" />
              {t("access:groups.createGroup")}
            </Button>
            <p className="text-xs text-muted-foreground">
              {t("access:adminOnly")}
            </p>
          </div>
        ) : (
          <Dialog
            open={createDialogOpen}
            onOpenChange={(open) => {
              setCreateDialogOpen(open);
              if (!open) form.reset();
            }}
          >
            <DialogTrigger asChild>
              <Button>
                <Plus className="h-4 w-4 mr-2" />
                {t("access:groups.createGroup")}
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>{t("access:groups.createGroup")}</DialogTitle>
                <DialogDescription>
                  {t("access:groups.createGroupDescription")}
                </DialogDescription>
              </DialogHeader>

              <Form {...form}>
                <form
                  onSubmit={form.handleSubmit((data) =>
                    createMutation.mutate({
                      name: data.name.trim(),
                      description: data.description?.trim() || undefined,
                    }),
                  )}
                  className="space-y-4"
                >
                  <FormField
                    control={form.control}
                    name="name"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>{t("access:groups.nameLabel")}</FormLabel>
                        <FormControl>
                          <Input
                            {...field}
                            placeholder={t("access:groups.namePlaceholder")}
                          />
                        </FormControl>
                        <FormDescription>
                          {t("access:groups.nameHelp")}
                        </FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="description"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>
                          {t("access:groups.descriptionLabel")}
                        </FormLabel>
                        <FormControl>
                          <Input {...field} value={field.value ?? ""} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <div className="flex justify-end gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => setCreateDialogOpen(false)}
                    >
                      {t("common:cancel")}
                    </Button>
                    <Button type="submit" disabled={createMutation.isPending}>
                      {createMutation.isPending
                        ? t("access:groups.creating")
                        : t("access:groups.create")}
                    </Button>
                  </div>
                </form>
              </Form>
            </DialogContent>
          </Dialog>
        )}
      </div>

      {roleLoaded && !isAdmin ? (
        <p className="text-sm text-muted-foreground">{t("access:adminOnly")}</p>
      ) : (
        <>
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <h2 className="text-xl font-semibold tracking-tight">
                {t("access:groups.heading")}
              </h2>
              <Badge variant="outline">Admin</Badge>
            </div>

            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("access:groups.columnName")}</TableHead>
                    <TableHead>
                      {t("access:groups.columnDescription")}
                    </TableHead>
                    <TableHead>{t("access:groups.columnMembers")}</TableHead>
                    <TableHead>{t("access:groups.columnEndpoints")}</TableHead>
                    <TableHead className="w-[160px]">
                      {t("access:columnActions")}
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {isLoading ? (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center py-12">
                        <p className="text-muted-foreground">
                          {t("access:loading")}
                        </p>
                      </TableCell>
                    </TableRow>
                  ) : groups.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center py-12">
                        <p className="text-muted-foreground">
                          {t("access:groups.noGroups")}
                        </p>
                        <p className="text-sm text-muted-foreground">
                          {t("access:groups.noGroupsDescription")}
                        </p>
                      </TableCell>
                    </TableRow>
                  ) : (
                    groups.map((group) => (
                      <TableRow key={group.uuid}>
                        <TableCell className="font-medium">
                          {group.name}
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {group.description}
                        </TableCell>
                        <TableCell>{group.member_count}</TableCell>
                        <TableCell>{group.endpoint_count}</TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1">
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() =>
                                setSelectedGroupUuid(
                                  selectedGroupUuid === group.uuid
                                    ? null
                                    : group.uuid,
                                )
                              }
                            >
                              {selectedGroupUuid === group.uuid
                                ? t("access:groups.hide")
                                : t("access:groups.manage")}
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() =>
                                setGroupToDelete({
                                  uuid: group.uuid,
                                  name: group.name,
                                })
                              }
                            >
                              <Trash2 className="h-4 w-4 text-destructive" />
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

          {selectedGroupUuid && detail && (
            <div className="space-y-6 rounded-md border p-4">
              <h2 className="text-xl font-semibold tracking-tight">
                {t("access:groups.managing", { name: detail.name })}
              </h2>

              <div className="space-y-2">
                <h3 className="text-sm font-medium">
                  {t("access:groups.membersHeading")}
                </h3>
                <p className="text-xs text-muted-foreground">
                  {t("access:groups.membersHelp")}
                </p>

                <div className="flex items-center gap-2">
                  <Select value={memberToAdd} onValueChange={setMemberToAdd}>
                    <SelectTrigger className="w-[320px]">
                      <SelectValue
                        placeholder={t("access:groups.selectUser")}
                      />
                    </SelectTrigger>
                    <SelectContent>
                      {addableUsers.map((user) => (
                        <SelectItem key={user.id} value={user.id}>
                          {user.email}
                          {user.role === "admin"
                            ? ` (${t("access:groups.adminSuffix")})`
                            : ""}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Button
                    size="sm"
                    disabled={!memberToAdd || addMemberMutation.isPending}
                    onClick={() => {
                      addMemberMutation.mutate({
                        group_uuid: selectedGroupUuid,
                        user_id: memberToAdd,
                      });
                      setMemberToAdd("");
                    }}
                  >
                    {t("access:groups.addMember")}
                  </Button>
                </div>

                {detail.members.length === 0 ? (
                  <p className="text-xs text-muted-foreground">
                    {t("access:groups.noMembers")}
                  </p>
                ) : (
                  <div className="rounded-md border">
                    <Table>
                      <TableBody>
                        {detail.members.map((member) => (
                          <TableRow key={member.user_id}>
                            <TableCell className="font-medium">
                              {member.email}
                            </TableCell>
                            <TableCell>{member.name}</TableCell>
                            <TableCell>
                              <Badge variant="outline">{member.role}</Badge>
                            </TableCell>
                            <TableCell className="w-[80px]">
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() =>
                                  removeMemberMutation.mutate({
                                    group_uuid: selectedGroupUuid,
                                    user_id: member.user_id,
                                  })
                                }
                              >
                                <Trash2 className="h-4 w-4 text-destructive" />
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </div>

              <div className="space-y-2">
                <h3 className="text-sm font-medium">
                  {t("access:groups.endpointsHeading")}
                </h3>
                <p className="text-xs text-muted-foreground">
                  {t("access:groups.endpointsHelp")}
                </p>

                <div className="flex items-center gap-2">
                  <Select
                    value={endpointToAdd}
                    onValueChange={setEndpointToAdd}
                  >
                    <SelectTrigger className="w-[320px]">
                      <SelectValue
                        placeholder={t("access:groups.selectEndpoint")}
                      />
                    </SelectTrigger>
                    <SelectContent>
                      {addableEndpoints.map((endpoint) => (
                        <SelectItem key={endpoint.uuid} value={endpoint.uuid}>
                          {endpoint.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Button
                    size="sm"
                    disabled={!endpointToAdd || addEndpointMutation.isPending}
                    onClick={() => {
                      addEndpointMutation.mutate({
                        group_uuid: selectedGroupUuid,
                        endpoint_uuid: endpointToAdd,
                      });
                      setEndpointToAdd("");
                    }}
                  >
                    {t("access:groups.addEndpoint")}
                  </Button>
                </div>

                {detail.endpoints.length === 0 ? (
                  <p className="text-xs text-muted-foreground">
                    {t("access:groups.noEndpoints")}
                  </p>
                ) : (
                  <div className="rounded-md border">
                    <Table>
                      <TableBody>
                        {detail.endpoints.map((endpoint) => (
                          <TableRow key={endpoint.endpoint_uuid}>
                            <TableCell className="font-medium">
                              {endpoint.name}
                            </TableCell>
                            <TableCell>
                              {/* Four states, because `restricted` alone is not
                                  the answer. The gate governs OAuth callers
                                  only, so it is INERT on an endpoint with OAuth
                                  off and PARTIAL on one that also accepts API
                                  keys. Collapsing those into "Enforcing" is the
                                  difference between a grant list an operator can
                                  trust and one they misread as protection that
                                  is already fully switched on. */}
                              <Badge
                                variant={
                                  endpointGateState(endpoint) === "enforcing"
                                    ? "default"
                                    : "outline"
                                }
                              >
                                {t(
                                  `access:groups.gate.${endpointGateState(endpoint)}`,
                                )}
                              </Badge>
                            </TableCell>
                            <TableCell className="w-[80px]">
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() =>
                                  removeEndpointMutation.mutate({
                                    group_uuid: selectedGroupUuid,
                                    endpoint_uuid: endpoint.endpoint_uuid,
                                  })
                                }
                              >
                                <Trash2 className="h-4 w-4 text-destructive" />
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </div>

              <p className="text-xs text-muted-foreground">
                {t("access:groups.scopeNote")}
              </p>
            </div>
          )}
        </>
      )}

      <AlertDialog
        open={Boolean(groupToDelete)}
        onOpenChange={(open) => {
          if (!open) setGroupToDelete(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("access:groups.deleteConfirmTitle")}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t("access:groups.deleteConfirmDescription", {
                name: groupToDelete?.name ?? "",
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("common:cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (groupToDelete) {
                  deleteMutation.mutate({ uuid: groupToDelete.uuid });
                }
              }}
              disabled={deleteMutation.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteMutation.isPending
                ? t("common:deleting")
                : t("access:groups.deleteConfirmAction")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
