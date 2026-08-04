"use client";

import { CreateOAuthClientFormSchema } from "@repo/zod-types";
import { format } from "date-fns";
import { Copy, KeyRound, Plus, RefreshCw, Trash2 } from "lucide-react";
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
import { Textarea } from "@/components/ui/textarea";
import { useTranslations } from "@/hooks/useTranslations";
import { authClient } from "@/lib/auth-client";
import { trpc } from "@/lib/trpc";
import { createTranslatedZodResolver } from "@/lib/zod-resolver";

type CreateOAuthClientFormData = z.infer<typeof CreateOAuthClientFormSchema>;

// The two callbacks an Anthropic-hosted Claude connector redirects to. Pairing
// one is the overwhelmingly common reason to register a client here, and it
// was previously a hand-written curl against /oauth/register, so the preset
// fills both rather than making the operator remember them.
const CLAUDE_REDIRECT_URIS = [
  "https://claude.ai/api/mcp/auth_callback",
  "https://claude.com/api/mcp/auth_callback",
];

// Newline-separated Textarea -> the string[] the API expects. The frontend has
// no array-field component anywhere; every multi-value input in this codebase
// is a Textarea split at submit time (see mcp-servers' `env`), so this follows
// that convention rather than introducing a new dependency.
function parseRedirectUris(raw: string): string[] {
  return raw
    .split("\n")
    .map((uri) => uri.trim())
    .filter((uri) => uri.length > 0);
}

export default function OAuthClientsPage() {
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [newClient, setNewClient] = useState<{
    client_id: string;
    client_secret: string | null;
  } | null>(null);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [clientToDelete, setClientToDelete] = useState<{
    client_id: string;
    client_name: string;
  } | null>(null);
  const { t } = useTranslations();

  // Current session role, read from the better-auth session exactly as the
  // API-keys page does. EVERY procedure on this page is adminProcedure, so
  // this is presentation only — it keeps a member from being shown controls
  // that could only ever return FORBIDDEN. The backend is the boundary.
  //
  // roleLoaded matters for the same reason it does on the API-keys page:
  // isAdmin starts false, so without it an admin sees a flash of the false
  // "administrators only" claim while the session request is in flight. A
  // failed fetch surfaces a retry rather than pinning the neutral state
  // forever. Fail-closed throughout.
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

  // `enabled: isAdmin` keeps a member from firing an adminProcedure query
  // that would only FORBIDDEN.
  const { data: clientsResponse, isLoading } =
    trpc.frontend.oauthClients.list.useQuery(undefined, { enabled: isAdmin });
  const clients = clientsResponse?.clients ?? [];

  const form = useForm<CreateOAuthClientFormData>({
    resolver: createTranslatedZodResolver(CreateOAuthClientFormSchema, t),
    defaultValues: {
      client_name: "",
      redirect_uris: "",
      token_endpoint_auth_method: "none",
      scope: "admin",
    },
  });

  const createMutation = trpc.frontend.oauthClients.create.useMutation({
    onSuccess: (data) => {
      // Hold the credentials in state instead of closing the dialog: the
      // secret is disclosed exactly once and closing here would lose it.
      setNewClient({
        client_id: data.client_id,
        client_secret: data.client_secret,
      });
      utils.frontend.oauthClients.list.invalidate();
      toast.success(t("oauth-clients:clientCreated"));
    },
    onError: (error) => {
      toast.error(t("oauth-clients:createError") + ": " + error.message);
    },
  });

  const deleteMutation = trpc.frontend.oauthClients.delete.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        utils.frontend.oauthClients.list.invalidate();
        toast.success(t("oauth-clients:clientDeleted"));
      } else {
        // A delete that matched no row resolves successfully at the transport
        // layer but did nothing — report it rather than showing a green toast.
        toast.error(data.message || t("oauth-clients:deleteError"));
      }
      setDeleteDialogOpen(false);
      setClientToDelete(null);
    },
    onError: (error) => {
      toast.error(t("oauth-clients:deleteError") + ": " + error.message);
    },
  });

  const onSubmit = (data: CreateOAuthClientFormData) => {
    // grant_types / response_types are deliberately not exposed here. The
    // server applies the same OAuth 2.1 defaults the /oauth/register DCR path
    // applies (authorization_code + code), so a client minted from this form
    // is identical to one minted by the curl this page replaces.
    createMutation.mutate({
      client_name: data.client_name.trim(),
      redirect_uris: parseRedirectUris(data.redirect_uris),
      token_endpoint_auth_method: data.token_endpoint_auth_method,
      scope: data.scope.trim(),
      grant_types: ["authorization_code"],
      response_types: ["code"],
    });
  };

  const applyClaudePreset = () => {
    form.setValue("redirect_uris", CLAUDE_REDIRECT_URIS.join("\n"), {
      shouldValidate: true,
    });
    if (!form.getValues("client_name").trim()) {
      form.setValue("client_name", "Claude");
    }
    toast.success(t("oauth-clients:claudePresetApplied"));
  };

  const closeCreateDialog = () => {
    setCreateDialogOpen(false);
    setNewClient(null);
    form.reset();
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success(t("oauth-clients:copiedToClipboard"));
  };

  const handleDeleteConfirm = () => {
    if (!clientToDelete) return;
    deleteMutation.mutate({ client_id: clientToDelete.client_id });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <KeyRound className="h-8 w-8 text-primary" />
          <div>
            <h1 className="text-3xl font-bold tracking-tight">
              {t("oauth-clients:title")}
            </h1>
            <p className="text-muted-foreground">
              {t("oauth-clients:description")}
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
                {t("oauth-clients:loadError")}
              </p>
            </div>
          ) : (
            <Button disabled aria-busy="true">
              <Plus className="h-4 w-4 mr-2" />
              {t("oauth-clients:createClient")}
            </Button>
          )
        ) : !isAdmin ? (
          <div className="flex flex-col items-end gap-1">
            <Button disabled title={t("oauth-clients:adminOnly")}>
              <Plus className="h-4 w-4 mr-2" />
              {t("oauth-clients:createClient")}
            </Button>
            <p className="text-xs text-muted-foreground">
              {t("oauth-clients:adminOnly")}
            </p>
          </div>
        ) : (
          <Dialog
            open={createDialogOpen}
            onOpenChange={(open) => {
              // Reuse the same teardown as the Done button so dismissing the
              // dialog can never leave a stale secret in state.
              if (!open) closeCreateDialog();
              else setCreateDialogOpen(true);
            }}
          >
            <DialogTrigger asChild>
              <Button>
                <Plus className="h-4 w-4 mr-2" />
                {t("oauth-clients:createClient")}
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>{t("oauth-clients:createClient")}</DialogTitle>
                <DialogDescription>
                  {t("oauth-clients:createClientDescription")}
                </DialogDescription>
              </DialogHeader>

              {newClient ? (
                <div className="space-y-4">
                  <div className="p-4 bg-muted rounded-lg space-y-3">
                    <p className="text-sm font-medium">
                      {t("oauth-clients:credentialsTitle")}
                    </p>

                    <div className="space-y-1">
                      <p className="text-xs text-muted-foreground">
                        {t("oauth-clients:clientId")}
                      </p>
                      <div className="flex items-center gap-2">
                        <code className="flex-1 p-2 bg-background rounded border text-sm font-mono break-all">
                          {newClient.client_id}
                        </code>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => copyToClipboard(newClient.client_id)}
                        >
                          <Copy className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>

                    {newClient.client_secret ? (
                      <div className="space-y-1">
                        <p className="text-xs text-muted-foreground">
                          {t("oauth-clients:clientSecret")}
                        </p>
                        <div className="flex items-center gap-2">
                          <code className="flex-1 p-2 bg-background rounded border text-sm font-mono break-all">
                            {newClient.client_secret}
                          </code>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() =>
                              copyToClipboard(newClient.client_secret!)
                            }
                          >
                            <Copy className="h-4 w-4" />
                          </Button>
                        </div>
                        <p className="text-xs text-destructive font-medium">
                          {t("oauth-clients:secretWarning")}
                        </p>
                      </div>
                    ) : (
                      // A PKCE public client genuinely has no secret. Say that
                      // outright — an empty space where a secret should be
                      // reads as a bug or a lost credential.
                      <p className="text-xs text-muted-foreground">
                        {t("oauth-clients:publicClientNote")}
                      </p>
                    )}
                  </div>

                  <Button onClick={closeCreateDialog} className="w-full">
                    {t("oauth-clients:done")}
                  </Button>
                </div>
              ) : (
                <Form {...form}>
                  <form
                    onSubmit={form.handleSubmit(onSubmit)}
                    className="space-y-4"
                  >
                    <FormField
                      control={form.control}
                      name="client_name"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>{t("oauth-clients:clientName")}</FormLabel>
                          <FormControl>
                            <Input
                              {...field}
                              placeholder={t(
                                "oauth-clients:clientNamePlaceholder",
                              )}
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="redirect_uris"
                      render={({ field }) => (
                        <FormItem>
                          <div className="flex items-center justify-between">
                            <FormLabel>
                              {t("oauth-clients:redirectUris")}
                            </FormLabel>
                            <Button
                              type="button"
                              size="sm"
                              variant="outline"
                              onClick={applyClaudePreset}
                            >
                              {t("oauth-clients:useClaudePreset")}
                            </Button>
                          </div>
                          <FormControl>
                            <Textarea
                              {...field}
                              rows={3}
                              placeholder={t(
                                "oauth-clients:redirectUrisPlaceholder",
                              )}
                              className="whitespace-pre-wrap break-all overflow-x-hidden font-mono text-sm"
                            />
                          </FormControl>
                          <FormDescription>
                            {t("oauth-clients:redirectUrisHelp")}
                          </FormDescription>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="token_endpoint_auth_method"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>{t("oauth-clients:authMethod")}</FormLabel>
                          <Select
                            value={field.value}
                            onValueChange={field.onChange}
                          >
                            <FormControl>
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              <SelectItem value="none">
                                {t("oauth-clients:authMethodNone")}
                              </SelectItem>
                              <SelectItem value="client_secret_post">
                                {t("oauth-clients:authMethodPost")}
                              </SelectItem>
                              <SelectItem value="client_secret_basic">
                                {t("oauth-clients:authMethodBasic")}
                              </SelectItem>
                            </SelectContent>
                          </Select>
                          <FormDescription>
                            {t("oauth-clients:authMethodHelp")}
                          </FormDescription>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="scope"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>{t("oauth-clients:scope")}</FormLabel>
                          <FormControl>
                            <Input
                              {...field}
                              placeholder={t("oauth-clients:scopePlaceholder")}
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <div className="flex justify-end gap-2">
                      <Button
                        type="button"
                        variant="outline"
                        onClick={closeCreateDialog}
                      >
                        {t("oauth-clients:cancel")}
                      </Button>
                      <Button type="submit" disabled={createMutation.isPending}>
                        {createMutation.isPending
                          ? t("oauth-clients:creating")
                          : t("oauth-clients:create")}
                      </Button>
                    </div>
                  </form>
                </Form>
              )}
            </DialogContent>
          </Dialog>
        )}
      </div>

      {roleLoaded && !isAdmin ? (
        <p className="text-sm text-muted-foreground">
          {t("oauth-clients:adminOnly")}
        </p>
      ) : (
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-semibold tracking-tight">
              {t("oauth-clients:registeredClients")}
            </h2>
            <Badge variant="outline">Admin</Badge>
          </div>

          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("oauth-clients:columnName")}</TableHead>
                  <TableHead>{t("oauth-clients:columnClientId")}</TableHead>
                  <TableHead>{t("oauth-clients:columnRedirectUris")}</TableHead>
                  <TableHead>{t("oauth-clients:columnAuthMethod")}</TableHead>
                  <TableHead>{t("oauth-clients:columnSecret")}</TableHead>
                  <TableHead>{t("oauth-clients:columnCreated")}</TableHead>
                  <TableHead className="w-[100px]">
                    {t("oauth-clients:columnActions")}
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-12">
                      <p className="text-muted-foreground">
                        {t("oauth-clients:loading")}
                      </p>
                    </TableCell>
                  </TableRow>
                ) : clients.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-12">
                      <p className="text-muted-foreground">
                        {t("oauth-clients:noClients")}
                      </p>
                      <p className="text-sm text-muted-foreground">
                        {t("oauth-clients:noClientsDescription")}
                      </p>
                    </TableCell>
                  </TableRow>
                ) : (
                  clients.map((client) => (
                    <TableRow key={client.client_id}>
                      <TableCell className="font-medium">
                        {client.client_name}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <code className="text-sm font-mono break-all">
                            {client.client_id}
                          </code>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => copyToClipboard(client.client_id)}
                          >
                            <Copy className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-col gap-1">
                          {client.redirect_uris.map((uri) => (
                            <code
                              key={uri}
                              className="text-xs font-mono break-all"
                            >
                              {uri}
                            </code>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell>
                        <code className="text-xs font-mono">
                          {client.token_endpoint_auth_method}
                        </code>
                      </TableCell>
                      <TableCell>
                        {/* Presence only — the stored secret is never sent to
                            the browser after the one-time create response. */}
                        <Badge
                          variant={
                            client.has_client_secret ? "default" : "outline"
                          }
                        >
                          {client.has_client_secret
                            ? t("oauth-clients:hasSecret")
                            : t("oauth-clients:noSecret")}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {format(new Date(client.created_at), "MMM d, yyyy")}
                      </TableCell>
                      <TableCell>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => {
                            setClientToDelete({
                              client_id: client.client_id,
                              client_name: client.client_name,
                            });
                            setDeleteDialogOpen(true);
                          }}
                        >
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </Button>
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
            <AlertDialogTitle>
              {t("oauth-clients:deleteConfirmTitle")}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t("oauth-clients:deleteConfirmDescription", {
                name: clientToDelete?.client_name ?? "",
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setClientToDelete(null)}>
              {t("oauth-clients:cancel")}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDeleteConfirm}
              disabled={deleteMutation.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteMutation.isPending
                ? t("common:deleting")
                : t("oauth-clients:deleteConfirmAction")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
