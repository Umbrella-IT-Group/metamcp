"use client";

import type {
  GetEndpointPresentationResponse,
  PresentationTextProblem,
  SetEndpointPresentationRequest,
  ToolListingMode,
} from "@repo/zod-types";
import { ENDPOINT_INSTRUCTIONS_MAX, ENDPOINT_TITLE_MAX } from "@repo/zod-types";
import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { useTranslations } from "@/hooks/useTranslations";
import { authClient } from "@/lib/auth-client";
import {
  hasProblems,
  instructionsLength,
  isDirty,
  type PresentationFormState,
  swallowEnter,
  toFormState,
  toRequest,
  validate,
} from "@/lib/endpoint-presentation-form";
import { trpc } from "@/lib/trpc";

type Translate = (
  key: string,
  params?: Record<string, string | number>,
) => string;

type StoredWithEffective = NonNullable<GetEndpointPresentationResponse["data"]>;

/**
 * The text a problem is reported with. The same rules and bounds the server
 * enforces (they come from the shared types), worded for the field.
 */
function problemText(
  t: Translate,
  problem: PresentationTextProblem,
  max: number,
): string {
  return t(`endpoints:presentation.problem.${problem}`, { max });
}

/**
 * The editing form, driven entirely by props: no tRPC, no session lookup. The
 * wrapper below supplies those; keeping them apart is what lets a test render
 * every state of this form directly.
 */
export function EndpointPresentationForm({
  endpointUuid,
  t,
  status,
  errorMessage,
  stored,
  saving,
  onSave,
}: {
  endpointUuid: string;
  t: Translate;
  /** `loading` and `error` never offer Save: the stored state is unknown. */
  status: "loading" | "error" | "ready";
  errorMessage?: string;
  stored: StoredWithEffective | undefined;
  saving: boolean;
  onSave: (request: SetEndpointPresentationRequest) => void;
}) {
  const [form, setForm] = useState<PresentationFormState>(() =>
    toFormState(stored),
  );

  // Re-seed when the stored state changes underneath the form: the first load,
  // or a save that came back. `updated_at` is null until a row exists, so the
  // other fields are part of the key too.
  const storedKey = stored
    ? `${stored.updated_at ?? ""}|${stored.title ?? ""}|${stored.instructions ?? ""}|${stored.omit_output_schemas}|${stored.tool_listing}`
    : "";
  useEffect(() => {
    setForm(toFormState(stored));
    // `stored` is summarized by storedKey; depending on the object itself
    // would re-seed on every query refetch that returns the same data.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [storedKey]);

  return (
    <div className="space-y-4 border-t pt-4">
      <h4 className="text-sm font-medium">
        {t("endpoints:presentation.title")}
      </h4>

      {status === "loading" && (
        <p className="text-xs text-muted-foreground">
          {t("endpoints:presentation.loading")}
        </p>
      )}

      {status === "error" && (
        // No form and no Save: replacing settings that could not be read would
        // overwrite them with whatever the fields happen to hold.
        <p className="text-sm text-destructive">
          {errorMessage || t("endpoints:presentation.loadFailed")}
        </p>
      )}

      {status === "ready" && stored && (
        <ReadyForm
          endpointUuid={endpointUuid}
          t={t}
          stored={stored}
          saving={saving}
          onSave={onSave}
          form={form}
          setForm={setForm}
        />
      )}
    </div>
  );
}

/**
 * The fields, once the stored state is known. HOOK-FREE on purpose (the form
 * state lives in the parent and arrives as props), so a test can call it as a
 * plain function and walk the element tree: that is how the handlers (Enter in
 * the title, Save, Reset, the trim switch) are exercised without a DOM.
 */
export function ReadyForm({
  endpointUuid,
  t,
  stored,
  saving,
  onSave,
  form,
  setForm,
}: {
  endpointUuid: string;
  t: Translate;
  stored: StoredWithEffective;
  saving: boolean;
  onSave: (request: SetEndpointPresentationRequest) => void;
  form: PresentationFormState;
  setForm: (next: PresentationFormState) => void;
}) {
  const problems = validate(form);
  const dirty = isDirty(form, stored);
  const canSave = dirty && !hasProblems(problems) && !saving;

  return (
    <>
      <p className="text-xs text-muted-foreground">
        {t("endpoints:presentation.description")}
      </p>

      {!stored.effective.presentation_enabled && (
        // The settings are saved but the gateway is not applying them. Said
        // outright: a field that reads as live and does nothing misleads.
        <div className="p-3 bg-yellow-50 dark:bg-yellow-950/20 border border-yellow-200 dark:border-yellow-800/30 rounded-md">
          <p className="text-sm text-yellow-800 dark:text-yellow-200">
            {t("endpoints:presentation.killSwitch")}
          </p>
        </div>
      )}

      {(stored.tool_listing === "lean" || form.toolListing === "lean") &&
        !stored.effective.lean_enabled && (
          // Lean is saved (or about to be) but this process serves the full
          // list: the lean switch is narrower than the master one, so title,
          // instructions and the trim still apply. Said outright for the same
          // reason as the master banner above.
          <div className="p-3 bg-yellow-50 dark:bg-yellow-950/20 border border-yellow-200 dark:border-yellow-800/30 rounded-md">
            <p className="text-sm text-yellow-800 dark:text-yellow-200">
              {t("endpoints:presentation.leanKillSwitch")}
            </p>
          </div>
        )}

      <div className="space-y-1">
        <label
          className="text-sm font-medium"
          htmlFor="endpoint-presentation-title"
        >
          {t("endpoints:presentation.titleLabel")}
        </label>
        <Input
          id="endpoint-presentation-title"
          value={form.title}
          placeholder={t("endpoints:presentation.titlePlaceholder")}
          onChange={(event) => setForm({ ...form, title: event.target.value })}
          // Enter must not submit the endpoint form around this panel.
          onKeyDown={swallowEnter}
          disabled={saving}
        />
        {problems.title && (
          <p className="text-xs text-destructive">
            {problemText(t, problems.title, ENDPOINT_TITLE_MAX)}
          </p>
        )}
        <p className="text-xs text-muted-foreground">
          {t("endpoints:presentation.titleHelp")}
        </p>
      </div>

      <div className="space-y-1">
        <label
          className="text-sm font-medium"
          htmlFor="endpoint-presentation-instructions"
        >
          {t("endpoints:presentation.instructionsLabel")}
        </label>
        <Textarea
          id="endpoint-presentation-instructions"
          rows={6}
          value={form.instructions}
          placeholder={t("endpoints:presentation.instructionsPlaceholder")}
          onChange={(event) =>
            setForm({ ...form, instructions: event.target.value })
          }
          disabled={saving}
        />
        <div className="flex items-start justify-between gap-2">
          <div>
            {problems.instructions && (
              <p className="text-xs text-destructive">
                {problemText(
                  t,
                  problems.instructions,
                  ENDPOINT_INSTRUCTIONS_MAX,
                )}
              </p>
            )}
            <p className="text-xs text-muted-foreground">
              {t("endpoints:presentation.instructionsHelp")}
            </p>
          </div>
          <span className="text-xs text-muted-foreground whitespace-nowrap">
            {t("endpoints:presentation.counter", {
              count: instructionsLength(form),
              max: ENDPOINT_INSTRUCTIONS_MAX,
            })}
          </span>
        </div>
      </div>

      <div className="space-y-1">
        <label
          className="text-sm font-medium"
          htmlFor="endpoint-presentation-listing"
        >
          {t("endpoints:presentation.listingLabel")}
        </label>
        <Select
          value={form.toolListing}
          onValueChange={(value) =>
            setForm({ ...form, toolListing: value as ToolListingMode })
          }
          disabled={saving}
        >
          <SelectTrigger id="endpoint-presentation-listing">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="full">
              {t("endpoints:presentation.listingFull")}
            </SelectItem>
            <SelectItem value="lean">
              {t("endpoints:presentation.listingLean")}
            </SelectItem>
          </SelectContent>
        </Select>
        <p className="text-xs text-muted-foreground">
          {t("endpoints:presentation.listingHelp")}
        </p>
        {form.toolListing === "lean" && (
          // The consequences are spelled out where the choice is made: they are
          // the ones an administrator cannot see from the gateway afterwards.
          <div className="space-y-2 p-3 bg-yellow-50 dark:bg-yellow-950/20 border border-yellow-200 dark:border-yellow-800/30 rounded-md">
            <p className="text-xs text-yellow-800 dark:text-yellow-200">
              {t("endpoints:presentation.leanTradeoffs")}
            </p>
            <p className="text-xs text-yellow-800 dark:text-yellow-200">
              {t("endpoints:presentation.leanTwin")}
            </p>
          </div>
        )}
      </div>

      <div className="flex items-center justify-between">
        <div className="space-y-0.5">
          <label className="text-sm font-medium">
            {t("endpoints:presentation.omitLabel")}
          </label>
          <p className="text-xs text-muted-foreground">
            {form.toolListing === "lean"
              ? t("endpoints:presentation.omitLeanNote")
              : t("endpoints:presentation.omitHelp")}
          </p>
        </div>
        <Switch
          checked={form.omitOutputSchemas}
          onCheckedChange={(checked) =>
            setForm({ ...form, omitOutputSchemas: checked })
          }
          // The lean list carries no output schemas, so the trim has nothing to
          // do while lean is chosen. Disabled rather than cleared: the value is
          // kept for the day the endpoint goes back to the full list.
          disabled={saving || form.toolListing === "lean"}
        />
      </div>

      <p className="text-xs text-muted-foreground">
        {t("endpoints:presentation.timing")}
      </p>
      <p className="text-xs text-muted-foreground">
        {t("endpoints:presentation.auditNote")}
      </p>

      <div className="flex justify-end gap-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => setForm(toFormState(stored))}
          disabled={!dirty || saving}
        >
          {t("endpoints:presentation.reset")}
        </Button>
        <Button
          type="button"
          size="sm"
          onClick={() => onSave(toRequest(endpointUuid, form))}
          disabled={!canSave}
        >
          {saving
            ? t("endpoints:presentation.saving")
            : t("endpoints:presentation.save")}
        </Button>
      </div>
    </>
  );
}

/**
 * The Presentation panel on the endpoint edit dialog (migration 0044).
 *
 * NOT A FIELD OF THAT DIALOG'S FORM, like the Access panel beside it: it reads
 * and writes through its own procedures, so a Save on the panel never rides
 * along with an endpoint edit and Cancel on the dialog does not discard it.
 *
 * Read AND write are `adminProcedure`, so this renders nothing for anyone else.
 * That is presentation only; the backend is the boundary.
 */
export function EndpointPresentationSection({
  endpointUuid,
}: {
  endpointUuid: string;
}) {
  const { t } = useTranslations();
  const utils = trpc.useUtils();

  // Fail closed: isAdmin starts false and a failed session lookup leaves it
  // false, so an error hides the panel rather than showing a dead one. Same
  // idiom as the Access panel.
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

  const query = trpc.frontend.endpointPresentation.get.useQuery(
    { endpoint_uuid: endpointUuid },
    { enabled: isAdmin && Boolean(endpointUuid) },
  );

  const saveMutation = trpc.frontend.endpointPresentation.set.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        utils.frontend.endpointPresentation.get.invalidate({
          endpoint_uuid: endpointUuid,
        });
        toast.success(t("endpoints:presentation.saved"));
      } else {
        toast.error(data.message || t("endpoints:presentation.saveFailed"));
      }
    },
    onError: (error) => {
      toast.error(
        `${t("endpoints:presentation.saveFailed")}: ${error.message}`,
      );
    },
  });

  if (!isAdmin) return null;

  // A failed read, a refetch that failed after earlier success, and a
  // `success: false` answer all leave the stored state unknown or stale: none
  // of them may offer Save.
  const answer = query.data;
  const stored = answer?.success ? answer.data : undefined;
  let status: "loading" | "error" | "ready" = "ready";
  let errorMessage: string | undefined;
  if (query.isError) {
    status = "error";
    errorMessage = query.error?.message;
  } else if (query.data === undefined) {
    status = "loading";
  } else if (!stored) {
    status = "error";
    errorMessage = answer?.message;
  }

  return (
    <EndpointPresentationForm
      endpointUuid={endpointUuid}
      t={t}
      status={status}
      errorMessage={errorMessage}
      stored={stored}
      saving={saveMutation.isPending}
      onSave={(request) => saveMutation.mutate(request)}
    />
  );
}
