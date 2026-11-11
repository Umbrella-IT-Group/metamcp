import { Button } from "@/components/ui/button";

/** The fields the backend's /oauth/consent/info returns for the screen. */
export interface ConsentInfo {
  client_id: string;
  client_name: string;
  redirect_uri: string;
  scope: string;
}

export interface ConsentDecisionProps {
  info: ConsentInfo;
  /** The signed authorization request the decision posts back. */
  areq: string;
  /** The deployment's organization name (lib/branding), for the warning. */
  orgName: string;
  t: (key: string, params?: Record<string, string | number>) => string;
}

/**
 * The consent screen's request details, warning and Approve/Deny form.
 *
 * Kept free of hooks so it renders on its own in a test. The warning sits
 * directly above the Approve button on purpose: it is the last thing read
 * before approving. It says who supplied the application name and callback
 * (whoever started the request, unverified), what approving grants (that
 * application acts as you), and that nobody from the organization asks anyone
 * to approve or to hand over a code, which is how a consent phish is phrased.
 * Every value from the request is rendered as React text, never as HTML.
 *
 * The form is a plain HTML POST, not a fetch: the backend answers with a 302
 * to the client's redirect_uri (or the loopback code page), and only a real
 * top-level form submission lets the browser follow it. It also carries the
 * double-submit cookie on a same-site POST, which SameSite=Lax permits and a
 * cross-site page cannot reproduce.
 */
export function ConsentDecision({
  info,
  areq,
  orgName,
  t,
}: ConsentDecisionProps) {
  return (
    <>
      <div className="space-y-3 rounded-md border p-4 text-sm">
        <div className="space-y-1">
          <p className="text-base font-medium break-words">
            {info.client_name}
          </p>
          <p className="text-xs text-muted-foreground">
            {t("auth:consentClientNameNote")}
          </p>
        </div>
        <div className="space-y-1">
          <span className="text-muted-foreground">
            {t("auth:consentRedirectLabel")}
          </span>
          <p className="font-mono text-xs break-all">{info.redirect_uri}</p>
        </div>
        <div className="flex justify-between gap-4">
          <span className="text-muted-foreground">
            {t("auth:consentScopeLabel")}
          </span>
          <span className="font-mono">{info.scope}</span>
        </div>
      </div>

      <div
        id="consent-warning"
        role="note"
        className="space-y-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm"
      >
        <p className="font-medium">{t("auth:consentWarning")}</p>
        <p>{t("auth:consentSuppliedBy")}</p>
        <p>{t("auth:consentActsAsYou")}</p>
        <p className="font-medium">{t("auth:consentNoSharing", { orgName })}</p>
      </div>

      <form
        method="POST"
        action="/oauth/authorize/decision"
        className="space-y-3"
      >
        <input type="hidden" name="areq" value={areq} />
        <Button
          type="submit"
          name="decision"
          value="approve"
          className="w-full"
        >
          {t("auth:consentApprove")}
        </Button>
        <Button
          type="submit"
          name="decision"
          value="deny"
          variant="outline"
          className="w-full"
        >
          {t("auth:consentDeny")}
        </Button>
      </form>
    </>
  );
}
