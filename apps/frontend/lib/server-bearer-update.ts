/**
 * The bearer-token fields of a server edit's update payload.
 *
 * The form never sees the stored token (the API never returns it), so its
 * bearer field is blank unless the administrator typed a new one. The gateway
 * reads a blank token as "keep the stored one" only while the URL is
 * unchanged; on a URL change it refuses the save unless the payload replaces
 * the token or clears it (mcp-servers.repo.ts planServerUpdate on the
 * backend). Clearing is its own flag, sent only when ticked, and it wins over
 * any text left in the field so the payload never asks for both.
 */
export function bearerFieldsForUpdate(form: {
  bearerToken?: string;
  clearBearerToken?: boolean;
}): { bearerToken?: string; clearBearerToken?: true } {
  if (form.clearBearerToken === true) {
    return { bearerToken: "", clearBearerToken: true };
  }
  return { bearerToken: form.bearerToken };
}
