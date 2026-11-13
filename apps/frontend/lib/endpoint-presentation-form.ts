import {
  ENDPOINT_INSTRUCTIONS_MAX,
  ENDPOINT_TITLE_MAX,
  type EndpointPresentation,
  normalizePresentationText,
  type PresentationTextProblem,
  presentationTextProblem,
  type SetEndpointPresentationRequest,
} from "@repo/zod-types";

/**
 * Pure helpers behind the endpoint presentation panel
 * (`components/endpoint-presentation-section.tsx`), kept out of the component so
 * the rules that decide what may be saved are unit-testable without a DOM. The
 * bounds and the character rules are the ones the backend enforces, imported
 * from the shared types rather than restated, so the panel cannot drift from
 * the server it talks to.
 */

/** What the panel edits. Texts are the raw field values, not yet normalized. */
export interface PresentationFormState {
  title: string;
  instructions: string;
  omitOutputSchemas: boolean;
}

/** The part of a stored presentation the form needs. */
export type StoredPresentation = Pick<
  EndpointPresentation,
  "title" | "instructions" | "omit_output_schemas" | "tool_listing"
>;

export function toFormState(
  stored: StoredPresentation | undefined,
): PresentationFormState {
  return {
    title: stored?.title ?? "",
    instructions: stored?.instructions ?? "",
    omitOutputSchemas: stored?.omit_output_schemas ?? false,
  };
}

/**
 * Does saving this form change anything? Texts are compared in their
 * normalized form, so a trailing newline or CRLF line ends do not light up
 * Save, and the stored value (already normalized by the server) is compared
 * as it is.
 *
 * A stored `lean` mode counts as a change: this form cannot represent it and
 * always saves the full listing, so Save has to stay available for an
 * administrator to clear a lean row this gateway version does not serve.
 */
export function isDirty(
  form: PresentationFormState,
  stored: StoredPresentation | undefined,
): boolean {
  if (stored?.tool_listing !== undefined && stored.tool_listing !== "full") {
    return true;
  }
  return (
    normalizePresentationText(form.title) !== (stored?.title ?? null) ||
    normalizePresentationText(form.instructions) !==
      (stored?.instructions ?? null) ||
    form.omitOutputSchemas !== (stored?.omit_output_schemas ?? false)
  );
}

export interface PresentationFormProblems {
  title?: PresentationTextProblem;
  instructions?: PresentationTextProblem;
}

/** The rule each text breaks, judged on the normalized value the server sees. */
export function validate(
  form: PresentationFormState,
): PresentationFormProblems {
  const problems: PresentationFormProblems = {};
  const title = normalizePresentationText(form.title);
  if (title !== null) {
    const problem = presentationTextProblem(title, {
      max: ENDPOINT_TITLE_MAX,
      singleLine: true,
    });
    if (problem !== null) problems.title = problem;
  }
  const instructions = normalizePresentationText(form.instructions);
  if (instructions !== null) {
    const problem = presentationTextProblem(instructions, {
      max: ENDPOINT_INSTRUCTIONS_MAX,
      singleLine: false,
    });
    if (problem !== null) problems.instructions = problem;
  }
  return problems;
}

export function hasProblems(problems: PresentationFormProblems): boolean {
  return problems.title !== undefined || problems.instructions !== undefined;
}

/**
 * The request for the current form. Always the full listing: this gateway
 * version does not serve any other mode. Texts are sent normalized, so what
 * the server stores is what the counter showed.
 */
export function toRequest(
  endpointUuid: string,
  form: PresentationFormState,
): SetEndpointPresentationRequest {
  return {
    endpoint_uuid: endpointUuid,
    title: normalizePresentationText(form.title),
    instructions: normalizePresentationText(form.instructions),
    tool_listing: "full",
    omit_output_schemas: form.omitOutputSchemas,
  };
}

/** How many characters count against the instructions limit. */
export function instructionsLength(form: PresentationFormState): number {
  return normalizePresentationText(form.instructions)?.length ?? 0;
}

/**
 * Enter in the Title field must not submit the endpoint form this panel sits
 * inside (an Enter in a text input is an implicit submit of its form, and that
 * would save the endpoint, not the panel). The panel's buttons are all
 * `type="button"` for the same reason.
 */
export function swallowEnter(event: {
  key: string;
  preventDefault: () => void;
}): void {
  if (event.key === "Enter") event.preventDefault();
}
