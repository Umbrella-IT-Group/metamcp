/**
 * Pick the singular or plural label for a count.
 *
 * The app's i18n layer does `{{param}}` interpolation only, it has no ICU
 * plural rules, so count-driven noun agreement is handled at the call site
 * instead of in the locale files. Callers pass both forms (usually two `t()`
 * lookups) so the choice stays translatable; the `plural` argument is optional
 * for the English-only internal case, where the regular "+s" plural is enough.
 *
 * Chinese and Korean do not inflect for number, so their locale files carry the
 * same word for both forms and this helper returns it unchanged either way.
 */
export function pluralize(
  count: number,
  singular: string,
  plural?: string,
): string {
  if (count === 1) {
    return singular;
  }
  return plural ?? `${singular}s`;
}
