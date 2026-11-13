/**
 * The translator the Inspector's presentational components take as a prop.
 *
 * `useTranslations()` returns raw keys until its dictionary has loaded, and
 * the frontend test harness has no DOM, so a component that called the hook
 * itself could not be rendered in a test. These components take `t` from their
 * container instead (the same shape `oauth-client-approval.tsx` uses), and the
 * tests build a real one from the locale JSON.
 */
export type Translate = (
  key: string,
  params?: Record<string, string | number>,
) => string;
