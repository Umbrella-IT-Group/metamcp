// Presentation metadata for gateway log/event categories: short tag, filter
// label, and colour. Shared by the Live Logs tail and the History view on the
// same page so a `connection` row looks identical in both — the two render the
// same events, one from the in-memory ring buffer and one from `gateway_events`.
//
// Strings are intentionally literal (not i18n): this is an internal admin
// surface and the operator works in English.
// Literal Tailwind classes (text-*/bg-*) — never build these by string
// concatenation or the JIT purge drops them from the bundle.
export const CATEGORIES = [
  {
    key: "tool_call",
    tag: "TOOL",
    label: "Tool calls",
    text: "text-emerald-400",
    dot: "bg-emerald-400",
  },
  {
    key: "client",
    tag: "CLIENT",
    label: "Client sessions",
    text: "text-fuchsia-400",
    dot: "bg-fuchsia-400",
  },
  {
    key: "connection",
    tag: "CONN",
    label: "Connections",
    text: "text-sky-400",
    dot: "bg-sky-400",
  },
  {
    key: "server",
    tag: "SRV",
    label: "Server",
    text: "text-amber-400",
    dot: "bg-amber-400",
  },
  {
    key: "system",
    tag: "SYS",
    label: "System",
    text: "text-violet-400",
    dot: "bg-violet-400",
  },
] as const;

/**
 * The categories the durable history can actually contain.
 *
 * `tool_call` is deliberately absent: those rows are persisted to
 * `tool_call_audit` instead, so offering the filter here would produce an
 * always-empty page that reads as "no tool calls happened".
 */
export const HISTORY_CATEGORIES = CATEGORIES.filter(
  (category) => category.key !== "tool_call",
);

export const categoryMeta = (category: string) =>
  CATEGORIES.find((c) => c.key === category) ?? {
    tag: "LOG",
    label: category,
    text: "text-gray-400",
  };

export const messageColor = (level: string | null | undefined) =>
  level === "error"
    ? "text-red-300"
    : level === "warn"
      ? "text-amber-300"
      : "text-gray-300";
