import * as React from "react";

import { cn } from "@/lib/utils";

/**
 * The list-page header wrapper: title and description over the actions on a
 * narrow viewport, and a single justified row from the `sm` breakpoint up.
 *
 * The pages used a plain `flex items-center justify-between` here, which never
 * wraps, so on a phone the action buttons stayed on the title's row, collided
 * with it, and pushed the page body wider than the viewport. Exported as a
 * shared constant so every header wraps the same way and a page with a bespoke
 * header (the live-logs console toolbar) can reuse the behaviour without
 * copying the class list.
 */
export const pageHeaderRow =
  "flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between";

interface PageHeaderProps {
  /** Leading icon element, rendered at the caller's own size. */
  icon?: React.ReactNode;
  title: React.ReactNode;
  description?: React.ReactNode;
  /** Header actions (buttons, dialogs). Laid out in a wrapping flex row. */
  actions?: React.ReactNode;
  className?: string;
}

/**
 * Shared header for the list pages (title + description + actions). One
 * component so the responsive stacking lives in a single place instead of a
 * per-page copy of the flex classes. `min-w-0` on the text column lets a long
 * title/description shrink instead of forcing the row wider than its container.
 */
export function PageHeader({
  icon,
  title,
  description,
  actions,
  className,
}: PageHeaderProps) {
  return (
    <div className={cn(pageHeaderRow, className)}>
      <div className="flex min-w-0 items-center gap-3">
        {icon}
        <div className="min-w-0">
          <h1 className="text-3xl font-bold tracking-tight">{title}</h1>
          {description ? (
            <p className="text-muted-foreground">{description}</p>
          ) : null}
        </div>
      </div>
      {actions ? (
        <div className="flex flex-wrap items-center gap-2">{actions}</div>
      ) : null}
    </div>
  );
}
