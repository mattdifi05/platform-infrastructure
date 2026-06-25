"use client";

import type { ReactNode } from "react";
import type { IconType } from "./icons";
import { classNames } from "./classNames";

export function Spinner({ className = "loader-ring ui-async-spinner" }: { className?: string }) {
  return <div aria-hidden="true" className={className} />;
}

export function EmptyState({
  children,
  className,
  icon: Icon,
  role,
  surface,
}: {
  children: ReactNode;
  className: string;
  icon?: IconType;
  role?: "alert" | "status";
  surface?: "gray" | "white";
}) {
  return (
    <div aria-live={role === "status" ? "polite" : undefined} className={className} data-ui-surface={surface} role={role}>
      {Icon ? <Icon aria-hidden="true" size={18} /> : null}
      {children}
    </div>
  );
}

export function InlineAlert({
  children,
  className = "ui-feedback-alert is-info",
  icon: Icon,
  role = "alert",
}: {
  children: ReactNode;
  className?: string;
  icon?: IconType;
  role?: "alert" | "status";
}) {
  return (
    <div className={classNames(className)} role={role}>
      {Icon ? <Icon aria-hidden="true" size={18} /> : null}
      <span>{children}</span>
    </div>
  );
}
