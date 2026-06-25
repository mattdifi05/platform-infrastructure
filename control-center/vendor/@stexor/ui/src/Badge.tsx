"use client";

import type { ReactNode } from "react";
import type { IconType } from "./icons";
import { classNames } from "./classNames";

export type BadgeTone = "current" | "danger" | "good" | "neutral" | "warn";

export function Badge({
  children,
  className,
  tone = "neutral",
}: {
  children: ReactNode;
  className?: string;
  tone?: BadgeTone;
}) {
  return <span className={classNames("badge", tone, className)}>{children}</span>;
}

export function StatusBadge({
  icon: Icon,
  label,
  tone,
}: {
  icon: IconType;
  label: string;
  tone: "danger" | "good" | "neutral" | "warn";
}) {
  return (
    <span className={classNames("ui-status", tone)}>
      <Icon aria-hidden="true" size={15} />
      {label}
    </span>
  );
}
