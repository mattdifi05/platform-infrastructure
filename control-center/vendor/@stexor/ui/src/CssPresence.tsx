"use client";

import type { ReactNode } from "react";

export function CssPresence({
  children,
  className,
  motionKey: _motionKey,
}: {
  children: ReactNode;
  className: string;
  motionKey: number | string;
}) {
  return <div className={className}>{children}</div>;
}
