"use client";

import type { ReactNode } from "react";

export type FactItem = {
  label: string;
  value: ReactNode;
  wide?: boolean;
};

export function FactGrid({
  className,
  emptyValue = "-",
  items,
}: {
  className: string;
  emptyValue?: ReactNode;
  items: FactItem[];
}) {
  return (
    <dl className={className}>
      {items.map((item) => (
        <div className={item.wide ? "wide" : undefined} key={item.label}>
          <dt>{item.label}</dt>
          <dd>{isEmptyFact(item.value) ? emptyValue : item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function isEmptyFact(value: ReactNode) {
  return value === "" || value === null || typeof value === "undefined";
}
