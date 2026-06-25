"use client";
export function UiToken({
  meta,
  title,
  tone = "surface",
}: {
  meta: string;
  title: string;
  tone?: "accent" | "danger" | "green" | "muted" | "surface" | "yellow";
}) {
  return (
    <div className={`ui-token is-${tone}`}>
      <span>{title}</span>
      <strong>{meta}</strong>
    </div>
  );
}
