"use client";

export function BrandLogo({
  ariaLabel = "STEXOR",
  href = "https://ui.localhost.com",
  subtitle = null,
  title = "STEXOR",
}: {
  ariaLabel?: string;
  href?: string;
  subtitle?: string | null;
  title?: string;
}) {
  return (
    <a
      aria-label={ariaLabel}
      className="stexor-wordmark"
      href={href}
    >
      <span>{title}</span>
      {subtitle ? <small>{subtitle}</small> : null}
    </a>
  );
}
