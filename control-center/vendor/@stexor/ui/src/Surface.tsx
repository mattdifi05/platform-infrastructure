"use client";

import type { ReactNode } from "react";
import type { IconType } from "./icons";
import { CssPresence } from "./CssPresence";
import { EmptyState } from "./States";
import { FactGrid } from "./FactGrid";
import { classNames } from "./classNames";
import { uiClassNames } from "./styleClasses";

export type UiTone = "danger" | "good" | "neutral" | "warning";

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="ui-metric motion-surface">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export function UiMetricGrid({ items }: { items: Array<{ label: string; value: string }> }) {
  return (
    <div className="ui-overview-grid ui-overview-cluster">
      {items.map((item) => (
        <Metric key={item.label} label={item.label} value={item.value} />
      ))}
    </div>
  );
}

export function SectionHeader({
  aside,
  className = uiClassNames.sectionHead,
  icon: Icon,
  iconClassName = uiClassNames.sectionIcon,
  meta,
  title,
}: {
  aside?: ReactNode;
  className?: string;
  icon: IconType;
  iconClassName?: string;
  meta?: string;
  title: string;
}) {
  return (
    <div className={className}>
      <span className={iconClassName}><Icon size={16} /></span>
      <div>
        <h3>{title}</h3>
        {meta ? <p>{meta}</p> : null}
      </div>
      {aside ? <div className={uiClassNames.sectionAside}>{aside}</div> : null}
    </div>
  );
}

export function SectionCard({
  ariaLabel,
  aside,
  bodyClassName,
  children,
  className,
  headClassName,
  headerVisible = true,
  icon: Icon,
  iconClassName,
  meta,
  surface,
  title,
}: {
  ariaLabel?: string;
  aside?: ReactNode;
  bodyClassName: string;
  children: ReactNode;
  className: string;
  headClassName: string;
  headerVisible?: boolean;
  icon: IconType;
  iconClassName: string;
  meta?: string;
  surface?: "gray" | "white";
  title: string;
}) {
  const resolvedSurface = surface ?? "white";

  return (
    <section aria-label={ariaLabel ?? (!headerVisible ? title : undefined)} className={className} data-ui-surface={resolvedSurface}>
      {headerVisible ? (
        <SectionHeader aside={aside} className={headClassName} icon={Icon} iconClassName={iconClassName} meta={meta} title={title} />
      ) : null}
      <div className={bodyClassName}>
        {children}
      </div>
    </section>
  );
}

type UiSectionCardProps = Omit<Parameters<typeof SectionCard>[0], "bodyClassName" | "className" | "headClassName" | "iconClassName"> & {
  bodyClassName?: string;
  className?: string;
  headClassName?: string;
  iconClassName?: string;
};

export function UiSectionCard({
  bodyClassName = "ui-section-body",
  className = "ui-section",
  headClassName = "ui-section-head",
  iconClassName = "ui-section-icon",
  ...props
}: UiSectionCardProps) {
  return (
    <SectionCard
      bodyClassName={bodyClassName}
      className={className}
      headClassName={headClassName}
      iconClassName={iconClassName}
      {...props}
    />
  );
}

export function UiSectionStack({ children }: { children: ReactNode }) {
  return <div className="ui-section-body">{children}</div>;
}

export function UiPanelFrame({
  ariaLabel,
  beforePanel,
  children,
  id,
  motionKey,
}: {
  ariaLabel?: string;
  beforePanel?: ReactNode;
  children: ReactNode;
  id?: string;
  motionKey: number | string;
}) {
  return (
    <div className="ui-page">
      <div className="ui-workspace">
        {beforePanel}
        <CssPresence className="ui-panel-motion" motionKey={motionKey}>
          <div aria-label={ariaLabel} className="ui-panel-stack ui-section-panel" id={id} role="region">
            {children}
          </div>
        </CssPresence>
      </div>
    </div>
  );
}

export function UiFactGrid({
  className = "ui-facts ui-overview-cluster",
  ...props
}: Omit<Parameters<typeof FactGrid>[0], "className"> & {
  className?: string;
}) {
  return <FactGrid className={className} {...props} />;
}

export function UiFeedbackEmpty({
  copy,
  icon,
  surface = "white",
  title,
  tone = "info",
}: {
  copy?: string;
  icon: IconType;
  surface?: "gray" | "white";
  title: string;
  tone?: "danger" | "good" | "info" | "warn";
}) {
  return (
    <EmptyState className={`ui-feedback-empty is-${tone}`} icon={icon} role="status" surface={surface}>
      <div>
        <strong>{title}</strong>
        {copy ? <span>{copy}</span> : null}
      </div>
    </EmptyState>
  );
}

export function StatusPill({
  children,
  className,
  tone = "neutral",
}: {
  children: ReactNode;
  className?: string;
  tone?: UiTone;
}) {
  return <span className={classNames(uiClassNames.statusPill, `is-${tone}`, className)}>{children}</span>;
}
