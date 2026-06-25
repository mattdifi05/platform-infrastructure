"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import { BadgeCheck, Play, X } from "../icons";
import { ActionFlow, Badge, Spinner } from "../client";
import { classNames } from "../classNames";
import { createUiAsyncMachine, type UiAsyncMachine, type UiAsyncSnapshot } from "../AsyncState";
import { useI18n } from "../i18n";
import { createDynamicCssRule, cssEscape, nextCssRuleId, setDynamicCssProperties } from "../cssom";
const getUiAsyncJobs = (t: ReturnType<typeof useI18n>["t"]) => [
  { label: t("ui.async.job.avatar"), meta: t("ui.async.job.avatar.meta"), progress: 92, tone: "good" as const },
  { label: t("ui.async.job.sessions"), meta: t("ui.async.job.sessions.meta"), progress: 64, tone: "current" as const },
  { label: t("ui.async.job.backup"), meta: t("ui.async.job.backup.meta"), progress: 28, tone: "warn" as const },
];

export function UiAsyncSurface() {
  const { t } = useI18n();
  const [syncMachine, syncSnapshot] = useUiDemoAsyncMachine();
  const syncing = isUiAsyncActive(syncSnapshot);
  useUiDemoAsyncProgress(syncMachine, syncSnapshot, syncing, 32, 94, 2.4);
  const progress = syncing ? syncSnapshot.progress ?? 32 : 100;

  return (
    <div className="ui-async-board" aria-label={t("ui.async.aria")}>
      <div className="ui-async-grid">
        <UiAsyncPanel className="is-loading" title={t("ui.async.loading.title")} meta={t("ui.async.loading.meta")}>
          <div className="ui-async-loading-variants">
            <UiAsyncLoadingSurface
              label={t("ui.surface.white")}
              onToggle={() => toggleUiDemoAsync(syncMachine, "sync")}
              progress={progress}
              syncing={syncing}
              variant="white"
            />
            <UiAsyncLoadingSurface
              label={t("ui.surface.gray")}
              onToggle={() => toggleUiDemoAsync(syncMachine, "sync")}
              progress={progress}
              syncing={syncing}
              variant="gray"
            />
          </div>
        </UiAsyncPanel>

        <UiAsyncPanel className="is-skeleton" title={t("ui.async.skeleton.title")} meta={t("ui.async.skeleton.meta")}>
          <div className="ui-async-skeleton-variants">
            <UiAsyncSkeletonSurface label={t("ui.surface.white")} variant="white" />
            <UiAsyncSkeletonSurface label={t("ui.surface.gray")} variant="gray" />
          </div>
        </UiAsyncPanel>

        <UiAsyncPanel className="is-queue" title={t("ui.async.queue.title")} meta={t("ui.async.queue.meta")}>
          <div className="ui-async-queue-variants">
            <UiAsyncQueueSurface label={t("ui.surface.white")} variant="white" />
            <UiAsyncQueueSurface label={t("ui.surface.gray")} variant="gray" />
          </div>
        </UiAsyncPanel>
      </div>
    </div>
  );
}

function UiAsyncLoadingSurface({
  label,
  onToggle,
  progress,
  syncing,
  variant,
}: {
  label: string;
  onToggle: () => void;
  progress: number;
  syncing: boolean;
  variant: "gray" | "white";
}) {
  const { t } = useI18n();
  return (
    <div className="ui-async-loading-surface" data-ui-surface={variant} aria-label={label}>
      <span className="ui-async-queue-label">{label}</span>
      <div className="ui-async-loading-card" aria-busy={syncing} role="status">
        <Spinner className="loader-ring ui-async-spinner" />
        <div>
          <strong>{syncing ? t("ui.async.loading.syncing") : t("ui.async.loading.done")}</strong>
          <span>{syncing ? t("ui.async.loading.syncingCopy") : t("ui.async.loading.doneCopy")}</span>
        </div>
        <Badge tone={syncing ? "current" : "good"}>{syncing ? t("ui.async.loading.badgeLoading") : t("ui.async.loading.badgeDone")}</Badge>
      </div>
      <UiProgressBar label={t("ui.async.loading.progress", { label })} value={progress} compact />
      <ActionFlow
        active={syncing}
        action={{
          icon: syncing ? X : Play,
          label: syncing ? t("ui.action.interrupt") : t("ui.action.start"),
          onClick: onToggle,
          variant: syncing ? "danger" : "violet",
        }}
        revealAction={{
          icon: BadgeCheck,
          label: t("ui.action.complete"),
          variant: "primary",
        }}
      />
    </div>
  );
}

function UiAsyncSkeletonSurface({
  label,
  variant,
}: {
  label: string;
  variant: "gray" | "white";
}) {
  return (
    <div className="ui-async-skeleton-surface" data-ui-surface={variant} aria-label={label}>
      <span className="ui-async-queue-label">{label}</span>
      <div className="ui-async-skeleton-card" aria-hidden="true">
        <span className="ui-async-skeleton-avatar" />
        <div>
          <span className="ui-async-skeleton-line is-strong" />
          <span className="ui-async-skeleton-line" />
          <span className="ui-async-skeleton-line is-short" />
        </div>
      </div>
      <div className="ui-async-skeleton-list" aria-hidden="true">
        {["a", "b", "c"].map((item) => (
          <span className="ui-async-skeleton-row" key={`${variant}-${item}`} />
        ))}
      </div>
    </div>
  );
}

function UiAsyncPanel({
  children,
  className,
  meta,
  title,
}: {
  children: ReactNode;
  className?: string;
  meta: string;
  title: string;
}) {
  return (
    <section className={classNames("ui-async-panel", className)} aria-label={title}>
      <div className="ui-async-panel-head">
        <div>
          <strong>{title}</strong>
          {" "}
          <span>{meta}</span>
        </div>
      </div>
      {children}
    </section>
  );
}

function UiAsyncQueueSurface({
  label,
  variant,
}: {
  label: string;
  variant: "gray" | "white";
}) {
  const { t } = useI18n();
  const UiAsyncJobs = getUiAsyncJobs(t);

  return (
    <div className="ui-async-queue-surface" data-ui-surface={variant} aria-label={label}>
      <span className="ui-async-queue-label">{label}</span>
      <div className="ui-async-job-list">
        {UiAsyncJobs.map((job) => (
          <div className="ui-async-job" key={`${variant}-${job.label}`}>
            <div>
              <strong>{job.label}</strong>
              <span>{job.meta}</span>
            </div>
            <Badge tone={job.tone}>{job.progress}%</Badge>
            <UiProgressBar label={t("ui.async.queue.progress", { label, job: job.label })} value={job.progress} compact />
          </div>
        ))}
      </div>
    </div>
  );
}

function UiProgressBar({
  compact = false,
  label,
  value,
}: {
  compact?: boolean;
  label: string;
  value: number;
}) {
  const progressIdRef = useRef<string | null>(null);
  const progressRuleRef = useRef<CSSStyleRule | null>(null);
  const clampedValue = Math.max(0, Math.min(100, value));
  if (progressIdRef.current === null) progressIdRef.current = nextCssRuleId("ui-progress");
  const progressId = progressIdRef.current;

  useEffect(() => {
    progressRuleRef.current = createDynamicCssRule(`.ui-async-progress-fill[data-progress-id="${cssEscape(progressId)}"]`);
    return () => {
      setDynamicCssProperties(progressRuleRef.current, {
        "min-width": "",
        width: "",
      });
      progressRuleRef.current = null;
    };
  }, [progressId]);

  useEffect(() => {
    setDynamicCssProperties(progressRuleRef.current, {
      "min-width": clampedValue > 0 ? "var(--ui-progress-fill-min)" : "0",
      width: `${clampedValue}%`,
    });
  }, [clampedValue]);

  return (
    <div className={classNames("ui-async-progress", compact && "is-compact")}>
      {compact ? null : (
        <div>
          <span>{label}</span>
          <strong>{Math.round(clampedValue)}%</strong>
        </div>
      )}
      <div
        aria-label={label}
        aria-valuemax={100}
        aria-valuemin={0}
        aria-valuenow={Math.round(clampedValue)}
        className="ui-async-progress-track"
        role="progressbar"
      >
        <span className="ui-async-progress-fill" data-progress-id={progressId} />
      </div>
    </div>
  );
}

function useUiDemoAsyncMachine() {
  const machineRef = useRef<UiAsyncMachine<string> | null>(null);
  if (machineRef.current === null) machineRef.current = createUiAsyncMachine<string>();
  const [snapshot, setSnapshot] = useState<UiAsyncSnapshot<string>>(machineRef.current.getSnapshot());

  useEffect(() => machineRef.current?.subscribe(setSnapshot), []);

  return [machineRef.current, snapshot] as const;
}

function useUiDemoAsyncProgress(
  machine: UiAsyncMachine<string>,
  snapshot: UiAsyncSnapshot<string>,
  active: boolean,
  min: number,
  max: number,
  step: number,
) {
  const directionRef = useRef(1);
  const progressRef = useRef(min);

  useEffect(() => {
    if (!active) return undefined;
    directionRef.current = 1;
    progressRef.current = min;
    machine.setProgress(min);
    const intervalId = window.setInterval(() => {
      const next = progressRef.current + directionRef.current * step;
      if (next >= max) {
        directionRef.current = -1;
        progressRef.current = max;
        machine.setProgress(max);
        return;
      }
      if (next <= min) {
        directionRef.current = 1;
        progressRef.current = min;
        machine.setProgress(min);
        return;
      }
      progressRef.current = next;
      machine.setProgress(next);
    }, 150);

    return () => window.clearInterval(intervalId);
  }, [active, machine, max, min, snapshot.requestId, step]);
}

function isUiAsyncActive(snapshot: UiAsyncSnapshot<string>) {
  return snapshot.status === "loading" || snapshot.status === "optimistic" || snapshot.status === "progress";
}

function toggleUiDemoAsync(machine: UiAsyncMachine<string>, label: string) {
  const snapshot = machine.getSnapshot();
  if (isUiAsyncActive(snapshot)) {
    machine.cancel();
    return;
  }
  startUiDemoAsync(machine, label);
}

function startUiDemoAsync(machine: UiAsyncMachine<string>, label: string) {
  void machine.run((signal) => new Promise<string>((resolve, reject) => {
    const timer = window.setTimeout(() => resolve(label), 4800);
    signal.addEventListener("abort", () => {
      window.clearTimeout(timer);
      reject(new Error(`${label}_cancelled`));
    }, { once: true });
  }), { progress: 32 });
}
