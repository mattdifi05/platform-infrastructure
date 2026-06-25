"use client";

import { useState, type ReactNode } from "react";
import { AlertTriangle, BadgeCheck, Bell, CircleInfo, ShieldCheck, X, type IconType } from "../icons";
import { Button, FieldGroup, InlineAlert, SelectField, StatusBadge, StatusPill, TextField, UiFeedbackEmpty, UiPopupProvider, useDynamicCssProperties, useUiPopup } from "../client";
import { useI18n, type TranslationKey } from "../i18n";

type FeedbackBuilderTone = "danger" | "good" | "neutral" | "warn";

const feedbackBuilderTones: Array<{ labelKey: TranslationKey; value: FeedbackBuilderTone }> = [
  { labelKey: "ui.badge.good", value: "good" },
  { labelKey: "ui.badge.warn", value: "warn" },
  { labelKey: "ui.badge.danger", value: "danger" },
  { labelKey: "ui.badge.neutral", value: "neutral" },
];

const feedbackBuilderToneClassNames: Record<FeedbackBuilderTone, string> = {
  danger: "is-danger",
  good: "is-good",
  neutral: "is-info",
  warn: "is-warn",
};
const feedbackPopupDemoDynamicProperties = { "--ui-feedback-popup-action-gap": "10px" } as const;
const feedbackPopupDemoDynamicPropertyNames = ["--ui-feedback-popup-action-gap"] as const;

export function UiFeedbackSurface() {
  const { t } = useI18n();

  return (
    <UiPopupProvider ariaLabel={t("ui.feedback.popup.aria")}>
      <div className="ui-feedback-layout" aria-label={t("ui.section.feedback.title")}>
        <UiFeedbackPopupDemo />
        <UiFeedbackBuilderSurface />
      </div>
    </UiPopupProvider>
  );
}

function UiFeedbackPopupDemo() {
  const { t } = useI18n();
  const { showPopup } = useUiPopup();
  useDynamicCssProperties(
    ".ui-feedback-popup-demo .ui-feedback-popup-actions",
    feedbackPopupDemoDynamicProperties,
    feedbackPopupDemoDynamicPropertyNames,
  );

  return (
    <section className="ui-feedback-panel ui-feedback-popup-demo" aria-label={t("ui.feedback.popup.title")} data-ui-surface="white">
      <div className="ui-feedback-panel-head">
        <div>
          <strong>{t("ui.feedback.popup.title")}</strong>
          <span>{t("ui.feedback.popup.meta")}</span>
        </div>
        <StatusPill tone="neutral">{t("ui.feedback.popup.badge")}</StatusPill>
      </div>
      <InlineAlert className="ui-feedback-alert is-info" icon={CircleInfo} role="status">
        {t("ui.feedback.popup.info.copy")}
      </InlineAlert>
      <div className="ui-feedback-popup-actions">
        <Button
          icon={CircleInfo}
          onClick={() => showPopup({
            closeLabel: t("ui.feedback.popup.close"),
            copy: t("ui.feedback.popup.info.copy"),
            title: t("ui.feedback.popup.info.title"),
            tone: "info",
          })}
          variant="primary"
        >
          {t("ui.feedback.popup.info.trigger")}
        </Button>
        <Button
          icon={BadgeCheck}
          onClick={() => showPopup({
            closeLabel: t("ui.feedback.popup.close"),
            copy: t("ui.feedback.popup.good.copy"),
            duration: "short",
            title: t("ui.feedback.popup.good.title"),
            tone: "good",
          })}
          variant="edit"
        >
          {t("ui.feedback.popup.good.trigger")}
        </Button>
        <Button
          icon={AlertTriangle}
          onClick={() => showPopup({
            closeLabel: t("ui.feedback.popup.close"),
            copy: t("ui.feedback.popup.warning.copy"),
            duration: "long",
            title: t("ui.feedback.popup.warning.title"),
            tone: "warning",
          })}
          variant="warning"
        >
          {t("ui.feedback.popup.warning.trigger")}
        </Button>
      </div>
    </section>
  );
}

function UiFeedbackBuilderSurface() {
  const { t } = useI18n();
  const [emptyCopy, setEmptyCopy] = useState(t("ui.feedback.builder.defaultCopy"));
  const [emptyLabel, setEmptyLabel] = useState(t("ui.feedback.empty.noResults"));
  const [emptyTone, setEmptyTone] = useState<FeedbackBuilderTone>("neutral");
  const [pillLabel, setPillLabel] = useState(t("ui.status.confirmed"));
  const [pillTone, setPillTone] = useState<FeedbackBuilderTone>("good");
  const [statusLabel, setStatusLabel] = useState(t("ui.status.protected"));
  const [statusTone, setStatusTone] = useState<FeedbackBuilderTone>("good");
  const resolvedEmptyCopy = emptyCopy.trim() || t("ui.feedback.builder.defaultCopy");
  const resolvedEmptyLabel = emptyLabel.trim() || t("ui.feedback.builder.fallbackLabel");
  const resolvedPillLabel = pillLabel.trim() || t("ui.feedback.builder.fallbackLabel");
  const resolvedStatusLabel = statusLabel.trim() || t("ui.feedback.builder.fallbackLabel");

  return (
    <section className="ui-feedback-board ui-feedback-builder-layout" aria-label={t("ui.feedback.builder.aria")} data-ui-surface="gray">
      <div className="ui-feedback-panel-head">
        <div>
          <strong>{t("ui.feedback.builder.title")}</strong>
          <span>{t("ui.feedback.builder.meta")}</span>
        </div>
      </div>
      <div className="ui-feedback-builder-card-grid">
        <FeedbackBuilderCard
          controls={(
            <>
              <SelectField icon={CircleInfo} label={t("ui.feedback.builder.tone")} onChange={(value) => setPillTone(value as FeedbackBuilderTone)} options={feedbackBuilderTones.map((item) => ({ label: t(item.labelKey), value: item.value }))} value={pillTone} />
              <TextField icon={BadgeCheck} label={t("ui.feedback.builder.label")} onChange={setPillLabel} value={pillLabel} />
            </>
          )}
          meta={t("ui.feedback.builder.pill.meta")}
          title={t("ui.feedback.builder.pill.title")}
        >
          <FeedbackBuilderPreviewPair label={resolvedPillLabel} tone={pillTone} type="pill" />
        </FeedbackBuilderCard>
        <FeedbackBuilderCard
          controls={(
            <>
              <SelectField icon={CircleInfo} label={t("ui.feedback.builder.tone")} onChange={(value) => setStatusTone(value as FeedbackBuilderTone)} options={feedbackBuilderTones.map((item) => ({ label: t(item.labelKey), value: item.value }))} value={statusTone} />
              <TextField icon={ShieldCheck} label={t("ui.feedback.builder.label")} onChange={setStatusLabel} value={statusLabel} />
            </>
          )}
          meta={t("ui.feedback.builder.status.meta")}
          title={t("ui.feedback.builder.status.title")}
        >
          <FeedbackBuilderPreviewPair label={resolvedStatusLabel} tone={statusTone} type="status" />
        </FeedbackBuilderCard>
        <FeedbackBuilderCard
          controls={(
            <>
              <SelectField icon={CircleInfo} label={t("ui.feedback.builder.tone")} onChange={(value) => setEmptyTone(value as FeedbackBuilderTone)} options={feedbackBuilderTones.map((item) => ({ label: t(item.labelKey), value: item.value }))} value={emptyTone} />
              <TextField icon={BadgeCheck} label={t("ui.feedback.builder.label")} onChange={setEmptyLabel} value={emptyLabel} />
              <TextField icon={Bell} label={t("ui.feedback.builder.copy")} onChange={setEmptyCopy} value={emptyCopy} />
            </>
          )}
          meta={t("ui.feedback.builder.empty.meta")}
          title={t("ui.feedback.builder.empty.title")}
        >
          <FeedbackBuilderPreviewPair copy={resolvedEmptyCopy} label={resolvedEmptyLabel} tone={emptyTone} type="empty" />
        </FeedbackBuilderCard>
      </div>
    </section>
  );
}

function FeedbackBuilderCard({
  children,
  controls,
  meta,
  title,
}: {
  children: ReactNode;
  controls: ReactNode;
  meta: string;
  title: string;
}) {
  return (
    <section className="ui-feedback-panel ui-feedback-builder-card" aria-label={title} data-ui-surface="gray">
      <div className="ui-feedback-panel-head">
        <div>
          <strong>{title}</strong>
          <span>{meta}</span>
        </div>
      </div>
      <div className="ui-feedback-builder-card-body">
        <FieldGroup className="ui-feedback-builder-controls">
          {controls}
        </FieldGroup>
        {children}
      </div>
    </section>
  );
}

function FeedbackBuilderPreviewPair({
  copy,
  label,
  tone,
  type,
}: {
  copy?: string;
  label: string;
  tone: FeedbackBuilderTone;
  type: "empty" | "pill" | "status";
}) {
  const { t } = useI18n();
  return (
    <div className="ui-feedback-builder-preview-grid" aria-label={t("ui.feedback.builder.preview")}>
      <div className="ui-feedback-builder-preview" data-ui-surface="white">
        <span className="ui-feedback-empty-label">{t("ui.surface.whiteShort")}</span>
        <FeedbackBuilderPreview copy={copy} label={label} surface="white" tone={tone} type={type} />
      </div>
      <div className="ui-feedback-builder-preview" data-ui-surface="gray">
        <span className="ui-feedback-empty-label">{t("ui.surface.grayShort")}</span>
        <FeedbackBuilderPreview copy={copy} label={label} surface="gray" tone={tone} type={type} />
      </div>
    </div>
  );
}

function FeedbackBuilderPreview({
  copy,
  label,
  surface,
  tone,
  type,
}: {
  copy?: string;
  label: string;
  surface: "gray" | "white";
  tone: FeedbackBuilderTone;
  type: "empty" | "pill" | "status";
}) {
  const Icon = getFeedbackBuilderIcon(tone);
  const statusTone: "danger" | "good" | "neutral" | "warn" = tone;
  const pillTone: "danger" | "good" | "neutral" | "warning" = tone === "warn" ? "warning" : tone;
  const emptyTone: "danger" | "good" | "info" | "warn" = tone === "neutral" ? "info" : tone === "warn" ? "warn" : tone;
  const emptySurface = surface === "white" ? "gray" : "white";

  return (
    <div className={`ui-feedback-builder-preview-content ${feedbackBuilderToneClassNames[tone]}`}>
      {type === "status" ? <StatusBadge icon={Icon} label={label} tone={statusTone} /> : null}
      {type === "pill" ? <StatusPill tone={pillTone}>{label}</StatusPill> : null}
      {type === "empty" ? <UiFeedbackEmpty copy={copy} icon={Icon} surface={emptySurface} title={label} tone={emptyTone} /> : null}
    </div>
  );
}

function getFeedbackBuilderIcon(tone: FeedbackBuilderTone): IconType {
  if (tone === "danger") return X;
  if (tone === "good") return ShieldCheck;
  if (tone === "warn") return AlertTriangle;
  return CircleInfo;
}
