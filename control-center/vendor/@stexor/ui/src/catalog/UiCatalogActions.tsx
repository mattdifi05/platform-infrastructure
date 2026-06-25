"use client";

import { useState } from "react";
import { ActionFlow, CheckboxField, ChoiceCard, RadioField, RangeField, SwitchField } from "../client";
import { Play, X } from "../icons";
import { useI18n } from "../i18n";
import { getUiModalChoiceItems, type UiModalChoiceId } from "./UiCatalogModals";
import { UiButtonBuilderSurface } from "./UiCatalogActionBuilder";
export function UiButtonsSurface({
  checkEnabled,
  onCheckChange,
  onRadioChange,
  onSwitchChange,
  radioValue,
  switchEnabled,
}: {
  checkEnabled: boolean;
  onCheckChange: (checked: boolean) => void;
  onRadioChange: (value: "primary" | "secondary") => void;
  onSwitchChange: (checked: boolean) => void;
  radioValue: "primary" | "secondary";
  switchEnabled: boolean;
}) {
  const { t } = useI18n();
  const [grayCheckEnabled, setGrayCheckEnabled] = useState(false);
  const [grayChoiceValue, setGrayChoiceValue] = useState<UiModalChoiceId>("balanced");
  const [grayRadioValue, setGrayRadioValue] = useState<"primary" | "secondary">("primary");
  const [grayRangeValue, setGrayRangeValue] = useState(42);
  const [graySwitchEnabled, setGraySwitchEnabled] = useState(false);
  const [choiceValue, setChoiceValue] = useState<UiModalChoiceId>("balanced");
  const [rangeValue, setRangeValue] = useState(64);
  const [flowCompact, setFlowCompact] = useState(false);
  const [flowRunning, setFlowRunning] = useState(false);
  const [flowShowLabel, setFlowShowLabel] = useState(true);

  return (
    <div className="ui-actions-layout" aria-label={t("ui.section.actions.title")}>
      <UiButtonBuilderSurface />
      <CatalogActionFlowRows
        compact={flowCompact}
        onCompactChange={setFlowCompact}
        onShowLabelChange={setFlowShowLabel}
        onStop={() => setFlowRunning(false)}
        onToggle={() => setFlowRunning((current) => !current)}
        running={flowRunning}
        showLabel={flowShowLabel}
      />
      <section className="ui-actions-block ui-actions-paired-block ui-actions-choices-block" data-ui-surface="gray" aria-label={t("ui.actions.choicesAria")}>
        <div className="ui-actions-block-head">
          <strong>{t("ui.actions.choices")}</strong>
          <span>{t("ui.actions.choicesMeta")}</span>
        </div>
        <div className="ui-actions-surface-grid">
          <div className="ui-actions-surface-panel" data-ui-surface="white">
            <span className="ui-actions-column-label">{t("ui.surface.whiteShort")}</span>
            <UiChoiceCardRows choiceValue={choiceValue} onChoiceChange={setChoiceValue} showHeader={false} variant="white" />
          </div>
          <div className="ui-actions-surface-panel" data-ui-surface="gray">
            <span className="ui-actions-column-label">{t("ui.surface.grayShort")}</span>
            <UiChoiceCardRows choiceValue={grayChoiceValue} onChoiceChange={setGrayChoiceValue} showHeader={false} variant="gray" />
          </div>
        </div>
      </section>
      <section className="ui-actions-block ui-actions-paired-block" data-ui-surface="gray" aria-label={t("ui.actions.controls")}>
        <div className="ui-actions-block-head">
          <strong>{t("ui.actions.controls")}</strong>
          <span>{t("ui.actions.surfacePairMeta")}</span>
        </div>
        <div className="ui-actions-surface-grid">
          <div className="ui-actions-surface-panel" data-ui-surface="white">
            <span className="ui-actions-column-label">{t("ui.surface.whiteShort")}</span>
            <UiControlRows
              checkEnabled={checkEnabled}
              onCheckChange={onCheckChange}
              onRangeChange={setRangeValue}
              onRadioChange={onRadioChange}
              onSwitchChange={onSwitchChange}
              radioName="ui-radio"
              radioValue={radioValue}
              rangeValue={rangeValue}
              switchEnabled={switchEnabled}
            />
          </div>
          <div className="ui-actions-surface-panel" data-ui-surface="gray">
            <span className="ui-actions-column-label">{t("ui.surface.grayShort")}</span>
            <UiControlRows
              checkEnabled={grayCheckEnabled}
              onCheckChange={setGrayCheckEnabled}
              onRangeChange={setGrayRangeValue}
              onRadioChange={setGrayRadioValue}
              onSwitchChange={setGraySwitchEnabled}
              radioName="ui-gray-radio"
              radioValue={grayRadioValue}
              rangeValue={grayRangeValue}
              switchEnabled={graySwitchEnabled}
            />
          </div>
        </div>
      </section>
    </div>
  );
}

function CatalogActionFlowRows({
  compact,
  onCompactChange,
  onShowLabelChange,
  onStop,
  onToggle,
  running,
  showLabel,
}: {
  compact: boolean;
  onCompactChange: (checked: boolean) => void;
  onShowLabelChange: (checked: boolean) => void;
  onStop: () => void;
  onToggle: () => void;
  running: boolean;
  showLabel: boolean;
}) {
  const { t } = useI18n();
  const action = {
    icon: running ? undefined : Play,
    label: running ? t("ui.async.loading.badgeLoading") : t("ui.action.start"),
    loading: running,
    onClick: running ? undefined : onToggle,
    variant: running ? "muted" : "violet",
  } as const;
  const revealAction = {
    icon: X,
    label: t("ui.action.stop"),
    onClick: onStop,
    variant: "danger",
  } as const;

  return (
    <section className="ui-actions-block ui-actions-flow-block" data-ui-surface="gray" aria-label="Action flow">
      <div className="ui-actions-block-head">
        <div>
          <strong>Action flow</strong>
          <span>Loading e stop con dimensione e testo configurabili.</span>
        </div>
      </div>
      <div className="ui-action-flow-controls" aria-label="Action flow controls">
        <SwitchField checked={compact} label="Piccolo" onChange={onCompactChange} />
        <SwitchField checked={showLabel} label="Scritta" onChange={onShowLabelChange} />
      </div>
      <div className="ui-action-builder-preview-grid" aria-label="Action flow preview">
        <div className="ui-action-builder-preview" data-ui-surface="white">
          <span className="ui-actions-column-label">{t("ui.surface.white")}</span>
          <ActionFlow active={running} action={action} revealAction={revealAction} showLabel={showLabel} size={compact ? "compact" : "regular"} />
        </div>
        <div className="ui-action-builder-preview" data-ui-surface="gray">
          <span className="ui-actions-column-label">{t("ui.surface.gray")}</span>
          <ActionFlow active={running} action={action} revealAction={revealAction} showLabel={showLabel} size={compact ? "compact" : "regular"} />
        </div>
      </div>
    </section>
  );
}

function UiChoiceCardRows({
  choiceValue,
  onChoiceChange,
  showHeader = true,
  variant,
}: {
  choiceValue: UiModalChoiceId;
  onChoiceChange: (value: UiModalChoiceId) => void;
  showHeader?: boolean;
  variant: "gray" | "white";
}) {
  const { t } = useI18n();
  const choiceItems = getUiModalChoiceItems(t);

  return (
    <div className="ui-choice-card-board" data-ui-surface={variant} aria-label={t("ui.actions.choicesAria")}>
      {showHeader ? (
        <div className="ui-choice-card-board-head">
          <strong>{t("ui.actions.choices")}</strong>
          <span>{t("ui.actions.choicesMeta")}</span>
        </div>
      ) : null}
      <div className="ui-choice-card-grid" role="listbox" aria-label={t("ui.actions.choices")}>
        {choiceItems.map((item) => (
          <ChoiceCard
            aria-selected={choiceValue === item.id}
            className="ui-choice-card"
            icon={item.icon}
            key={`${variant}-${item.id}`}
            onClick={() => onChoiceChange(item.id)}
            role="option"
            selected={choiceValue === item.id}
            text={item.text}
            title={item.title}
          />
        ))}
      </div>
    </div>
  );
}

function UiControlRows({
  checkEnabled,
  onCheckChange,
  onRangeChange,
  onRadioChange,
  onSwitchChange,
  radioName,
  radioValue,
  rangeValue,
  switchEnabled,
}: {
  checkEnabled: boolean;
  onCheckChange: (checked: boolean) => void;
  onRangeChange: (value: number) => void;
  onRadioChange: (value: "primary" | "secondary") => void;
  onSwitchChange: (checked: boolean) => void;
  radioName: string;
  radioValue: "primary" | "secondary";
  rangeValue: number;
  switchEnabled: boolean;
}) {
  const { t } = useI18n();
  return (
    <div className="ui-switch-list">
      <CheckboxField checked={checkEnabled} onChange={onCheckChange}>{t("ui.controls.checkbox")}</CheckboxField>
      <RadioField checked={radioValue === "primary"} name={radioName} onChange={(checked) => { if (checked) onRadioChange("primary"); }}>{t("ui.controls.radioA")}</RadioField>
      <RadioField checked={radioValue === "secondary"} name={radioName} onChange={(checked) => { if (checked) onRadioChange("secondary"); }}>{t("ui.controls.radioB")}</RadioField>
      <SwitchField checked={switchEnabled} label={t("ui.controls.switch")} onChange={onSwitchChange} />
      <div className="ui-range-list">
        <RangeField label={t("ui.controls.range")} onChange={onRangeChange} value={rangeValue} />
      </div>
    </div>
  );
}
