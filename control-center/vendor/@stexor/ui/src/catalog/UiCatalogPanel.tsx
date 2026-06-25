"use client";

import { memo, useState, type ReactNode } from "react";
import { BadgeCheck, CircleInfo, Globe2, LayoutGrid, Mail, RefreshCcw, Save, Sliders, UserRound } from "../icons";
import {
  AvatarCropper,
  Badge,
  DateInputField,
  FieldGroup,
  SelectField,
  TextareaField,
  TextField,
  UiFactGrid,
  UiMetricGrid,
  UiPanelFrame,
  createUiFieldValidationState,
} from "../client";
import { useI18n } from "../i18n";
import {
  getUiSectionTabs,
  getUiSectionGuides,
  getUiSelectOptions,
  UiSection,
  type UiNavId,
  type UiSectionId,
} from "./catalog-data";
import type { UiSeed } from "./catalog-types";
import { UiButtonsSurface } from "./UiCatalogActions";
import { UiAsyncSurface } from "./UiCatalogAsync";
import { UiBlocksSurface } from "./UiCatalogBlocks";
import { UiFeedbackSurface } from "./UiCatalogFeedback";
import { UiModalsSurface } from "./UiCatalogModals";
import { UiNavigationSurface } from "./UiCatalogNavigation";
import { UiToken } from "./UiCatalogToken";

export type { UiSeed } from "./catalog-types";

export const UiCatalogPanel = memo(function UiCatalogPanel({
  seed,
  section,
}: {
  seed: UiSeed;
  section: UiSectionId;
}) {
  const { locale, t } = useI18n();
  const selectOptions = getUiSelectOptions(t);
  const sectionGuides = getUiSectionGuides(t);
  const sectionTabs = getUiSectionTabs(t);
  const initialDisplayName = `${seed.firstName} ${seed.lastName}`.trim() || t("ui.fallbackName");
  const [checkEnabled, setCheckEnabled] = useState(true);
  const [inputArea, setInputArea] = useState("ui");
  const [inputDate, setInputDate] = useState(seed.dateOfBirth || "1998-05-17");
  const [inputEmail, setInputEmail] = useState(seed.email);
  const [inputName, setInputName] = useState(initialDisplayName);
  const [inputNote, setInputNote] = useState(t("ui.inputs.noteValue"));
  const [activeNav, setActiveNav] = useState<UiNavId>("identity");
  const [radioValue, setRadioValue] = useState<"primary" | "secondary">("primary");
  const [surfaceArea, setSurfaceArea] = useState("ui");
  const [surfaceDate, setSurfaceDate] = useState(seed.dateOfBirth || "1998-05-17");
  const [surfaceEmail, setSurfaceEmail] = useState(seed.email);
  const [surfaceName, setSurfaceName] = useState(initialDisplayName);
  const [switchEnabled, setSwitchEnabled] = useState(true);
  const sectionIndex = Math.max(0, sectionTabs.findIndex((item) => item.id === section));
  const activeSectionItem = sectionTabs[sectionIndex] ?? sectionTabs[0]!;
  const inputEmailValidation = createUiEmailValidation("ui-input-email-help", inputEmail, seed.email, t("ui.validation.email"));
  const surfaceEmailValidation = createUiEmailValidation("ui-surface-email-help", surfaceEmail, seed.email, t("ui.validation.email"));

  const sectionPanels: Record<UiSectionId, ReactNode> = {
    overview: (
      <UiSection
        guide={sectionGuides.overview}
        icon={LayoutGrid}
        title={t("ui.section.overview.title")}
        meta={t("ui.section.overview.meta")}
        aside={<Badge tone="current">{t("ui.overview.badge")}</Badge>}
      >
        <UiMetricGrid items={[
          { label: t("ui.overview.metric.primitives"), value: "24" },
          { label: t("ui.overview.metric.radius"), value: t("ui.overview.metric.radiusValue") },
          { label: t("ui.overview.metric.borders"), value: t("ui.overview.metric.bordersValue") },
          { label: t("ui.overview.metric.inputBg"), value: t("ui.overview.metric.inputBgValue") },
        ]} />
        <div className="ui-token-grid">
          <UiToken title={t("ui.overview.token.gray")} meta={t("ui.overview.token.gray.meta")} tone="muted" />
          <UiToken title={t("ui.overview.token.accent")} meta={t("ui.overview.token.accent.meta")} tone="accent" />
          <UiToken title={t("ui.overview.token.green")} meta={t("ui.overview.token.green.meta")} tone="green" />
          <UiToken title={t("ui.overview.token.yellow")} meta={t("ui.overview.token.yellow.meta")} tone="yellow" />
          <UiToken title={t("ui.overview.token.danger")} meta={t("ui.overview.token.danger.meta")} tone="danger" />
        </div>
        <UiOverviewIconDemo />
        <UiOverviewAvatarBlock name={initialDisplayName} />
        <UiFactGrid
          items={[
            { label: t("ui.overview.fact.identity"), value: seed.username || seed.email },
            { label: t("ui.overview.fact.locale"), value: locale },
            { label: t("ui.overview.fact.primaryRole"), value: seed.primaryRole },
            { label: t("ui.overview.fact.rule"), value: t("ui.overview.fact.ruleValue"), wide: true },
          ]}
        />
      </UiSection>
    ),
    inputs: (
      <UiSection guide={sectionGuides.inputs} icon={UserRound} title={t("ui.section.inputs.title")} meta={t("ui.section.inputs.meta")}>
        <div className="ui-inputs-board">
          <div className="ui-inputs-layout">
            <UiInputGroup label={t("ui.inputs.group.identity.title")}>
              <FieldGroup className="ui-form-grid ui-inputs-grid">
                <TextField icon={UserRound} iconTone="brand" label={t("ui.inputs.name")} value={inputName} onChange={setInputName} />
                <TextField icon={Mail} iconTone="email" inputMode="email" label={t("ui.inputs.email")} validation={inputEmailValidation} value={inputEmail} onChange={setInputEmail} />
                <DateInputField iconTone="date" label={t("ui.inputs.date")} value={inputDate} onChange={setInputDate} />
                <SelectField icon={Globe2} iconTone="country" label={t("ui.inputs.area")} options={selectOptions} value={inputArea} onChange={setInputArea} />
                <TextareaField icon={CircleInfo} iconTone="brand" label={t("ui.inputs.note")} value={inputNote} onChange={setInputNote} />
              </FieldGroup>
            </UiInputGroup>
          </div>
          <UiInputGroup label={t("ui.inputs.group.surface.title")} surface="gray">
            <div className="ui-inputs-surface-grid" aria-label={t("ui.inputs.surfaceGroup")}>
              <FieldGroup className="ui-form-grid ui-inputs-grid">
                <TextField icon={UserRound} iconTone="brand" label={t("ui.inputs.surfaceName")} value={surfaceName} onChange={setSurfaceName} />
                <TextField icon={Mail} iconTone="email" inputMode="email" label={t("ui.inputs.surfaceEmail")} validation={surfaceEmailValidation} value={surfaceEmail} onChange={setSurfaceEmail} />
                <DateInputField iconTone="date" label={t("ui.inputs.surfaceDate")} value={surfaceDate} onChange={setSurfaceDate} />
                <SelectField icon={Globe2} iconTone="country" label={t("ui.inputs.surfaceArea")} options={selectOptions} value={surfaceArea} onChange={setSurfaceArea} />
              </FieldGroup>
            </div>
          </UiInputGroup>
        </div>
      </UiSection>
    ),
    actions: (
      <UiSection guide={sectionGuides.actions} icon={Save} title={t("ui.section.actions.title")} meta={t("ui.section.actions.meta")}>
        <UiButtonsSurface
          checkEnabled={checkEnabled}
          onCheckChange={setCheckEnabled}
          onRadioChange={setRadioValue}
          onSwitchChange={setSwitchEnabled}
          radioValue={radioValue}
          switchEnabled={switchEnabled}
        />
      </UiSection>
    ),
    navigation: (
      <UiSection guide={sectionGuides.navigation} icon={Sliders} title={t("ui.section.navigation.title")} meta={t("ui.section.navigation.meta")}>
        <UiNavigationSurface activeNav={activeNav} onNavChange={setActiveNav} />
      </UiSection>
    ),
    blocks: (
      <UiSection guide={sectionGuides.blocks} icon={LayoutGrid} title={t("ui.section.blocks.title")} meta={t("ui.section.blocks.meta")}>
        <UiBlocksSurface />
      </UiSection>
    ),
    feedback: (
      <UiSection guide={sectionGuides.feedback} icon={BadgeCheck} title={t("ui.section.feedback.title")} meta={t("ui.section.feedback.meta")}>
        <UiFeedbackSurface />
      </UiSection>
    ),
    async: (
      <UiSection guide={sectionGuides.async} icon={RefreshCcw} title={t("ui.section.async.title")} meta={t("ui.section.async.meta")}>
        <UiAsyncSurface />
      </UiSection>
    ),
    modals: (
      <UiSection guide={sectionGuides.modals} icon={Globe2} title={t("ui.section.modals.title")} meta={t("ui.section.modals.meta")}>
        <UiModalsSurface seed={seed} />
      </UiSection>
    ),
  };

  return (
    <UiPanelFrame
      ariaLabel={typeof activeSectionItem.label === "string" ? activeSectionItem.label : undefined}
      id={activeSectionItem.panelId ?? `ui-${activeSectionItem.id}-panel`}
      motionKey={section}
    >
      {sectionPanels[section]}
    </UiPanelFrame>
  );
});

const overviewAvatarCrop = { size: 0.72, x: 0.14, y: 0.14 };

function UiOverviewAvatarBlock({ name }: { name: string }) {
  return (
    <section className="ui-overview-avatar-block ui-overview-cluster" aria-label="Blocco avatar" data-ui-surface="gray">
      <div className="ui-overview-icon-demo-head">
        <div>
          <strong>Blocco avatar</strong>
          <span>Stage grigio squircle con foto rotonda e bordo bianco.</span>
        </div>
      </div>
      <AvatarCropper
        crop={overviewAvatarCrop}
        cropLabel="Preview avatar"
        initials="ST"
        name={name}
        onCropChange={() => undefined}
        source={null}
      />
    </section>
  );
}

function UiOverviewIconDemo() {
  return (
    <section className="ui-overview-icon-demo ui-overview-cluster" aria-label="Icone blocchi">
      <div className="ui-overview-icon-demo-head">
        <div>
          <strong>Icone blocchi</strong>
          <span>Le icone dei blocchi ereditano gli stessi contrasti degli input.</span>
        </div>
      </div>
      <div className="ui-overview-icon-preview-grid" aria-label="Preview icone blocchi">
        <UiOverviewIconPreview
          description="Icona e titolo con superficie chiara."
          label="Blocco bianco"
          surface="white"
        />
        <UiOverviewIconPreview
          description="Icona e titolo con superficie grigia."
          label="Blocco grigio"
          surface="gray"
        />
      </div>
    </section>
  );
}

function UiOverviewIconPreview({
  description,
  label,
  surface,
}: {
  description: string;
  label: string;
  surface: "gray" | "white";
}) {
  return (
    <div className="ui-overview-icon-preview" data-ui-surface={surface}>
      <div className="ui-section-head">
        <span className="ui-section-icon" aria-hidden="true"><Sliders size={18} /></span>
        <div>
          <h3>{label}</h3>
          <p>{description}</p>
        </div>
      </div>
    </div>
  );
}

function createUiEmailValidation(describedBy: string, value: string, initialValue: string, message: string) {
  const valid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
  return createUiFieldValidationState({
    describedBy,
    initialValue,
    issues: valid ? [] : [{ message, severity: "error" }],
    touched: value !== initialValue,
    value,
  });
}

function UiInputGroup({
  children,
  className = "",
  label,
  surface = "white",
}: {
  children: ReactNode;
  className?: string;
  label: string;
  surface?: "gray" | "white";
}) {
  return (
    <section className={`ui-inputs-group ${className}`.trim()} data-ui-surface={surface} aria-label={label}>
      {children}
    </section>
  );
}
