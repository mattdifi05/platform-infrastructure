import type { ReactNode } from "react";
import type { IconType } from "../icons";
import {
  BadgeCheck,
  Bell,
  Globe2,
  LayoutDashboard,
  LayoutGrid,
  RefreshCcw,
  Save,
  ShieldCheck,
  Sliders,
  Smartphone,
  UserRound,
} from "../icons";
import type { TranslationKey } from "../i18n";
import { UiSectionCard, type PillNavItem, type PillTabItem } from "../client";
import type { UiSectionId } from "./catalog-routing";

export type UiNavId = "identity" | "security" | "notifications" | "sessions";
export type { UiSectionId };
type UiT = (key: TranslationKey, values?: Record<string, string | number>) => string;
type UiSectionGuideItem = {
  label: string;
  value: string;
};

type UiSectionGuide = {
  ariaLabel: string;
  items: [UiSectionGuideItem, UiSectionGuideItem, UiSectionGuideItem];
};

export const getUiSelectOptions = (t: UiT) => [
  { label: t("ui.option.ui"), value: "ui" },
  { label: t("ui.option.identity"), value: "identity" },
  { label: t("ui.option.database"), value: "database" },
];

export const countryOptions = [
  { label: "Italia", value: "it" },
  { label: "Francia", value: "fr" },
  { label: "Germania", value: "de" },
  { label: "Spagna", value: "es" },
];

export const languageOptions = [
  { label: "Italiano", value: "it-IT" },
  { label: "English", value: "en-US" },
  { label: "Deutsch", value: "de-DE" },
  { label: "Francais", value: "fr-FR" },
];

export const getUiNavItems = (t: UiT): Array<PillNavItem<UiNavId>> => [
  { icon: UserRound, id: "identity", label: t("ui.nav.profile") },
  { icon: ShieldCheck, id: "security", label: t("ui.nav.security") },
  { icon: Bell, id: "notifications", label: t("ui.nav.notifications") },
  { icon: Smartphone, id: "sessions", label: t("ui.nav.sessions") },
];

export const getUiSectionTabs = (t: UiT): Array<PillTabItem<UiSectionId>> => [
  { icon: LayoutDashboard, id: "overview", label: t("ui.tabs.overview"), panelId: "ui-overview-panel" },
  { icon: UserRound, id: "inputs", label: t("ui.tabs.inputs"), panelId: "ui-inputs-panel" },
  { icon: Save, id: "actions", label: t("ui.tabs.actions"), panelId: "ui-actions-panel" },
  { icon: Sliders, id: "navigation", label: t("ui.tabs.navigation"), panelId: "ui-navigation-panel" },
  { icon: LayoutGrid, id: "blocks", label: t("ui.tabs.blocks"), panelId: "ui-blocks-panel" },
  { icon: BadgeCheck, id: "feedback", label: t("ui.tabs.feedback"), panelId: "ui-feedback-panel" },
  { icon: RefreshCcw, id: "async", label: t("ui.tabs.async"), panelId: "ui-async-panel" },
  { icon: Globe2, id: "modals", label: t("ui.tabs.modals"), panelId: "ui-modals-panel" },
];

const guideItems = (t: UiT, section: UiSectionId): UiSectionGuide => ({
  ariaLabel: t("ui.guide.aria"),
  items: [
    { label: t("ui.guide.import"), value: t(`ui.guide.${section}.import` as TranslationKey) },
    { label: t("ui.guide.compose"), value: t(`ui.guide.${section}.compose` as TranslationKey) },
    { label: t("ui.guide.rule"), value: t(`ui.guide.${section}.rule` as TranslationKey) },
  ],
});

export const getUiSectionGuides = (t: UiT): Record<UiSectionId, UiSectionGuide> => ({
  actions: guideItems(t, "actions"),
  async: guideItems(t, "async"),
  blocks: guideItems(t, "blocks"),
  feedback: guideItems(t, "feedback"),
  inputs: guideItems(t, "inputs"),
  modals: guideItems(t, "modals"),
  navigation: guideItems(t, "navigation"),
  overview: guideItems(t, "overview"),
});

export function UiSection({
  aside,
  children,
  guide,
  icon,
  meta,
  title,
}: {
  aside?: ReactNode;
  children: ReactNode;
  guide?: UiSectionGuide;
  icon: IconType;
  meta: string;
  title: string;
}) {
  return (
    <UiSectionCard
      aside={aside}
      headClassName="ui-section-head"
      icon={icon}
      meta={meta}
      title={title}
    >
      {children}
      {guide ? <UiSectionGuidePanel guide={guide} /> : null}
    </UiSectionCard>
  );
}

function UiSectionGuidePanel({ guide }: { guide: UiSectionGuide }) {
  return (
    <aside className="ui-section-guide" aria-label={guide.ariaLabel}>
      {guide.items.map((item) => (
        <div className="ui-section-guide-item" key={item.label}>
          <span>{item.label}</span>
          <strong>{item.value}</strong>
        </div>
      ))}
    </aside>
  );
}
