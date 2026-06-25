"use client";

import { BadgeCheck, Bell, Check, CircleInfo, ShieldCheck, Smartphone, UserRound, type IconType } from "../icons";
import { Badge, Button, FactGrid, PillSidebarNav, PillTabs, SectionHeader, StatusBadge } from "../client";
import { useI18n } from "../i18n";
import { getUiNavItems, type UiNavId } from "./catalog-data";
import { CssPresence } from "../CssPresence";
type NavigationDetails = {
  badge: string;
  facts: Array<{ label: string; value: string }>;
  icon: IconType;
  meta: string;
  status: string;
  statusTone: "danger" | "good" | "neutral" | "warn";
  title: string;
};


const getNavigationDetails = (t: ReturnType<typeof useI18n>["t"]): Record<UiNavId, NavigationDetails> => ({
  identity: {
    badge: t("ui.navigation.profile.badge"),
    facts: [
      { label: t("ui.fact.view"), value: t("ui.nav.profile") },
      { label: t("ui.fact.pattern"), value: t("ui.navigation.pattern.sidebarPill") },
      { label: t("ui.fact.surface"), value: t("ui.navigation.surface.whiteOnGray") },
    ],
    icon: UserRound,
    meta: t("ui.navigation.profile.meta"),
    status: t("ui.status.active"),
    statusTone: "good",
    title: t("ui.nav.profile"),
  },
  security: {
    badge: t("ui.navigation.security.badge"),
    facts: [
      { label: t("ui.fact.view"), value: t("ui.nav.security") },
      { label: t("ui.fact.pattern"), value: t("ui.navigation.pattern.sectionChange") },
      { label: t("ui.fact.surface"), value: t("ui.navigation.surface.criticalState") },
    ],
    icon: ShieldCheck,
    meta: t("ui.navigation.security.meta"),
    status: t("ui.status.protected"),
    statusTone: "good",
    title: t("ui.nav.security"),
  },
  notifications: {
    badge: t("ui.navigation.notifications.badge"),
    facts: [
      { label: t("ui.fact.view"), value: t("ui.nav.notifications") },
      { label: t("ui.fact.pattern"), value: t("ui.navigation.pattern.activeItem") },
      { label: t("ui.fact.surface"), value: t("ui.navigation.surface.quietState") },
    ],
    icon: Bell,
    meta: t("ui.navigation.notifications.meta"),
    status: t("ui.status.quiet"),
    statusTone: "neutral",
    title: t("ui.nav.notifications"),
  },
  sessions: {
    badge: t("ui.navigation.sessions.badge"),
    facts: [
      { label: t("ui.fact.view"), value: t("ui.nav.sessions") },
      { label: t("ui.fact.pattern"), value: t("ui.navigation.pattern.verticalDock") },
      { label: t("ui.fact.surface"), value: t("ui.navigation.surface.compactList") },
    ],
    icon: Smartphone,
    meta: t("ui.navigation.sessions.meta"),
    status: t("ui.status.twoActive"),
    statusTone: "warn",
    title: t("ui.nav.sessions"),
  },
});

export function UiNavigationSurface({
  activeNav,
  onNavChange,
}: {
  activeNav: UiNavId;
  onNavChange: (id: UiNavId, index: number) => void;
}) {
  const { t } = useI18n();
  const navItems = getUiNavItems(t);
  const NavigationDetails = getNavigationDetails(t);
  const activeDetails = NavigationDetails[activeNav];
  const navigationTabItems = navItems.map((item) => ({ icon: item.icon, id: item.id, label: item.label }));

  return (
    <div className="ui-navigation-layout">
      <div className="ui-navigation-tabs-showcase">
        <div className="ui-navigation-tabs-card" data-ui-surface="white">
          <div className="ui-navigation-tabs-card-head">
            <strong>{t("ui.navigation.tabs.white")}</strong>
            <span>{t("ui.navigation.tabs.whiteMeta")}</span>
          </div>
          <div className="ui-navigation-tabs-card-stage">
            <PillTabs activeId={activeNav} ariaLabel={`${t("ui.navigation.tabsAria")} ${t("ui.navigation.tabs.white")}`} className="ui-navigation-tabs is-wide" items={navigationTabItems} onSelect={onNavChange} />
          </div>
        </div>
        <div className="ui-navigation-tabs-card" data-ui-surface="gray">
          <div className="ui-navigation-tabs-card-head">
            <strong>{t("ui.navigation.tabs.gray")}</strong>
            <span>{t("ui.navigation.tabs.grayMeta")}</span>
          </div>
          <div className="ui-navigation-tabs-card-stage">
            <PillTabs activeId={activeNav} ariaLabel={`${t("ui.navigation.tabsAria")} ${t("ui.navigation.tabs.gray")}`} className="ui-navigation-tabs is-wide" items={navigationTabItems} onSelect={onNavChange} tone="gray" />
          </div>
        </div>
      </div>
      <div className="ui-navigation-panel-stack">
        <div className="ui-navigation-panel" id="ui-sidebar-panel">
          <div className="ui-navigation-surface">
            <div className="ui-navigation-surface-head">
              <div>
                <strong>{t("ui.navigation.sidebar.title")}</strong>
                <span>{t("ui.navigation.sidebar.meta")}</span>
              </div>
              <Badge tone="current">{activeDetails.badge}</Badge>
            </div>
            <div className="ui-navigation-sidebar-stage">
              <div className="ui-navigation-sidebar-shell">
                <PillSidebarNav activeId={activeNav} ariaLabel={t("ui.navigation.sidebarAria")} className="ui-navigation-sidebar-nav" items={navItems} onSelect={onNavChange} />
              </div>
              <UiNavigationContent activeNav={activeNav} details={activeDetails} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function UiNavigationContent({
  activeNav,
  details,
}: {
  activeNav: UiNavId;
  details: NavigationDetails;
}) {
  const { t } = useI18n();
  const ActiveIcon = details.icon;

  return (
    <CssPresence className="ui-navigation-preview ui-navigation-content-motion" motionKey={activeNav}>
        <SectionHeader
          aside={<StatusBadge icon={BadgeCheck} label={details.status} tone={details.statusTone} />}
          className="ui-section-head ui-navigation-preview-head"
          icon={ActiveIcon}
          iconClassName="ui-section-icon"
          meta={details.meta}
          title={details.title}
        />
        <FactGrid className="ui-navigation-facts" items={details.facts} />
        <div className="ui-navigation-actions">
          <Button icon={Check} variant="primary">{t("ui.action.confirm")}</Button>
          <Button icon={CircleInfo} solid={false} variant="primary">{t("ui.action.details")}</Button>
        </div>
    </CssPresence>
  );
}
