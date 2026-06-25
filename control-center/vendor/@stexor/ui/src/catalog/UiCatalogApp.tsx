"use client";

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { Button, ChoiceModalHeader, Modal, UiShell } from "../client";
import { Check, ChevronDown, Sliders } from "../icons";
import { useI18n, type TranslationKey } from "../i18n";
import { UiCatalogPanel, type UiSeed } from "./UiCatalogPanel";
import { ThemeWaveOverlay, useThemeWave } from "../theme-wave";
import { getUiSectionTabs, type UiSectionId } from "./catalog-data";
import {
  decodeUiCatalogSection,
  isUiCatalogSectionId,
  normalizeUiCatalogSection,
  UI_CATALOG_SECTION_COOKIE,
  UI_CATALOG_SECTION_QUERY_KEY,
} from "./catalog-routing";
import {
  DEFAULT_UI_ACCENT,
  DEFAULT_UI_THEME,
  readStoredUiAccent,
  readStoredUiTheme,
  uiAccentOptions,
  writeStoredUiAccent,
  writeStoredUiTheme,
  type UiAccent,
  type UiTheme,
} from "./catalog-theme";

const uiSeed: UiSeed = {
  dateOfBirth: "1998-05-17",
  email: "design@stexor.local",
  firstName: "UI",
  language: "it-IT",
  lastName: "UI",
  primaryRole: "developer",
  username: "ui",
};

export function UiCatalogApp({ initialSection = "overview" }: { initialSection?: UiSectionId }) {
  const { t } = useI18n();
  const uiSectionTabs = getUiSectionTabs(t);
  const [section, setSection] = useState<UiSectionId>(() => readUiCatalogSectionFromLocation(initialSection));
  const [theme, setTheme] = useState<UiTheme>(DEFAULT_UI_THEME);
  const [accent, setAccent] = useState<UiAccent>(DEFAULT_UI_ACCENT);
  const [catalogBooting, setCatalogBooting] = useState(true);
  const [preferencesReady, setPreferencesReady] = useState(false);
  const accentRef = useRef<UiAccent>(DEFAULT_UI_ACCENT);
  const themeRef = useRef<UiTheme>(DEFAULT_UI_THEME);
  const { startThemeWave, themeWave } = useThemeWave();

  useLayoutEffect(() => {
    const syncSectionFromLocation = () => {
      const nextSection = readUiCatalogSectionFromLocation(initialSection);
      writeStoredUiCatalogSection(nextSection);
      setSection((current) => current === nextSection ? current : nextSection);
    };

    syncSectionFromLocation();
    setCatalogBooting(false);
    document.documentElement.removeAttribute("data-ui-catalog-hydrating");
    window.addEventListener("hashchange", syncSectionFromLocation);
    window.addEventListener("popstate", syncSectionFromLocation);
    return () => {
      window.removeEventListener("hashchange", syncSectionFromLocation);
      window.removeEventListener("popstate", syncSectionFromLocation);
    };
  }, [initialSection]);

  useEffect(() => {
    const storedTheme = readStoredUiTheme();
    const storedAccent = readStoredUiAccent();
    themeRef.current = storedTheme;
    accentRef.current = storedAccent;
    setTheme(storedTheme);
    setAccent(storedAccent);
    applyCatalogPreferences(storedTheme, storedAccent);
    setPreferencesReady(true);
  }, []);

  useEffect(() => {
    if (!preferencesReady) return;
    applyCatalogPreferences(theme, accent);
    writeStoredUiTheme(theme);
    writeStoredUiAccent(accent);
  }, [accent, preferencesReady, theme]);

  const setCatalogTheme = useCallback((nextTheme: UiTheme) => {
    themeRef.current = nextTheme;
    applyCatalogPreferences(nextTheme, accentRef.current);
    setTheme(nextTheme);
  }, []);

  const setCatalogAccent = useCallback((nextAccent: UiAccent) => {
    accentRef.current = nextAccent;
    applyCatalogPreferences(themeRef.current, nextAccent);
    setAccent(nextAccent);
  }, []);

  const handleThemeChange = useCallback((nextTheme: UiTheme, source: HTMLElement) => {
    if (nextTheme === themeRef.current) {
      setCatalogTheme(nextTheme);
      return;
    }
    startThemeWave(nextTheme, source, () => setCatalogTheme(nextTheme));
  }, [setCatalogTheme, startThemeWave]);

  const handleThemeToggle = useCallback((source: HTMLElement) => {
    handleThemeChange(themeRef.current === "dark" ? "light" : "dark", source);
  }, [handleThemeChange]);

  const handleSectionSelect = useCallback((nextSection: UiSectionId) => {
    setSection(nextSection);
    writeUiCatalogSectionToLocation(nextSection);
  }, []);

  if (catalogBooting) return null;

  return (
    <UiShell
      activeId={section}
      brand={{ ariaLabel: "STEXOR UI / UX", href: "https://ui.localhost.com", subtitle: "UI / UX", title: "STEXOR" }}
      canvas={(
        <>
          <div className="ui-canvas" />
          <div className="ui-theme-controls" aria-label={t("ui.themes.default.title")}>
            <Button
              aria-pressed={theme === "dark"}
              className="ui-theme-toggle"
              compact
              icon={Sliders}
              onClick={(event) => handleThemeToggle(event.currentTarget)}
              variant="muted"
            >
              {theme === "dark" ? t("ui.theme.light") : t("ui.theme.dark")}
            </Button>
            <HeaderAccentPicker
              accent={accent}
              label={t("ui.themes.accent.title")}
              labelForAccent={(item) => t(`ui.themes.accent.${item}` as TranslationKey)}
              onAccentChange={setCatalogAccent}
            />
          </div>
          <ThemeWaveOverlay wave={themeWave} />
        </>
      )}
      className="ui-experience"
      headerClassName="ui-homebar"
      navClassName="ui-dock"
      navItems={uiSectionTabs}
      navLabel={t("ui.tabs.aria")}
      onSelect={handleSectionSelect}
      sceneClassName="ui-scene"
      sceneLabel="UI"
      sheetClassName="ui-content-sheet"
      stageClassName="ui-stage-grid"
    >
      <UiCatalogPanel
        seed={uiSeed}
        section={section}
      />
    </UiShell>
  );
}

function HeaderAccentPicker({
  accent,
  label,
  labelForAccent,
  onAccentChange,
}: {
  accent: UiAccent;
  label: string;
  labelForAccent: (accent: UiAccent) => string;
  onAccentChange: (accent: UiAccent) => void;
}) {
  const [open, setOpen] = useState(false);
  const selectedLabel = labelForAccent(accent);

  return (
    <Modal
      backdropClassName="choice-modal-backdrop"
      onOpenChange={setOpen}
      open={open}
      panelClassName="choice-modal-panel ui-modal-panel ui-theme-list-modal"
      restoreFocus={false}
      size="sm"
      trigger={({ isOpen, sourceRef, triggerButtonProps }) => {
        const { ref: _ref, ...buttonProps } = triggerButtonProps;
        return (
          <Button
            {...buttonProps}
            aria-label={`${label}: ${selectedLabel}`}
            aria-pressed={isOpen}
            className="ui-theme-color-trigger"
            compact
            data-ui-accent-option={accent}
            ref={(node) => sourceRef(node)}
            variant="muted"
          >
            <span className="ui-theme-trigger-swatch" aria-hidden="true" />
            <span>{selectedLabel}</span>
            <ChevronDown aria-hidden="true" size={12} />
          </Button>
        );
      }}
    >
      {({ closeModal, titleId }) => (
        <>
          <ChoiceModalHeader closeLabel="Chiudi" icon={Sliders} iconTone="brand" kicker="Accent" onClose={closeModal} title={label} titleId={titleId} />
          <div aria-label={label} className="custom-select-menu choice-modal-list ui-theme-header-color-list" role="listbox">
            {uiAccentOptions.map((item) => {
              const selected = accent === item;
              return (
                <button
                  aria-selected={selected}
                  className={selected ? "selected" : ""}
                  data-ui-accent-option={item}
                  key={item}
                  onClick={() => {
                    onAccentChange(item);
                    closeModal();
                  }}
                  role="option"
                  type="button"
                >
                  <span className="ui-theme-list-option-label">
                    <span className="ui-theme-trigger-swatch" aria-hidden="true" />
                    <span>{labelForAccent(item)}</span>
                  </span>
                  {selected ? <Check aria-hidden="true" size={14} /> : null}
                </button>
              );
            })}
          </div>
        </>
      )}
    </Modal>
  );
}

function applyCatalogPreferences(theme: UiTheme, accent: UiAccent) {
  const root = document.documentElement;
  root.setAttribute("data-ui-theme", theme);
  root.setAttribute("data-ui-accent", accent);
}

function readUiCatalogSectionFromLocation(fallback: UiSectionId): UiSectionId {
  if (typeof window === "undefined") return fallback;
  const querySection = new URLSearchParams(window.location.search).get(UI_CATALOG_SECTION_QUERY_KEY);
  const hashSection = decodeUiCatalogSection(window.location.hash);
  return normalizeUiCatalogSection(hashSection || querySection, fallback);
}

function writeUiCatalogSectionToLocation(section: UiSectionId) {
  if (typeof window === "undefined") return;
  writeStoredUiCatalogSection(section);
  const url = new URL(window.location.href);
  url.searchParams.set(UI_CATALOG_SECTION_QUERY_KEY, section);
  const nextHash = `#${section}`;
  url.hash = nextHash;
  if (window.location.href === url.href) return;
  window.history.pushState({ ...(window.history.state ?? {}), uiSection: section }, "", `${url.pathname}${url.search}${nextHash}`);
}

function writeStoredUiCatalogSection(section: UiSectionId) {
  if (typeof document === "undefined" || !isUiCatalogSectionId(section)) return;
  document.cookie = `${UI_CATALOG_SECTION_COOKIE}=${encodeURIComponent(section)}; Path=/; Max-Age=31536000; SameSite=Lax`;
}
