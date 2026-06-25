"use client";

import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { countryOptions } from "./countries";
import { itIT } from "./locales/it-IT";

const localeIds = ["it-IT", "en-US", "de-DE", "fr-FR", "es-ES"] as const;
export type SupportedLocale = (typeof localeIds)[number];
export type TranslationKey = keyof typeof itIT;
type Dictionary = Record<TranslationKey, string>;

const dictionaryLoaders: Record<SupportedLocale, () => Promise<Dictionary>> = {
  "it-IT": () => Promise.resolve(itIT),
  "en-US": () => import("./locales/en-US").then((module) => module.enUS),
  "de-DE": () => import("./locales/de-DE").then((module) => module.deDE),
  "fr-FR": () => import("./locales/fr-FR").then((module) => module.frFR),
  "es-ES": () => import("./locales/es-ES").then((module) => module.esES),
};

const storageKey = "stexor.locale.v1";
const fallbackLocale: SupportedLocale = "it-IT";

type Interpolation = Record<string, string | number>;

type I18nContextValue = {
  locale: SupportedLocale;
  setLocale: (locale: string) => void;
  t: (key: TranslationKey, values?: Interpolation) => string;
};

const I18nContext = createContext<I18nContextValue | null>(null);

export function normalizeLocale(locale?: string | null): SupportedLocale {
  if (!locale) return fallbackLocale;
  const exact = localeIds.find((candidate) => candidate === locale);
  if (exact) return exact;
  const base = locale.toLowerCase().slice(0, 2);
  return localeIds.find((candidate) => candidate.toLowerCase().startsWith(base)) ?? fallbackLocale;
}

function readStoredLocale() {
  try {
    return window.localStorage.getItem(storageKey);
  } catch {
    return null;
  }
}

function writeStoredLocale(locale: SupportedLocale) {
  try {
    window.localStorage.setItem(storageKey, locale);
  } catch {
    // Locale changes still apply in memory if persistent storage is blocked.
  }
}

function browserLocale() {
  const [preferred] = window.navigator.languages?.length ? window.navigator.languages : [window.navigator.language];
  return preferred;
}

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [locale, setLocaleState] = useState<SupportedLocale>(() => {
    if (typeof window === "undefined") return fallbackLocale;
    const requested = new URLSearchParams(window.location.search).get("lang");
    return normalizeLocale(requested ?? readStoredLocale() ?? browserLocale());
  });
  const [dictionary, setDictionary] = useState<Dictionary>(itIT);

  useEffect(() => {
    const requested = new URLSearchParams(window.location.search).get("lang");
    if (requested) {
      const normalized = normalizeLocale(requested);
      writeStoredLocale(normalized);
      setLocaleState(normalized);
      return;
    }
    const stored = readStoredLocale();
    setLocaleState(normalizeLocale(stored ?? browserLocale()));
  }, [typeof window === "undefined" ? "" : window.location.search]);

  useEffect(() => {
    let active = true;
    dictionaryLoaders[locale]()
      .then((nextDictionary) => {
        if (active) setDictionary(nextDictionary);
      })
      .catch(() => {
        if (active) setDictionary(itIT);
      });
    return () => {
      active = false;
    };
  }, [locale]);

  const value = useMemo<I18nContextValue>(() => {
    function setLocale(nextLocale: string) {
      const normalized = normalizeLocale(nextLocale);
      writeStoredLocale(normalized);
      document.documentElement.lang = normalized;
      setLocaleState(normalized);
    }

    function t(key: TranslationKey, values?: Interpolation) {
      const template = dictionary[key] ?? itIT[key] ?? key;
      if (!values) return template;
      return template.replace(/\{(\w+)\}/g, (match, name) => String(values[name] ?? match));
    }

    return { locale, setLocale, t };
  }, [dictionary, locale]);

  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n() {
  const context = useContext(I18nContext);
  if (!context) throw new Error("useI18n must be used inside I18nProvider");
  return context;
}

export function languageOptions(t: I18nContextValue["t"]) {
  return localeIds.map((locale) => ({ value: locale, label: t(`language.${locale}` as TranslationKey) }));
}

export { countryOptions };
