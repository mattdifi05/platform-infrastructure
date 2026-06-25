export const DEFAULT_UI_ACCENT = "blue";
export const DEFAULT_UI_THEME = "light";
export const UI_ACCENT_STORAGE_KEY = "stexor.ui.accent.v1";
export const UI_DEFAULT_THEME_STORAGE_KEY = "stexor.ui.defaultTheme.v1";
export const UI_THEME_STORAGE_KEY = "stexor.ui.theme.v1";

export const uiAccentOptions = [
  "blue",
  "sky",
  "cyan",
  "teal",
  "emerald",
  "green",
  "lime",
  "olive",
  "yellow",
  "amber",
  "orange",
  "red",
  "rose",
  "pink",
  "fuchsia",
  "purple",
  "violet",
  "indigo",
  "slate",
  "neutral",
] as const;
const uiThemeOptions = ["light", "dark"] as const;

export type UiAccent = (typeof uiAccentOptions)[number];
export type UiTheme = (typeof uiThemeOptions)[number];

export function normalizeUiAccent(value?: string | null): UiAccent {
  return uiAccentOptions.find((candidate) => candidate === value) ?? DEFAULT_UI_ACCENT;
}

export function normalizeUiTheme(value?: string | null): UiTheme {
  return uiThemeOptions.find((candidate) => candidate === value) ?? DEFAULT_UI_THEME;
}

export function readStoredUiAccent(): UiAccent {
  return normalizeUiAccent(readStorage(UI_ACCENT_STORAGE_KEY));
}

export function readStoredUiTheme(): UiTheme {
  return normalizeUiTheme(readStorage(UI_THEME_STORAGE_KEY) ?? readStorage(UI_DEFAULT_THEME_STORAGE_KEY));
}

export function writeStoredUiAccent(accent: UiAccent) {
  writeStorage(UI_ACCENT_STORAGE_KEY, accent);
  writeCookie(UI_ACCENT_STORAGE_KEY, accent);
}

export function writeStoredUiTheme(theme: UiTheme) {
  writeStorage(UI_THEME_STORAGE_KEY, theme);
  writeStorage(UI_DEFAULT_THEME_STORAGE_KEY, theme);
  writeCookie(UI_THEME_STORAGE_KEY, theme);
  writeCookie(UI_DEFAULT_THEME_STORAGE_KEY, theme);
}

function readStorage(key: string) {
  try {
    return typeof window === "undefined" ? null : window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeStorage(key: string, value: string) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // The catalog still applies preferences in memory when persistent storage is unavailable.
  }
}

function writeCookie(key: string, value: string) {
  try {
    if (typeof document === "undefined") return;
    document.cookie = `${key}=${encodeURIComponent(value)}; Max-Age=31536000; Path=/; SameSite=Lax`;
  } catch {
    // Theme still applies in memory when cookies are unavailable.
  }
}
