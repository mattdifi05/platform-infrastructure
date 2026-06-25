import type { Metadata, Viewport } from "next";
import { cookies, headers } from "next/headers";
import type { ReactNode } from "react";
import { normalizeUiAccent, normalizeUiTheme, UI_ACCENT_STORAGE_KEY, UI_DEFAULT_THEME_STORAGE_KEY, UI_THEME_STORAGE_KEY } from "./catalog/catalog-theme";
import {
  decodeUiCatalogSection,
  isUiCatalogSectionId,
  normalizeUiCatalogSection,
  uiCatalogSectionIds,
  UI_CATALOG_SECTION_COOKIE,
  UI_CATALOG_SECTION_QUERY_KEY,
  type UiSectionId,
} from "./catalog/catalog-routing";
import { I18nProvider } from "./i18n";
import { CustomScrollbar } from "./CustomScrollbar";
import { classNames } from "./classNames";

export const stexorUiMetadata: Metadata = {
  title: "Stexor",
  description: "Stexor UI surfaces",
  icons: {
    icon: [
      { url: "/favicon.ico", sizes: "any" },
      { url: "/icon.svg", type: "image/svg+xml" },
    ],
    shortcut: "/favicon.ico",
    apple: "/icon.svg",
  },
};

export const stexorUiViewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  viewportFit: "cover",
};

export async function resolveStexorThemeAttributes() {
  const cookieStore = await cookies();
  const theme = normalizeUiTheme(cookieStore.get(UI_THEME_STORAGE_KEY)?.value ?? cookieStore.get(UI_DEFAULT_THEME_STORAGE_KEY)?.value);
  const accent = normalizeUiAccent(cookieStore.get(UI_ACCENT_STORAGE_KEY)?.value);

  return {
    "data-ui-accent": accent,
    "data-ui-theme": theme,
  };
}

export async function resolveStexorCatalogInitialSection(sectionParam?: string | string[] | null): Promise<UiSectionId> {
  const cookieStore = await cookies();
  const querySection = Array.isArray(sectionParam) ? sectionParam[0] : sectionParam;
  return normalizeUiCatalogSection(querySection ?? cookieStore.get(UI_CATALOG_SECTION_COOKIE)?.value);
}

export async function resolveStexorScriptNonce() {
  return (await headers()).get("x-nonce") ?? undefined;
}

export function StexorCatalogBootScript({ initialSection, nonce }: { initialSection: UiSectionId; nonce?: string }) {
  const script = `
(() => {
  const sections = ${JSON.stringify(uiCatalogSectionIds)};
  const initialSection = ${JSON.stringify(initialSection)};
  const queryKey = ${JSON.stringify(UI_CATALOG_SECTION_QUERY_KEY)};
  const cookieKey = ${JSON.stringify(UI_CATALOG_SECTION_COOKIE)};
  const normalize = (value) => {
    if (!value) return "";
    try {
      const decoded = decodeURIComponent(String(value).replace(/^#\\/?/, "").trim());
      return sections.includes(decoded) ? decoded : "";
    } catch {
      return "";
    }
  };
  const root = document.documentElement;
  const params = new URLSearchParams(window.location.search);
  const querySection = normalize(params.get(queryKey));
  const hashSection = normalize(window.location.hash);
  const activeSection = hashSection || querySection || initialSection;
  if (activeSection !== initialSection) root.setAttribute("data-ui-catalog-hydrating", "true");
  root.setAttribute("data-ui-catalog-initial-section", activeSection);
  document.cookie = cookieKey + "=" + encodeURIComponent(activeSection) + "; Path=/; Max-Age=31536000; SameSite=Lax";
  if (activeSection && params.get(queryKey) !== activeSection) {
    params.set(queryKey, activeSection);
    const nextSearch = params.toString();
    window.history.replaceState(window.history.state, "", window.location.pathname + (nextSearch ? "?" + nextSearch : "") + window.location.hash);
  }
})();
`;
  return <script id="stexor-catalog-boot" nonce={nonce} suppressHydrationWarning>{script}</script>;
}

export { decodeUiCatalogSection, isUiCatalogSectionId, normalizeUiCatalogSection, UI_CATALOG_SECTION_COOKIE, UI_CATALOG_SECTION_QUERY_KEY, type UiSectionId };

export function StexorThemeBootScript() {
  return null;
}

export function StexorNextUiProviders({
  children,
  className,
  scrollbar = true,
}: {
  children: ReactNode;
  className?: string;
  scrollbar?: boolean;
}) {
  const content = className ? (
    <div className={classNames(className)} data-ui-provider="">
      {children}
    </div>
  ) : (
    children
  );

  return (
    <I18nProvider>
      {content}
      {scrollbar ? <CustomScrollbar /> : null}
    </I18nProvider>
  );
}
