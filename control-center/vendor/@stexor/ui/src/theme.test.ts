import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workspaceRoot = new URL("../../../", import.meta.url);

function readText(relativePath: string): string {
  return readFileSync(new URL(relativePath, workspaceRoot), "utf8").replace(/\r\n/g, "\n");
}

test("theme entrypoints keep base and demo layers separate", () => {
  const baseEntry = readText("packages/ui/src/styles.css");
  const demoEntry = readText("packages/ui/src/ui.css");

  assert(baseEntry.includes('@import "./styles/base-01-foundation.css";'));
  assert(baseEntry.includes('@import "./styles/base-01-accent.css";'));
  assert(baseEntry.includes('@import "./styles/ui-02-controls.css";'));
  assert(baseEntry.includes('@import "./styles/ui-02-forms.css";'));
  assert(baseEntry.includes('@import "./styles/ui-03-data.css";'));
  assert.equal(baseEntry.includes("ui-03-monochrome-surfaces"), false);
  assert.equal(baseEntry.includes("ui-04-app"), false);
  assert.deepEqual(demoEntry.trim().split("\n"), [
    '@import "./styles/ui-04-app.css";',
    '@import "./styles/ui-03-monochrome-surfaces.css";',
  ]);
});

test("theme exposes automatic surface tokens", () => {
  const surfaces = readText("packages/ui/src/styles/ui-03-monochrome-surfaces.css");

  for (const token of ["--ui-auto-control-bg", "--ui-auto-good-pill-bg", "--ui-auto-muted-button-bg"]) {
    assert(surfaces.includes(token), `Missing theme token: ${token}`);
  }
});

test("theme exposes light/dark semantic tokens and z-index architecture", () => {
  const foundation = [
    readText("packages/ui/src/styles/base-01-foundation.css"),
    readText("packages/ui/src/styles/base-01-accent.css"),
  ].join("\n");
  const modalStyles = readText("packages/ui/src/styles/base-06-modal.css");
  const shellStyles = readText("packages/ui/src/styles/ui-app-01-shell.css");

  for (const token of [
    '[data-ui-theme="dark"]',
    "--ui-z-shell",
    "--ui-z-shell-control",
    "--ui-z-overlay",
    "--ui-theme-accent-preview-blue",
    "--ui-theme-accent-preview-olive",
    "--ui-theme-accent-preview-orange",
    "--ui-theme-accent-preview-neutral",
    "--ui-theme-accent-preview-indigo",
    "--ui-theme-accent-preview-slate",
    '[data-ui-accent="blue"]',
    '[data-ui-accent="olive"]',
    '[data-ui-accent="orange"]',
    '[data-ui-accent="neutral"]',
    '[data-ui-accent="indigo"]',
    '[data-ui-accent="violet"]',
    '[data-ui-accent="cyan"]',
    '[data-ui-accent="slate"]',
    '[data-ui-theme="dark"][data-ui-accent="indigo"]',
    '[data-ui-theme="dark"][data-ui-accent="violet"]',
    '[data-ui-theme="dark"][data-ui-accent="orange"]',
    '[data-ui-theme="dark"][data-ui-accent="neutral"]',
    '[data-ui-theme="dark"][data-ui-accent="slate"]',
    "--ui-feedback-good-bg-on-gray",
    "--ui-action-primary-disabled-bg",
    "--ui-overlay-modal-soft",
  ]) {
    assert(foundation.includes(token), `Missing enterprise token: ${token}`);
  }
  assert(modalStyles.includes("z-index: var(--ui-z-overlay);"));
  assert(shellStyles.includes("z-index: var(--ui-z-shell);"));
  assert(shellStyles.includes(".ui-theme-controls"));
  assert(shellStyles.includes(".ui-theme-toggle"));
  assert(shellStyles.includes(".ui-theme-toggle.muted-button"));
  assert(shellStyles.includes("background: var(--mono-cell);"));
  assert(shellStyles.includes(".ui-theme-wave-overlay"));
  assert(shellStyles.includes("::view-transition-new(root)"));
  assert(shellStyles.includes("@keyframes ui-theme-wave-overlay"));
  assert(shellStyles.includes("circle closest-side at center"));
  assert(shellStyles.includes("var(--ui-theme-wave-duration) var(--ui-motion-ease-linear)"));
  assert(shellStyles.includes("scale(var(--ui-theme-wave-exit-scale))"));
  const waveBlock = shellStyles.match(/\.ui-theme-wave-overlay\s*\{[\s\S]*?\n\}/)?.[0] ?? "";
  assert.equal(waveBlock.includes("backdrop-filter"), false);
  assert.equal(shellStyles.includes("@keyframes ui-theme-wave-ripple"), false);
  assert(foundation.includes("--ui-theme-wave-blur-start"));
  assert(foundation.includes("--ui-theme-wave-duration: 550ms"));
  assert(foundation.includes("--ui-theme-wave-exit-scale"));
  assert.equal(/z-index:\s*214748\d+/.test(`${modalStyles}\n${shellStyles}`), false);
});

test("catalog theme toggle applies theme changes with the button-origin wave overlay", () => {
  const app = readText("packages/ui/src/catalog/UiCatalogApp.tsx");
  const themeWaveSource = readText("packages/ui/src/theme-wave.tsx");
  const catalogThemeSource = readText("packages/ui/src/catalog/catalog-theme.ts");
  const foundation = [
    readText("packages/ui/src/styles/base-01-foundation.css"),
    readText("packages/ui/src/styles/base-01-accent.css"),
  ].join("\n");

  for (const snippet of [
    "handleThemeToggle",
    "writeStoredUiTheme",
    "writeStoredUiAccent",
    "HeaderAccentPicker",
    "data-ui-accent",
    "themeRef.current",
    "uiAccentOptions.map",
    "onAccentChange(item)",
    "data-ui-accent-option",
    "startThemeWave",
    "ThemeWaveOverlay",
  ]) {
    assert(app.includes(snippet), `Theme toggle is missing ${snippet}.`);
  }
  for (const snippet of [
    "cancelThemeWave",
    "getBoundingClientRect",
    "startViewTransition",
    "THEME_WAVE_EXIT_SCALE",
    "THEME_WAVE_REVEAL_EDGE_OFFSET",
    "exitRadius",
    "--ui-motion-ease-linear",
    "::view-transition-new(root)",
    "clipPath",
    "data-ui-theme-wave",
    "data-ui-theme-wave-mode",
    "mode: canRevealTheme ? \"reveal\" : \"paint\"",
    "ui-theme-wave-overlay",
  ]) {
    assert(themeWaveSource.includes(snippet), `Theme wave primitive is missing ${snippet}.`);
  }
  assert.equal(themeWaveSource.includes("filter: \"blur("), false, "Theme transition must not blur the full root snapshot.");
  assert.equal(themeWaveSource.includes("transform: \"scale("), false, "Theme transition must not scale the full root snapshot.");
  for (const accent of ["blue", "sky", "cyan", "teal", "emerald", "green", "lime", "olive", "yellow", "amber", "orange", "red", "rose", "pink", "fuchsia", "purple", "violet", "indigo", "slate", "neutral"]) {
    assert(catalogThemeSource.includes(`"${accent}"`), `Catalog must expose the full governed header accent palette: ${accent}.`);
  }
  assert.equal(foundation.includes(":root:is("), false, "Accent calibration must not rely on per-surface light-mode icon exceptions.");
});

test("Next layout boots stored theme before hydration to avoid flash", () => {
  const nextSource = readText("packages/ui/src/next.tsx");
  const catalogThemeSource = readText("packages/ui/src/catalog/catalog-theme.ts");
  const themeRuntimeSource = `${nextSource}\n${catalogThemeSource}`;
  const rootLayout = readText("apps/web/src/app/layout.tsx");

  for (const snippet of [
    "resolveStexorThemeAttributes",
    "cookies",
    "stexor.ui.theme.v1",
    "stexor.ui.defaultTheme.v1",
    "stexor.ui.accent.v1",
    "\"data-ui-theme\": theme",
    "\"data-ui-accent\": accent",
  ]) {
    assert(themeRuntimeSource.includes(snippet), `Theme server boot is missing ${snippet}.`);
  }

  assert(rootLayout.includes("resolveStexorThemeAttributes"));
  assert(rootLayout.includes("{...themeAttributes}"));
  assert(rootLayout.includes("suppressHydrationWarning"));
  assert.equal(nextSource.includes(["dangerously", "SetInnerHTML"].join("")), false);
});

test("dark theme uses a dedicated low-contrast feedback and action palette", () => {
  const foundation = [
    readText("packages/ui/src/styles/base-01-foundation.css"),
    readText("packages/ui/src/styles/base-01-accent.css"),
  ].join("\n");
  const darkBlock = foundation.match(/\[data-ui-theme="dark"\]\s*\{([\s\S]*?)\n\}/)?.[1] ?? "";

  for (const token of [
    "--ui-dark-mono-bg",
    "--ui-dark-mono-soft",
    "--ui-dark-info-bg",
    "--ui-dark-good-bg",
    "--ui-dark-warn-bg",
    "--ui-dark-danger-bg",
    "--ui-dark-violet-bg",
    "--ui-dark-violet-border",
    "--ui-dark-icon-brand",
    "--ui-dark-icon-email",
    "--ui-dark-icon-date",
    "--ui-dark-icon-country-start",
    "--ui-dark-icon-language",
    "--ui-dark-primary-bg",
    "--ui-dark-primary-border",
    "--ui-accent-primary: var(--ui-dark-primary-bg);",
    "--ui-accent-selection: var(--ui-dark-info-bg);",
    "--ui-pill-active-bg-surface: var(--ui-action-primary-soft-bg);",
    "--ui-pill-active-bg-gray: var(--ui-action-primary-soft-bg-on-gray);",
    "--ui-field-focus-border: var(--ui-action-primary-bg);",
    "--ui-icon-on-tone: var(--ui-dark-mono-inverse);",
    "--ui-icon-tone-brand: var(--ui-dark-icon-brand);",
    "--ui-icon-tone-email: var(--ui-dark-icon-email);",
    "--ui-icon-tone-date: var(--ui-dark-icon-date);",
    "--ui-icon-tone-country-start: var(--ui-dark-icon-country-start);",
    "--ui-icon-tone-brand-ring: var(--ui-dark-icon-brand-ring);",
    "--ui-icon-tone-email-ring: var(--ui-dark-icon-email-ring);",
    "--ui-icon-tone-date-ring: var(--ui-dark-icon-date-ring);",
    "--ui-feedback-info-fg: var(--ui-dark-info-fg);",
    "--ui-feedback-good-fg: var(--ui-dark-good-fg);",
    "--ui-feedback-warn-fg: var(--ui-dark-warn-fg);",
    "--ui-feedback-danger-fg: var(--ui-dark-danger-fg);",
    "--ui-action-primary-bg: var(--ui-accent-primary);",
    "--ui-action-danger-fg: var(--ui-feedback-danger-fg);",
    "--ui-input-icon-fg: var(--ui-action-primary-soft-fg);",
    "--ui-input-icon-fg-on-gray: var(--ui-action-primary-soft-fg);",
    "--ui-input-icon-bg: var(--ui-action-primary-soft-bg);",
    "--ui-input-icon-bg-on-gray: var(--ui-action-primary-soft-bg-on-gray);",
  ]) {
    assert(darkBlock.includes(token), `Dark mode must expose ${token} through dedicated semantic tokens.`);
  }

  const panel = darkBlock.match(/--ui-dark-mono-panel:\s*(#[0-9a-fA-F]{6});/)?.[1];
  const soft = darkBlock.match(/--ui-dark-mono-soft:\s*(#[0-9a-fA-F]{6});/)?.[1];
  assert(panel && soft, "Dark mode must expose panel and soft dark surfaces.");
  assert(colorDistance(panel, soft) <= 20, "Dark panel and gray block surfaces must stay visually close.");
  assert.equal(foundation.includes('[data-ui-theme="dark"]:is('), false, "Accent calibration must not rely on per-surface dark-mode icon exceptions.");
});


function colorDistance(a: string, b: string) {
  const first = hexToRgb(a);
  const second = hexToRgb(b);
  return Math.max(
    Math.abs(first.r - second.r),
    Math.abs(first.g - second.g),
    Math.abs(first.b - second.b),
  );
}

function hexToRgb(value: string) {
  return {
    r: Number.parseInt(value.slice(1, 3), 16),
    g: Number.parseInt(value.slice(3, 5), 16),
    b: Number.parseInt(value.slice(5, 7), 16),
  };
}
