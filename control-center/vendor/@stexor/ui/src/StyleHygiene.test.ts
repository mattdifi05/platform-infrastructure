import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workspaceRoot = new URL("../../../", import.meta.url);

function readText(relativePath: string): string {
  return readFileSync(new URL(relativePath, workspaceRoot), "utf8").replace(/\r\n/g, "\n");
}

test("radius and squircle geometry are centralized behind semantic tokens", () => {
  const foundation = readText("packages/ui/src/styles/base-01-foundation.css");
  const styleFiles = [
    "packages/ui/src/styles/base-02-navigation.css",
    "packages/ui/src/styles/base-06-modal.css",
    "packages/ui/src/styles/base-07-popup.css",
    "packages/ui/src/styles/ui-01-navigation.css",
    "packages/ui/src/styles/ui-02-controls.css",
    "packages/ui/src/styles/ui-02-forms.css",
    "packages/ui/src/styles/ui-03-data.css",
    "packages/ui/src/styles/ui-03-monochrome-surfaces.css",
    "packages/ui/src/styles/ui-app-01-shell.css",
    "packages/ui/src/styles/ui-app-02-overview.css",
    "packages/ui/src/styles/ui-app-03-actions.css",
    "packages/ui/src/styles/ui-app-04-feedback.css",
    "packages/ui/src/styles/ui-app-05-navigation.css",
    "packages/ui/src/styles/ui-app-06-async.css",
    "packages/ui/src/styles/ui-app-07-modals.css",
    "packages/ui/src/styles/ui-app-08-responsive.css",
    "packages/ui/src/styles/ui-app-09-blocks.css",
    "packages/ui/src/styles/ui-app-10-themes.css",
    "packages/ui/src/styles/ui-app-11-action-builder.css",
    "packages/ui/src/styles/ui-shared-foundation.css",
    "packages/ui/src/styles/ui-shared-controls.css",
    "packages/ui/src/styles/ui-shared-surfaces.css",
  ].map(readText).join("\n");

  for (const token of [
    "--ui-radius-panel",
    "--ui-radius-section",
    "--ui-radius-card",
    "--ui-radius-cell",
    "--ui-radius-icon",
    "--ui-corner-shape: squircle;",
  ]) {
    assert(foundation.includes(token), `Foundation must own radius token ${token}.`);
  }

  assert.equal(/border-radius:\s*(?:[1-9]\d*px|[1-9]\d*px\s)/.test(styleFiles), false, "Style layers must not use hardcoded px border-radius values.");
  assert.equal(/corner-shape:\s*squircle\s*;/.test(styleFiles), false, "Style layers must use the shared squircle token.");
  assert(styleFiles.includes("corner-shape: var(--ui-corner-shape);"), "Squircle support must consume the shared squircle token.");
});

test("demo style layers use tokens for colors, timings and CSS variable defaults", () => {
  const foundation = readText("packages/ui/src/styles/base-01-foundation.css");
  const styleFiles = [
    "packages/ui/src/styles/base-02-navigation.css",
    "packages/ui/src/styles/base-06-modal.css",
    "packages/ui/src/styles/base-07-popup.css",
    "packages/ui/src/styles/ui-01-navigation.css",
    "packages/ui/src/styles/ui-02-controls.css",
    "packages/ui/src/styles/ui-02-forms.css",
    "packages/ui/src/styles/ui-03-data.css",
    "packages/ui/src/styles/ui-03-monochrome-surfaces.css",
    "packages/ui/src/styles/ui-app-01-shell.css",
    "packages/ui/src/styles/ui-app-02-overview.css",
    "packages/ui/src/styles/ui-app-03-actions.css",
    "packages/ui/src/styles/ui-app-04-feedback.css",
    "packages/ui/src/styles/ui-app-05-navigation.css",
    "packages/ui/src/styles/ui-app-06-async.css",
    "packages/ui/src/styles/ui-app-07-modals.css",
    "packages/ui/src/styles/ui-app-08-responsive.css",
    "packages/ui/src/styles/ui-app-09-blocks.css",
    "packages/ui/src/styles/ui-app-10-themes.css",
    "packages/ui/src/styles/ui-app-11-action-builder.css",
    "packages/ui/src/styles/ui-shared-foundation.css",
    "packages/ui/src/styles/ui-shared-controls.css",
    "packages/ui/src/styles/ui-shared-surfaces.css",
  ];
  for (const token of ["--ui-surface-soft", "--ui-focus-ring", "--button-icon-spin-duration"]) {
    assert(foundation.includes(token), `Foundation must own shared token ${token}`);
  }

  for (const file of styleFiles) {
    const source = readText(file);
    assert.equal(/#[0-9a-fA-F]{3,8}\b|rgba?\(/.test(source), false, `${file} must use foundation color tokens.`);
    assert.equal(/\b(?:0\.2s|0\.18s|0\.16s|0\.04s|40ms|80ms|100ms|1ms)\b/.test(source), false, `${file} must use motion tokens.`);
    assert.equal(source.includes("-fallback"), false, `${file} must not keep CSS default variables.`);
  }

  const motionSources = [
    "packages/ui/src/PillSidebarNav.tsx",
    "packages/ui/src/PillTabs.tsx",
  ].map(readText).join("\n");
  assert.equal(motionSources.includes("-fallback"), false, "Motion writers must not emit default-suffixed variables.");
});
