import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import test from "node:test";

const workspaceRoot = new URL("../../../", import.meta.url);
const forbiddenSurfaceClasses = [
  ["is", "gray"].join("-"),
  ["is", "white"].join("-"),
];
const classContainsCheck = ["classList", "contains"].join(".");

function readText(relativePath: string): string {
  return readFileSync(new URL(relativePath, workspaceRoot), "utf8").replace(/\r\n/g, "\n");
}

function walk(relativePath: string): string[] {
  const directory = new URL(relativePath, workspaceRoot);
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const childPath = `${relativePath}/${entry.name}`;
    return entry.isDirectory() ? walk(childPath) : childPath;
  });
}

test("surface state is expressed only through data attributes", () => {
  const checkedFiles = [
    ...walk("packages/ui/src").filter((file) => /\.(?:css|ts|tsx)$/.test(file)),
    ...walk("e2e").filter((file) => /\.ts$/.test(file)),
  ];
  const resolver = readText("packages/ui/src/useResolvedSurface.ts");
  const overlays = readText("packages/ui/src/OverlayPatterns.tsx");
  const surfaces = readText("packages/ui/src/styles/ui-03-monochrome-surfaces.css");

  for (const file of checkedFiles) {
    const source = readText(file);
    for (const className of forbiddenSurfaceClasses) {
      assert.equal(source.includes(className), false, `${file} must not use private surface class ${className}.`);
    }
  }

  assert(resolver.includes('attributeFilter: ["data-ui-surface"]'), "Resolved surface observer must watch only the surface attribute.");
  assert.equal(resolver.includes(classContainsCheck), false, "Resolved surface detection must not read classes.");
  assert.equal(overlays.includes(classContainsCheck), false, "Overlay surface detection must not read classes.");
  assert(surfaces.includes('[data-ui-surface="white"]'), "White surface rules must use data-ui-surface.");
  assert(surfaces.includes('[data-ui-surface="gray"]'), "Gray surface rules must use data-ui-surface.");
  assert(surfaces.includes('[data-ui-resolved-surface="white"]'), "Resolved white controls must use data-ui-resolved-surface.");
  assert(surfaces.includes('[data-ui-resolved-surface="gray"]'), "Resolved gray controls must use data-ui-resolved-surface.");
});
