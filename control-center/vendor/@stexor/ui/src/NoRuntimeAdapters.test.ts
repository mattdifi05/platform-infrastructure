import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import test from "node:test";

const workspaceRoot = new URL("../../../", import.meta.url);
const forbiddenIconRegistryAdapter = ["listed", "Icon", ["Ali", "ases"].join("")].join("");
const privateShortcutAdapter = ["with", "Private", ["Ali", "ases"].join("")].join("");
const classAttributeObserver = ["attributeFilter: [", '"class"'].join("");
const broadForwardSpinShortcuts = ["redo", "|"].join("");
const broadReverseSpinShortcuts = ["rotate", "back"].join("");

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

test("runtime adapters stay out of framework runtime and styles", () => {
  const packageSource = walk("packages/ui/src")
    .filter((file) => /\.(?:css|ts|tsx)$/.test(file))
    .map((file) => readText(file))
    .join("\n");
  const styles = walk("packages/ui/src/styles")
    .filter((file) => /\.css$/.test(file))
    .map((file) => readText(file))
    .join("\n");
  const actionConfig = readText("packages/ui/src/ActionConfig.ts");
  const surfacePrimitive = readText("packages/ui/src/Surface.tsx");

  assert.equal(packageSource.includes(classAttributeObserver), false, "Runtime observers must not watch class attributes.");
  assert.equal(packageSource.includes(forbiddenIconRegistryAdapter), false, "Icon registry must not keep listed-name adapters.");
  assert.equal(packageSource.includes(privateShortcutAdapter), false, "Icon registry must not keep private-name adapters.");
  assert.equal(styles.includes("-fallback"), false, "CSS must not keep fallback-suffixed variables.");
  assert.equal(surfacePrimitive.includes("className.split"), false, "Surface primitives must not infer surface from class names.");
  assert.equal(actionConfig.includes(broadForwardSpinShortcuts), false, "Action spin direction must not keep broad forward-name regexes.");
  assert.equal(actionConfig.includes(broadReverseSpinShortcuts), false, "Action spin direction must not keep broad reverse-name regexes.");
});
