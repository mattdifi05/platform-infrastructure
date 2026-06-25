import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import test from "node:test";

const workspaceRoot = new URL("../../../", import.meta.url);
const forbiddenLayerPrefix = ["ui", ["mat", "erial"].join("")].join("-");

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

test("shared style layers use Stexor naming without foreign layer names", () => {
  const styleEntrypoint = readText("packages/ui/src/styles.css");
  const styleFiles = readdirSync(new URL("packages/ui/src/styles", workspaceRoot), { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .sort();
  const checkedFiles = [
    "packages/ui/README.md",
    "packages/ui/MIGRATION.md",
    ...walk("packages/ui/docs").filter((file) => /\.(?:md|mdx)$/.test(file)),
    ...walk("packages/ui/src").filter((file) => /\.(?:css|ts|tsx)$/.test(file)),
    ...walk("e2e").filter((file) => /\.ts$/.test(file)),
  ];

  for (const fileName of styleFiles) {
    assert.equal(fileName.includes(forbiddenLayerPrefix), false, `Style file keeps foreign layer name: ${fileName}`);
  }

  for (const file of checkedFiles) {
    assert.equal(readText(file).includes(forbiddenLayerPrefix), false, `${file} must not reference foreign style layer naming.`);
  }

  for (const layer of ["foundation", "controls", "surfaces"]) {
    assert(styleEntrypoint.includes(`./styles/ui-shared-${layer}.css`), `styles.css must import ui-shared-${layer}.css`);
  }
});
