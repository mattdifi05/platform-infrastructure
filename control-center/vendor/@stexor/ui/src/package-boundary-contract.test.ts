import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import test from "node:test";

const workspaceRoot = new URL("../../../", import.meta.url);

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

function joinToken(...parts: string[]): string {
  return parts.join("");
}

const forbiddenUiTokens = [
  joinToken("Account", "Loading"),
  joinToken("account.", "loading"),
  joinToken("ui-", "notice"),
  joinToken('className = "', "form", "-grid", '"'),
  joinToken("\n.", "form", "-grid"),
  joinToken('className = "', "modal", "-footer", '"'),
  joinToken("\n.", "modal", "-footer"),
  joinToken("ui-section-", "card"),
  joinToken("ui-fact-", "grid"),
  joinToken("ui-", "empty"),
  joinToken("ui-", "muted"),
  joinToken("ui-action-", "panel"),
  joinToken("ui-action-", "copy"),
  joinToken("ui-action-", "row"),
  joinToken("ui-icon-", "row"),
  joinToken("ui-gray-action-", "grid"),
  joinToken("ui-gray-button-", "stack"),
  joinToken("ui-gray-control-", "stack"),
  joinToken("ui-", "preview"),
  joinToken("ui-", "inline"),
  joinToken("ui-date-year-", "grid"),
  joinToken("ui-date-year-", "grid-wrap"),
  joinToken("modal-panel-", "lg"),
  joinToken("modal-panel-", "full"),
  joinToken("ui-modal-header-", "copy"),
  joinToken("ui-modal-", "controls"),
  joinToken("gre", "captcha-", "badge"),
  joinToken("ui-shell-", "canvas"),
];

test("forbidden package tokens stay out of all source files", () => {
  const packageSource = walk("packages/ui/src").filter((file) => /\.(?:css|ts|tsx)$/.test(file)).map((file) => readText(file)).join("\n");

  for (const token of forbiddenUiTokens) {
    assert.equal(packageSource.includes(token), false, `Forbidden package token must stay out: ${token}`);
  }
});
