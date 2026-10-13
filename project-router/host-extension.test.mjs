import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  loadProjectRouterHostExtension,
  parseProjectRouterHostExtension,
  PROJECT_ROUTER_HOST_EXTENSION_SCHEMA,
} from "./host-extension.mjs";

const suffix = ".example.test";

function emptyExtension() {
  return {
    schema: PROJECT_ROUTER_HOST_EXTENSION_SCHEMA,
    hostSuffix: suffix,
    services: [],
    routes: [],
  };
}

function sampleExtension() {
  return {
    schema: PROJECT_ROUTER_HOST_EXTENSION_SCHEMA,
    hostSuffix: suffix,
    services: ["node-alpha:3000", "php-beta:80"],
    routes: [
      { slug: "alpha", sourceSlug: "source-alpha", projectSlug: "alpha", type: "node", service: "node-alpha", port: 3000 },
      { slug: "beta", sourceSlug: "source-beta", projectSlug: "beta", type: "php", service: "php-beta", port: 80 },
      { slug: "beta-alt", sourceSlug: "source-beta", projectSlug: "beta", type: "php", service: "php-beta", port: 80 },
    ],
  };
}

test("an empty host extension is a valid zero-project baseline", () => {
  const parsed = parseProjectRouterHostExtension(emptyExtension(), suffix);
  assert.equal(parsed.routes.size, 0);
  assert.equal(parsed.services.size, 0);
  assert.equal(parsed.projectUpstreams.size, 0);
});

test("a synthetic host extension binds routes to exact source, project, runtime and services", () => {
  const parsed = parseProjectRouterHostExtension(sampleExtension(), suffix);
  assert.equal(parsed.routes.get("alpha").upstream, "http://node-alpha:3000");
  assert.equal(parsed.routes.get("beta-alt").projectSlug, "beta");
  assert.equal(parsed.projectUpstreams.get("source-beta/beta/php").upstream, "http://php-beta:80");
  assert.throws(() => parseProjectRouterHostExtension(sampleExtension(), ".other.test"), /suffix/i);
});

test("the host extension parser rejects reserved slugs, duplicate ownership, bad type and unused services", () => {
  const mutations = [
    (value) => { value.routes[0].slug = "portal"; },
    (value) => { value.routes[1].slug = "alpha"; },
    (value) => { value.routes[0].service = "php-alpha"; },
    (value) => { value.services.push("node-unused:9000"); value.services.sort(); },
  ];
  for (const mutate of mutations) {
    const value = sampleExtension();
    mutate(value);
    assert.throws(() => parseProjectRouterHostExtension(value, suffix));
  }
});

test("external extension loading requires a pinned read-only file and missing means no projects", (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), "project-router-extension-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const pathToMissing = path.join(root, "missing.json");
  assert.equal(loadProjectRouterHostExtension({ filePath: pathToMissing, hostSuffix: suffix, testMode: true }).routes.size, 0);

  const extensionPath = path.join(root, "extension.json");
  const bytes = `${JSON.stringify(sampleExtension())}\n`;
  writeFileSync(extensionPath, bytes, { mode: 0o444 });
  chmodSync(extensionPath, 0o444);
  const expectedSha256 = createHash("sha256").update(bytes).digest("hex");
  const loaded = loadProjectRouterHostExtension({
    filePath: extensionPath,
    expectedSha256,
    hostSuffix: suffix,
    testMode: true,
  });
  assert.equal(loaded.routes.size, 3);
  assert.throws(() => loadProjectRouterHostExtension({
    filePath: extensionPath,
    expectedSha256: "0".repeat(64),
    hostSuffix: suffix,
    testMode: true,
  }), /digest/i);
});
