#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { assertCoreProjectGenericSources } from "./local-private-compatibility-source-boundary.mjs";

const root = path.resolve(import.meta.dirname, "..");
const compose = fs.readFileSync(path.join(root, "compose.yaml"), "utf8");
const controlCenterServer = fs.readFileSync(path.join(root, "control-center", "server.mjs"), "utf8");
const projectRouterServer = fs.readFileSync(path.join(root, "project-router", "server.mjs"), "utf8");
const forbiddenTokens = ["fixture-private-catalog", "fixture-app-repository"];

test("generic core sources use the external host-profile boundary", () => {
  assert.equal(assertCoreProjectGenericSources({ compose, controlCenterServer, projectRouterServer, forbiddenTokens }), true);
});

test("app-specific source tokens outside the host profile fail closed", () => {
  assert.throws(() => assertCoreProjectGenericSources({
    compose: `${compose}\n# fixture-private-catalog`,
    controlCenterServer,
    projectRouterServer,
    forbiddenTokens,
  }), /app-specific source or route token/);
});

test("generic Compose defaults reject app overlays and repository-specific source locks", () => {
  for (const path of ["compose.local-private-applications.yaml", "config/v1-local-private-source-lock.json"]) {
    assert.throws(() => assertCoreProjectGenericSources({
      compose: `${compose}\n# ${path}`,
      controlCenterServer,
      projectRouterServer,
      forbiddenTokens,
    }), /must not seed application overlays/);
  }
});

test("static route maps cannot replace the external host-profile boundary", () => {
  assert.throws(() => assertCoreProjectGenericSources({
    compose,
    controlCenterServer,
    projectRouterServer: projectRouterServer.replaceAll("loadProjectRouterHostExtension", "externalProfileLoader"),
    forbiddenTokens,
  }), /external host-profile boundary/);
});
