#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  assertCoreProjectGenericSources,
  isolateLocalPrivateCompatibilityContract,
} from "./local-private-compatibility-source-boundary.mjs";

const root = path.resolve(import.meta.dirname, "..");
const compose = fs.readFileSync(path.join(root, "compose.yaml"), "utf8");
const controlCenterServer = fs.readFileSync(path.join(root, "control-center", "server.mjs"), "utf8");
const projectRouterServer = fs.readFileSync(path.join(root, "project-router", "server.mjs"), "utf8");

test("legacy project tokens are confined to the one exact LOCAL_PRIVATE compatibility block", () => {
  const isolated = assertCoreProjectGenericSources({ compose, controlCenterServer, projectRouterServer });
  assert.match(isolated.compatibilityContractSource, /stexor/i);
  assert.match(isolated.compatibilityContractSource, /fireport/i);
  assert.match(isolated.compatibilityContractSource, /matthewdifilippo/i);
  assert.doesNotMatch(isolated.projectRouterOutsideCompatibilityContract, /stexor|fireport|matthewdifilippo/i);
});

test("a project token mutant outside the compatibility block fails closed", () => {
  const mutant = `${projectRouterServer}\n// accidental fireport routing exception\n`;
  assert.throws(
    () => assertCoreProjectGenericSources({ compose, controlCenterServer, projectRouterServer: mutant }),
    /outside the exact LOCAL_PRIVATE compatibility contract/,
  );
});

test("duplicated or unterminated compatibility boundaries fail closed", () => {
  const declaration = "const localPrivateCompatibilityContract = Object.freeze({";
  assert.throws(() => isolateLocalPrivateCompatibilityContract(`${projectRouterServer}\n${declaration}`), /exactly one/);
  assert.throws(
    () => isolateLocalPrivateCompatibilityContract(projectRouterServer.replace("\n});\nconst localPrivateRouteOwnership = new Map(", "\n};\nconst localPrivateRouteOwnership = new Map(")),
    /exactly one/,
  );
});
