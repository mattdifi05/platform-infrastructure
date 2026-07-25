import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const composeVps = read("scripts/compose-vps.sh");
const identityOverlay = read("compose.runtime-identity.yaml");
const infraOps = read("scripts/infra-ops.mjs");

test("ULTRA-GAP-024 all platform runtime services receive the exact identity tuple", () => {
  const platformFiles = [
    "compose.yaml",
    "compose.waf.yaml",
    "compose.backup-scheduler.yaml",
    "compose.runtime.yaml",
  ];
  const expectedServices = new Set(platformFiles.flatMap((file) => composeServices(read(file))));
  const labeledServices = new Set(composeServices(identityOverlay));
  assert.deepEqual([...labeledServices].sort(), [...expectedServices].sort());
  for (const label of ["candidate-id", "commit", "tree", "deployment-id", "render-sha256", "workload-lock-sha256"]) {
    assert.match(identityOverlay, new RegExp(`com\\.platform\\.runtime\\.${label}:`));
  }
});

test("ULTRA-GAP-024 VPS wrapper rejects partial identity and loads its overlay last", () => {
  for (const variable of [
    "PLATFORM_RUNTIME_CANDIDATE_ID",
    "PLATFORM_RUNTIME_COMMIT",
    "PLATFORM_RUNTIME_TREE",
    "PLATFORM_RUNTIME_DEPLOYMENT_ID",
    "PLATFORM_RUNTIME_RENDER_SHA256",
    "PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256",
  ]) {
    assert.match(composeVps, new RegExp(`\\b${variable}\\b`));
  }
  assert.match(composeVps, /runtime_identity_count != 0[\s\S]*complete approved candidate\/deployment tuple/);
  const identityPosition = composeVps.indexOf("compose.runtime-identity.yaml");
  const workloadPosition = composeVps.indexOf("workload_files");
  assert.ok(identityPosition > workloadPosition, "identity overlay must load after workload Compose files");
});

test("ULTRA-GAP-024 runtime consumer requires an independently hashed FG-048 target and observed labels", () => {
  assert.match(infraOps, /platform\.runtime-target\/v1/);
  assert.match(infraOps, /platform\.release-candidate\/v1 receipt plus deployment image expectations/);
  assert.match(infraOps, /SHA256 does not match the approved receipt/);
  assert.match(infraOps, /candidateIdentityMatches\(candidateEvidence\.candidate,\s*candidateEndEvidence\.candidate\)/);
  assert.match(infraOps, /candidateIdentityMatches\(candidateEvidence\.candidate,\s*target\.expected\.candidate\)/);
  assert.match(infraOps, /const checkoutTree = String\(git\.tree \?\? ""\)/);
  for (const label of ["candidate-id", "commit", "tree", "deployment-id", "render-sha256", "workload-lock-sha256"]) {
    assert.match(infraOps, new RegExp(`com\\.platform\\.runtime\\.${label}`));
  }
});

function read(name) {
  return fs.readFileSync(path.join(root, name), "utf8");
}

function composeServices(source) {
  const lines = source.split(/\r?\n/);
  const services = [];
  let inServices = false;
  for (const line of lines) {
    if (line === "services:") {
      inServices = true;
      continue;
    }
    if (inServices && /^\S/.test(line)) break;
    const match = inServices ? line.match(/^  ([a-zA-Z0-9][a-zA-Z0-9_-]*):\s*$/) : null;
    if (match) services.push(match[1]);
  }
  return services;
}
