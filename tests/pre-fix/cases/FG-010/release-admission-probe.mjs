#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const AFFECTED_REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const EXPECTED_HASHES = new Map([
  ["scripts/infra-ops.mjs", "379d0c79ab22eb4e7210212eb564c173c77b32a89d2e58a87ea4d9158790ac2b"],
  ["scripts/release-artifact-gate.sh", "e518b601e71a3dbd4889389668cd95436a2d288fe3c24c6da33590cfa70c171a"],
  ["scripts/release-trust.mjs", "69a5a538a8125eb756e515812be161d97e8699d63124c935f5425d86eea7bdc0"],
  [".github/workflows/enterprise-infra.yml", "1cc02a79d482c2bee65e0173c879d7cf06f74f84ee5d9a6ed6893b2907fd8650"],
  ["security/admission/cosign-digest-policy.rego", "62c6052d50c2445ef1fd9c16af6587299282de3b5bda48c87780e0dc043b863f"],
]);

const args = parseArgs(process.argv.slice(2));
const sourceRoot = path.resolve(required(args["source-root"], "--source-root"));
const revision = String(args.revision || "unknown");
const expectation = String(args.expect || "vulnerable");
if (!["vulnerable", "fixed", "either"].includes(expectation)) {
  throw new Error(`--expect must be vulnerable, fixed, or either; received ${expectation}`);
}

verifySourceArchive(sourceRoot, revision, expectation);
verifyWorkflowDefault(sourceRoot);

const cases = [
  {
    id: "no-provenance",
    label: "plausible SBOM, no provenance",
    sbom: ".poc/plausible-release-sbom.cdx.json",
  },
  {
    id: "unrelated-json",
    label: "unrelated JSON, no provenance",
    sbom: ".poc/unrelated.json",
  },
  {
    id: "wrong-subject",
    label: "wrong commit/digest SBOM",
    sbom: ".poc/wrong-subject-sbom.cdx.json",
  },
];

const results = cases.map((testCase) => runGate(sourceRoot, testCase));
printResults(results, revision);

const allAccepted = results.every(({ accepted }) => accepted);
const allRejected = results.every(({ accepted }) => !accepted);
if (expectation === "vulnerable") {
  assert.equal(allAccepted, true, "expected every unproven or unrelated evidence set to be admitted");
} else if (expectation === "fixed") {
  assert.equal(allRejected, true, "expected every unproven evidence set to be rejected");
}

if (allAccepted) {
  process.stdout.write("\n[CAN-065] Missing cryptographic provenance was accepted.\n");
  process.stdout.write("[CAN-066] Unrelated JSON and a wrong-subject SBOM were accepted.\n");
} else if (allRejected) {
  process.stdout.write("\n[FIXED] Every unproven evidence set was rejected.\n");
} else {
  process.stdout.write("\n[MIXED] Admission behavior differs by evidence set; inspect the rows above.\n");
}

function runGate(root, testCase) {
  const infraOps = path.join(root, "scripts/infra-ops.mjs");
  const result = spawnSync(process.execPath, [
    infraOps,
    "release-artifact-gate",
    "--envFile", ".poc/release.env",
    "--imageManifest", ".poc/release-images.json",
    "--sbom", testCase.sbom,
    "--releaseSha", AFFECTED_REVISION,
  ], {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env,
      PLATFORM_GIT_COMMIT: AFFECTED_REVISION,
      PLATFORM_GIT_BRANCH: "poc/archive",
      PLATFORM_GIT_DIRTY: "0",
    },
    maxBuffer: 8 * 1024 * 1024,
  });
  return {
    ...testCase,
    accepted: result.status === 0,
    status: result.status,
    message: conciseMessage(result),
  };
}

function verifySourceArchive(root, selectedRevision, selectedExpectation) {
  const observed = [];
  for (const [relative, expected] of EXPECTED_HASHES) {
    const actual = crypto.createHash("sha256")
      .update(fs.readFileSync(path.join(root, relative)))
      .digest("hex");
    observed.push({ relative, actual, expected });
  }

  if (selectedExpectation === "vulnerable") {
    assert.equal(selectedRevision, AFFECTED_REVISION, `vulnerable expectation requires revision ${AFFECTED_REVISION}`);
    for (const item of observed) {
      assert.equal(item.actual, item.expected, `unexpected source digest for ${item.relative}`);
    }
    process.stdout.write(`[+] clean archive source digests match affected revision ${selectedRevision}\n`);
  } else {
    process.stdout.write(`[+] evaluating clean archive revision ${selectedRevision}\n`);
  }
}

function verifyWorkflowDefault(root) {
  const workflow = fs.readFileSync(path.join(root, ".github/workflows/enterprise-infra.yml"), "utf8");
  const match = workflow.match(/- name: Release artifact gate dry run([\s\S]*?)(?=\n\s+- name:)/);
  assert.ok(match, "release artifact gate workflow step not found");
  assert.match(match[1], /release-artifact-gate/);
  assert.match(match[1], /"components":\[\]/);
  assert.doesNotMatch(match[1], /--requireProvenance/);
  process.stdout.write("[+] workflow gate call omits --requireProvenance and supplies an empty-component JSON SBOM\n");
}

function printResults(rows, selectedRevision) {
  process.stdout.write(`\nRevision: ${selectedRevision}\n\n`);
  process.stdout.write("case                              exit admission\n");
  process.stdout.write("--------------------------------- ---- ---------\n");
  for (const row of rows) {
    process.stdout.write(`${row.label.padEnd(33)} ${String(row.status).padStart(4)} ${row.accepted ? "ACCEPTED" : "REJECTED"}\n`);
    if (!row.accepted && row.message) process.stdout.write(`  reason: ${row.message}\n`);
  }
}

function conciseMessage(result) {
  const text = `${result.stderr || ""}\n${result.stdout || ""}`
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .find((line) => !line.startsWith("Local check report written"));
  return String(text || `exit ${result.status}`).slice(0, 500);
}

function parseArgs(values) {
  const parsed = {};
  for (let index = 0; index < values.length; index += 1) {
    if (!values[index].startsWith("--")) continue;
    parsed[values[index].slice(2)] = values[index + 1] && !values[index + 1].startsWith("--")
      ? values[++index]
      : true;
  }
  return parsed;
}

function required(value, flag) {
  if (!value || value === true) throw new Error(`${flag} is required`);
  return String(value);
}
