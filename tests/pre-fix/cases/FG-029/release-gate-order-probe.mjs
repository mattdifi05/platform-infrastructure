#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const EXPECTED_HASHES = new Map([
  [".github/workflows/enterprise-infra.yml", "1cc02a79d482c2bee65e0173c879d7cf06f74f84ee5d9a6ed6893b2907fd8650"],
  ["SECURITY.md", "b72a0abd090dfa15832d5af3e389edeee50cf5128cbd515e7c74b6a72f4d9cb3"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
  ["scripts/deploy-vps.sh", "ee572ce2164fa620c59eb63cecc5d75db02f58d9e664bf923400b5315ef75245"],
  ["scripts/deploy-vps-remote.sh", "e7460e9db36765e6078d778d8a5388d54a78ee4620ddb70f2f7a19187f937804"],
  ["scripts/infra-ops.mjs", "379d0c79ab22eb4e7210212eb564c173c77b32a89d2e58a87ea4d9158790ac2b"],
  ["scripts/prepare-vps-runtime.sh", "e260cd2f9daa7db2f31a911ec50e9086e1ff07974ec3478e938a7456a30a2734"],
  ["scripts/vps-postdeploy.sh", "e88fa132b375d110933e473a0dc80f10ebe06ab37eb8741ba2a8139a06da7963"],
  ["scripts/vps-preflight.sh", "7ef50ca582463092bbd0d2e6be5150b2c7cfe7979c931e8c74fe1988fe9eca03"],
]);

const GATES = [
  "waf-smoke",
  "rate-limit-evidence",
  "audit-log-evidence",
  "retention-evidence",
  "infra-health",
  "production-preflight",
  "pre-go-live-evidence",
  "secret-rotation-evidence",
  "production-go-no-go",
  "production-readiness-live",
];

const PRODUCTION_ADMISSION_GATES = [
  "production-preflight",
  "pre-go-live-evidence",
  "secret-rotation-evidence",
  "production-go-no-go",
  "production-readiness-live",
];

const EFFECTS = ["build", "container", "network", "volume", "runtime"];
const sourceRoot = path.resolve(process.argv[2] ?? "");

if (!process.argv[2] || !fs.statSync(sourceRoot, { throwIfNoEntry: false })?.isDirectory()) {
  throw new Error("usage: release-gate-order-probe.mjs /path/to/archived/source");
}

for (const [relativePath, expected] of EXPECTED_HASHES) {
  assert.equal(
    sha256File(path.join(sourceRoot, relativePath)),
    expected,
    `${relativePath} is not the expected vulnerable source`,
  );
}
console.log("[PASS] exact pre-fix source fingerprints verified");

const client = readSource("scripts/deploy-vps.sh");
const remote = readSource("scripts/deploy-vps-remote.sh");
const postdeploy = readSource("scripts/vps-postdeploy.sh");
const compose = readSource("scripts/compose-vps.sh");
const workflow = readSource(".github/workflows/enterprise-infra.yml");
const security = readSource("SECURITY.md");
const infraOps = readSource("scripts/infra-ops.mjs");
const deployJob = workflow.slice(workflow.indexOf("  deploy-vps:"));

assert.match(client, /run_production_preflight=\$\{DEPLOY_RUN_PRODUCTION_PREFLIGHT:-0\}/);
assert.match(client, /run_pre_go_live=\$\{DEPLOY_RUN_PRE_GO_LIVE:-0\}/);
assert.match(client, /run_go_no_go=\$\{DEPLOY_RUN_GO_NO_GO:-0\}/);
console.log("[PASS] direct deploy defaults disable production-preflight, pre-go-live, and go/no-go");

assertOrdered(remote, [
  "git pull --ff-only origin \"$branch\"",
  "sh ./scripts/vps-preflight.sh \"$env_file\"",
  "sh ./scripts/prepare-vps-runtime.sh",
  "bash ./scripts/compose-vps.sh up -d --build --remove-orphans",
  "sh ./scripts/vps-postdeploy.sh \"$env_file\"",
]);
assert.match(compose, /exec "\$\{compose\[@\]\}" --profile backup "\$@"/);
console.log("[PASS] exact remote order is fetched-code execution, preparation, Compose activation, then postdeploy gates");

assert.doesNotMatch(remote, /release-artifact-gate|requireProvenance|production-go-no-go\.sh/);
assertOrdered(postdeploy, GATES.map((gate) => `./scripts/${gate}.sh`));
assert.match(infraOps, /async function releaseArtifactGate\(options = \{\}\)/);
assert.match(infraOps, /if \(requireProvenance\) \{[\s\S]*verifyGithubReleaseImages\(/);
assert.match(security, /production-preflight\.sh` before every VPS release/);
assert.match(security, /Release admission must invoke the checksum-pinned GitHub verifier directly/);
console.log("[PASS] no release-artifact or provenance admission is invoked before activation");

assert.match(deployJob, /DEPLOY_RUN_PRODUCTION_PREFLIGHT: "1"/);
assert.match(deployJob, /DEPLOY_RUN_PRE_GO_LIVE: "1"/);
assert.match(deployJob, /DEPLOY_RUN_GO_NO_GO: "1"/);
assert.match(deployJob, /run: sh \.\/scripts\/deploy-vps\.sh/);
console.log("[PASS] canonical workflow enables late gates but retains the same activation-before-gates sequence");

const temporaryParent = process.env.RELEASE_GATE_POC_TMP || os.tmpdir();
const fixtureRoot = fs.mkdtempSync(path.join(temporaryParent, "release-gate-fixture-"));
let completed = false;

try {
  const remoteRoot = path.join(fixtureRoot, "remote");
  const scriptsDir = path.join(remoteRoot, "scripts");
  const mockBin = path.join(fixtureRoot, "bin");
  fs.mkdirSync(scriptsDir, { recursive: true });
  fs.mkdirSync(mockBin);
  fs.writeFileSync(path.join(remoteRoot, ".env"), "", { mode: 0o600 });
  fs.copyFileSync(path.join(sourceRoot, "scripts/vps-postdeploy.sh"), path.join(scriptsDir, "vps-postdeploy.sh"));

  writeExecutable(path.join(mockBin, "git"), `#!/bin/sh
set -eu
printf 'git:%s\\n' "$*" >> "$TRACE_FILE"
`);

  writeExecutable(path.join(scriptsDir, "vps-preflight.sh"), `#!/bin/sh
set -eu
printf '%s\\n' 'preactivation:vps-preflight' >> "$TRACE_FILE"
`);

  writeExecutable(path.join(scriptsDir, "prepare-vps-runtime.sh"), `#!/bin/sh
set -eu
printf '%s\\n' 'preactivation:prepare-vps-runtime' >> "$TRACE_FILE"
`);

  writeExecutable(path.join(scriptsDir, "compose-vps.sh"), `#!/bin/sh
set -eu
printf 'sink:compose %s\\n' "$*" >> "$TRACE_FILE"
printf '%s\\n' 'effect:build' 'effect:container' 'effect:network' 'effect:volume' 'effect:runtime' >> "$TRACE_FILE"
`);

  const gateStub = `#!/bin/sh
set -eu
name=\${0##*/}
name=\${name%.sh}
printf 'gate:%s:start\\n' "$name" >> "$TRACE_FILE"
if [ "\${FAIL_GATE:-}" = "$name" ]; then
  printf 'gate:%s:fail\\n' "$name" >> "$TRACE_FILE"
  exit 42
fi
printf 'gate:%s:pass\\n' "$name" >> "$TRACE_FILE"
`;
  for (const gate of GATES) {
    writeExecutable(path.join(scriptsDir, `${gate}.sh`), gateStub);
  }

  const directDefaults = runScenario({
    label: "direct-defaults",
    remoteRoot,
    mockBin,
    fixtureRoot,
    productionFlags: false,
  });
  assert.equal(directDefaults.status, 0, directDefaults.diagnostics);
  assert.equal(countLine(directDefaults.lines, "sink:compose "), 1);
  for (const gate of PRODUCTION_ADMISSION_GATES) {
    assert.equal(directDefaults.lines.some((line) => line.startsWith(`gate:${gate}:`)), false);
  }
  console.log("[TRACE] direct_defaults compose=1 production_admission_gates=0");

  for (const gate of GATES) {
    const result = runScenario({
      label: `fail-${gate}`,
      failGate: gate,
      remoteRoot,
      mockBin,
      fixtureRoot,
      productionFlags: true,
    });
    assert.equal(result.status, 42, result.diagnostics);
    const sinkIndex = findLine(result.lines, "sink:compose ");
    const failureIndex = findLine(result.lines, `gate:${gate}:fail`);
    assert.ok(sinkIndex >= 0, `Compose sink was not reached before ${gate}`);
    assert.ok(failureIndex > sinkIndex, `${gate} did not fail after the Compose sink`);
    for (const effect of EFFECTS) {
      const effectIndex = findLine(result.lines, `effect:${effect}`);
      assert.ok(effectIndex > sinkIndex && effectIndex < failureIndex, `${effect} marker was not before ${gate}`);
    }
    console.log(`[TRACE] fail=${gate} compose_before_failure=true effects=${EFFECTS.join(",")}`);
  }

  console.log(`[PASS] ${GATES.length}/${GATES.length} injected postdeploy failures occur after the Compose mutation sink`);
  console.log("[REFERENCE] closure requires effects=0 for every failed admission gate");
  console.log("[SAFE] exact remote and postdeploy control flow used local stubs only; no Git transport, Docker, network, container, volume, runtime, SSH, or live-state access");
  completed = true;
} finally {
  fs.rmSync(fixtureRoot, { recursive: true, force: true });
}

assert.equal(completed, true);
assert.equal(fs.existsSync(fixtureRoot), false);
console.log("[+] temporary fixture removed");

function runScenario({ label, failGate = "", remoteRoot, mockBin, fixtureRoot, productionFlags }) {
  const traceFile = path.join(fixtureRoot, `${label}.trace`);
  fs.writeFileSync(traceFile, "", { mode: 0o600 });
  const flag = productionFlags ? "1" : "0";
  const result = spawnSync("/bin/sh", [path.join(sourceRoot, "scripts/deploy-vps-remote.sh")], {
    cwd: fixtureRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${mockBin}${path.delimiter}${process.env.PATH ?? ""}`,
      TRACE_FILE: traceFile,
      FAIL_GATE: failGate,
      DEPLOY_RUN_RATE_LIMIT_EVIDENCE: "1",
      DEPLOY_RUN_AUDIT_LOG_EVIDENCE: "1",
      DEPLOY_RUN_RETENTION_EVIDENCE: "1",
      PLATFORM_REMOTE_DIR_B64: encodeField(remoteRoot),
      PLATFORM_BRANCH_B64: encodeField("main"),
      PLATFORM_ENV_FILE_B64: encodeField(".env"),
      PLATFORM_PROJECT_NAME_B64: encodeField("release_gate_poc"),
      PLATFORM_RUN_WAF_SMOKE_B64: encodeField("1"),
      PLATFORM_RUN_INFRA_HEALTH_B64: encodeField("1"),
      PLATFORM_RUN_PRODUCTION_PREFLIGHT_B64: encodeField(flag),
      PLATFORM_RUN_PRE_GO_LIVE_B64: encodeField(flag),
      PLATFORM_RUN_GO_NO_GO_B64: encodeField(flag),
      PLATFORM_DEPLOY_REPO_B64: encodeField("owner/repository"),
      PLATFORM_PRE_GO_LIVE_PRODUCTION_PREFLIGHT_B64: encodeField("1"),
      PLATFORM_PRE_GO_LIVE_RESTORE_DRILL_B64: encodeField("1"),
      PLATFORM_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN_B64: encodeField("1"),
      PLATFORM_PRE_GO_LIVE_GITHUB_REMOTE_B64: encodeField("0"),
    },
  });
  const lines = fs.readFileSync(traceFile, "utf8").trim().split("\n").filter(Boolean);
  return {
    status: result.status,
    lines,
    diagnostics: `scenario=${label} status=${result.status} stdout=${result.stdout.trim()} stderr=${result.stderr.trim()} trace=${lines.join("|")}`,
  };
}

function assertOrdered(source, fragments) {
  let cursor = -1;
  for (const fragment of fragments) {
    const next = source.indexOf(fragment, cursor + 1);
    assert.ok(next > cursor, `missing or out-of-order source fragment: ${fragment}`);
    cursor = next;
  }
}

function countLine(lines, prefix) {
  return lines.filter((line) => line.startsWith(prefix)).length;
}

function findLine(lines, value) {
  return lines.findIndex((line) => line === value || line.startsWith(value));
}

function encodeField(value) {
  return Buffer.from(value, "utf8").toString("base64");
}

function readSource(relativePath) {
  return fs.readFileSync(path.join(sourceRoot, relativePath), "utf8");
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function writeExecutable(filePath, contents) {
  fs.writeFileSync(filePath, contents, { mode: 0o700 });
}
