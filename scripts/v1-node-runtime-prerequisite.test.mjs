#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const source = path.join(import.meta.dirname, "v1-node-runtime-prerequisite.py");
const installConsumerSource = path.join(import.meta.dirname, "v1-brownfield-install-consumer.py");
const python = process.env.PLATFORM_TEST_PYTHON || "/usr/bin/python3";
const packageVersion = "22.22.1+dfsg+~cs22.19.15-1ubuntu1";
const candidateCommit = "1".repeat(40);
const candidateTree = "2".repeat(40);
const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
const stable = (value) => Array.isArray(value) ? `[${value.map(stable).join(",")}]` : value && typeof value === "object"
  ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`
  : JSON.stringify(value);
const fixed = (root, logical) => path.join(root, logical.slice(1));
const shell = (value) => `'${String(value).replaceAll("'", `'"'"'`)}'`;

function write(filename, value, mode = 0o600) {
  fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
  fs.writeFileSync(filename, value, { mode });
  fs.chmodSync(filename, mode);
}

function fixture(t, { available = true, installedVersion = null, runtimeVersion = "v22.22.1" } = {}) {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "v1-node-runtime-test-")));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const archive = Buffer.from("exact source archive fixture\n");
  const archiveSha256 = sha(archive);
  const releaseRoot = `/srv/platform-infrastructure/releases/${candidateCommit}-${archiveSha256}`;
  const helper = fixed(root, `${releaseRoot}/scripts/v1-node-runtime-prerequisite.py`);
  const installReceiptPath = fixed(root, `/var/lib/platform-infrastructure/v1/install-receipts/${candidateCommit}-${archiveSha256}.json`);
  const sourceArchivePath = fixed(root, "/var/lib/platform-infrastructure/v1/predeploy/current/exact-source-archive.tar");
  const persistedReceipt = fixed(root, "/var/lib/platform-infrastructure/v1/local-private/node-runtime-prerequisite-receipt.json");
  const state = path.join(root, "tool-state", "node-version");
  const installCount = path.join(root, "tool-state", "apt-install-count");
  const tools = path.join(root, "tools");
  const aptCache = path.join(tools, "apt-cache");
  const aptGet = path.join(tools, "apt-get");
  const dpkgQuery = path.join(tools, "dpkg-query");
  const node = fixed(root, "/usr/bin/node");

  fs.mkdirSync(path.dirname(state), { recursive: true, mode: 0o700 });
  write(helper, fs.readFileSync(source), 0o444);
  write(sourceArchivePath, archive, 0o444);
  const installReceipt = {
    activationAuthorized: false,
    authorizationSource: "ROOT_OPERATOR_EXPLICIT_INSTALL_ONLY",
    backupEvidenceAuthoritative: false,
    candidateCommit,
    candidateTree,
    dataMutation: false,
    dockerMutation: false,
    readyButDisabled: ["PROVIDER_ADMISSION"],
    releaseRoot,
    schema: "platform.v1-brownfield-install-receipt/v1",
    sourceArchiveSha256: archiveSha256,
    status: "INSTALL_ONLY_COMPLETE",
  };
  write(installReceiptPath, `${stable(installReceipt)}\n`, 0o400);
  if (installedVersion !== null) write(state, `${installedVersion}\n`, 0o600);
  write(node, `#!/bin/sh\nprintf '%s\\n' ${shell(runtimeVersion)}\n`, 0o700);
  write(dpkgQuery, `#!/bin/sh
set -eu
[ "$#" -eq 3 ]
[ "$1" = -W ]
[ "$2" = '-f=\${Package}\\t\${Status}\\t\${Version}\\t\${Architecture}\\n' ]
[ "$3" = nodejs ]
if [ ! -f ${shell(state)} ]; then exit 1; fi
version=$(tr -d '\\n' < ${shell(state)})
printf 'nodejs\\tinstall ok installed\\t%s\\tamd64\\n' "$version"
`, 0o700);
  write(aptCache, `#!/bin/sh
set -eu
[ "$#" -eq 2 ] && [ "$1" = show ] && [ "$2" = ${shell(`nodejs=${packageVersion}`)} ]
${available ? `printf 'Package: nodejs\\nVersion: %s\\nArchitecture: amd64\\n\\n' ${shell(packageVersion)}` : "exit 1"}
`, 0o700);
  write(aptGet, `#!/bin/sh
set -eu
[ "$#" -eq 6 ]
[ "$1" = -y ]
[ "$2" = --no-install-recommends ]
[ "$3" = --option ]
[ "$4" = 'Dpkg::Options::=--force-confold' ]
[ "$5" = install ]
[ "$6" = ${shell(`nodejs=${packageVersion}`)} ]
count=0
[ ! -f ${shell(installCount)} ] || count=$(cat ${shell(installCount)})
count=$((count + 1))
printf '%s\\n' "$count" > ${shell(installCount)}
printf '%s\\n' ${shell(packageVersion)} > ${shell(state)}
`, 0o700);

  return {
    archiveSha256, helper, installCount, persistedReceipt, root, state,
    environment: {
      ...process.env,
      PLATFORM_V1_NODE_RUNTIME_TEST_ROOT: root,
      PLATFORM_V1_NODE_RUNTIME_TEST_APT_CACHE: aptCache,
      PLATFORM_V1_NODE_RUNTIME_TEST_APT_GET: aptGet,
      PLATFORM_V1_NODE_RUNTIME_TEST_DPKG_QUERY: dpkgQuery,
      PLATFORM_V1_NODE_RUNTIME_TEST_NODE: node,
    },
  };
}

function execute(current, extra = []) {
  return spawnSync(python, ["-I", current.helper, "apply", ...extra], {
    cwd: "/", encoding: "utf8", env: current.environment, timeout: 30_000,
  });
}

test("production-shaped install receipt owner follows the root bootstrap consumer", () => {
  const helperText = fs.readFileSync(source, "utf8");
  const consumerText = fs.readFileSync(installConsumerSource, "utf8");
  assert.match(consumerText, /OUTPUT_UID = os\.geteuid\(\)/);
  assert.match(helperText, /strict_json\(install_receipt_path, "exact-release install receipt"\)/);
  assert.doesNotMatch(helperText, /getpwnam|platform_infrastructure[^\n]*pw_uid/);
});

test("installs the exact absent Ubuntu package and emits a canonical mutation-truth receipt", (t) => {
  const current = fixture(t);
  const result = execute(current);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  const receipt = JSON.parse(result.stdout);
  assert.equal(result.stdout, `${stable(receipt)}\n`);
  assert.equal(receipt.schema, "platform.v1-node-runtime-prerequisite-receipt/v1");
  assert.equal(receipt.status, "NODE_RUNTIME_READY");
  assert.equal(receipt.candidateCommit, candidateCommit);
  assert.equal(receipt.candidateTree, candidateTree);
  assert.equal(receipt.sourceArchiveSha256, current.archiveSha256);
  assert.equal(receipt.packageName, "nodejs");
  assert.equal(receipt.packageVersion, packageVersion);
  assert.equal(receipt.packageArchitecture, "amd64");
  assert.equal(receipt.runtimeVersion, "v22.22.1");
  assert.equal(receipt.binaryPath, "/usr/bin/node");
  assert.match(receipt.binarySha256, /^[a-f0-9]{64}$/);
  assert.equal(receipt.hostControlMutation, true);
  assert.equal(receipt.activationAuthorized, false);
  assert.equal(receipt.dataMutation, false);
  assert.equal(receipt.dockerMutation, false);
  assert.equal(receipt.workloadMutation, false);
  const base = { ...receipt };
  delete base.documentId;
  assert.equal(receipt.documentId, sha(stable(base)));
  assert.equal(fs.readFileSync(current.persistedReceipt, "utf8"), result.stdout);
  assert.equal(fs.statSync(current.persistedReceipt).mode & 0o777, 0o444);
  assert.equal(fs.readFileSync(current.installCount, "utf8"), "1\n");
  const retry = execute(current);
  assert.equal(retry.status, 0, retry.stderr);
  assert.equal(retry.stdout, result.stdout);
  assert.equal(JSON.parse(retry.stdout).hostControlMutation, true);
  assert.equal(fs.readFileSync(current.installCount, "utf8"), "1\n");
});

test("an exact installed runtime is idempotent and does not invoke apt-get", (t) => {
  const current = fixture(t, { installedVersion: packageVersion });
  const first = execute(current);
  assert.equal(first.status, 0, first.stderr);
  assert.equal(JSON.parse(first.stdout).hostControlMutation, false);
  assert.equal(fs.existsSync(current.installCount), false);
  const second = execute(current);
  assert.equal(second.status, 0, second.stderr);
  assert.equal(JSON.parse(second.stdout).hostControlMutation, false);
  assert.equal(fs.existsSync(current.installCount), false);
  assert.equal(fs.readFileSync(current.persistedReceipt, "utf8"), second.stdout);
});

test("refuses a foreign installed package without implicit upgrade or downgrade", (t) => {
  const current = fixture(t, { installedVersion: "23.0.0-foreign" });
  const result = execute(current);
  assert.equal(result.status, 78);
  assert.match(result.stderr, /refusing an implicit upgrade or downgrade/);
  assert.equal(fs.existsSync(current.installCount), false);
  assert.equal(fs.existsSync(current.persistedReceipt), false);
});

test("fails closed when the exact Ubuntu package pin is unavailable", (t) => {
  const current = fixture(t, { available: false });
  const result = execute(current);
  assert.equal(result.status, 78);
  assert.match(result.stderr, /exact Node package pin is unavailable/);
  assert.equal(fs.existsSync(current.installCount), false);
  assert.equal(fs.existsSync(current.persistedReceipt), false);
});

test("rejects runtime drift, archive drift, and every caller-selected argument", (t) => {
  let current = fixture(t, { installedVersion: packageVersion, runtimeVersion: "v22.22.0" });
  let result = execute(current);
  assert.equal(result.status, 78);
  assert.match(result.stderr, /exact required version/);

  current = fixture(t, { installedVersion: packageVersion });
  const archivePath = fixed(current.root, "/var/lib/platform-infrastructure/v1/predeploy/current/exact-source-archive.tar");
  fs.chmodSync(archivePath, 0o600);
  fs.appendFileSync(archivePath, "drift");
  fs.chmodSync(archivePath, 0o444);
  result = execute(current);
  assert.equal(result.status, 78);
  assert.match(result.stderr, /source archive differs/);

  current = fixture(t, { installedVersion: packageVersion });
  result = execute(current, ["nodejs=latest"]);
  assert.equal(result.status, 64);
  assert.match(result.stderr, /usage:/);
  assert.equal(fs.existsSync(current.installCount), false);
});
