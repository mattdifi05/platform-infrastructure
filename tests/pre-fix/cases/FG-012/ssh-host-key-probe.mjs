#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const AFFECTED_REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const EXPECTED_HASHES = new Map([
  ["scripts/deploy-vps.sh", "ee572ce2164fa620c59eb63cecc5d75db02f58d9e664bf923400b5315ef75245"],
  ["scripts/deploy-vps-remote.sh", "e7460e9db36765e6078d778d8a5388d54a78ee4620ddb70f2f7a19187f937804"],
  ["scripts/vps-evidence-request.mjs", "b5214592c3ea5cbcbc9b52142a2236708e23f20ffb95ae48d4bf9de790977e40"],
  ["scripts/vps-evidence-remote.sh", "c5a893a722addfa3da16d405caf2239a4c89228dd6f7858facc61a9b2716cb2d"],
  [".github/workflows/enterprise-vps-evidence.yml", "312d035fea9b16017289c1c87b2222a48f292d6a93f8f725bf486227588b9f1d"],
  [".github/workflows/enterprise-infra.yml", "1cc02a79d482c2bee65e0173c879d7cf06f74f84ee5d9a6ed6893b2907fd8650"],
]);

const args = parseArgs(process.argv.slice(2));
const sourceRoot = path.resolve(required(args["source-root"], "--source-root"));
const revision = String(args.revision || "unknown");
const expectation = String(args.expect || "vulnerable");
if (!["vulnerable", "fixed", "either"].includes(expectation)) {
  throw new Error(`--expect must be vulnerable, fixed, or either; received ${expectation}`);
}

verifySourceArchive(sourceRoot, revision, expectation);
const sourceState = inspectSourceState(sourceRoot);

if (expectation === "fixed") {
  printStaticState(sourceState, revision);
  assert.equal(sourceState.fixed, true, "expected strict pinned-host-key policy at both call sites");
  process.stdout.write("\n[FIXED] Both SSH surfaces require a pinned known-hosts file.\n");
  process.exit(0);
}

const deploy = captureDeployInvocation(sourceRoot);
const evidence = captureEvidenceInvocation(sourceRoot);
printVulnerableResults({ deploy, evidence, revision });

const vulnerable = sourceState.vulnerable
  && deploy.policy === "accept-new"
  && deploy.userKnownHostsFile === null
  && evidence.policy === "accept-new"
  && evidence.userKnownHostsFile === null
  && evidence.archiveMembers.includes("reports/vps-host/forged-readiness.json");

if (expectation === "vulnerable") {
  assert.equal(vulnerable, true, "expected first-use trust at deployment and evidence call sites");
}

if (vulnerable) {
  process.stdout.write("\n[CAN-049] deploy-vps.sh sends its deployment request after first-use host-key acceptance.\n");
  process.stdout.write("[CAN-098] the evidence workflow accepts the first host key and can consume impostor evidence.\n");
} else {
  process.stdout.write("\n[MIXED] SSH host-key behavior differs across the two surfaces.\n");
}

function captureDeployInvocation(root) {
  const captureRoot = path.join(root, ".poc", "capture-deploy");
  fs.mkdirSync(captureRoot, { recursive: true });
  const argvFile = path.join(captureRoot, "argv.txt");
  const stdinFile = path.join(captureRoot, "stdin.sh");
  const result = spawnSync("sh", [path.join(root, "scripts/deploy-vps.sh")], {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${path.join(root, ".poc", "fake-bin")}:${process.env.PATH || ""}`,
      HOME: path.join(root, ".poc", "home"),
      DEPLOY_REMOTE: "deploy@vps.example.test",
      DEPLOY_REMOTE_DIR: "/opt/platform/platform-infrastructure",
      DEPLOY_SSH_PORT: "2222",
      DEPLOY_SSH_KEY_PATH: path.join(root, ".poc", "fixtures", "deploy_key"),
      POC_SSH_ARGV: argvFile,
      POC_SSH_STDIN: stdinFile,
      POC_SSH_MODE: "capture",
    },
    maxBuffer: 8 * 1024 * 1024,
  });
  assert.equal(result.status, 0, `deploy capture failed: ${result.stderr || result.stdout}`);
  const capturedArgs = fs.readFileSync(argvFile, "utf8").trim().split(/\r?\n/);
  const payload = fs.readFileSync(stdinFile);
  return {
    policy: sshOption(capturedArgs, "StrictHostKeyChecking"),
    userKnownHostsFile: sshOption(capturedArgs, "UserKnownHostsFile"),
    requestBytes: payload.length,
    requestSha256: sha256(payload),
  };
}

function captureEvidenceInvocation(root) {
  const captureRoot = path.join(root, ".poc", "capture-evidence");
  fs.mkdirSync(captureRoot, { recursive: true });
  const argvFile = path.join(captureRoot, "argv.txt");
  const stdinFile = path.join(captureRoot, "stdin.sh");
  const render = spawnSync(process.execPath, [path.join(root, "scripts/vps-evidence-request.mjs"), "render"], {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env,
      DEPLOY_REMOTE: "deploy@vps.example.test",
      DEPLOY_REMOTE_DIR: "/opt/platform/platform-infrastructure",
      DEPLOY_SSH_PORT: "2222",
      VPS_HARDENED_SSH_PORT: "2222",
      RUN_BOOTSTRAP: "false",
      RUN_HARDENING: "false",
      RELOAD_SSHD: "false",
      REPLACE_DOCKER_DAEMON_CONFIG: "false",
      CONFIRM_MUTATING_VPS: "false",
      DEPLOY_USER: "",
    },
    maxBuffer: 8 * 1024 * 1024,
  });
  assert.equal(render.status, 0, `evidence request render failed: ${render.stderr}`);

  const fakeSsh = path.join(root, ".poc", "fake-bin", "ssh");
  const sshArgs = [
    "-i", path.join(root, ".poc", "fixtures", "deploy_key"),
    "-p", "2222",
    "-o", "StrictHostKeyChecking=accept-new",
    "deploy@vps.example.test", "bash -s",
  ];
  const result = spawnSync(fakeSsh, sshArgs, {
    cwd: root,
    input: render.stdout,
    encoding: "utf8",
    env: {
      ...process.env,
      POC_SSH_ARGV: argvFile,
      POC_SSH_STDIN: stdinFile,
      POC_SSH_MODE: "evidence",
      POC_FORGED_ARCHIVE_ROOT: path.join(root, ".poc", "fixtures", "forged-archive-root"),
    },
    maxBuffer: 8 * 1024 * 1024,
  });
  assert.equal(result.status, 0, `evidence fake SSH failed: ${result.stderr}`);
  const match = result.stdout.match(/__PLATFORM_VPS_EVIDENCE_TGZ_BEGIN__\n([A-Za-z0-9+/=]+)\n__PLATFORM_VPS_EVIDENCE_TGZ_END__/);
  assert.ok(match, "fake evidence archive markers were not emitted");
  const archiveFile = path.join(captureRoot, "forged-evidence.tgz");
  fs.writeFileSync(archiveFile, Buffer.from(match[1], "base64"));
  const listing = spawnSync("tar", ["-tzf", archiveFile], { encoding: "utf8" });
  assert.equal(listing.status, 0, `could not list harmless evidence archive: ${listing.stderr}`);
  const capturedArgs = fs.readFileSync(argvFile, "utf8").trim().split(/\r?\n/);
  return {
    policy: sshOption(capturedArgs, "StrictHostKeyChecking"),
    userKnownHostsFile: sshOption(capturedArgs, "UserKnownHostsFile"),
    remoteScriptBytes: Buffer.byteLength(render.stdout),
    archiveMembers: listing.stdout.trim().split(/\r?\n/),
  };
}

function inspectSourceState(root) {
  const deploy = fs.readFileSync(path.join(root, "scripts/deploy-vps.sh"), "utf8");
  const workflow = fs.readFileSync(path.join(root, ".github/workflows/enterprise-vps-evidence.yml"), "utf8");
  const deployAcceptNew = /StrictHostKeyChecking=accept-new/.test(deploy);
  const workflowAcceptNew = /StrictHostKeyChecking=accept-new/.test(workflow);
  const deployPinned = /StrictHostKeyChecking=(?:yes|true)/.test(deploy) && /UserKnownHostsFile/.test(deploy);
  const workflowPinned = /StrictHostKeyChecking=(?:yes|true)/.test(workflow)
    && /UserKnownHostsFile/.test(workflow)
    && /known_hosts/i.test(workflow);
  return {
    vulnerable: deployAcceptNew && workflowAcceptNew && !deployPinned && !workflowPinned,
    fixed: !deployAcceptNew && !workflowAcceptNew && deployPinned && workflowPinned,
    deployAcceptNew,
    workflowAcceptNew,
    deployPinned,
    workflowPinned,
  };
}

function printVulnerableResults({ deploy, evidence, revision: selectedRevision }) {
  process.stdout.write(`\nRevision: ${selectedRevision}\n\n`);
  process.stdout.write("surface                         policy      pinned-known-hosts transmitted\n");
  process.stdout.write("------------------------------- ----------- ------------------ -----------------------------\n");
  process.stdout.write(`deploy-vps.sh                   ${deploy.policy.padEnd(11)} ${"absent".padEnd(18)} request=${deploy.requestBytes} bytes\n`);
  process.stdout.write(`enterprise-vps-evidence.yml     ${evidence.policy.padEnd(11)} ${"absent".padEnd(18)} forged-readiness.json accepted\n`);
}

function printStaticState(state, selectedRevision) {
  process.stdout.write(`\nRevision: ${selectedRevision}\n`);
  process.stdout.write(`deploy: accept-new=${state.deployAcceptNew} pinned=${state.deployPinned}\n`);
  process.stdout.write(`evidence workflow: accept-new=${state.workflowAcceptNew} pinned=${state.workflowPinned}\n`);
}

function sshOption(values, name) {
  const prefix = `${name}=`;
  const value = values.find((entry) => entry.startsWith(prefix));
  return value ? value.slice(prefix.length) : null;
}

function verifySourceArchive(root, selectedRevision, selectedExpectation) {
  const observed = [];
  for (const [relative, expected] of EXPECTED_HASHES) {
    const actual = sha256(fs.readFileSync(path.join(root, relative)));
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

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
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
