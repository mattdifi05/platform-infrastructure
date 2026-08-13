#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { renderPinnedKnownHost, verifyPinnedKnownHostsFile } from "./pinned-ssh-host-key.mjs";

const repositoryRoot = path.resolve(import.meta.dirname, "..");

function sshString(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

const keyBlob = Buffer.concat([
  sshString("ssh-ed25519"),
  sshString(Buffer.alloc(32, 7)),
]).toString("base64");
const hostKey = `ssh-ed25519 ${keyBlob}`;

test("dedicated host key is independently bound to the exact SSH host and port", () => {
  assert.equal(
    renderPinnedKnownHost({ remote: "deploy_user@example.internal", port: "2222", hostKey }),
    `[example.internal]:2222 ${hostKey}\n`,
  );
  assert.equal(
    renderPinnedKnownHost({ remote: "deploy_user@example.internal", port: "22", hostKey }),
    `example.internal ${hostKey}\n`,
  );
});

test("malformed, multiline, and mismatched host keys fail closed", () => {
  assert.throws(() => renderPinnedKnownHost({ remote: "deploy_user@example.internal", port: "2222", hostKey: `${hostKey}\nssh-ed25519 ${keyBlob}` }), /single pinned key/);
  assert.throws(() => renderPinnedKnownHost({ remote: "deploy_user@example.internal", port: "2222", hostKey: `ssh-rsa ${keyBlob}` }), /algorithm/);
  assert.throws(() => renderPinnedKnownHost({ remote: "-oProxyCommand=id", port: "2222", hostKey }), /user@hostname/);
  assert.throws(() => renderPinnedKnownHost({ remote: "deploy_user@example.internal", port: "22;id", hostKey }), /port/);
});

test("known_hosts verification rejects wrong endpoints and extra trust entries", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "pinned-ssh-host-"));
  const file = path.join(directory, "known_hosts");
  try {
    fs.writeFileSync(file, renderPinnedKnownHost({ remote: "deploy_user@example.internal", port: "2222", hostKey }), { mode: 0o600 });
    assert.equal(verifyPinnedKnownHostsFile({ remote: "deploy_user@example.internal", port: "2222", file }).host, "example.internal");
    assert.throws(() => verifyPinnedKnownHostsFile({ remote: "deploy_user@other.internal", port: "2222", file }), /endpoint/);
    fs.appendFileSync(file, `other.internal ${hostKey}\n`);
    assert.throws(() => verifyPinnedKnownHostsFile({ remote: "deploy_user@example.internal", port: "2222", file }), /exactly one/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("SSH workflows require pinned trust and contain no trust-on-first-use path", () => {
  const evidenceWorkflow = fs.readFileSync(path.join(repositoryRoot, ".github", "workflows", "enterprise-vps-evidence.yml"), "utf8");
  const deployWorkflow = fs.readFileSync(path.join(repositoryRoot, ".github", "workflows", "enterprise-infra.yml"), "utf8");
  const deployScript = fs.readFileSync(path.join(repositoryRoot, "scripts", "deploy-vps.sh"), "utf8");
  const combined = [evidenceWorkflow, deployWorkflow, deployScript].join("\n");
  const forbiddenTrustOnFirstUse = new RegExp([
    ["accept", "new"].join("-"),
    ["StrictHostKeyChecking", "no"].join("="),
    ["ssh", "keyscan"].join("-"),
  ].join("|"), "i");
  assert.doesNotMatch(combined, forbiddenTrustOnFirstUse);
  assert.match(evidenceWorkflow, /DEPLOY_SSH_HOST_KEY: \$\{\{ secrets\.DEPLOY_SSH_HOST_KEY \}\}/);
  assert.match(deployWorkflow, /DEPLOY_SSH_HOST_KEY: \$\{\{ secrets\.DEPLOY_SSH_HOST_KEY \}\}/);
  assert.match(combined, /StrictHostKeyChecking=yes/);
  assert.match(combined, /UserKnownHostsFile=/);
  assert.match(deployScript, /pinned-ssh-host-key\.mjs"\s+verify/);
});

test("a fake endpoint cannot emit an archive or receipt through any pre-trust gate", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "fake-ssh-endpoint-"));
  const fakeSsh = path.join(directory, "ssh");
  const invoked = path.join(directory, "invoked");
  const missingTrust = path.join(directory, "missing-known-hosts");
  try {
    fs.writeFileSync(fakeSsh, `#!/bin/sh\nprintf invoked > ${JSON.stringify(invoked)}\nprintf '%s\\n' '__PLATFORM_VPS_EVIDENCE_RECEIPT_BEGIN__' 'ZmFrZQ==' '__PLATFORM_VPS_EVIDENCE_RECEIPT_END__' '__PLATFORM_VPS_EVIDENCE_TGZ_BEGIN__' 'ZmFrZQ==' '__PLATFORM_VPS_EVIDENCE_TGZ_END__'\n`, { mode: 0o700 });
    const result = spawnSync("sh", [path.join(repositoryRoot, "scripts", "deploy-vps.sh")], {
      cwd: repositoryRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${directory}:${process.env.PATH}`,
        DEPLOY_REMOTE: "deploy_user@example.internal",
        DEPLOY_REMOTE_DIR: "/opt/platform/platform-infrastructure",
        DEPLOY_SSH_PORT: "2222",
        DEPLOY_SSH_KNOWN_HOSTS_PATH: missingTrust,
      },
    });
    assert.notEqual(result.status, 0);
    assert.equal(fs.existsSync(invoked), false);
    assert.match(
      result.stderr,
      /provider-attested ops image entrypoint|authoritative V1 brownfield admission|pinned SSH host trust/i,
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
