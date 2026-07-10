#!/usr/bin/env node
import assert from "node:assert/strict";
import {
  renderVpsEvidenceRemoteScript,
  validateVpsEvidenceRequest,
} from "./vps-evidence-request.mjs";

const valid = {
  DEPLOY_REMOTE: "deploy_user@example.internal",
  DEPLOY_REMOTE_DIR: "/opt/platform-infrastructure",
  DEPLOY_SSH_PORT: "2222",
  VPS_HARDENED_SSH_PORT: "2222",
  RUN_BOOTSTRAP: "false",
  RUN_HARDENING: "false",
  RELOAD_SSHD: "false",
  REPLACE_DOCKER_DAEMON_CONFIG: "false",
  CONFIRM_MUTATING_VPS: "false",
  DEPLOY_USER: "platform_deploy",
};

let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  process.stdout.write(`ok ${passed} - ${name}\n`);
}

test("valid request renders only encoded remote values", () => {
  const request = validateVpsEvidenceRequest(valid);
  const rendered = renderVpsEvidenceRemoteScript(request, "printf done\n");
  assert.ok(!rendered.includes(valid.DEPLOY_USER));
  assert.ok(!rendered.includes(valid.DEPLOY_REMOTE_DIR));
  assert.match(rendered, /^PLATFORM_REMOTE_DIR_B64='[A-Za-z0-9+/=]+'/);
});
test("deploy user command substitution is rejected", () => {
  assert.throws(() => validateVpsEvidenceRequest({ ...valid, DEPLOY_USER: "x$(touch /tmp/pwn)" }), /Unix account/);
});
test("deploy user command separator is rejected", () => {
  assert.throws(() => validateVpsEvidenceRequest({ ...valid, DEPLOY_USER: "valid;id" }), /Unix account/);
});
test("newline injection is rejected", () => {
  assert.throws(() => validateVpsEvidenceRequest({ ...valid, DEPLOY_USER: "valid\nid" }), /Unix account/);
});
test("SSH option injection is rejected", () => {
  assert.throws(() => validateVpsEvidenceRequest({ ...valid, DEPLOY_REMOTE: "-oProxyCommand=id" }), /user@hostname/);
});
test("remote path shell syntax is rejected", () => {
  assert.throws(() => validateVpsEvidenceRequest({ ...valid, DEPLOY_REMOTE_DIR: "/opt/platform;id" }), /absolute path/);
});
test("remote path traversal is rejected", () => {
  assert.throws(() => validateVpsEvidenceRequest({ ...valid, DEPLOY_REMOTE_DIR: "/opt/../root" }), /absolute path/);
});
test("invalid SSH port is rejected", () => {
  assert.throws(() => validateVpsEvidenceRequest({ ...valid, DEPLOY_SSH_PORT: "22;id" }), /SSH port/);
});
test("mutation requires explicit confirmation", () => {
  assert.throws(() => validateVpsEvidenceRequest({ ...valid, RUN_HARDENING: "true" }), /CONFIRM_MUTATING_VPS/);
});
test("confirmed mutation remains valid", () => {
  const request = validateVpsEvidenceRequest({ ...valid, RUN_HARDENING: "true", CONFIRM_MUTATING_VPS: "true" });
  assert.equal(request.runHardening, "true");
});

process.stdout.write(`VPS evidence request tests passed ${passed}/${passed}\n`);
