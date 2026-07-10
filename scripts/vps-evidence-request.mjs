#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));

function invalid(message) {
  throw new Error(message);
}

function exactBoolean(value, label) {
  const text = String(value ?? "");
  if (!["true", "false"].includes(text)) {
    invalid(`${label} must be true or false.`);
  }
  return text;
}

function sshPort(value, label) {
  const text = String(value ?? "");
  const number = Number(text);
  if (!/^\d{1,5}$/.test(text) || !Number.isInteger(number) || number < 1 || number > 65535) {
    invalid(`${label} must be an SSH port between 1 and 65535.`);
  }
  return text;
}

function deployRemote(value) {
  const text = String(value ?? "");
  if (!/^[a-z_][a-z0-9_-]{0,31}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/.test(text)) {
    invalid("DEPLOY_REMOTE must be a simple user@hostname value.");
  }
  return text;
}

function remotePath(value) {
  const text = String(value ?? "");
  if (!/^\/[A-Za-z0-9._/-]+$/.test(text) || text.includes("//") || text.split("/").includes("..")) {
    invalid("DEPLOY_REMOTE_DIR must be an absolute path without whitespace, traversal or shell syntax.");
  }
  return text;
}

function optionalDeployUser(value) {
  const text = String(value ?? "");
  if (text && !/^[a-z_][a-z0-9_-]{0,31}$/.test(text)) {
    invalid("DEPLOY_USER must be empty or a valid Unix account name.");
  }
  return text;
}

export function validateVpsEvidenceRequest(input) {
  const request = {
    deployRemote: deployRemote(input.DEPLOY_REMOTE),
    remoteDir: remotePath(input.DEPLOY_REMOTE_DIR),
    sshPort: sshPort(input.DEPLOY_SSH_PORT, "DEPLOY_SSH_PORT"),
    hardenedSshPort: sshPort(input.VPS_HARDENED_SSH_PORT, "VPS_HARDENED_SSH_PORT"),
    runBootstrap: exactBoolean(input.RUN_BOOTSTRAP, "RUN_BOOTSTRAP"),
    runHardening: exactBoolean(input.RUN_HARDENING, "RUN_HARDENING"),
    reloadSshd: exactBoolean(input.RELOAD_SSHD, "RELOAD_SSHD"),
    replaceDockerDaemonConfig: exactBoolean(input.REPLACE_DOCKER_DAEMON_CONFIG, "REPLACE_DOCKER_DAEMON_CONFIG"),
    confirmMutatingVps: exactBoolean(input.CONFIRM_MUTATING_VPS, "CONFIRM_MUTATING_VPS"),
    deployUser: optionalDeployUser(input.DEPLOY_USER),
  };
  if ((request.runBootstrap === "true" || request.runHardening === "true") && request.confirmMutatingVps !== "true") {
    invalid("CONFIRM_MUTATING_VPS must be true before bootstrap or hardening.");
  }
  return request;
}

function encodedAssignment(name, value) {
  const encoded = Buffer.from(String(value), "utf8").toString("base64");
  return `${name}='${encoded}'`;
}

export function renderVpsEvidenceRemoteScript(request, remoteScriptText) {
  const assignments = [
    encodedAssignment("PLATFORM_REMOTE_DIR_B64", request.remoteDir),
    encodedAssignment("PLATFORM_HARDENED_SSH_PORT_B64", request.hardenedSshPort),
    encodedAssignment("PLATFORM_RUN_BOOTSTRAP_B64", request.runBootstrap),
    encodedAssignment("PLATFORM_RUN_HARDENING_B64", request.runHardening),
    encodedAssignment("PLATFORM_RELOAD_SSHD_B64", request.reloadSshd),
    encodedAssignment("PLATFORM_REPLACE_DOCKER_DAEMON_CONFIG_B64", request.replaceDockerDaemonConfig),
    encodedAssignment("PLATFORM_DEPLOY_USER_B64", request.deployUser),
  ];
  return `${assignments.join("\n")}\n${String(remoteScriptText)}`;
}

export function requestFromEnvironment(environment = process.env) {
  return validateVpsEvidenceRequest(environment);
}

function main() {
  if ((process.argv[2] ?? "render") !== "render") {
    invalid("Usage: vps-evidence-request.mjs render [remote-script-path]");
  }
  const request = requestFromEnvironment();
  const remoteScriptPath = path.resolve(process.argv[3] ?? path.join(scriptDir, "vps-evidence-remote.sh"));
  const remoteScriptText = fs.readFileSync(remoteScriptPath, "utf8");
  process.stdout.write(renderVpsEvidenceRemoteScript(request, remoteScriptText));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
