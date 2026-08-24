#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const paths = [
  "scripts/deploy-vps.sh",
  "scripts/deploy-v1-local-private.sh",
  ".github/workflows/enterprise-infra.yml",
  ".github/workflows/enterprise-vps-evidence.yml",
  ".github/workflows/v1-local-private.yml",
];
const sources = Object.fromEntries(paths.map((pathname) => [pathname, fs.readFileSync(pathname, "utf8")]));
const combined = Object.values(sources).join("\n");
assert.doesNotMatch(combined, /StrictHostKeyChecking=accept-new|ssh-keyscan/);
assert.match(combined, /StrictHostKeyChecking=yes/);
assert.match(combined, /UserKnownHostsFile=/);
assert.match(combined, /GlobalKnownHostsFile=\/dev\/null/);
assert.match(combined, /UpdateHostKeys=no/);
assert.match(combined, /BatchMode=yes/);
assert.match(combined, /IdentitiesOnly=yes/);
assert.match(sources["scripts/deploy-vps.sh"], /pinned-ssh-host-key\.mjs" verify/);
assert.match(sources[".github/workflows/enterprise-vps-evidence.yml"], /DEPLOY_SSH_HOST_KEY[\s\S]*pinned-ssh-host-key\.mjs verify/);
assert.match(sources["scripts/deploy-vps.sh"], /pinned-ssh-host-key\.mjs" verify[\s\S]*ssh "\$@" -- "\$REMOTE" '\/usr\/bin\/sudo -n -- \/usr\/local\/libexec\/platform-activation-broker activate'/);
assert.match(sources[".github/workflows/enterprise-vps-evidence.yml"], /known_hosts_snapshot[\s\S]*pinned-ssh-host-key\.mjs verify[\s\S]*ssh -F \/dev\/null -i "\$ssh_key_snapshot"/);
assert.match(sources["scripts/deploy-vps.sh"], /require_input_file "SSH private key" "\$SSH_KEY_SOURCE"/);
assert.match(sources["scripts/deploy-vps.sh"], /require_input_file "SSH known-hosts input" "\$KNOWN_HOSTS_SOURCE"/);
assert.match(sources["scripts/deploy-vps.sh"], /key_before=.*[\s\S]*cp "\$SSH_KEY_SOURCE" "\$ssh_key"[\s\S]*hash_file "\$SSH_KEY_SOURCE"/);
assert.match(sources["scripts/deploy-v1-local-private.sh"], /pinned-ssh-host-key\.mjs" verify/);
assert.doesNotMatch(
  sources[".github/workflows/v1-local-private.yml"],
  /DEPLOY_SSH_HOST_KEY|pinned-ssh-host-key|\/usr\/bin\/ssh|deploy-v1-local-private\.sh/,
  "the hosted LOCAL_PRIVATE workflow must stop before every SSH/deploy boundary",
);
assert.match(sources[".github/workflows/v1-local-private.yml"], /STOP 78 LOCAL_OPERATOR_ESCROW_REQUIRED/);
assert.match(sources["scripts/deploy-v1-local-private.sh"], /pinned-ssh-host-key\.mjs" verify[\s\S]*exec "\$SSH" "\$@" -- "\$REMOTE" "\$REMOTE_COMMAND" < \/dev\/null/);
assert.match(sources["scripts/deploy-v1-local-private.sh"], /REMOTE_COMMAND='\/usr\/bin\/sudo -n -- \/usr\/local\/libexec\/platform-v1-local-private-control activate'/);
assert.match(sources["scripts/deploy-v1-local-private.sh"], /require_input_file "SSH private key" "\$SSH_KEY_SOURCE"/);
assert.match(sources["scripts/deploy-v1-local-private.sh"], /require_input_file "SSH known-hosts input" "\$KNOWN_HOSTS_SOURCE"/);
assert.match(sources["scripts/deploy-v1-local-private.sh"], /key_before=.*[\s\S]*cp "\$SSH_KEY_SOURCE" "\$ssh_key"[\s\S]*hash_file "\$SSH_KEY_SOURCE"/);

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-host-key-policy-"));
process.on("exit", () => fs.rmSync(temporary, { recursive: true, force: true }));
const helper = path.resolve("scripts/ssh-known-host-endpoint.sh");
const endpoint = "[example.internal]:2222";
const key1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILBajvJtpsX+LmnBbwAcOXdb9LRHK+d9WJlVKLaAklDO";
const key2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAtGTSaFMsqramyTprMstB+XUzWdhAegQpEZoNyZT02T";

function verify(contents, host = "example.internal", port = "2222") {
  const file = path.join(temporary, `known-hosts-${crypto.randomUUID()}`);
  fs.writeFileSync(file, contents, { mode: 0o600 });
  return spawnSync("sh", [helper, host, port, file], { encoding: "utf8" });
}

assert.equal(verify(`${endpoint} ${key1}\n`).status, 0, "the exact initial pin must pass");
assert.equal(verify(`${endpoint} ${key2}\n`).status, 0, "an atomically replaced rotation pin must pass");
assert.notEqual(verify(`${endpoint} ${key1}\n`, "unknown.internal").status, 0, "an unknown endpoint must fail");
assert.notEqual(verify(`${endpoint} ${key1}\n`, "example.internal", "2200").status, 0, "a wrong endpoint port must fail");
assert.notEqual(verify(`${endpoint} ${key1}\n${endpoint} ${key2}\n`).status, 0, "a conflicting old/new key set must fail until atomically approved");
assert.notEqual(verify(`[*.internal]:2222 ${key1}\n`).status, 0, "a wildcard host pattern must not satisfy an exact endpoint pin");
assert.notEqual(verify(`${endpoint},[alias.internal]:2222 ${key1}\n`).status, 0, "a comma-separated alias must not widen the exact endpoint pin");
assert.notEqual(verify(`${endpoint} ssh-ed25519 definitely-not-a-key\n`).status, 0, "malformed key base64 must fail before SSH");
assert.notEqual(verify(`${endpoint} ssh-unknown ${key1.split(" ")[1]}\n`).status, 0, "an unsupported key type must fail before SSH");

process.stdout.write("SSH host key policy tests passed 30/30\n");
