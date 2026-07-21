#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";

const paths = [
  "scripts/deploy-vps.sh",
  ".github/workflows/enterprise-infra.yml",
  ".github/workflows/enterprise-vps-evidence.yml",
];
const combined = paths.map((pathname) => fs.readFileSync(pathname, "utf8")).join("\n");
assert.doesNotMatch(combined, /StrictHostKeyChecking=accept-new|ssh-keyscan/);
assert.match(combined, /StrictHostKeyChecking=yes/);
assert.match(combined, /UserKnownHostsFile=/);
assert.match(combined, /GlobalKnownHostsFile=\/dev\/null/);
assert.match(combined, /DEPLOY_KNOWN_HOSTS/);
process.stdout.write("SSH host key policy tests passed 5/5\n");
