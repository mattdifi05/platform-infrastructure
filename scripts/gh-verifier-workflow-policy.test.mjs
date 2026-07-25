#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";

const installer = fs.readFileSync("scripts/install-gh-attestation-verifier.sh", "utf8");
const trust = fs.readFileSync("scripts/release-trust.mjs", "utf8");
const dockerfile = fs.readFileSync("docker/ops.Dockerfile", "utf8");
const release = fs.readFileSync(".github/workflows/release-attestation.yml", "utf8");
const enterprise = fs.readFileSync(".github/workflows/enterprise-infra.yml", "utf8");

assert.match(installer, /^GH_VERSION=2\.93\.0$/m);
assert.match(installer, /^GH_ARCHIVE_SHA256=02d1290eba130e0b896f3709ffff22e1c75a51475ddb70476a85abc6b5807af0$/m);
assert.match(installer, /^INSTALL_PATH=\/usr\/local\/bin\/gh$/m);
assert.match(installer, /sha256sum -c -/);
assert.match(installer, /sudo install -o root -g root -m 0755/);
assert.match(trust, /verifyGithubAttestation\(options, \{ verifierBinary = "\/usr\/local\/bin\/gh" \} = \{\}\)/);
assert.doesNotMatch(trust, /GITHUB_CLI_BIN|PLATFORM_RELEASE_TRUST_TEST_MODE/);
assert.match(dockerfile, /ARG GH_VERSION=2\.93\.0/);
assert.match(dockerfile, /ARG GH_SHA256=02d1290eba130e0b896f3709ffff22e1c75a51475ddb70476a85abc6b5807af0/);
assert.match(release, /node \.\/scripts\/infra-ops\.mjs github-attestation-evidence/);
assert.doesNotMatch(release, /sh \.\/scripts\/github-attestation-evidence\.sh/);

for (const [name, workflow] of [["producer", release], ["consumer", enterprise]]) {
  const install = workflow.indexOf("sh ./scripts/install-gh-attestation-verifier.sh");
  const gate = workflow.indexOf("node ./scripts/infra-ops.mjs release-artifact-gate", install + 1);
  assert.ok(install >= 0 && gate > install, `${name} workflow must install the pinned verifier before the direct-node gate`);
}

process.stdout.write("GitHub attestation verifier workflow policy tests passed 13/13\n");
