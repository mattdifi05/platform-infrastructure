#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import { privilegedWorkflowMismatches } from "./privileged-workflow-policy.mjs";

const fixtures = [
  [".github/workflows/enterprise-infra.yml", "deploy-vps", false],
  [".github/workflows/enterprise-vps-evidence.yml", "vps-host-evidence", false],
  [".github/workflows/enterprise-live-evidence.yml", "production-live-evidence", false],
  [".github/workflows/release-attestation.yml", "github-sigstore-release-evidence", true],
];

for (const [pathname, jobName, forbidTagTrigger] of fixtures) {
  const text = fs.readFileSync(pathname, "utf8");
  assert.deepEqual(privilegedWorkflowMismatches(text, { jobName, forbidTagTrigger }), []);
  assert.match(
    privilegedWorkflowMismatches(text.replaceAll("github.ref_protected == true", "true"), { jobName, forbidTagTrigger }).join(" "),
    /protected-main/,
  );
  assert.match(
    privilegedWorkflowMismatches(text.replaceAll("persist-credentials: false", "persist-credentials: true"), { jobName, forbidTagTrigger }).join(" "),
    /persisted credentials/,
  );
}

const release = fs.readFileSync(".github/workflows/release-attestation.yml", "utf8");
assert.match(
  privilegedWorkflowMismatches(`${release}\n  push:\n    tags: ['v*']\n`, { jobName: "github-sigstore-release-evidence", forbidTagTrigger: true }).join(" "),
  /tag triggers/,
);
process.stdout.write(`privileged workflow policy tests passed ${fixtures.length * 3 + 1}/${fixtures.length * 3 + 1}\n`);
