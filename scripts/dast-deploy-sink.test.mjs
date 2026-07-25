#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";

const localSink = fs.readFileSync("scripts/deploy-vps.sh", "utf8");
const remoteSink = fs.readFileSync("scripts/deploy-vps-remote.sh", "utf8");
const workflow = fs.readFileSync(".github/workflows/enterprise-infra.yml", "utf8");

for (const variable of [
  "DEPLOY_STAGING_RECEIPT_PATH",
  "DEPLOY_STAGING_RECEIPT_SHA256",
  "DEPLOY_DAST_RECEIPT_PATH",
  "DEPLOY_DAST_RECEIPT_SHA256",
  "DEPLOY_CONSUMER_RUN_ID",
  "DEPLOY_CONSUMER_RUN_ATTEMPT",
  "DEPLOY_CONSUMER_JOB",
  "DEPLOY_CHALLENGE_NONCE",
]) {
  assert.match(localSink, new RegExp(variable), `${variable} is not mandatory at the deploy-vps.sh sink`);
  assert.match(workflow, new RegExp(`${variable}:`), `${variable} is not handed to the deploy-vps.sh sink`);
}

const localValidation = localSink.indexOf("dast-runtime-receipt-policy.mjs");
const sshConnection = localSink.indexOf('ssh "$@" "$REMOTE"');
assert.ok(localValidation >= 0 && sshConnection > localValidation,
  "the exact DAST receipt and challenge must be revalidated before SSH");
assert.match(localSink, /PLATFORM_STAGING_RECEIPT_B64=/);
assert.match(localSink, /PLATFORM_DAST_RECEIPT_B64=/);
assert.match(remoteSink, /dast-runtime-receipt-policy\.mjs/);
assert.match(remoteSink, /consumerRunId/);
assert.match(remoteSink, /challengeNonce/);

process.stdout.write("DAST deploy sink policy tests passed 22/22\n");
