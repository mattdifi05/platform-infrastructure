#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const gatePath = path.join(import.meta.dirname, "hosted-workload-activation-gate.sh");
const gateSource = fs.readFileSync(gatePath, "utf8");
const functionStart = gateSource.indexOf("verify_model_for_bundle() {");
const functionEndMarker = "\n}\n\nverify_inputs()";
const functionEnd = gateSource.indexOf(functionEndMarker, functionStart);
assert.notEqual(functionStart, -1, "verify_model_for_bundle() is missing");
assert.notEqual(functionEnd, -1, "verify_model_for_bundle() boundary is missing");
const verifyModelFunction = gateSource.slice(functionStart, functionEnd + 2);

test("activation boundary invokes final Node validation before create or start", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "hosted-activation-secret-"));
  try {
    const modelPath = path.join(root, "combined.json");
    const corePath = path.join(root, "core.json");
    const lockPath = path.join(root, "verified-lock.json");
    const mutationMarker = path.join(root, "mutations");
    const validatorMarker = path.join(root, "validator");
    const model = {
      services: {
        "billing-web": {
          labels: { "com.platform.workload-id": "billing" },
          secrets: [{ source: "billing-api-key", target: "billing-api-key" }],
          environment: { BILLING_TOKEN_FILE: "/run/secrets/ungranted-secret" },
        },
      },
    };
    fs.writeFileSync(modelPath, JSON.stringify(model));
    fs.writeFileSync(corePath, JSON.stringify({ services: {} }));
    fs.writeFileSync(lockPath, "{}");
    const modelSha = sha256(fs.readFileSync(modelPath));
    const bundle = {
      combinedRenderSha256: modelSha,
      serviceRecords: [{ workloadId: "billing", serviceName: "billing-web" }],
    };
    assert.equal(
      model.services["billing-web"].environment.BILLING_TOKEN_FILE,
      "/run/secrets/ungranted-secret",
    );

    const result = spawnSync("/bin/bash", [
      "-c",
      `set -u
SCRIPT_DIR=$1
model=$2
model_sha=$3
bundle=$4
lock=$5
core=$6
mutation_marker=$7
validator_marker=$8
sha256_file() { shasum -a 256 "$1" | awk '{ print $1 }'; }
node() {
  if [[ "$1" == "$SCRIPT_DIR/hosted-workload-contract.mjs" \
    && "$2" == "verify-activation-render" \
    && " $* " == *" --lock $lock "* \
    && " $* " == *" --coreRender $core "* \
    && " $* " == *" --combinedRender $model "* ]]; then
    printf validated > "$validator_marker"
    return 73
  fi
  return 99
}
create_services() { printf create >> "$mutation_marker"; }
start_services() { printf start >> "$mutation_marker"; }
${verifyModelFunction}
if verify_model_for_bundle "$model" "$model_sha" "$bundle" "$lock" "$core"; then
  create_services
  start_services
fi
[[ -s "$validator_marker" && ! -e "$mutation_marker" ]]
`,
      "hosted-activation-secret-boundary",
      import.meta.dirname,
      modelPath,
      modelSha,
      JSON.stringify(bundle),
      lockPath,
      corePath,
      mutationMarker,
      validatorMarker,
    ], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(fs.existsSync(mutationMarker), false);
    assert.equal(fs.readFileSync(validatorMarker, "utf8"), "validated");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}
