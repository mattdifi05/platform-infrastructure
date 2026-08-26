import assert from "node:assert/strict";
import test from "node:test";
import {
  SCHEMA,
  BROWNFIELD_SECRETS_ROOT,
  RCLONE_CONF_AUTHORITY_NOTE,
  GREENFIELD_SECRET_BASELINE_DIGESTS,
  GREENFIELD_ADDITIONAL_SECRET_MATERIAL_PATHS,
  buildSecretProjectionPlan,
  serializeSecretPlan,
  verifyObservedSecretSet,
  assertNoSecretMaterialization,
  buildSecretReceipt,
} from "./greenfield-secret-projection.mjs";

const GREENFIELD_SECRETS_ROOT = "/srv/platform-infrastructure/greenfield/secrets";
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

function syntheticPlan() {
  return buildSecretProjectionPlan({ greenfieldSecretsRoot: GREENFIELD_SECRETS_ROOT });
}

function observationFor(entry) {
  return {
    logicalName: entry.logicalName,
    sha256: entry.expectedSha256 ?? "a".repeat(64),
    sizeBytes: entry.sizeBytes ?? 128,
    mode: entry.requiredMode,
  };
}

test("baseline integrity mirrors the preservation manifest verbatim", () => {
  const names = Object.keys(GREENFIELD_SECRET_BASELINE_DIGESTS);
  // 37 keys total: the manifest _comment annotation plus 36 name -> sha256
  // file entries (the manifest hostStateTrees counts 37 txt files on host;
  // the published baseline map carries 36 digests + its comment key).
  assert.equal(names.length, 37);
  const digestNames = names.filter((name) => name !== "_comment");
  assert.equal(digestNames.length, 36);
  for (const name of digestNames) {
    assert.match(name, /\.txt$/, name);
    assert.match(GREENFIELD_SECRET_BASELINE_DIGESTS[name], SHA256_PATTERN, name);
  }
  // Spot-checks of digests already public in the manifest (never values).
  assert.equal(
    GREENFIELD_SECRET_BASELINE_DIGESTS["alertmanager_webhook_token.txt"],
    "36931d9f0eaaf574aac83a99d6c2a12894648a24c387d94346515e734ee941fb",
  );
  assert.equal(
    GREENFIELD_SECRET_BASELINE_DIGESTS["restic_password.txt"],
    "defa337fa044c77f414ae7938b896d71781794a46bfbb58bff63855fff4c741f",
  );
  assert.equal(
    GREENFIELD_SECRET_BASELINE_DIGESTS["session_secret.txt"],
    "3823e5a05dbbc4e8e12eb71decb3a5af9cc13e8d8774b033040d892db3ddea17",
  );
});

test("additional secret material list preserves all six critical paths as metadata", () => {
  assert.equal(GREENFIELD_ADDITIONAL_SECRET_MATERIAL_PATHS.length, 6);
  const byLogicalName = new Map(GREENFIELD_ADDITIONAL_SECRET_MATERIAL_PATHS.map((m) => [m.logicalName, m]));
  for (const expected of [
    "rclone_conf",
    "infra_secret_manager_store_json",
    "infra_secret_manager_audit_log",
    "infra_secret_manager_master_key",
    "confidential_backup_passphrase",
    "traefik_local_tls_certs",
  ]) {
    assert.ok(byLogicalName.has(expected), expected);
  }
  assert.equal(byLogicalName.get("rclone_conf").sizeBytes, 4562);
  assert.equal(byLogicalName.get("infra_secret_manager_store_json").sizeBytes, 19072);
  assert.equal(byLogicalName.get("confidential_backup_passphrase").sizeBytes, 87);
  // Metadata only: no entry carries anything resembling content.
  for (const material of GREENFIELD_ADDITIONAL_SECRET_MATERIAL_PATHS) {
    const serialized = JSON.stringify(material);
    assert.equal(assertNoSecretMaterialization(serialized), true, material.logicalName);
  }
});

test("plan construction is deterministic and structurally sound", () => {
  const plan = syntheticPlan();
  assert.equal(plan.schema, SCHEMA);
  assert.equal(plan.greenfieldSecretsRoot, GREENFIELD_SECRETS_ROOT);
  assert.equal(Object.isFrozen(plan), true);
  assert.equal(plan.entries.length, 36);
  assert.equal(plan.additionalMaterial.length, 6);

  const serializedOnce = serializeSecretPlan(plan);
  const rebuilt = buildSecretProjectionPlan({ greenfieldSecretsRoot: GREENFIELD_SECRETS_ROOT });
  assert.equal(serializeSecretPlan(rebuilt), serializedOnce);

  const logicalNames = plan.entries.map((entry) => entry.logicalName);
  const sortedCopy = [...logicalNames].sort();
  assert.deepEqual(logicalNames, sortedCopy);

  for (const entry of plan.entries) {
    assert.match(entry.expectedSha256, SHA256_PATTERN, entry.logicalName);
    assert.equal(entry.sourcePath, `${BROWNFIELD_SECRETS_ROOT}/${entry.logicalName}.txt`, entry.logicalName);
    assert.equal(entry.copyMethod, "byte-exact-copy-with-metadata");
    assert.equal(entry.verifyMethod, "sha256-after-copy");
    assert.equal(entry.requiredMode, "0600", entry.logicalName);
    assert.equal(entry.targetPath.includes("/"), false, entry.logicalName);
    assert.equal(
      `${GREENFIELD_SECRETS_ROOT}/${entry.targetPath}`.startsWith(`${GREENFIELD_SECRETS_ROOT}/`),
      true,
      entry.logicalName,
    );
  }
});

test("plan embeds nothing resembling a secret value", () => {
  const plan = syntheticPlan();
  const serialized = serializeSecretPlan(plan);
  assert.equal(assertNoSecretMaterialization(serialized), true);
  assert.doesNotMatch(serialized, /-----BEGIN/i);
  assert.doesNotMatch(serialized, /(?:password|passwd|pwd|token)\s*=/i);
  // The only long hex runs are the published 64-char baseline digests.
  for (const match of serialized.matchAll(/[A-Za-z0-9+/]{40,}/g)) {
    assert.match(match[0], SHA256_PATTERN, match[0]);
  }
});

function fullObservationSet(plan) {
  return [...plan.entries, ...plan.additionalMaterial].map(observationFor);
}

test("verifyObservedSecretSet reports MATCH when observations equal the plan", () => {
  const plan = syntheticPlan();
  const result = verifyObservedSecretSet({ plan, observed: fullObservationSet(plan) });
  assert.equal(result.status, "MATCH");
  assert.equal(result.violations.length, 0);
});

test("verifyObservedSecretSet fails closed on missing and empty observation sets", () => {
  const plan = syntheticPlan();
  const observations = fullObservationSet(plan);
  const withoutOne = observations.filter((o) => o.logicalName !== "restic_password");
  const missingResult = verifyObservedSecretSet({ plan, observed: withoutOne });
  assert.equal(missingResult.status, "FAIL");
  assert.deepEqual(
    missingResult.violations.map((violation) => violation.reason),
    ["missing"],
  );
  assert.equal(missingResult.violations[0].entry, "restic_password");

  const emptyResult = verifyObservedSecretSet({ plan, observed: [] });
  assert.equal(emptyResult.status, "FAIL");
  assert.equal(emptyResult.violations.length, plan.entries.length + plan.additionalMaterial.length);
  for (const violation of emptyResult.violations) {
    assert.equal(violation.reason, "missing");
  }
});

test("verifyObservedSecretSet flags extra observations not present in the plan", () => {
  const plan = syntheticPlan();
  const observations = fullObservationSet(plan);
  observations.push({
    logicalName: "unplanned_mystery_material",
    sha256: "b".repeat(64),
    sizeBytes: 10,
    mode: "0600",
  });
  const result = verifyObservedSecretSet({ plan, observed: observations });
  assert.equal(result.status, "FAIL");
  assert.equal(result.violations.length, 1);
  assert.equal(result.violations[0].entry, "unplanned_mystery_material");
  assert.equal(result.violations[0].reason, "extra");
});

test("verifyObservedSecretSet detects altered digests and mode mismatches", () => {
  const plan = syntheticPlan();

  const altered = fullObservationSet(plan).map((observation) => observation.logicalName === "session_secret"
    ? { ...observation, sha256: "c".repeat(64) }
    : observation);
  const alteredResult = verifyObservedSecretSet({ plan, observed: altered });
  assert.equal(alteredResult.status, "FAIL");
  assert.deepEqual(alteredResult.violations, [{ entry: "session_secret", reason: "digest-altered" }]);

  const modeMismatch = fullObservationSet(plan).map((observation) => observation.logicalName === "github_token"
    ? { ...observation, mode: "0644" }
    : observation);
  const modeResult = verifyObservedSecretSet({ plan, observed: modeMismatch });
  assert.equal(modeResult.status, "FAIL");
  assert.deepEqual(modeResult.violations, [{ entry: "github_token", reason: "mode-mismatch" }]);

  const sizeMissing = fullObservationSet(plan).map((observation) => observation.logicalName === "smtp_password"
    ? { ...observation, sizeBytes: undefined }
    : observation);
  const sizeResult = verifyObservedSecretSet({ plan, observed: sizeMissing });
  assert.equal(sizeResult.status, "FAIL");
  assert.deepEqual(sizeResult.violations, [{ entry: "smtp_password", reason: "size-missing" }]);
});

test("receipt carries metadata only and refuses leaky strings", () => {
  const plan = syntheticPlan();
  const verifyResult = verifyObservedSecretSet({ plan, observed: fullObservationSet(plan) });
  const receipt = buildSecretReceipt({ plan, verifyResult, runId: "20260826T000000Z-greenfield-projection" });

  assert.equal(receipt.schema, SCHEMA);
  assert.equal(receipt.status, "MATCH");
  assert.equal(receipt.counts.plannedEntries, 36);
  assert.equal(receipt.counts.plannedAdditionalMaterial, 6);
  assert.equal(receipt.counts.observedViolations, 0);
  assert.equal(receipt.counts.verifiedWithoutViolation, 42);
  for (const entry of receipt.entries) {
    assert.equal(entry.sha256Matched, true, entry.logicalName);
    assert.equal(Object.hasOwn(entry, "sha256") || Object.hasOwn(entry, "value"), false, entry.logicalName);
  }
  const serializedReceipt = JSON.stringify(receipt);
  assert.equal(assertNoSecretMaterialization(serializedReceipt), true);
  assert.doesNotMatch(serializedReceipt, /-----BEGIN/i);

  assert.throws(() => buildSecretReceipt({
    plan,
    verifyResult,
    runId: "run -----BEGIN RSA PRIVATE KEY leaked",
  }), /potential secret materialization detected/);
});

test("rclone.conf is planned as authoritative-current operational state", () => {
  const plan = syntheticPlan();
  const rclone = plan.additionalMaterial.find((entry) => entry.sourcePath.endsWith("/rclone/rclone.conf"));
  assert.ok(rclone, "rclone.conf entry must exist in the projection plan");
  assert.equal(rclone.classification, "critical-material");
  assert.equal(rclone.authority, RCLONE_CONF_AUTHORITY_NOTE);
  assert.match(rclone.authority, /authoritative-current-operational-state/);
  assert.match(rclone.authority, /never suggest rollback of rclone\.conf/i);
  assert.equal(rclone.rollbackPolicy, "never-suggest-rollback-of-rclone-conf");
  assert.equal(rclone.requiredMode, "0600");
});

test("leak guard distinguishes clean metadata from credential-shaped text", () => {
  assert.equal(assertNoSecretMaterialization("projection complete: 42 entries verified"), true);
  assert.equal(assertNoSecretMaterialization("sha256=3823e5a05dbbc4e8e12eb71decb3a5af9cc13e8d8774b033040d892db3ddea17"), true);
  assert.equal(assertNoSecretMaterialization("-----BEGIN RSA PRIVATE KEY"), false);
  assert.equal(assertNoSecretMaterialization("-----BEGIN CERTIFICATE"), false);
  assert.equal(assertNoSecretMaterialization("password=hunter2"), false);
  assert.equal(assertNoSecretMaterialization("token=abc123"), false);
  assert.equal(assertNoSecretMaterialization("A".repeat(65)), false);
  assert.equal(assertNoSecretMaterialization("A".repeat(64)), true);
});
