// Greenfield secret projection planner for V1 LOCAL_PRIVATE GREENFIELD.
//
// Byte-identity contract: every preserved secret must satisfy
// OLD_SHA256 == NEW_SHA256 after projection. This module plans and verifies
// that projection using ONLY digests and metadata. Secret VALUES are never
// read, printed, logged, exported, or embedded anywhere in this module, its
// outputs, or its receipts.
//
// Ground truth: platform.v1-greenfield-preservation-manifest/v1
// (secretFileSha256Baseline, additionalSecretMaterialPaths, hostStateTrees).
//
// rclone authority rule: rclone.conf current bytes are the AUTHORITATIVE
// operational state (a prior read-only probe refreshed an OAuth token). The
// captured digest of the current file is the baseline. Rollback of rclone.conf
// to any earlier capture is never suggested; the plan marks the entry
// authoritative-current.

export const SCHEMA = "platform.greenfield-secret-projection/v1";

const SHA256_PATTERN = /^[0-9a-f]{64}$/;

// Brownfield secrets root as measured in the preservation manifest
// hostStateTrees["/home/platform_infrastructure/platform-infrastructure/secrets"]
// (size 220K, 37 txt files counted on host, storeJsonBytes 19072). Used only
// as the SOURCE path prefix in plans; never read by this module.
export const BROWNFIELD_SECRETS_ROOT = "/home/platform_infrastructure/platform-infrastructure/secrets";

// Authoritative-current marker for rclone.conf (see header comment).
export const RCLONE_CONF_AUTHORITY_NOTE =
  "authoritative-current-operational-state: rclone.conf current bytes are the operational truth "
  + "(a prior read-only probe refreshed an OAuth token); captured digest is the baseline; "
  + "never suggest rollback of rclone.conf";

// Baseline digests copied VERBATIM from preservation-manifest.json field
// secretFileSha256Baseline: 36 name -> sha256 entries plus the manifest
// _comment annotation key (37 keys total). Values are digests, not secrets.
export const GREENFIELD_SECRET_BASELINE_DIGESTS = Object.freeze({
  "_comment": "SHA256 of each secrets/*.txt file; values never read or printed. Baseline for byte-identical projection check.",
  "alertmanager_webhook_token.txt": "36931d9f0eaaf574aac83a99d6c2a12894648a24c387d94346515e734ee941fb",
  "app_db_password.txt": "b84490692ca37804909f23e1572924364e52feca49b3e65b9cba0e098dd4ce9b",
  "backup_signing_keys.txt": "a62163d7ffab9c7d6963851d9a80303e6530664a1ec21faffdc0072b68db8c82",
  "cloudflare_turnstile_secret_key.txt": "04ec780ab94dc6adc6d895819f8e48299517b420b1b03a464ffac2856dd6c1a3",
  "control_center_database_url.txt": "5779e87b059ea3971b1ad12cc6c72bff0098311fa21bb14b438e033b9eefd540",
  "control_center_first_configuration_bootstrap_token.txt": "aef742081980f3a569a124348d541eb9bb98c169c85a88b041921d8165dcf9cf",
  "control_center_first_configuration_keycloak_client_secret.txt": "7ea09c4a4498f4b862dca5e6bdf3d76f66c734f09b8a9c30a26b88044da72919",
  "control_center_vault_keys.txt": "fffe8ed374b43662f3bc992287d415d26f684298c92524ab76a061943b40e39b",
  "database_url.txt": "cd4d11d3eedadaeb86381126576552d722294e1898b5fe3d21a9266d923c7dd2",
  "docker_action_backup_catalog.txt": "be27ae6f78af9cd4039608b14a7e181c04c20368e35cf07619ee6242cbe837c9",
  "docker_action_backup_job_execute.txt": "6a18447899be4aacb67f8580bdc3e696de50909fb0763387a5b95f5e49529a0c",
  "docker_action_backup_offsite_sync.txt": "bb1c8a2160ba15e766a7602937755d8decb849551f26841d03e89c8ec0aff9ea",
  "docker_action_backup_prune_apply.txt": "d3fb7026d0a0b00a903c6b2180cb90788c5fb53780e401e10d19e96dfa8582f1",
  "docker_action_backup_prune_plan.txt": "9df0666b431781a8d8c223ed4efdf6946d025dd1d95cc0f253e21fd73994a71e",
  "docker_action_evidence_runtime_snapshot.txt": "e5834de528f3cd0703a103a8ef7e6a506148fc9dc53c687078bf7f1827dab325",
  "docker_action_restore_drill_full.txt": "57fb749d7eeff3497b0a8c1f7afb28627daad994f1803bbeb297d26724ec31db",
  "docker_action_runtime_intent_trust_key.txt": "98bfc10999dde0327b0e7946caca2fd85a627d36fc77e2f92b9572effa646b81",
  "github_token.txt": "f231c4b9a1a4478914eead4299df9cc84e6e32c364025435bc40b7973aaa1801",
  "grafana_admin_password.txt": "12970d9d617fdf6bcf5c4c16079cd8ca48ea5154532048e0a26c3eb33676d17e",
  "hash_pepper_keys.txt": "4d5652b9cf8d9b7a791ed9957b09693c5b732de43652256fcbb6416e8000638e",
  "keycloak_admin_password.txt": "9a2a5135d63dee86924ed41178424c1a0a0d77dc14515575d8523fcd0b3ae3a4",
  "keycloak_db_password.txt": "cd9d9e66569a2fa1584ffb5851e9068c21116a9da29102a8216d4d061b10f255",
  "mariadb_root_password.txt": "a4b2d9c02cdd73f04d00fed5691f92bb9c318bc21e74cd5eba804b8f944eaacf",
  "minio_root_password.txt": "1712c637f22faad464287a2b9ac23c00fec6e10e25a6e10d4b1d3249b8eed6c3",
  "nats_password.txt": "1b007b1af98aae5a01a32d4c21b8cc535b818bfc1700d66a6960c77578eaab2b",
  "nats_url.txt": "2df18270d51d8b8c421bd94709e723fb72c32cfb0ea70a2f5c6ed4e1c4b6abc2",
  "pgadmin_default_password.txt": "e43a6aab0a6f19183637f1ecce349cee84c4a70e461de5fed46329a551848261",
  "pgadmin_internal_key.txt": "ab5dcd6f5b51fa36d03c053da8e7c1a9c66974ba3c4e0d53deaed49a43ed7df6",
  "phpmyadmin_control_password.txt": "87da5ca6cde53fef048a5077565d086dfdc6b46f253e58a2383d06efdf627327",
  "postgres_superuser_password.txt": "474b54475c019482925e6d13cecaa44ab9b44aa2f207b1c973b9572c086a5456",
  "projects_gateway_signing_keys.txt": "4fb01c913ddafcebefffdfb4f33f67e7f91b06cd36b968a014d7a34f63710ab4",
  "redis_password.txt": "3771978799d168c5dc12eb5651fdc418541da800830ee28194adb0d13ac487e3",
  "restic_password.txt": "defa337fa044c77f414ae7938b896d71781794a46bfbb58bff63855fff4c741f",
  "session_secret.txt": "3823e5a05dbbc4e8e12eb71decb3a5af9cc13e8d8774b033040d892db3ddea17",
  "session_signing_keys.txt": "10835e60357877b5b0a3b87d4c014547a392d11c5b6957040a8c4e154e650bbe",
  "smtp_password.txt": "361573afc475425b3c4c4fe5fc78cbaa08bafa4dad1220fa304c1d12ce3a98de",
});

// Additional critical secret material paths copied from the preservation
// manifest additionalSecretMaterialPaths (6 entries; metadata only — sizes,
// modes, owners, purposes; NEVER content). Digests for these paths were not
// published in the manifest (some were explicitly never read), so their
// expectedSha256 is null in plans and is captured at execution time.
// The rclone entry carries the authoritative-current marker per the special
// rclone rule in the module header.
export const GREENFIELD_ADDITIONAL_SECRET_MATERIAL_PATHS = Object.freeze([
  Object.freeze({
    logicalName: "rclone_conf",
    path: "/home/platform_infrastructure/platform-infrastructure/secrets/rclone/rclone.conf",
    relativeTargetPath: "rclone/rclone.conf",
    sizeBytes: 4562,
    mode: "0600",
    owner: "root:platform_infrastructure",
    purpose: "rclone offsite sync OAuth configuration; current bytes are operational truth",
    classification: "critical-material",
    authority: RCLONE_CONF_AUTHORITY_NOTE,
    rollbackPolicy: "never-suggest-rollback-of-rclone-conf",
    manifestNotation: "/home/platform_infrastructure/platform-infrastructure/secrets/rclone/rclone.conf (4562B, root:platform_infrastructure 0600)",
  }),
  Object.freeze({
    logicalName: "infra_secret_manager_store_json",
    path: "/home/platform_infrastructure/platform-infrastructure/secrets/infra-secret-manager-store.json",
    relativeTargetPath: "infra-secret-manager-store.json",
    sizeBytes: 19072,
    mode: "0600",
    owner: "root",
    purpose: "secret-manager encrypted store snapshot (storeJsonBytes 19072 per manifest)",
    classification: "critical-material",
    manifestNotation: "/home/platform_infrastructure/platform-infrastructure/secrets/infra-secret-manager-store.json (19072B root 0600)",
  }),
  Object.freeze({
    logicalName: "infra_secret_manager_audit_log",
    path: "/home/platform_infrastructure/platform-infrastructure/secrets/infra-secret-manager-audit.log",
    relativeTargetPath: "infra-secret-manager-audit.log",
    sizeBytes: null,
    mode: null,
    owner: null,
    purpose: "secret-manager audit trail preserved alongside the store",
    classification: "critical-material",
    manifestNotation: "/home/platform_infrastructure/platform-infrastructure/secrets/infra-secret-manager-audit.log",
  }),
  Object.freeze({
    logicalName: "infra_secret_manager_master_key",
    path: "/home/platform_infrastructure/platform-infrastructure/secrets/infra-secret-manager-master.key",
    relativeTargetPath: "infra-secret-manager-master.key",
    sizeBytes: null,
    mode: null,
    owner: null,
    purpose: "secret-manager master key; path recorded but never read during preservation",
    classification: "critical-material",
    manifestNotation: "/home/platform_infrastructure/platform-infrastructure/secrets/infra-secret-manager-master.key (path recorded; not read)",
  }),
  Object.freeze({
    logicalName: "confidential_backup_passphrase",
    path: "/var/lib/platform-infrastructure/v1/local-private/confidential-backup-passphrase",
    relativeTargetPath: "confidential-backup-passphrase",
    sizeBytes: 87,
    mode: null,
    owner: "root",
    purpose: "GPG passphrase material for the confidential backup overlay (secret-manager-real tar.gpg family)",
    classification: "critical-material",
    manifestNotation: "/var/lib/platform-infrastructure/v1/local-private/confidential-backup-passphrase (87B root)",
  }),
  Object.freeze({
    logicalName: "traefik_local_tls_certs",
    // Manifest records the pair as one line; both concrete member files below.
    path: "/home/platform_infrastructure/platform-infrastructure/traefik/certs/local-cert.pem",
    relativeTargetPath: "traefik/certs/local-cert.pem",
    sizeBytes: null,
    mode: "0644",
    owner: null,
    purpose: "TLS certificate and key pair for the local edge (cert 0644 + key 0640 uid/gid 1000, host ACL u:101:r--)",
    classification: "critical-material",
    members: Object.freeze([
      Object.freeze({
        path: "/home/platform_infrastructure/platform-infrastructure/traefik/certs/local-cert.pem",
        relativeTargetPath: "traefik/certs/local-cert.pem",
        mode: "0644",
      }),
      Object.freeze({
        path: "/home/platform_infrastructure/platform-infrastructure/traefik/certs/local-key.pem",
        relativeTargetPath: "traefik/certs/local-key.pem",
        mode: "0640",
        owner: "uid/gid 1000",
        acl: "host ACL u:101:r--",
      }),
    ]),
    manifestNotation: "traefik certs: traefik/certs/local-cert.pem (0644) + local-key.pem (0640 uid/gid 1000, host ACL u:101:r--)",
  }),
]);

function fail(message) {
  throw new Error(`Greenfield secret projection: ${message}`);
}

function compareLogicalNames(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function assertSafeRelativeTarget(value) {
  if (typeof value !== "string" || value.length === 0
      || value.startsWith("/") || value.split("/").includes("..")
      || value.includes("\\")) {
    fail(`Unsafe greenfield-relative target path: ${JSON.stringify(value)}`);
  }
}

function deriveRequiredMode(pathOrName) {
  const value = String(pathOrName);
  if (value.endsWith(".txt")) return "0600";
  if (value.includes("cert") || value.includes(".pem")) return "0644";
  return null;
}

function freezeEntry(entry) {
  return Object.freeze({ ...entry });
}

// Builds the frozen deterministic projection plan. Inputs are metadata only;
// this function never touches the filesystem or reads any secret content.
export function buildSecretProjectionPlan({
  baselineDigests = GREENFIELD_SECRET_BASELINE_DIGESTS,
  additionalMaterialPaths = GREENFIELD_ADDITIONAL_SECRET_MATERIAL_PATHS,
  greenfieldSecretsRoot,
} = {}) {
  if (!baselineDigests || typeof baselineDigests !== "object" || Array.isArray(baselineDigests)) {
    fail("baselineDigests must be a name -> sha256 record.");
  }
  if (!Array.isArray(additionalMaterialPaths)) {
    fail("additionalMaterialPaths must be an array.");
  }
  if (typeof greenfieldSecretsRoot !== "string" || !greenfieldSecretsRoot.startsWith("/")
      || greenfieldSecretsRoot === "/" || greenfieldSecretsRoot.endsWith("/")) {
    fail("greenfieldSecretsRoot must be a canonical absolute directory path without a trailing slash.");
  }

  const entries = [];
  for (const [name, digest] of Object.entries(baselineDigests)) {
    if (name === "_comment") continue;
    if (!name.endsWith(".txt") || name.includes("/") || name.includes("\\")
        || name.split("/").includes("..")) {
      fail(`Baseline entry name is not a plain secrets/*.txt basename: ${JSON.stringify(name)}`);
    }
    if (typeof digest !== "string" || !SHA256_PATTERN.test(digest)) {
      fail(`Baseline digest for ${JSON.stringify(name)} is not a lowercase sha256 hex digest.`);
    }
    assertSafeRelativeTarget(name);
    entries.push(freezeEntry({
      logicalName: name.replace(/\.txt$/, ""),
      sourcePath: `${BROWNFIELD_SECRETS_ROOT}/${name}`,
      targetPath: name,
      expectedSha256: digest,
      copyMethod: "byte-exact-copy-with-metadata",
      requiredMode: deriveRequiredMode(name),
      verifyMethod: "sha256-after-copy",
    }));
  }
  entries.sort((left, right) => compareLogicalNames(left.logicalName, right.logicalName));

  const additionalMaterial = [];
  for (const material of additionalMaterialPaths) {
    if (!material || typeof material !== "object" || typeof material.path !== "string"
        || typeof material.logicalName !== "string") {
      fail("Additional secret material entry is missing path/logicalName metadata.");
    }
    const targetPath = material.relativeTargetPath ?? material.path.split("/").pop();
    assertSafeRelativeTarget(targetPath);
    additionalMaterial.push(freezeEntry({
      logicalName: material.logicalName,
      sourcePath: material.path,
      targetPath,
      expectedSha256: null,
      copyMethod: "byte-exact-copy-with-metadata",
      requiredMode: material.mode ?? deriveRequiredMode(material.path),
      verifyMethod: "sha256-after-copy",
      classification: "critical-material",
      ...(material.sizeBytes !== undefined ? { sizeBytes: material.sizeBytes } : {}),
      ...(material.purpose !== undefined ? { purpose: material.purpose } : {}),
      ...(material.authority !== undefined ? { authority: material.authority } : {}),
      ...(material.rollbackPolicy !== undefined ? { rollbackPolicy: material.rollbackPolicy } : {}),
      ...(material.members !== undefined ? { members: material.members } : {}),
    }));
  }
  additionalMaterial.sort((left, right) => compareLogicalNames(left.logicalName, right.logicalName));

  return Object.freeze({
    schema: SCHEMA,
    greenfieldSecretsRoot,
    entries: Object.freeze(entries),
    additionalMaterial: Object.freeze(additionalMaterial),
  });
}

// Deterministic serialization (recursively key-sorted canonical JSON), so two
// builds of the same plan serialize byte-for-byte identically.
export function serializeSecretPlan(plan) {
  return JSON.stringify(canonicalValue(plan));
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
  }
  return value;
}

// Verifies an execution-time observation set against the plan. FAIL-closed:
// any missing, extra, digest-altered, mode-mismatched, or size-less
// observation is a violation. This module never collects observations itself
// in production paths; the caller supplies them.
export function verifyObservedSecretSet({ plan, observed }) {
  if (!plan || typeof plan !== "object" || !Array.isArray(plan.entries)
      || !Array.isArray(plan.additionalMaterial)) {
    fail("plan must be a buildSecretProjectionPlan() result.");
  }
  if (!Array.isArray(observed)) {
    fail("observed must be an array of {logicalName, sha256, sizeBytes, mode} records.");
  }

  const plannedEntries = new Map();
  for (const entry of [...plan.entries, ...plan.additionalMaterial]) {
    plannedEntries.set(entry.logicalName, entry);
  }

  const violations = [];
  const seen = new Set();
  for (const observation of observed) {
    const name = observation?.logicalName;
    const entry = plannedEntries.get(name);
    if (!entry) {
      violations.push({ entry: String(name), reason: "extra" });
      continue;
    }
    if (seen.has(name)) {
      violations.push({ entry: name, reason: "extra" });
      continue;
    }
    seen.add(name);
    if (typeof observation.sizeBytes !== "number" || !Number.isSafeInteger(observation.sizeBytes)
        || observation.sizeBytes < 0) {
      violations.push({ entry: name, reason: "size-missing" });
    }
    if (typeof entry.expectedSha256 === "string" && observation.sha256 !== entry.expectedSha256) {
      violations.push({ entry: name, reason: "digest-altered" });
    }
    if (entry.requiredMode !== null && observation.mode !== entry.requiredMode) {
      violations.push({ entry: name, reason: "mode-mismatch" });
    }
  }
  for (const [name] of plannedEntries) {
    if (!seen.has(name)) {
      violations.push({ entry: name, reason: "missing" });
    }
  }

  violations.sort((left, right) => compareLogicalNames(left.entry, right.entry)
    || compareLogicalNames(left.reason, right.reason));
  const status = violations.length === 0 ? "MATCH" : "FAIL";
  return Object.freeze({
    status,
    violations: Object.freeze(violations.map((violation) => Object.freeze(violation))),
  });
}

// Scans free text (logs, receipts) for patterns that look like leaked
// credential material: private/key headers ("-----BEGIN"), password/token
// assignments, and base64 blobs longer than 64 characters. Returns true when
// NO such pattern is found; false means potential secret materialization and
// callers must refuse to emit the text. Long runs are capped at >64 chars so
// 64-character sha256 hex digests stay publishable.
export function assertNoSecretMaterialization(text) {
  if (typeof text !== "string") return true;
  const leakPatterns = [
    /-----BEGIN/i,
    /(?:password|passwd|pwd)\s*=/i,
    /token\s*=/i,
    /[A-Za-z0-9+/]{65,}={0,2}/,
  ];
  return !leakPatterns.some((pattern) => pattern.test(text));
}

function guardReceiptString(value, fieldLabel) {
  if (typeof value !== "string") return value;
  if (!assertNoSecretMaterialization(value)) {
    // Fail-closed WITHOUT echoing the offending content anywhere.
    fail(`receipt string field ${fieldLabel} was rejected: potential secret materialization detected`);
  }
  return value;
}

// Builds the projection receipt. Metadata ONLY: schema, runId, counts, and
// per-entry verification status. Zero secret-value fields exist on this
// object; every embedded string passes the leak guard first.
export function buildSecretReceipt({ plan, verifyResult, runId }) {
  if (!plan || typeof plan !== "object" || !Array.isArray(plan.entries)
      || !Array.isArray(plan.additionalMaterial)) {
    fail("plan must be a buildSecretProjectionPlan() result.");
  }
  if (!verifyResult || typeof verifyResult !== "object"
      || (verifyResult.status !== "MATCH" && verifyResult.status !== "FAIL")
      || !Array.isArray(verifyResult.violations)) {
    fail("verifyResult must be a verifyObservedSecretSet() result.");
  }

  const guardedRunId = guardReceiptString(String(runId), "runId");
  const violatedEntries = new Set(verifyResult.violations.map((violation) => violation.entry));
  const combined = [...plan.entries, ...plan.additionalMaterial];

  const receipt = {
    schema: SCHEMA,
    runId: guardedRunId,
    status: guardReceiptString(verifyResult.status, "status"),
    counts: {
      plannedEntries: plan.entries.length,
      plannedAdditionalMaterial: plan.additionalMaterial.length,
      observedViolations: verifyResult.violations.length,
      verifiedWithoutViolation: combined.filter((entry) => !violatedEntries.has(entry.logicalName)).length,
    },
    entries: combined.map((entry) => ({
      logicalName: guardReceiptString(entry.logicalName, "logicalName"),
      sha256Matched: !violatedEntries.has(entry.logicalName),
      mode: entry.requiredMode ?? null,
    })),
  };
  return Object.freeze(receipt);
}
