import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const SCRIPT = fileURLToPath(new URL("./governance-documentation-closure.mjs", import.meta.url));
const REPOSITORY_ROOT = fileURLToPath(new URL("../", import.meta.url));
const SCHEMA_DIRECTORY = path.join(REPOSITORY_ROOT, "governance", "schemas");
const REQUIRED_DOMAINS = [
  "hardware",
  "network",
  "applications",
  "data",
  "backups",
  "secrets",
  "observability",
  "ci",
  "providers",
];
const REQUIRED_CAPABILITIES = [
  "host-capacity",
  "host-recovery",
  "network-segmentation",
  "edge-routing",
  "platform-service-lifecycle",
  "hosted-workload-boundary",
  "database-storage",
  "object-storage",
  "backup",
  "restore",
  "secret-lifecycle",
  "key-recovery",
  "metrics",
  "logs",
  "alerting",
  "source-governance",
  "release-provenance",
  "dns-edge-provider",
  "identity-provider",
  "notification-provider",
];
const REQUIRED_RUNBOOK_TYPES = [
  "operations",
  "incident",
  "provider",
  "rollout",
  "rollback",
  "backup",
  "restore",
  "access-recovery",
];
const CANONICAL_ROLE_IDS = [
  "role:platform-governance-primary",
  "role:platform-governance-substitute",
  "role:release-approval-authority",
  "role:incident-escalation-authority",
];

function sha256(contents) {
  return createHash("sha256").update(contents).digest("hex");
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function initFixture() {
  const root = mkdtempSync(path.join(tmpdir(), "governance-closure-"));
  mkdirSync(path.join(root, "docs"), { recursive: true });
  mkdirSync(path.join(root, "governance", "receipts", "acceptance"), { recursive: true });
  mkdirSync(path.join(root, "governance", "receipts", "drills"), { recursive: true });

  const reference = [
    "# Governance Fixture",
    ...REQUIRED_DOMAINS.map((domain) => `## Domain ${domain}`),
    ...REQUIRED_RUNBOOK_TYPES.map((kind) => `## Runbook ${kind}`),
    "",
  ].join("\n");
  writeFileSync(path.join(root, "docs", "reference.md"), reference, "utf8");

  const roles = [
    "role:platform-governance-primary",
    "role:platform-governance-substitute",
    "role:release-approval-authority",
    "role:incident-escalation-authority",
  ].map((id) => ({
    id,
    kind: "human-accountability-role",
    runtimePrincipalAllowed: false,
    identityBinding: {
      state: "GOVERNANCE-EXTERNAL",
      authenticatedReceiptRequired: true,
    },
  }));

  let capabilityIndex = 0;
  const assets = REQUIRED_DOMAINS.map((domain, index) => {
    const remainingAssets = REQUIRED_DOMAINS.length - index;
    const remainingCapabilities = REQUIRED_CAPABILITIES.length - capabilityIndex;
    const take = Math.ceil(remainingCapabilities / remainingAssets);
    const capabilities = REQUIRED_CAPABILITIES.slice(capabilityIndex, capabilityIndex + take);
    capabilityIndex += take;
    return {
      id: `asset:${domain}`,
      domain,
      capabilities,
      artifactRefs: [{
        path: "docs/reference.md",
        sha256: sha256(reference),
        anchors: [`## Domain ${domain}`],
      }],
      roles: {
        primary: "role:platform-governance-primary",
        substitute: "role:platform-governance-substitute",
        approval: "role:release-approval-authority",
        escalation: "role:incident-escalation-authority",
      },
      acknowledgement: {
        state: "GOVERNANCE-EXTERNAL",
        authenticatedReceiptRequired: true,
      },
      lifecycle: {
        preserve: "Preserve exact configuration, state, and evidence before mutation.",
        rollback: "Restore only the bounded prior state after an approved failed change.",
        review: {
          cadenceDays: 90,
          beforeRollout: true,
          afterMaterialChange: true,
        },
      },
    };
  });

  const ownership = {
    schema: "platform.service-asset-ownership/v1",
    scope: "platform-infrastructure",
    status: "LOCAL-SUPPORT-READY-EXTERNAL-PENDING",
    gateAdmissible: false,
    requiredDomains: REQUIRED_DOMAINS,
    requiredCapabilities: REQUIRED_CAPABILITIES,
    roles,
    assets,
    externalConditions: [
      "Authenticated primary and substitute acknowledgements for every catalog asset remain GOVERNANCE-EXTERNAL and GO-blocking.",
    ],
  };

  const runbooks = {
    schema: "platform.runbook-catalog/v1",
    scope: "platform-infrastructure",
    status: "LOCAL-SUPPORT-READY-EXTERNAL-PENDING",
    gateAdmissible: false,
    requiredTypes: REQUIRED_RUNBOOK_TYPES,
    requiredIndependentDrillTypes: ["rollout", "rollback", "backup", "restore", "access-recovery"],
    runbooks: REQUIRED_RUNBOOK_TYPES.map((kind) => ({
      id: `runbook:${kind}`,
      type: kind,
      artifact: {
        path: "docs/reference.md",
        sha256: sha256(reference),
        anchors: [`## Runbook ${kind}`],
      },
      roles: {
        primary: "role:platform-governance-primary",
        substitute: "role:platform-governance-substitute",
        approval: "role:release-approval-authority",
        escalation: "role:incident-escalation-authority",
      },
      preservationRequired: true,
      rollbackRequired: true,
      review: {
        cadenceDays: 90,
        beforeRollout: true,
        afterMaterialChange: true,
      },
      drill: {
        state: "GOVERNANCE-EXTERNAL",
        independentOperatorRequired: true,
        exactArtifactBindingRequired: true,
      },
    })),
    externalConditions: [
      "Independent authenticated drills for rollout, rollback, backup, restore, and access-recovery remain GOVERNANCE-EXTERNAL and GO-blocking.",
    ],
  };

  writeJson(path.join(root, "governance", "service-asset-ownership.json"), ownership);
  writeJson(path.join(root, "governance", "runbook-catalog.json"), runbooks);

  execFileSync("git", ["init", "-q"], { cwd: root });
  execFileSync("git", ["config", "user.name", "Governance Test"], { cwd: root });
  execFileSync("git", ["config", "user.email", "governance-test.invalid@example.invalid"], { cwd: root });
  execFileSync("git", ["add", "."], { cwd: root });
  execFileSync("git", ["commit", "-qm", "fixture"], { cwd: root });

  return { root, ownership, runbooks, reference };
}

function runCli(root, args) {
  return spawnSync(process.execPath, [SCRIPT, ...args], {
    cwd: root,
    encoding: "utf8",
    env: { PATH: process.env.PATH },
  });
}

function catalogsArgs(root) {
  return [
    "catalogs",
    "--root", root,
    "--ownership", "governance/service-asset-ownership.json",
    "--runbooks", "governance/runbook-catalog.json",
  ];
}

function receiptArgs(root, kind, receiptPath) {
  return [
    "receipt",
    ...catalogsArgs(root).slice(1),
    "--kind", kind,
    "--receipt", receiptPath,
  ];
}

function commitFixture(root, message, paths = null) {
  execFileSync("git", paths ? ["add", "--", ...paths] : ["add", "--all"], { cwd: root });
  execFileSync("git", ["commit", "-qm", message], { cwd: root });
}

function expectedRepositoryBinding(root) {
  const commit = execFileSync("git", ["rev-parse", "--verify", "HEAD^{commit}"], { cwd: root, encoding: "utf8" }).trim();
  const tree = execFileSync("git", ["rev-parse", "--verify", "HEAD^{tree}"], { cwd: root, encoding: "utf8" }).trim();
  const authoritativePaths = [
    "docs/reference.md",
    "governance/runbook-catalog.json",
    "governance/service-asset-ownership.json",
  ].map((relative) => ({
    path: relative,
    sha256: sha256(readFileSync(path.join(root, relative))),
  }));
  return { commit, tree, authoritativePaths };
}

function parseOutput(result) {
  const source = result.stdout.trim() || result.stderr.trim();
  assert.ok(source, "validator must emit a machine-readable result");
  return JSON.parse(source);
}

function withFixture(callback) {
  const fixture = initFixture();
  try {
    callback(fixture);
  } finally {
    rmSync(fixture.root, { recursive: true, force: true });
  }
}

function assertClosedObjectSchemas(value, location = "$") {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertClosedObjectSchemas(entry, `${location}[${index}]`));
    return;
  }
  if (value === null || typeof value !== "object") return;
  if (value.type === "object") {
    assert.equal(value.additionalProperties, false, `${location} must reject additional properties`);
    if (value.properties) {
      assert.deepEqual(
        [...(value.required ?? [])].sort(),
        Object.keys(value.properties).sort(),
        `${location} must require every declared object property`,
      );
    }
  }
  Object.entries(value).forEach(([key, entry]) => assertClosedObjectSchemas(entry, `${location}.${key}`));
}

test("published catalog and receipt schemas are closed", () => {
  const files = [
    "governance-acceptance-receipt.schema.json",
    "runbook-catalog.schema.json",
    "runbook-drill-receipt.schema.json",
    "service-asset-ownership.schema.json",
  ];
  const ids = new Set();
  for (const file of files) {
    const schema = JSON.parse(readFileSync(path.join(SCHEMA_DIRECTORY, file), "utf8"));
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.match(schema.$id, /^urn:platform-infrastructure:schema:/);
    assert.equal(ids.has(schema.$id), false, `${file} has a duplicate schema id`);
    ids.add(schema.$id);
    assertClosedObjectSchemas(schema, file);
  }
});

test("published schemas lock canonical catalog paths and the exact four role ids", () => {
  const ownershipSchema = JSON.parse(readFileSync(path.join(SCHEMA_DIRECTORY, "service-asset-ownership.schema.json"), "utf8"));
  assert.equal(ownershipSchema.properties.roles.minItems, 4);
  assert.equal(ownershipSchema.properties.roles.maxItems, 4);
  assert.equal(ownershipSchema.properties.roles.uniqueItems, true);
  assert.deepEqual(ownershipSchema.$defs.roleRef.enum, CANONICAL_ROLE_IDS);
  assert.equal(ownershipSchema.$defs.roleAssignments.properties.primary.const, CANONICAL_ROLE_IDS[0]);
  assert.equal(ownershipSchema.$defs.roleAssignments.properties.substitute.const, CANONICAL_ROLE_IDS[1]);
  assert.equal(ownershipSchema.$defs.roleAssignments.properties.approval.const, CANONICAL_ROLE_IDS[2]);
  assert.equal(ownershipSchema.$defs.roleAssignments.properties.escalation.const, CANONICAL_ROLE_IDS[3]);

  const runbookSchema = JSON.parse(readFileSync(path.join(SCHEMA_DIRECTORY, "runbook-catalog.schema.json"), "utf8"));
  assert.deepEqual(runbookSchema.$defs.roleRef.enum, CANONICAL_ROLE_IDS);
  assert.equal(runbookSchema.$defs.roleAssignments.properties.primary.const, CANONICAL_ROLE_IDS[0]);
  assert.equal(runbookSchema.$defs.roleAssignments.properties.substitute.const, CANONICAL_ROLE_IDS[1]);
  assert.equal(runbookSchema.$defs.roleAssignments.properties.approval.const, CANONICAL_ROLE_IDS[2]);
  assert.equal(runbookSchema.$defs.roleAssignments.properties.escalation.const, CANONICAL_ROLE_IDS[3]);

  const acceptanceSchema = JSON.parse(readFileSync(path.join(SCHEMA_DIRECTORY, "governance-acceptance-receipt.schema.json"), "utf8"));
  assert.equal(acceptanceSchema.$defs.catalogBinding.properties.path.const, "governance/service-asset-ownership.json");
  const drillSchema = JSON.parse(readFileSync(path.join(SCHEMA_DIRECTORY, "runbook-drill-receipt.schema.json"), "utf8"));
  assert.equal(drillSchema.$defs.catalogBinding.properties.path.const, "governance/runbook-catalog.json");
});

test("tracked repository catalogs retain exact local-support bindings", () => {
  const result = runCli(REPOSITORY_ROOT, catalogsArgs(REPOSITORY_ROOT));
  assert.equal(result.status, 0, result.stdout || result.stderr);
  const parsed = parseOutput(result);
  assert.equal(parsed.valid, true);
  assert.equal(parsed.status, "LOCAL-SUPPORT-READY-EXTERNAL-PENDING");
  assert.equal(parsed.gateAdmissible, false);
  assert.equal(parsed.externalConditions.length, 2);
  assert.ok(parsed.externalConditions.every((condition) => condition.includes("GOVERNANCE-EXTERNAL")));
  assert.equal(parsed.repositoryBinding.commit, execFileSync("git", ["rev-parse", "HEAD"], { cwd: REPOSITORY_ROOT, encoding: "utf8" }).trim());
  assert.equal(parsed.repositoryBinding.tree, execFileSync("git", ["rev-parse", "HEAD^{tree}"], { cwd: REPOSITORY_ROOT, encoding: "utf8" }).trim());
  assert.deepEqual(
    parsed.repositoryBinding.authoritativePaths.map((entry) => entry.path),
    [
      "governance/catalog-artifacts/asset-ownership-scope.md",
      "governance/catalog-artifacts/governance-runbooks.md",
      "governance/runbook-catalog.json",
      "governance/service-asset-ownership.json",
    ],
  );
});

test("complete closed catalogs are locally ready but never claim GO", () => {
  withFixture(({ root }) => {
    const result = runCli(root, catalogsArgs(root));
    assert.equal(result.status, 0, result.stdout || result.stderr);
    assert.deepEqual(parseOutput(result), {
      schema: "platform.governance-documentation-closure-result/v1",
      valid: true,
      status: "LOCAL-SUPPORT-READY-EXTERNAL-PENDING",
      gateAdmissible: false,
      externalConditions: [
        "Authenticated primary and substitute acknowledgements for every catalog asset remain GOVERNANCE-EXTERNAL and GO-blocking.",
        "Independent authenticated drills for rollout, rollback, backup, restore, and access-recovery remain GOVERNANCE-EXTERNAL and GO-blocking.",
      ],
      repositoryBinding: expectedRepositoryBinding(root),
    });
  });
});

test("catalog validation rejects self-consistent worktree and index rehashes outside HEAD", () => {
  withFixture(({ root, ownership, runbooks, reference }) => {
    const mutatedReference = `${reference}Uncommitted authoritative mutation.\n`;
    writeFileSync(path.join(root, "docs", "reference.md"), mutatedReference, "utf8");
    const mutatedHash = sha256(mutatedReference);
    const mutatedOwnership = structuredClone(ownership);
    mutatedOwnership.assets.forEach((asset) => asset.artifactRefs.forEach((artifact) => artifact.sha256 = mutatedHash));
    const mutatedRunbooks = structuredClone(runbooks);
    mutatedRunbooks.runbooks.forEach((runbook) => runbook.artifact.sha256 = mutatedHash);
    writeJson(path.join(root, "governance", "service-asset-ownership.json"), mutatedOwnership);
    writeJson(path.join(root, "governance", "runbook-catalog.json"), mutatedRunbooks);

    const dirtyWorktree = runCli(root, catalogsArgs(root));
    assert.notEqual(dirtyWorktree.status, 0);
    assert.equal(parseOutput(dirtyWorktree).error.code, "DIRTY_AUTHORITATIVE_PATH");

    execFileSync("git", ["add", "docs/reference.md", "governance/service-asset-ownership.json", "governance/runbook-catalog.json"], { cwd: root });
    const dirtyIndex = runCli(root, catalogsArgs(root));
    assert.notEqual(dirtyIndex.status, 0);
    assert.equal(parseOutput(dirtyIndex).error.code, "DIRTY_AUTHORITATIVE_PATH");
  });
});

test("ownership uses a closed canonical role allowlist, not heuristic blacklists", () => {
  withFixture(({ root, ownership, runbooks }) => {
    const replacement = "role:accountable-platform-primary";
    const mutatedOwnership = structuredClone(ownership);
    mutatedOwnership.roles[0].id = replacement;
    mutatedOwnership.assets.forEach((asset) => asset.roles.primary = replacement);
    const mutatedRunbooks = structuredClone(runbooks);
    mutatedRunbooks.runbooks.forEach((runbook) => runbook.roles.primary = replacement);
    writeJson(path.join(root, "governance", "service-asset-ownership.json"), mutatedOwnership);
    writeJson(path.join(root, "governance", "runbook-catalog.json"), mutatedRunbooks);
    commitFixture(root, "replace primary with plausible shadow role");

    const result = runCli(root, catalogsArgs(root));
    assert.notEqual(result.status, 0);
    assert.equal(parseOutput(result).error.code, "NON_CANONICAL_ROLE");
  });
});

test("ownership coverage rejects missing or unknown domains and capabilities", () => {
  withFixture(({ root, ownership }) => {
    for (const mutate of [
      (copy) => copy.assets.pop(),
      (copy) => copy.assets[0].domain = "shadow-domain",
      (copy) => copy.assets[0].capabilities.push("shadow-capability"),
      (copy) => copy.assets[0].capabilities.pop(),
    ]) {
      const copy = structuredClone(ownership);
      mutate(copy);
      writeJson(path.join(root, "governance", "service-asset-ownership.json"), copy);
      const result = runCli(root, catalogsArgs(root));
      assert.notEqual(result.status, 0);
      assert.equal(parseOutput(result).valid, false);
    }
  });
});

test("artifact bindings reject untracked files, symlinks, stale hashes, and missing anchors", () => {
  withFixture(({ root, ownership, reference }) => {
    const ownershipPath = path.join(root, "governance", "service-asset-ownership.json");
    const untracked = path.join(root, "docs", "untracked.md");
    writeFileSync(untracked, "# untracked\n", "utf8");
    let copy = structuredClone(ownership);
    copy.assets[0].artifactRefs[0] = {
      path: "docs/untracked.md",
      sha256: sha256("# untracked\n"),
      anchors: ["# untracked"],
    };
    writeJson(ownershipPath, copy);
    assert.notEqual(runCli(root, catalogsArgs(root)).status, 0);

    copy = structuredClone(ownership);
    copy.assets[0].artifactRefs[0].sha256 = "0".repeat(64);
    writeJson(ownershipPath, copy);
    assert.notEqual(runCli(root, catalogsArgs(root)).status, 0);

    copy = structuredClone(ownership);
    copy.assets[0].artifactRefs[0].anchors = ["## absent anchor"];
    writeJson(ownershipPath, copy);
    assert.notEqual(runCli(root, catalogsArgs(root)).status, 0);

    writeJson(ownershipPath, ownership);
    const referencePath = path.join(root, "docs", "reference.md");
    const targetPath = path.join(root, "docs", "target.md");
    writeFileSync(targetPath, reference, "utf8");
    unlinkSync(referencePath);
    symlinkSync("target.md", referencePath);
    assert.notEqual(runCli(root, catalogsArgs(root)).status, 0);
  });
});

test("ownership rejects placeholders, runtime identities, shared primary/substitute, and incomplete lifecycle", () => {
  withFixture(({ root, ownership }) => {
    const ownershipPath = path.join(root, "governance", "service-asset-ownership.json");
    for (const mutate of [
      (copy) => {
        copy.roles[0].id = "role:tbd";
        copy.assets.forEach((asset) => asset.roles.primary = "role:tbd");
      },
      (copy) => {
        copy.roles[0].id = "role:root";
        copy.assets.forEach((asset) => asset.roles.primary = "role:root");
      },
      (copy) => copy.assets[0].roles.substitute = copy.assets[0].roles.primary,
      (copy) => copy.assets[0].roles.approval = copy.assets[0].roles.primary,
      (copy) => delete copy.assets[0].lifecycle.rollback,
      (copy) => copy.assets[0].lifecycle.review.beforeRollout = false,
    ]) {
      const copy = structuredClone(ownership);
      mutate(copy);
      writeJson(ownershipPath, copy);
      const result = runCli(root, catalogsArgs(root));
      assert.notEqual(result.status, 0);
      assert.equal(parseOutput(result).valid, false);
    }
  });
});

test("runbook catalog rejects missing types, duplicate ownership, and weak drill bindings", () => {
  withFixture(({ root, runbooks }) => {
    const runbookPath = path.join(root, "governance", "runbook-catalog.json");
    for (const mutate of [
      (copy) => copy.runbooks.pop(),
      (copy) => copy.runbooks[0].type = copy.runbooks[1].type,
      (copy) => copy.runbooks[0].roles.substitute = copy.runbooks[0].roles.primary,
      (copy) => copy.runbooks[0].preservationRequired = false,
      (copy) => copy.runbooks[0].rollbackRequired = false,
      (copy) => copy.runbooks[0].drill.independentOperatorRequired = false,
      (copy) => copy.runbooks[0].drill.exactArtifactBindingRequired = false,
    ]) {
      const copy = structuredClone(runbooks);
      mutate(copy);
      writeJson(runbookPath, copy);
      const result = runCli(root, catalogsArgs(root));
      assert.notEqual(result.status, 0);
      assert.equal(parseOutput(result).valid, false);
    }
  });
});

test("synthetic acknowledgement and drill receipts are structurally testable but never gate-admissible", () => {
  withFixture(({ root, ownership, runbooks }) => {
    const acceptance = {
      schema: "platform.governance-acceptance-receipt/v1",
      receiptId: "synthetic-acceptance-001",
      evidenceClass: "SYNTHETIC-TEST",
      synthetic: true,
      gateAdmissible: false,
      scope: "platform-infrastructure",
      catalog: {
        path: "governance/service-asset-ownership.json",
        sha256: sha256(readFileSync(path.join(root, "governance", "service-asset-ownership.json"))),
      },
      issuedAt: "2026-07-22T00:00:00Z",
      acknowledgements: ownership.assets.flatMap((asset) => [asset.roles.primary, asset.roles.substitute].map((roleRef) => ({
        assetId: asset.id,
        roleRef,
        authenticatedSubjectRef: `test-subject-sha256:${sha256(roleRef)}`,
        authentication: {
          method: "synthetic",
          issuerRef: "test-fixture",
          evidenceSha256: sha256(`auth:${asset.id}:${roleRef}`),
        },
        responsibilities: ["closure", "rollback", "preservation", "review"],
        acknowledgedAt: "2026-07-22T00:00:00Z",
      }))),
      approval: {
        roleRef: "role:release-approval-authority",
        authenticatedSubjectRef: `test-subject-sha256:${"2".repeat(64)}`,
        authentication: {
          method: "synthetic",
          issuerRef: "test-fixture",
          evidenceSha256: "5".repeat(64),
        },
        approvedAt: "2026-07-22T00:00:00Z",
      },
    };
    const drill = {
      schema: "platform.runbook-drill-receipt/v1",
      receiptId: "synthetic-drill-001",
      evidenceClass: "SYNTHETIC-TEST",
      synthetic: true,
      gateAdmissible: false,
      scope: "platform-infrastructure",
      runbookId: "runbook:rollback",
      runbookType: "rollback",
      catalog: {
        path: "governance/runbook-catalog.json",
        sha256: sha256(readFileSync(path.join(root, "governance", "runbook-catalog.json"))),
      },
      artifact: runbooks.runbooks.find((entry) => entry.type === "rollback").artifact,
      performedAt: "2026-07-22T00:00:00Z",
      independentOperator: {
        authenticatedSubjectRef: `test-subject-sha256:${"3".repeat(64)}`,
        authentication: {
          method: "synthetic",
          issuerRef: "test-fixture",
          evidenceSha256: "6".repeat(64),
        },
        independentFromPrimary: true,
      },
      result: "PASS",
      preservationVerified: true,
      rollbackVerified: true,
      evidenceSha256: "4".repeat(64),
    };
    const acceptancePath = path.join(root, "governance", "receipts", "acceptance", "synthetic.json");
    const drillPath = path.join(root, "governance", "receipts", "drills", "synthetic.json");
    writeJson(acceptancePath, acceptance);
    writeJson(drillPath, drill);

    for (const [kind, receiptPath] of [["acceptance", acceptancePath], ["drill", drillPath]]) {
      const result = runCli(root, receiptArgs(root, kind, path.relative(root, receiptPath)));
      assert.equal(result.status, 0, result.stdout || result.stderr);
      const parsed = parseOutput(result);
      assert.equal(parsed.valid, true);
      assert.equal(parsed.gateAdmissible, false);
      assert.equal(parsed.status, "SYNTHETIC-NON-GATE-ADMISSIBLE");
      assert.equal(parsed.doesNotAuthorizeDeployment, true);
    }

    const gate = runCli(root, [
      "gate",
      ...catalogsArgs(root).slice(1),
      "--acceptance-dir", "governance/receipts/acceptance",
      "--drill-dir", "governance/receipts/drills",
    ]);
    assert.notEqual(gate.status, 0);
    const parsedGate = parseOutput(gate);
    assert.equal(parsedGate.gateAdmissible, false);
    assert.equal(parsedGate.status, "GOVERNANCE-EXTERNAL-BLOCKING");

    const externalAcceptance = structuredClone(acceptance);
    externalAcceptance.receiptId = "external-acceptance-structural-001";
    externalAcceptance.evidenceClass = "GOVERNANCE-EXTERNAL";
    externalAcceptance.synthetic = false;
    externalAcceptance.gateAdmissible = false;
    externalAcceptance.acknowledgements.forEach((entry) => {
      entry.authenticatedSubjectRef = `provider-subject-sha256:${sha256(entry.roleRef)}`;
      entry.authentication = {
        method: "oidc-mfa",
        issuerRef: "external-governance-identity-verifier",
        evidenceSha256: sha256(`external-auth:${entry.roleRef}`),
      };
    });
    externalAcceptance.approval.authenticatedSubjectRef = `provider-subject-sha256:${"7".repeat(64)}`;
    externalAcceptance.approval.authentication = {
      method: "webauthn",
      issuerRef: "external-governance-identity-verifier",
      evidenceSha256: "8".repeat(64),
    };
    writeJson(acceptancePath, externalAcceptance);

    for (const [index, kind] of ["rollout", "rollback", "backup", "restore", "access-recovery"].entries()) {
      const externalDrill = structuredClone(drill);
      externalDrill.receiptId = `external-drill-structural-${kind}`;
      externalDrill.evidenceClass = "GOVERNANCE-EXTERNAL";
      externalDrill.synthetic = false;
      externalDrill.gateAdmissible = false;
      externalDrill.runbookId = `runbook:${kind}`;
      externalDrill.runbookType = kind;
      externalDrill.artifact = runbooks.runbooks.find((entry) => entry.type === kind).artifact;
      externalDrill.independentOperator.authenticatedSubjectRef = `provider-subject-sha256:${sha256(`independent:${kind}`)}`;
      externalDrill.independentOperator.authentication = {
        method: "provider-signed",
        issuerRef: "external-independent-drill-verifier",
        evidenceSha256: sha256(`external-drill-auth:${kind}`),
      };
      writeJson(
        path.join(root, "governance", "receipts", "drills", `${String(index + 1).padStart(2, "0")}-${kind}.json`),
        externalDrill,
      );
    }
    rmSync(drillPath);

    const structurallyValidExternal = runCli(root, receiptArgs(root, "acceptance", path.relative(root, acceptancePath)));
    assert.equal(structurallyValidExternal.status, 0, structurallyValidExternal.stdout || structurallyValidExternal.stderr);
    assert.deepEqual(parseOutput(structurallyValidExternal), {
      schema: "platform.governance-documentation-closure-result/v1",
      valid: true,
      status: "GOVERNANCE-EXTERNAL-VERIFICATION-PENDING",
      gateAdmissible: false,
      doesNotAuthorizeDeployment: true,
      repositoryBinding: expectedRepositoryBinding(root),
    });

    const externalGate = runCli(root, [
      "gate",
      ...catalogsArgs(root).slice(1),
      "--acceptance-dir", "governance/receipts/acceptance",
      "--drill-dir", "governance/receipts/drills",
    ]);
    assert.notEqual(externalGate.status, 0);
    const parsedExternalGate = parseOutput(externalGate);
    assert.equal(parsedExternalGate.valid, true);
    assert.equal(parsedExternalGate.status, "GOVERNANCE-EXTERNAL-VERIFICATION-PENDING");
    assert.equal(parsedExternalGate.gateAdmissible, false);
    assert.equal(parsedExternalGate.doesNotAuthorizeDeployment, true);
    assert.match(parsedExternalGate.blockers.join(" "), /independent trusted verifier/i);
    assert.deepEqual(parsedExternalGate.repositoryBinding, expectedRepositoryBinding(root));

    writeJson(path.join(root, "governance", "shadow-ownership.json"), ownership);
    writeJson(path.join(root, "governance", "shadow-runbooks.json"), runbooks);
    commitFixture(root, "add shadow governance catalogs", [
      "governance/shadow-ownership.json",
      "governance/shadow-runbooks.json",
    ]);
    externalAcceptance.catalog = {
      path: "governance/shadow-ownership.json",
      sha256: sha256(readFileSync(path.join(root, "governance", "shadow-ownership.json"))),
    };
    writeJson(acceptancePath, externalAcceptance);
    for (const kind of ["rollout", "rollback", "backup", "restore", "access-recovery"]) {
      const externalDrillPath = path.join(
        root,
        "governance",
        "receipts",
        "drills",
        `${String(["rollout", "rollback", "backup", "restore", "access-recovery"].indexOf(kind) + 1).padStart(2, "0")}-${kind}.json`,
      );
      const externalDrill = JSON.parse(readFileSync(externalDrillPath, "utf8"));
      externalDrill.catalog = {
        path: "governance/shadow-runbooks.json",
        sha256: sha256(readFileSync(path.join(root, "governance", "shadow-runbooks.json"))),
      };
      writeJson(externalDrillPath, externalDrill);
    }

    const shadowWithoutCanonical = runCli(root, [
      "receipt",
      "--root", root,
      "--kind", "acceptance",
      "--receipt", path.relative(root, acceptancePath),
    ]);
    assert.notEqual(shadowWithoutCanonical.status, 0);
    assert.equal(parseOutput(shadowWithoutCanonical).error.code, "MISSING_ARGUMENT");

    const shadowReceipt = runCli(root, receiptArgs(root, "acceptance", path.relative(root, acceptancePath)));
    assert.notEqual(shadowReceipt.status, 0);
    assert.equal(parseOutput(shadowReceipt).error.code, "CATALOG_BINDING_MISMATCH");

    const shadowGate = runCli(root, [
      "gate",
      ...catalogsArgs(root).slice(1),
      "--acceptance-dir", "governance/receipts/acceptance",
      "--drill-dir", "governance/receipts/drills",
    ]);
    assert.notEqual(shadowGate.status, 0);
    assert.equal(parseOutput(shadowGate).valid, false);
    assert.equal(parseOutput(shadowGate).error.code, "CATALOG_BINDING_MISMATCH");

    externalAcceptance.catalog = {
      path: "governance/service-asset-ownership.json",
      sha256: sha256(readFileSync(path.join(root, "governance", "service-asset-ownership.json"))),
    };
    externalAcceptance.gateAdmissible = true;
    writeJson(acceptancePath, externalAcceptance);
    const falseGateClaim = runCli(root, receiptArgs(root, "acceptance", path.relative(root, acceptancePath)));
    assert.notEqual(falseGateClaim.status, 0);
    assert.equal(parseOutput(falseGateClaim).error.code, "FALSE_GATE_CLAIM");
  });
});
