import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const SCRIPT = fileURLToPath(new URL("./governance-documentation-closure.mjs", import.meta.url));
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
    "role:platform-operations-primary",
    "role:platform-operations-substitute",
    "role:change-approval-authority",
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
        primary: "role:platform-operations-primary",
        substitute: "role:platform-operations-substitute",
        approval: "role:change-approval-authority",
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
      "Authenticated primary and substitute acknowledgements remain GOVERNANCE-EXTERNAL.",
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
        primary: "role:platform-operations-primary",
        substitute: "role:platform-operations-substitute",
        approval: "role:change-approval-authority",
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
      "Independent authenticated drills remain GOVERNANCE-EXTERNAL and GO-blocking.",
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

test("complete closed catalogs are locally ready but never claim GO", () => {
  withFixture(({ root }) => {
    const result = runCli(root, catalogsArgs(root));
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(parseOutput(result), {
      schema: "platform.governance-documentation-closure-result/v1",
      valid: true,
      status: "LOCAL-SUPPORT-READY-EXTERNAL-PENDING",
      gateAdmissible: false,
      externalConditions: [
        "Authenticated owner and substitute acknowledgements remain GOVERNANCE-EXTERNAL.",
        "Independent authenticated runbook drills remain GOVERNANCE-EXTERNAL.",
      ],
    });
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
        authenticatedSubjectRef: `test-subject-sha256:${"1".repeat(64)}`,
        responsibilities: ["closure", "rollback", "preservation", "review"],
        acknowledgedAt: "2026-07-22T00:00:00Z",
      }))),
      approval: {
        roleRef: "role:change-approval-authority",
        authenticatedSubjectRef: `test-subject-sha256:${"2".repeat(64)}`,
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
      const result = runCli(root, ["receipt", "--root", root, "--kind", kind, "--receipt", receiptPath]);
      assert.equal(result.status, 0, result.stderr);
      const parsed = parseOutput(result);
      assert.equal(parsed.valid, true);
      assert.equal(parsed.gateAdmissible, false);
      assert.equal(parsed.status, "SYNTHETIC-NON-GATE-ADMISSIBLE");
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
  });
});

