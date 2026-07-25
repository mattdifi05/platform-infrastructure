import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const infraRoot = path.resolve(import.meta.dirname, "..");
const handoffPath = path.join(
  infraRoot,
  "governance",
  "ultra-remediation",
  "handoffs",
  "release.jsonl",
);

const canonical = Object.freeze({
  "FG-010": ["CAN-065", "CAN-066"],
  "FG-012": ["CAN-049", "CAN-098"],
  "FG-028": ["CAN-051"],
  "FG-029": ["CAN-052"],
  "FG-049": ["CAN-227", "CAN-229", "CAN-230", "CAN-231"],
  "FG-050": ["CAN-121", "CAN-122", "CAN-149"],
  "FG-052": ["CAN-133", "CAN-142"],
  "FG-056": ["CAN-131"],
  "FG-059": ["CAN-155"],
  "FG-063": ["CAN-185"],
  "FG-065": ["CAN-192"],
  "FG-069": ["CAN-206"],
});

const conditions = Object.freeze([
  "DOC-EVD-006",
  "DOC-EVD-007",
  "ULTRA-GAP-023",
  "ULTRA-GAP-025",
  "ULTRA-GAP-042",
]);

const support = Object.freeze({
  "FG-010": ["c0c5dbfa85807e234bfb99158732a66f63e78989", "515344b818d8941451c879cbc9fc9a169bf82861", "d57ef7a5855198be1c90739f893827cb01bbff0c", "543806faba55606947c50fae6fc59334c02f8eec"],
  "FG-012": ["65eed4693c91b92d4a255912aaf0f4c2b6dcfa84", "4c36847a88bef6e05677230b1e572fc1c676202a"],
  "FG-028": [],
  "FG-029": ["8ca94c13f53cac88c8b2ba2fcc6d71935d39de61", "0fdbc6c4bfed79187d7945efaf0d7054934956c6", "2bd51013822609aba183b54c10bbe25f2ba3d108"],
  "FG-049": ["f6b7af6c308389a749496afcce71735a43ef43f0", "e1a074db0a8ebe9f034922329ba29b1f91f15638", "0a3b92902203000c845e056142937852c6fd7a35", "378c1e0feb7d91caa660da2b9ca8a2ad475ccf56", "7a062a6a0bdf113a0c38b214deda240138144fd3"],
  "FG-050": ["7cec32a531e94da0a8eb790ffc904bff4f86978e", "95a8d32332e32032f1f2ac02466452f332c0c82a", "78847d2a8d87d2e8b218634bb715416ea9808501", "29f1a541be04c488cafd715fdf3afb19992f0d3a", "0fdbc6c4bfed79187d7945efaf0d7054934956c6", "7fd8be3ae10f39059460619b810f45c6f787acd6"],
  "FG-052": ["473fa09bc17a22718bbd211c0c23a9fd792f51ef", "92e21a49ff109dd7727904baf54d89b1bab3c25f"],
  "FG-056": ["8996f2a29d49107c754508a001c50a97d47b10bd", "7a062a6a0bdf113a0c38b214deda240138144fd3"],
  "FG-059": ["c7e9177404a892f191b0f1d3dcbd9ebed1ef866d", "f6b7af6c308389a749496afcce71735a43ef43f0", "4870dd15afd70838f0f5067481f37a636f0e1cc1", "bf1b598eeb00202cd64c6e2c650c61b8ccb8830a"],
  "FG-063": [],
  "FG-065": ["543806faba55606947c50fae6fc59334c02f8eec", "2bd51013822609aba183b54c10bbe25f2ba3d108", "e1a074db0a8ebe9f034922329ba29b1f91f15638", "b5b19ecf23f5dc498bb15ffac9c24e66e21872ae", "0a3b92902203000c845e056142937852c6fd7a35", "7a062a6a0bdf113a0c38b214deda240138144fd3"],
  "FG-069": ["3edf80b077c7935699d27ec39e0a505d9dd1cdfc"],
});

const requiredKeys = Object.freeze([
  "group_id",
  "slug",
  "canonical_ids",
  "cohort_commit",
  "support_commits",
  "final_commit",
  "source",
  "control",
  "sink",
  "boundary",
  "pre_fix_negative",
  "tests",
  "independent_qa",
  "runtime_status",
  "external_conditions",
  "rollback",
]);
const optionalKeys = new Set(["integration_mode", "cross_cohort_dependencies"]);

function records() {
  return readFileSync(handoffPath, "utf8")
    .trim()
    .split("\n")
    .map((line, index) => {
      try {
        return JSON.parse(line);
      } catch (error) {
        throw new Error(`Invalid release handoff JSON on line ${index + 1}.`, { cause: error });
      }
    });
}

test("release handoff has twelve exact FG receipts plus five explicit condition receipts", () => {
  const rows = records();
  assert.equal(rows.length, 17);
  assert.equal(new Set(rows.map((row) => row.group_id)).size, rows.length);
  const fgRows = rows.filter((row) => row.group_id.startsWith("FG-"));
  assert.deepEqual(fgRows.map((row) => row.group_id), Object.keys(canonical));
  assert.deepEqual(
    rows.filter((row) => !row.group_id.startsWith("FG-")).map((row) => row.group_id),
    conditions,
  );
  for (const row of rows) {
    for (const key of requiredKeys) assert.ok(Object.hasOwn(row, key), `${row.group_id} missing ${key}`);
    for (const key of Object.keys(row)) {
      assert.ok(requiredKeys.includes(key) || optionalKeys.has(key), `${row.group_id} has undeclared key ${key}`);
    }
    assert.equal(row.final_commit, null, `${row.group_id} final_commit must remain null in the cohort handoff`);
    assert.ok(Array.isArray(row.canonical_ids));
    assert.ok(Array.isArray(row.support_commits));
    assert.ok(Array.isArray(row.external_conditions) && row.external_conditions.length > 0);
    assert.ok(row.source && row.control && row.sink && row.boundary && row.rollback);
    assert.ok(row.pre_fix_negative && row.tests && row.independent_qa && row.runtime_status);
    assert.notEqual(row.runtime_status.live, "PASS");
    assert.notEqual(row.runtime_status.provider, "PASS");
  }
});

test("release FG canonical IDs, support IDs and commit objects are exact", () => {
  const byId = new Map(records().map((row) => [row.group_id, row]));
  for (const [groupId, canonicalIds] of Object.entries(canonical)) {
    const row = byId.get(groupId);
    assert.deepEqual(row.canonical_ids, canonicalIds, groupId);
    assert.deepEqual(row.support_commits, support[groupId], groupId);
    assert.match(row.cohort_commit, /^[a-f0-9]{40}$/, `${groupId} cohort commit`);
    for (const commit of [row.cohort_commit, ...row.support_commits]) {
      const exists = spawnSync("git", ["cat-file", "-e", `${commit}^{commit}`], {
        cwd: infraRoot,
        encoding: "utf8",
      });
      assert.equal(exists.status, 0, `${groupId} missing commit ${commit}: ${exists.stderr}`);
    }
  }
  for (const conditionId of conditions) {
    assert.deepEqual(byId.get(conditionId).canonical_ids, []);
  }
});

test("cross-cohort release dependencies remain explicit and fail closed", () => {
  const byId = new Map(records().map((row) => [row.group_id, row]));
  const activation = JSON.stringify(byId.get("FG-029"));
  for (const requirement of [
    "activation lock v3",
    "daemon",
    "firewall",
    "project-router",
    "endpoint",
    "rollback",
  ]) {
    assert.match(activation, new RegExp(requirement, "i"));
  }
  const ops = JSON.stringify(byId.get("FG-056"));
  assert.match(ops, /OPS_IMAGE_ID/);
  assert.match(ops, /--pull=never/);
  assert.match(ops, /FG-068/);
  const queue = byId.get("FG-069");
  assert.deepEqual(queue.cross_cohort_dependencies, [{
    group_id: "FG-004",
    source_commit: "0145498196b90d1df867c4b1428dcefed03d3c6d",
    applied_commit: "d358e79c2522b6c42f57e000a69d31ad80cf4133",
    contract: "Authorization, dispatch and queue admission consume the same frozen route operation.",
  }]);
  for (const row of records()) {
    const serialized = JSON.stringify(row);
    assert.doesNotMatch(serialized, /"provider":"PASS"|"live":"PASS"/);
  }
});
