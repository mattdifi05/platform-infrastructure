from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.postfix_evidence.build_postfix_package import build_package
from scripts.postfix_evidence.common import ContractError, canonical_json_bytes, tree_index
from scripts.postfix_evidence.validate_postfix_package import validate_package


SHA256_RETIRED_BASELINE_SNAPSHOT = (
    "938add46f16c25fc823d881fb70980c57a601bb6c7169603e97e17ea93b011de"
)

REQUIRED_LOCAL_CLOSURES = (
    "DOC-EVD-004",
    "DOC-EVD-005",
    "ULTRA-GAP-027",
    "ULTRA-GAP-037",
    "ULTRA-GAP-040",
    "ULTRA-GAP-041",
    "ULTRA-GAP-042",
)

BASELINE_LOCAL_BLOCKERS = tuple(
    dict.fromkeys(
        (
            "DOC-EVD-001",
            "DOC-EVD-002",
            "DOC-EVD-006",
            "DOC-EVD-007",
            "ULTRA-GAP-023",
            "ULTRA-GAP-024",
            "ULTRA-GAP-025",
            "ULTRA-GAP-026",
            *REQUIRED_LOCAL_CLOSURES,
        )
    )
)

REQUIRED_LIVE_RESIDUALS = (
    "LIVE-BKP-006",
    "LIVE-OPS-001",
    "LIVE-OPS-002",
    "LIVE-OPS-004",
)

DOCUMENTATION_TOPICS = (
    "architecture",
    "threat-model",
    "inventory",
    "trust-boundaries",
    "auth-rbac-oidc",
    "workload-contract",
    "secret-management",
    "backup-restore",
    "deploy",
    "rollback",
    "disaster-recovery",
    "observability",
    "performance",
    "incident-response",
    "finding-fix-commit-test",
    "t1-t23",
    "candidate-vs-live",
    "provider-requirements",
    "post-deploy-validation",
    "accepted-risks",
    "unverifiable-elements",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_git(repo: Path, *args: str, input_bytes: bytes | None = None) -> str:
    completed = subprocess.run(
        ["git", "-C", os.fspath(repo), *args],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return completed.stdout.decode("utf-8").strip()


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.baseline = root / "baseline"
        self.handoff_root = root / "handoff"
        self.inputs = self.handoff_root / "inputs"
        self.logs = self.handoff_root / "logs"
        self.repo = root / "candidate"
        self.group_map = root / "security_fix_groups_v1.jsonl"
        self.handoff = self.handoff_root / "handoff.json"
        self.output = root / "postfix-package"
        for directory in (self.baseline, self.inputs, self.logs, self.repo):
            directory.mkdir(parents=True, exist_ok=True)

        self._make_repo()
        self._make_baseline()
        self._make_group_map()
        self._make_handoff_inputs()
        self._make_handoff_manifest()

    def _git_commit(self, message: str) -> str:
        run_git(self.repo, "add", "-A")
        run_git(
            self.repo,
            "-c",
            "user.name=Postfix Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-m",
            message,
        )
        return run_git(self.repo, "rev-parse", "HEAD")

    def _make_repo(self) -> None:
        run_git(self.repo, "init", "-q")
        (self.repo / "tracked.txt").write_text("baseline\n", encoding="utf-8")
        (self.repo / "docs.md").write_text("# Complete documentation\n", encoding="utf-8")
        self.baseline_commit = self._git_commit("baseline")
        self.baseline_tree = run_git(self.repo, "rev-parse", "HEAD^{tree}")

        run_git(self.repo, "switch", "-q", "-c", "cohort")
        (self.repo / "tracked.txt").write_text("baseline\nstructural fix\n", encoding="utf-8")
        self.cohort_commit = self._git_commit("cohort implementation")

        run_git(self.repo, "switch", "-q", "-c", "final", self.baseline_commit)
        (self.repo / "integration-note.txt").write_text("unrelated integration\n", encoding="utf-8")
        self.unrelated_commit = self._git_commit("unrelated integration")
        (self.repo / "tracked.txt").write_text("baseline\nstructural fix\n", encoding="utf-8")
        self.final_commit = self._git_commit("integrated implementation")
        self.final_tree = run_git(self.repo, "rev-parse", "HEAD^{tree}")
        if self.cohort_commit == self.final_commit:
            raise AssertionError("fixture commits must have distinct identities")

    @staticmethod
    def _classification_row(
        item_id: str,
        *,
        record_type: str,
        category: str,
        candidate_affected: bool,
        live_affected: bool,
        is_new: bool,
        blocks_merge: bool,
        blocks_deploy: bool,
        blocks_go: bool,
    ) -> dict[str, object]:
        return {
            "schema_version": 2,
            "id": item_id,
            "record_type": record_type,
            "title": f"Title {item_id}",
            "category": category,
            "severity": "High" if item_id in REQUIRED_LIVE_RESIDUALS else "Medium",
            "component": "fixture",
            "affected_scope": ["candidate"] if candidate_affected else (["live"] if live_affected else []),
            "candidate_affected": candidate_affected,
            "live_affected": live_affected,
            "corrected_in_t1_t23": False,
            "t1_t23_task_ids": [],
            "is_new": is_new,
            "newness_status": "known-new" if is_new else "known-preexisting",
            "newness_basis": "fixture lineage",
            "prior_coverage_evidence": ["fixture baseline"],
            "fix_evidence": ["pre-fix baseline"] if candidate_affected else ["not candidate affected"],
            "evidence": ["docs.md"],
            "live_evidence": ["not verified"],
            "source_input_ids": [f"SOURCE:{item_id}"],
            "source_hashes": {f"SOURCE:{item_id}": "1" * 64},
            "canonical_candidate_ids": [item_id] if item_id.startswith("CAN-") else [],
            "validation_receipt_ids": [f"{item_id}-validation"] if item_id.startswith("CAN-") else [],
            "attack_path_receipt_ids": [f"{item_id}-attack"] if item_id.startswith("CAN-") else [],
            "scenario": "source reaches sink",
            "prerequisites": "fixture",
            "impact": "fixture",
            "blast_radius": "fixture",
            "reproduction": "offline fixture",
            "locations": ["tracked.txt:1"],
            "remediation": "structural fix",
            "rollback": "revert the isolated commit",
            "closure_test": "negative fixture",
            "owner": "fixture owner",
            "blocks_merge": blocks_merge,
            "blocks_deploy": blocks_deploy,
            "blocks_go_to_deploy": blocks_go,
            "blocks_only_production_go": False,
            "remediation_timing": "pre-deploy",
            "condition_ids": [f"COND-{item_id}"],
            "final_state": "OPEN" if (candidate_affected or live_affected) else "NOT-APPLICABLE",
            "classification_boundary": "candidate and live are separate",
            "supersedes": [],
        }

    def _make_baseline(self) -> None:
        reportable_ids = [f"CAN-{number:03d}" for number in range(1, 136)]
        suppressed_ids = [f"CAN-{number:03d}" for number in range(136, 241)]
        auxiliary_ids = [*BASELINE_LOCAL_BLOCKERS, *REQUIRED_LIVE_RESIDUALS]
        auxiliary_ids.extend(f"AUX-{number:03d}" for number in range(1, 102 - len(auxiliary_ids)))
        if len(auxiliary_ids) != 101:
            raise AssertionError("fixture auxiliary cardinality")

        rows: list[dict[str, object]] = []
        for item_id in reportable_ids:
            rows.append(
                self._classification_row(
                    item_id,
                    record_type="security-finding",
                    category="NEW-FINDING",
                    candidate_affected=True,
                    live_affected=False,
                    is_new=True,
                    blocks_merge=True,
                    blocks_deploy=True,
                    blocks_go=True,
                )
            )
        for item_id in suppressed_ids:
            rows.append(
                self._classification_row(
                    item_id,
                    record_type="not-applicable",
                    category="FALSE-POSITIVE-OR-NOT-APPLICABLE",
                    candidate_affected=False,
                    live_affected=False,
                    is_new=False,
                    blocks_merge=False,
                    blocks_deploy=False,
                    blocks_go=False,
                )
            )
        for item_id in auxiliary_ids:
            is_local = item_id in BASELINE_LOCAL_BLOCKERS
            is_live = item_id in REQUIRED_LIVE_RESIDUALS
            rows.append(
                self._classification_row(
                    item_id,
                    record_type="gap" if is_local else "operational-finding",
                    category="STILL-OPEN-IN-CANDIDATE" if is_local else "LIVE-OPERATIONAL-FINDING",
                    candidate_affected=is_local,
                    live_affected=is_live,
                    is_new=False,
                    blocks_merge=is_local,
                    blocks_deploy=is_local or is_live,
                    blocks_go=is_local or is_live,
                )
            )
        if len(rows) != 341:
            raise AssertionError("fixture classification cardinality")
        self.baseline_rows = rows
        self.reportable_ids = reportable_ids
        self.suppressed_ids = suppressed_ids
        self._write_jsonl(self.baseline / "finding_classification_ledger.jsonl", rows)

        registry_dir = self.baseline / "evidence" / "validation"
        registry_dir.mkdir(parents=True)
        registry = []
        for item_id in [*reportable_ids, *suppressed_ids]:
            registry.append(
                {
                    "id": item_id,
                    "canonical_candidate_id": item_id,
                    "status": "CANONICAL",
                    "policy_decision": "reportable" if item_id in reportable_ids else "ignore",
                    "classification_item_ids": [item_id],
                    "candidate_commit": self.baseline_commit,
                    "candidate_tree": self.baseline_tree,
                    "evidence_cutoff_at": "2026-07-13T05:29:45Z",
                }
            )
        self._write_jsonl(registry_dir / "canonical_candidate_registry.jsonl", registry)
        self._write_jsonl(
            self.baseline / "inventory_ledger.jsonl",
            [{"id": f"INV-{number:03d}"} for number in range(1, 135)],
        )

        schemas = self.baseline / "schemas"
        schemas.mkdir()
        matrices = []
        for number in range(1, 16):
            matrix_id = f"M{number:02d}-FIXTURE"
            exact = {2: 23, 5: 34, 12: 6, 13: 13}.get(number)
            minimum = 20 if number == 11 else (0 if number == 15 else 1)
            columns = ["finding_id", "title", "category", "affected_scope", "risk", "action", "evidence"] if number == 15 else ["id", "value"]
            matrices.append(
                {
                    "id": matrix_id,
                    "columns": columns,
                    "boolean_columns": [],
                    "exact_count": exact,
                    "minimum_count": minimum,
                }
            )
        self.matrix_schema = {"matrix_schema_version": 1, "fixed_sets": {}, "matrices": matrices}
        self._write_json(schemas / "matrix-schema-v1.json", self.matrix_schema)
        self._write_manifest(self.baseline)

    def _make_group_map(self) -> None:
        groups = []
        cursor = 0
        for number in range(1, 78):
            width = 2 if number <= 58 else 1
            canonical_ids = self.reportable_ids[cursor : cursor + width]
            cursor += width
            groups.append(
                {
                    "group_id": f"FG-{number:03d}",
                    "slug": f"fixture-{number:03d}",
                    "canonical_ids": canonical_ids,
                    "root_control": "tracked.txt:1",
                    "remediation": "structural fix",
                    "test_boundary": "offline negative fixture",
                }
            )
        if cursor != 135:
            raise AssertionError("fixture group coverage")
        self.groups = groups
        self._write_jsonl(self.group_map, groups)

    def _write_log(self, relative: str, content: str) -> dict[str, str]:
        path = self.handoff_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return {"path": relative, "sha256": sha256(path)}

    def _make_handoff_inputs(self) -> None:
        post_rows = copy.deepcopy(self.baseline_rows)
        reportable = set(self.reportable_ids)
        local = set(BASELINE_LOCAL_BLOCKERS)
        for row in post_rows:
            item_id = str(row["id"])
            if item_id in reportable or item_id in local:
                row["candidate_affected"] = False
                row["affected_scope"] = []
                row["blocks_merge"] = False
                row["blocks_deploy"] = False
                row["blocks_go_to_deploy"] = False
                row["fix_evidence"] = [f"final candidate {self.final_commit}", "test registry"]
                row["final_state"] = "FIXED-IN-FINAL-CANDIDATE"
            if item_id in REQUIRED_LIVE_RESIDUALS:
                row["candidate_affected"] = False
                row["live_affected"] = True
                row["affected_scope"] = ["live"]
                row["blocks_merge"] = False
                row["blocks_deploy"] = True
                row["blocks_go_to_deploy"] = True
                row["final_state"] = "LIVE-NOT-VERIFIED"
        self._write_jsonl(self.inputs / "classification.jsonl", post_rows)

        group_ids = [row["group_id"] for row in self.groups]
        phase_ids = {
            "negative": "TEST-NEGATIVE",
            "positive": "TEST-POSITIVE",
            "regression": "TEST-REGRESSION",
            "hostile": "TEST-HOSTILE",
            "independent-qa": "TEST-INDEPENDENT-QA",
        }
        group_ledger = []
        for group in self.groups:
            group_ledger.append(
                {
                    "schema_version": 1,
                    "group_id": group["group_id"],
                    "canonical_ids": group["canonical_ids"],
                    "cohort": "fixture",
                    "integration_mode": "cherry-pick",
                    "cohort_commit": self.cohort_commit,
                    "final_commit": self.final_commit,
                    "source": ["untrusted fixture input"],
                    "control": ["structural admission control"],
                    "sink": ["protected fixture sink"],
                    "remediation_boundary": "candidate only; no live mutation",
                    "status": "PASS",
                    "consumer_evidence": ["tracked.txt:2"],
                    "negative_test_receipt_ids": [phase_ids["negative"]],
                    "positive_test_receipt_ids": [phase_ids["positive"]],
                    "regression_test_receipt_ids": [phase_ids["regression"]],
                    "hostile_test_receipt_ids": [phase_ids["hostile"]],
                    "independent_qa_receipt_ids": [phase_ids["independent-qa"]],
                }
            )
        self._write_jsonl(self.inputs / "fix-groups.jsonl", group_ledger)

        receipts = []
        for phase, receipt_id in phase_ids.items():
            receipts.append(
                {
                    "schema_version": 1,
                    "receipt_id": receipt_id,
                    "phase": phase,
                    "scope": "all-fix-groups",
                    "group_ids": group_ids,
                    "candidate_final_commit": self.final_commit,
                    "command": ["python3", "offline-fixture.py", phase],
                    "exit_code": 0,
                    "result": "PASS",
                    "log": self._write_log(f"logs/{receipt_id}.log", f"{phase}: PASS\n"),
                }
            )
        for phase in ("full-suite", "differential-scan", "adversarial-qa", "documentation-validation"):
            receipt_id = f"TEST-{phase.upper()}"
            receipts.append(
                {
                    "schema_version": 1,
                    "receipt_id": receipt_id,
                    "phase": phase,
                    "scope": "candidate",
                    "group_ids": [],
                    "candidate_final_commit": self.final_commit,
                    "command": ["python3", "offline-fixture.py", phase],
                    "exit_code": 0,
                    "result": "PASS",
                    "log": self._write_log(f"logs/{receipt_id}.log", f"{phase}: PASS\n"),
                }
            )
        self._write_jsonl(self.inputs / "test-receipts.jsonl", receipts)

        executions = []
        for index, group_id in enumerate(group_ids, start=1):
            runner_kind = "make-wrapper" if index <= 72 else "manual-harness"
            executions.append(
                {
                    "group_id": group_id,
                    "runner_kind": runner_kind,
                    "command": ["make", f"pre-fix-{group_id.lower()}"] if runner_kind == "make-wrapper" else ["python3", f"manual-{group_id.lower()}.py"],
                    "result": "PRE-FIX-NEGATIVE-REPRODUCED",
                    "exit_code": 0,
                    "log": self._write_log(f"logs/pre-fix-{group_id}.log", f"{group_id}: reproduced\n"),
                }
            )
        pre_fix = {
            "schema_version": 1,
            "baseline_commit": self.baseline_commit,
            "baseline_tree": self.baseline_tree,
            "detached_head": True,
            "worktree_clean": True,
            "forbidden_access": {"live": False, "docker": False, "network": False, "secrets": False},
            "executions": executions,
            "summary": {
                "fix_group_count": 77,
                "make_wrapper_count": 72,
                "manual_harness_count": 5,
                "reproduced_count": 77,
            },
        }
        self._write_json(self.inputs / "pre-fix-negative.json", pre_fix)

        closures = []
        for item_id in BASELINE_LOCAL_BLOCKERS:
            closures.append(
                {
                    "schema_version": 1,
                    "id": item_id,
                    "status": "CLOSED-LOCAL",
                    "candidate_final_commit": self.final_commit,
                    "final_commit": self.final_commit,
                    "test_receipt_ids": ["TEST-FULL-SUITE", "TEST-DOCUMENTATION-VALIDATION"],
                    "evidence": ["docs.md"],
                }
            )
        self._write_jsonl(self.inputs / "local-closures.jsonl", closures)

        documentation = {
            "schema_version": 1,
            "candidate_final_commit": self.final_commit,
            "status": "PASS",
            "topics": {topic: ["docs.md"] for topic in DOCUMENTATION_TOPICS},
            "test_receipt_ids": ["TEST-DOCUMENTATION-VALIDATION"],
        }
        self._write_json(self.inputs / "documentation.json", documentation)

        semantic = {
            "schema_version": 1,
            "candidate_final_commit": self.final_commit,
            "terminal_round": 3,
            "modes": {"require_terminal": True, "max_round": None},
            "summary": {"novel_findings": 0, "terminal_decision": "SATURATED/STOP"},
            "saturated": True,
            "cap_reached": False,
        }
        self._write_json(self.inputs / "semantic-completion.json", semantic)

        self._write_matrices(self.inputs / "required-matrices.md")

        verdicts = {
            "schema_version": 1,
            "candidate_final_commit": self.final_commit,
            "evidence_cutoff_at": "2026-07-21T20:00:00Z",
            "candidate_security": {"value": "PASS", "reason_ids": []},
            "merge": {"value": "READY", "reason_ids": []},
            "go_to_deploy": {"value": "NO-GO", "reason_ids": list(REQUIRED_LIVE_RESIDUALS)},
            "full_production_go": {"value": "NO-GO", "reason_ids": list(REQUIRED_LIVE_RESIDUALS)},
            "ready_for_commit_push_deploy_authorization": "NO",
        }
        self._write_json(self.inputs / "four-verdicts.json", verdicts)

        residuals = []
        for item_id in REQUIRED_LIVE_RESIDUALS:
            residuals.append(
                {
                    "schema_version": 1,
                    "id": item_id,
                    "locus": "LIVE-RUNTIME",
                    "verification_status": "NOT-VERIFIED",
                    "candidate_final_commit": self.final_commit,
                    "classification_ids": [item_id],
                    "blocks": ["go_to_deploy", "full_production_go"],
                    "required_evidence": ["direct live execution receipt"],
                    "owner": "platform operations",
                }
            )
        self._write_jsonl(self.inputs / "provider-live-residuals.jsonl", residuals)

    def _write_matrices(self, path: Path) -> None:
        lines = ["# Required matrices v3 — post-fix", "", "MATRIX-SCHEMA-VERSION: 1", ""]
        for matrix in self.matrix_schema["matrices"]:
            lines.extend([f"## {matrix['id']}", ""])
            columns = matrix["columns"]
            lines.append("| " + " | ".join(columns) + " |")
            lines.append("| " + " | ".join("---" for _ in columns) + " |")
            exact = matrix["exact_count"]
            count = exact if exact is not None else max(matrix["minimum_count"], 1)
            if matrix["id"].startswith("M01-"):
                count = 134
            if matrix["id"].startswith("M15-"):
                count = len(self.reportable_ids)
            for index in range(count):
                if matrix["id"].startswith("M15-"):
                    values = [self.reportable_ids[index], f"Title {self.reportable_ids[index]}", "NEW-FINDING", "candidate", "Medium", "fixed", "test registry"]
                else:
                    values = [f"ROW-{index + 1:03d}", "verified"]
                lines.append("| " + " | ".join(values) + " |")
            lines.append("")
        path.write_text("\n".join(lines), encoding="utf-8")

    def _make_handoff_manifest(self) -> None:
        names = {
            "postfix_classification_ledger": "inputs/classification.jsonl",
            "fix_group_ledger": "inputs/fix-groups.jsonl",
            "test_receipt_registry": "inputs/test-receipts.jsonl",
            "pre_fix_negative_receipt": "inputs/pre-fix-negative.json",
            "local_condition_closure": "inputs/local-closures.jsonl",
            "documentation_alignment_receipt": "inputs/documentation.json",
            "semantic_completion_receipt": "inputs/semantic-completion.json",
            "required_matrices": "inputs/required-matrices.md",
            "four_verdicts": "inputs/four-verdicts.json",
            "provider_live_residuals": "inputs/provider-live-residuals.jsonl",
        }
        manifest = {
            "schema_version": 1,
            "evidence_cutoff_at": "2026-07-21T20:00:00Z",
            "candidate_final_commit": self.final_commit,
            "files": {
                key: {"path": relative, "sha256": sha256(self.handoff_root / relative)}
                for key, relative in names.items()
            },
        }
        self._write_json(self.handoff, manifest)

    def semantic_sha256(self) -> str:
        return sha256(self.inputs / "semantic-completion.json")

    def refresh_handoff_hash(self, key: str) -> None:
        manifest = json.loads(self.handoff.read_text(encoding="utf-8"))
        relative = manifest["files"][key]["path"]
        manifest["files"][key]["sha256"] = sha256(self.handoff_root / relative)
        self._write_json(self.handoff, manifest)

    def load_json(self, relative: str) -> dict[str, object]:
        return json.loads((self.handoff_root / relative).read_text(encoding="utf-8"))

    def write_json(self, relative: str, value: object) -> None:
        self._write_json(self.handoff_root / relative, value)

    def load_jsonl(self, relative: str) -> list[dict[str, object]]:
        return [json.loads(line) for line in (self.handoff_root / relative).read_text(encoding="utf-8").splitlines() if line]

    def write_jsonl(self, relative: str, rows: list[dict[str, object]]) -> None:
        self._write_jsonl(self.handoff_root / relative, rows)

    @staticmethod
    def _write_json(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical_json_bytes(value, pretty=True))

    @staticmethod
    def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"".join(canonical_json_bytes(row) for row in rows))

    @staticmethod
    def _write_manifest(root: Path) -> None:
        rows = []
        for path in sorted(item for item in root.rglob("*") if item.is_file() and item.name != "MANIFEST.sha256"):
            rows.append(f"{sha256(path)}  {path.relative_to(root).as_posix()}\n")
        (root / "MANIFEST.sha256").write_text("".join(rows), encoding="utf-8")


class PostfixEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = Fixture(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build(self, *, output: Path | None = None, semantic_sha: str | None = None) -> dict[str, object]:
        return build_package(
            baseline=self.fixture.baseline,
            group_map=self.fixture.group_map,
            handoff=self.fixture.handoff,
            candidate_repo=self.fixture.repo,
            output=output or self.fixture.output,
            semantic_receipt_sha256=semantic_sha or self.fixture.semantic_sha256(),
        )

    def test_two_replay_build_is_byte_identical_and_valid(self) -> None:
        receipt = self.build()
        self.assertTrue(receipt["ok"])
        replay = json.loads((self.fixture.output / "receipts/replay_receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(replay["replay_count"], 2)
        self.assertTrue(replay["byte_identical"])
        validation = validate_package(
            package=self.fixture.output,
            baseline=self.fixture.baseline,
            group_map=self.fixture.group_map,
            candidate_repo=self.fixture.repo,
            semantic_receipt_sha256=self.fixture.semantic_sha256(),
        )
        self.assertTrue(validation["ok"])
        self.assertEqual(validation["counts"]["classification_rows"], 341)
        self.assertEqual(validation["counts"]["canonical_candidates"], 240)
        self.assertEqual(validation["counts"]["reportable"], 135)
        self.assertEqual(validation["counts"]["suppressed"], 105)
        self.assertEqual(validation["counts"]["fix_groups"], 77)

    def test_independent_publications_have_the_same_byte_index(self) -> None:
        first = self.fixture.root / "package-a"
        second = self.fixture.root / "package-b"
        self.build(output=first)
        self.build(output=second)
        self.assertEqual(tree_index(first), tree_index(second))

    def test_current_semantic_hash_is_not_pinned_to_retired_baseline_hash(self) -> None:
        self.assertNotEqual(self.fixture.semantic_sha256(), SHA256_RETIRED_BASELINE_SNAPSHOT)
        self.assertTrue(self.build()["ok"])

    def test_max_round_stop_is_rejected_even_with_current_caller_hash(self) -> None:
        semantic = self.fixture.load_json("inputs/semantic-completion.json")
        semantic["modes"] = {"require_terminal": False, "max_round": 3}
        semantic["summary"] = {"novel_findings": 1, "terminal_decision": "MAX_ROUND_REACHED/STOP"}
        semantic["saturated"] = False
        semantic["cap_reached"] = True
        self.fixture.write_json("inputs/semantic-completion.json", semantic)
        self.fixture.refresh_handoff_hash("semantic_completion_receipt")
        with self.assertRaisesRegex(ContractError, "SATURATED/STOP"):
            self.build(semantic_sha=self.fixture.semantic_sha256())

    def test_missing_or_duplicate_group_fails_closed(self) -> None:
        rows = self.fixture.load_jsonl("inputs/fix-groups.jsonl")
        rows.pop()
        self.fixture.write_jsonl("inputs/fix-groups.jsonl", rows)
        self.fixture.refresh_handoff_hash("fix_group_ledger")
        with self.assertRaisesRegex(ContractError, "fix-group"):
            self.build()

    def test_pre_fix_receipt_requires_77_unique_groups_and_72_plus_5_modes(self) -> None:
        receipt = self.fixture.load_json("inputs/pre-fix-negative.json")
        receipt["executions"][-1]["group_id"] = "FG-001"
        receipt["executions"][-1]["runner_kind"] = "make-wrapper"
        receipt["summary"]["make_wrapper_count"] = 73
        receipt["summary"]["manual_harness_count"] = 4
        self.fixture.write_json("inputs/pre-fix-negative.json", receipt)
        self.fixture.refresh_handoff_hash("pre_fix_negative_receipt")
        with self.assertRaisesRegex(ContractError, "pre-fix"):
            self.build()

    def test_pre_fix_receipt_is_bound_to_authoritative_baseline_commit_and_tree(self) -> None:
        receipt = self.fixture.load_json("inputs/pre-fix-negative.json")
        receipt["baseline_tree"] = "0" * 40
        self.fixture.write_json("inputs/pre-fix-negative.json", receipt)
        self.fixture.refresh_handoff_hash("pre_fix_negative_receipt")
        with self.assertRaisesRegex(ContractError, "baseline"):
            self.build()

    def test_every_baseline_local_blocker_requires_an_explicit_closure_row(self) -> None:
        rows = self.fixture.load_jsonl("inputs/local-closures.jsonl")
        rows = [row for row in rows if row["id"] != "DOC-EVD-001"]
        self.fixture.write_jsonl("inputs/local-closures.jsonl", rows)
        self.fixture.refresh_handoff_hash("local_condition_closure")
        with self.assertRaisesRegex(ContractError, "required proof rows missing"):
            self.build()

    def test_cohort_only_final_commit_mapping_is_rejected(self) -> None:
        rows = self.fixture.load_jsonl("inputs/fix-groups.jsonl")
        for row in rows:
            row["final_commit"] = row["cohort_commit"]
        self.fixture.write_jsonl("inputs/fix-groups.jsonl", rows)
        self.fixture.refresh_handoff_hash("fix_group_ledger")
        with self.assertRaisesRegex(ContractError, "cohort-only"):
            self.build()

    def test_reachable_but_non_equivalent_final_mapping_is_rejected(self) -> None:
        rows = self.fixture.load_jsonl("inputs/fix-groups.jsonl")
        for row in rows:
            row["final_commit"] = self.fixture.unrelated_commit
        self.fixture.write_jsonl("inputs/fix-groups.jsonl", rows)
        self.fixture.refresh_handoff_hash("fix_group_ledger")
        with self.assertRaisesRegex(ContractError, "patch-equivalent"):
            self.build()

    def test_explicit_direct_final_identity_is_accepted(self) -> None:
        rows = self.fixture.load_jsonl("inputs/fix-groups.jsonl")
        rows[0]["integration_mode"] = "direct-final"
        rows[0]["cohort_commit"] = self.fixture.final_commit
        rows[0]["final_commit"] = self.fixture.final_commit
        self.fixture.write_jsonl("inputs/fix-groups.jsonl", rows)
        self.fixture.refresh_handoff_hash("fix_group_ledger")
        self.assertTrue(self.build()["ok"])

    def test_dirty_final_candidate_is_rejected(self) -> None:
        (self.fixture.repo / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaisesRegex(ContractError, "clean"):
            self.build()

    def test_output_package_must_remain_external_to_candidate(self) -> None:
        with self.assertRaisesRegex(ContractError, "external"):
            self.build(output=self.fixture.repo / "evidence-package")

    def test_suppressed_row_mutation_is_rejected(self) -> None:
        rows = self.fixture.load_jsonl("inputs/classification.jsonl")
        target = next(row for row in rows if row["id"] == self.fixture.suppressed_ids[0])
        target["title"] = "silently changed suppression"
        self.fixture.write_jsonl("inputs/classification.jsonl", rows)
        self.fixture.refresh_handoff_hash("postfix_classification_ledger")
        with self.assertRaisesRegex(ContractError, "suppressed"):
            self.build()

    def test_missing_handoff_input_and_stale_hash_are_rejected(self) -> None:
        manifest = json.loads(self.fixture.handoff.read_text(encoding="utf-8"))
        del manifest["files"]["required_matrices"]
        self.fixture._write_json(self.fixture.handoff, manifest)
        with self.assertRaisesRegex(ContractError, "handoff"):
            self.build()

    def test_unsafe_test_receipt_identity_cannot_escape_package(self) -> None:
        rows = self.fixture.load_jsonl("inputs/test-receipts.jsonl")
        rows[0]["receipt_id"] = "../ESCAPE"
        self.fixture.write_jsonl("inputs/test-receipts.jsonl", rows)
        self.fixture.refresh_handoff_hash("test_receipt_registry")
        with self.assertRaisesRegex(ContractError, "unsafe receipt ID"):
            self.build()

    def test_matrix_set_requires_m01_through_m15_and_exact_m15_projection(self) -> None:
        matrix_path = self.fixture.inputs / "required-matrices.md"
        content = matrix_path.read_text(encoding="utf-8")
        content = content[: content.index("## M15-")]
        matrix_path.write_text(content, encoding="utf-8")
        self.fixture.refresh_handoff_hash("required_matrices")
        with self.assertRaisesRegex(ContractError, "M15"):
            self.build()

    def test_positive_deploy_verdict_cannot_hide_blocking_live_residuals(self) -> None:
        verdicts = self.fixture.load_json("inputs/four-verdicts.json")
        verdicts["go_to_deploy"] = {"value": "GO", "reason_ids": []}
        verdicts["ready_for_commit_push_deploy_authorization"] = "YES"
        self.fixture.write_json("inputs/four-verdicts.json", verdicts)
        self.fixture.refresh_handoff_hash("four_verdicts")
        with self.assertRaisesRegex(ContractError, "go_to_deploy"):
            self.build()

    def test_residual_block_axes_are_derived_from_the_full_classification_ledger(self) -> None:
        residuals = self.fixture.load_jsonl("inputs/provider-live-residuals.jsonl")
        for residual in residuals:
            residual["blocks"] = []
        self.fixture.write_jsonl("inputs/provider-live-residuals.jsonl", residuals)
        self.fixture.refresh_handoff_hash("provider_live_residuals")
        verdicts = self.fixture.load_json("inputs/four-verdicts.json")
        verdicts["go_to_deploy"] = {"value": "GO", "reason_ids": []}
        verdicts["ready_for_commit_push_deploy_authorization"] = "YES"
        self.fixture.write_json("inputs/four-verdicts.json", verdicts)
        self.fixture.refresh_handoff_hash("four_verdicts")
        with self.assertRaisesRegex(ContractError, "derived|exact residual"):
            self.build()

    def test_pass_log_cannot_substitute_for_a_script_present_at_final_commit(self) -> None:
        self.assertFalse((self.fixture.repo / "offline-fixture.py").exists())
        with self.assertRaisesRegex(ContractError, "script-at-commit|script at final commit"):
            self.build()

    def test_manifest_tamper_is_detected_after_build(self) -> None:
        self.build()
        target = self.fixture.output / "four_verdicts_v1.json"
        target.write_bytes(target.read_bytes() + b"\n")
        with self.assertRaisesRegex(ContractError, "manifest"):
            validate_package(
                package=self.fixture.output,
                baseline=self.fixture.baseline,
                group_map=self.fixture.group_map,
                candidate_repo=self.fixture.repo,
                semantic_receipt_sha256=self.fixture.semantic_sha256(),
            )


if __name__ == "__main__":
    unittest.main()
