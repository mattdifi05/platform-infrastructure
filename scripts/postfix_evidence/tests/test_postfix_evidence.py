from __future__ import annotations

import copy
import errno
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

import scripts.postfix_evidence.common as common_module
import scripts.postfix_evidence.build_postfix_package as builder_module
import scripts.postfix_evidence.validate_postfix_package as validator_module
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

REQUIRED_PROVIDER_RESIDUALS = ("PROVIDER-003",)

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

COHORT_GROUP_NUMBERS = {
    "control_auth": (4, 6, 20, 43),
    "control_services": (22, 24, 26, 27, 45, 51, 62, 76),
    "hosted": (
        1,
        2,
        3,
        7,
        8,
        9,
        13,
        14,
        15,
        16,
        17,
        18,
        19,
        30,
        31,
        38,
        39,
        41,
        44,
        46,
        57,
        61,
        66,
        68,
        71,
        72,
        73,
        74,
        75,
    ),
    "runtime": (5, 11, 21, 25, 40, 42, 53, 54, 55, 60),
    "backup_evidence": (23, 32, 33, 34, 35, 36, 37, 47, 48, 58, 64, 67, 70, 77),
    "release": (10, 12, 28, 29, 49, 50, 52, 56, 59, 63, 65, 69),
}

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
        (self.repo / "semantic.yml").write_text("value: base\n", encoding="utf-8")
        (self.repo / "offline-fixture.py").write_text(
            "#!/usr/bin/env python3\nprint('offline fixture')\n",
            encoding="utf-8",
        )
        self.baseline_commit = self._git_commit("baseline")
        self.baseline_tree = run_git(self.repo, "rev-parse", "HEAD^{tree}")

        run_git(self.repo, "switch", "-q", "-c", "cohort")
        (self.repo / "tracked.txt").write_text("baseline\nstructural fix\n", encoding="utf-8")
        self.cohort_commit = self._git_commit("cohort implementation")
        (self.repo / "semantic.yml").write_text("value: a b\n", encoding="utf-8")
        self.cohort_semantic_commit = self._git_commit("cohort semantic whitespace")
        (self.repo / "support.txt").write_text("shared support fix\n", encoding="utf-8")
        self.cohort_support_commit = self._git_commit("cohort support implementation")

        run_git(self.repo, "switch", "-q", "-c", "final", self.baseline_commit)
        (self.repo / "integration-note.txt").write_text("unrelated integration\n", encoding="utf-8")
        self.unrelated_commit = self._git_commit("unrelated integration")
        (self.repo / "semantic.yml").write_text("value: ab\n", encoding="utf-8")
        self.final_semantic_commit = self._git_commit("integrated semantic whitespace")
        (self.repo / "support.txt").write_text("shared support fix\n", encoding="utf-8")
        self.final_support_commit = self._git_commit("integrated support implementation")
        source_tool_root = Path(validator_module.__file__).parent
        candidate_tool_root = self.repo / "scripts" / "postfix_evidence"
        candidate_tool_root.mkdir(parents=True)
        for name in validator_module.TOOL_SOURCE_NAMES:
            shutil.copy2(source_tool_root / name, candidate_tool_root / name)
        pre_fix_dir = self.repo / "tests" / "pre-fix"
        pre_fix_dir.mkdir(parents=True)
        makefile = pre_fix_dir / "Makefile"
        makefile.write_text(
            "\n".join(
                (
                    f"pre-fix-fg-{number:03d}:\n"
                    f"\t@python3 manual-harness.py FG-{number:03d}"
                )
                for number in range(1, 73)
            )
            + "\n",
            encoding="utf-8",
        )
        manual_harness = pre_fix_dir / "manual-harness.py"
        manual_harness.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "assert len(sys.argv) == 2 and sys.argv[1].startswith('FG-')\n",
            encoding="utf-8",
        )
        make_descriptor = {
            "path": "tests/pre-fix/Makefile",
            "mode": "100644",
            "sha256": sha256(makefile),
        }
        manual_descriptor = {
            "path": "tests/pre-fix/manual-harness.py",
            "mode": "100644",
            "sha256": sha256(manual_harness),
        }
        self.pre_fix_definition_rows = []
        for number in range(1, 78):
            group_id = f"FG-{number:03d}"
            is_make = number <= 72
            self.pre_fix_definition_rows.append(
                {
                    "schema_version": 1,
                    "group_id": group_id,
                    "test_case_id": f"PRE-FIX-{group_id}",
                    "runner_kind": (
                        "make-wrapper" if is_make else "manual-harness"
                    ),
                    "cwd": "tests/pre-fix",
                    "argv": (
                        ["make", "-f", "Makefile", f"pre-fix-fg-{number:03d}"]
                        if is_make
                        else ["python3", "manual-harness.py", group_id]
                    ),
                    "test_definition_at_final_commit": (
                        make_descriptor if is_make else manual_descriptor
                    ),
                    "consumer_paths_at_baseline": ["tracked.txt"],
                }
            )
        self.pre_fix_registry_repo_path = (
            "tests/pre-fix/definition-registry.jsonl"
        )
        (self.repo / self.pre_fix_registry_repo_path).write_bytes(
            b"".join(
                canonical_json_bytes(row)
                for row in self.pre_fix_definition_rows
            )
        )
        self.pre_fix_definition_commit = self._git_commit(
            "integrated pre-fix test definitions"
        )
        (self.repo / "tracked.txt").write_text(
            "baseline\nstructural fix\n",
            encoding="utf-8",
        )
        self.final_commit = self._git_commit("integrated implementation")
        self.final_tree = run_git(self.repo, "rev-parse", "HEAD^{tree}")
        if self.cohort_commit == self.final_commit:
            raise AssertionError("fixture commits must have distinct identities")

    def _git_blob_descriptor(
        self,
        commit: str,
        path: str,
        *,
        kind: str | None = None,
    ) -> dict[str, str]:
        listing = run_git(self.repo, "ls-tree", commit, "--", path)
        mode = listing.split(" ", 1)[0]
        payload = subprocess.run(
            ["git", "-C", os.fspath(self.repo), "show", f"{commit}:{path}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout
        result = {"path": path, "mode": mode, "sha256": hashlib.sha256(payload).hexdigest()}
        if kind is not None:
            result["kind"] = kind
        return result

    @staticmethod
    def _executable_descriptor(argv0: str) -> dict[str, str]:
        located = shutil.which(argv0)
        if located is None:
            raise AssertionError(f"fixture executable unavailable: {argv0}")
        resolved = Path(located).resolve(strict=True)
        return {
            "argv0": argv0,
            "resolved_path": str(resolved),
            "sha256": sha256(resolved),
        }

    @staticmethod
    def _execution_log(
        receipt_id: str,
        head: str,
        tree: str,
        phase: str,
        semantic_anchor: str,
    ) -> str:
        return (
            f"RECEIPT {receipt_id} HEAD {head} TREE {tree} PHASE {phase} RESULT PASS\n"
            f"ANCHOR {semantic_anchor}\n"
        )

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
        auxiliary_ids = [
            *BASELINE_LOCAL_BLOCKERS,
            *REQUIRED_LIVE_RESIDUALS,
            *REQUIRED_PROVIDER_RESIDUALS,
        ]
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
            is_provider = item_id in REQUIRED_PROVIDER_RESIDUALS
            row = self._classification_row(
                item_id,
                record_type=(
                    "gap"
                    if (is_local or is_provider)
                    else ("operational-finding" if is_live else "documentation-drift")
                ),
                category=(
                    "STILL-OPEN-IN-CANDIDATE"
                    if is_local
                    else (
                        "PROVIDER-EXTERNAL"
                        if is_provider
                        else (
                            "LIVE-OPERATIONAL-FINDING"
                            if is_live
                            else "DOCUMENTATION-EVIDENCE-DRIFT"
                        )
                    )
                ),
                candidate_affected=is_local,
                live_affected=is_live,
                is_new=False,
                blocks_merge=is_local or is_provider,
                blocks_deploy=is_local or is_live or is_provider,
                blocks_go=is_local or is_live or is_provider,
            )
            if is_provider:
                row["affected_scope"] = ["provider", "evidence"]
                row["final_state"] = "EXTERNAL-VALIDATION-REQUIRED"
            rows.append(row)
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
        first_columns = validator_module.MATRIX_FIRST_COLUMNS
        matrices = []
        for number in range(1, 16):
            matrix_id = f"M{number:02d}-FIXTURE"
            exact = {2: 23, 5: 34, 12: 6, 13: 13}.get(number)
            minimum = 20 if number == 11 else (0 if number == 15 else 1)
            columns = (
                ["finding_id", "title", "category", "affected_scope", "risk", "action", "evidence"]
                if number == 15
                else [first_columns[number - 1], "value"]
            )
            matrices.append(
                {
                    "id": matrix_id,
                    "columns": columns,
                    "boolean_columns": [],
                    "exact_count": exact,
                    "minimum_count": minimum,
                }
            )
        self.matrix_schema = {
            "matrix_schema_version": 1,
            "fixed_sets": {
                "ci_check_ids": list(validator_module.CI_CHECK_IDS),
                "t23_blocker_slugs": list(validator_module.T23_BLOCKER_SLUGS),
            },
            "matrices": matrices,
        }
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
            pending_external = item_id in validator_module.EXTERNAL_PENDING_LOCAL_SUPPORT
            if item_id in reportable or item_id in local:
                row["candidate_affected"] = False
                row["affected_scope"] = ["evidence", "external-governance"] if pending_external else []
                row["blocks_merge"] = False
                row["blocks_deploy"] = pending_external
                row["blocks_go_to_deploy"] = pending_external
                row["fix_evidence"] = [f"final candidate {self.final_commit}", "test registry"]
                row["final_state"] = (
                    "LOCAL-SUPPORT-READY-EXTERNAL-PENDING"
                    if pending_external
                    else "FIXED-IN-FINAL-CANDIDATE"
                )
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
                    "boundary_paths": ["tracked.txt", "support.txt"],
                    "support_commits": [self.cohort_commit, self.cohort_support_commit],
                    "support_commit_mappings": [
                        {
                            "cohort_commit": self.cohort_commit,
                            "final_commit": self.final_commit,
                            "integration_mode": "cherry-pick",
                            "boundary_paths": ["tracked.txt"],
                        },
                        {
                            "cohort_commit": self.cohort_support_commit,
                            "final_commit": self.final_support_commit,
                            "integration_mode": "cherry-pick",
                            "boundary_paths": ["support.txt"],
                        },
                    ],
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
        self.cohort_handoff_names = {
            "control_auth": "inputs/cohorts/control-auth.jsonl",
            "control_services": "inputs/cohorts/control-services.jsonl",
            "hosted": "inputs/cohorts/hosted.jsonl",
            "runtime": "inputs/cohorts/runtime.jsonl",
            "backup_evidence": "inputs/cohorts/backup-evidence.jsonl",
            "release": "inputs/cohorts/release.jsonl",
        }
        group_by_id = {group["group_id"]: group for group in self.groups}
        projected_numbers = {
            number
            for numbers in COHORT_GROUP_NUMBERS.values()
            for number in numbers
        }
        if projected_numbers != set(range(1, 78)):
            raise AssertionError("fixture raw cohort assignment")
        for source_name, numbers in COHORT_GROUP_NUMBERS.items():
            raw_rows = []
            for number in numbers:
                group = group_by_id[f"FG-{number:03d}"]
                raw_rows.append(
                    {
                        "group_id": group["group_id"],
                        "slug": group["slug"],
                        "canonical_ids": group["canonical_ids"],
                        "cohort_commit": self.cohort_commit,
                        "support_commits": [self.cohort_support_commit],
                        "final_commit": None,
                        "source": "untrusted fixture input",
                        "control": "structural admission control",
                        "sink": "protected fixture sink",
                        "boundary": "candidate-only offline fixture",
                        "pre_fix_negative": {"status": "reproduced"},
                        "tests": {"status": "pass"},
                        "independent_qa": {"status": "pass-offline"},
                        "runtime_status": {"status": "not-run"},
                        "external_conditions": [],
                        "rollback": "git revert after disabling the protected sink",
                    }
                )
            self._write_jsonl(
                self.handoff_root / self.cohort_handoff_names[source_name],
                raw_rows,
            )

        semantic_by_phase = {
            "negative": "negative-boundary",
            "positive": "positive-control",
            "regression": "regression-suite",
            "hostile": "hostile-variant",
            "independent-qa": "independent-qa",
            "full-suite": "full-suite",
            "differential-scan": "differential-scan",
            "adversarial-qa": "adversarial-qa",
            "documentation-validation": "documentation-validation",
        }
        sandbox = {
            "mode": "offline-read-only",
            "network": False,
            "docker": False,
            "live": False,
            "provider": False,
            "secrets": False,
            "filesystem_write": False,
        }
        python_executable = self._executable_descriptor("python3")
        final_script = self._git_blob_descriptor(self.final_commit, "offline-fixture.py")
        final_test_anchor = self._git_blob_descriptor(
            self.final_commit,
            "offline-fixture.py",
            kind="test-script",
        )
        final_consumer_anchor = self._git_blob_descriptor(
            self.final_commit,
            "tracked.txt",
            kind="consumer",
        )
        final_documentation_anchor = self._git_blob_descriptor(
            self.final_commit,
            "docs.md",
            kind="documentation",
        )
        receipts = []
        for phase, receipt_id in phase_ids.items():
            semantic_anchor = semantic_by_phase[phase]
            receipts.append(
                {
                    "schema_version": 1,
                    "receipt_id": receipt_id,
                    "phase": phase,
                    "scope": "all-fix-groups",
                    "group_ids": group_ids,
                    "head_commit": self.final_commit,
                    "head_tree": self.final_tree,
                    "started_at": "2026-07-21T19:00:00Z",
                    "ended_at": "2026-07-21T19:00:01Z",
                    "cwd": ".",
                    "argv": ["python3", "offline-fixture.py", phase],
                    "executable": python_executable,
                    "script_at_commit": final_script,
                    "exit_code": 0,
                    "result": "PASS",
                    "sandbox": sandbox,
                    "semantic_anchors": [semantic_anchor],
                    "artifact_anchors": [final_test_anchor, final_consumer_anchor],
                    "log": self._write_log(
                        f"logs/{receipt_id}.log",
                        self._execution_log(
                            receipt_id,
                            self.final_commit,
                            self.final_tree,
                            phase,
                            semantic_anchor,
                        ),
                    ),
                }
            )
        for phase in ("full-suite", "differential-scan", "adversarial-qa", "documentation-validation"):
            receipt_id = f"TEST-{phase.upper()}"
            semantic_anchor = semantic_by_phase[phase]
            receipts.append(
                {
                    "schema_version": 1,
                    "receipt_id": receipt_id,
                    "phase": phase,
                    "scope": "candidate",
                    "group_ids": [],
                    "head_commit": self.final_commit,
                    "head_tree": self.final_tree,
                    "started_at": "2026-07-21T19:00:00Z",
                    "ended_at": "2026-07-21T19:00:01Z",
                    "cwd": ".",
                    "argv": ["python3", "offline-fixture.py", phase],
                    "executable": python_executable,
                    "script_at_commit": final_script,
                    "exit_code": 0,
                    "result": "PASS",
                    "sandbox": sandbox,
                    "semantic_anchors": [semantic_anchor],
                    "artifact_anchors": [
                        final_test_anchor,
                        final_documentation_anchor
                        if phase == "documentation-validation"
                        else final_consumer_anchor,
                    ],
                    "log": self._write_log(
                        f"logs/{receipt_id}.log",
                        self._execution_log(
                            receipt_id,
                            self.final_commit,
                            self.final_tree,
                            phase,
                            semantic_anchor,
                        ),
                    ),
                }
            )
        self._write_jsonl(self.inputs / "test-receipts.jsonl", receipts)

        make_executable = self._executable_descriptor("make")
        baseline_consumer_anchor = self._git_blob_descriptor(
            self.baseline_commit,
            "tracked.txt",
            kind="consumer",
        )
        self.pre_fix_definition_input_name = (
            "inputs/pre-fix-test-definitions.jsonl"
        )
        registry_bytes = subprocess.run(
            [
                "git",
                "-C",
                os.fspath(self.repo),
                "show",
                (
                    f"{self.final_commit}:"
                    f"{self.pre_fix_registry_repo_path}"
                ),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout
        (self.handoff_root / self.pre_fix_definition_input_name).write_bytes(
            registry_bytes
        )
        registry_by_group = {
            row["group_id"]: row for row in self.pre_fix_definition_rows
        }
        executions = []
        for group_id in group_ids:
            definition = registry_by_group[group_id]
            definition_path = definition[
                "test_definition_at_final_commit"
            ]["path"]
            pre_fix_log = (
                self._execution_log(
                    group_id,
                    self.baseline_commit,
                    self.baseline_tree,
                    "pre-fix-negative",
                    "pre-fix-negative-reproduced",
                )
                + (
                    f"TEST-DEFINITION HEAD {self.final_commit} "
                    f"TREE {self.final_tree} "
                    f"REGISTRY {self.pre_fix_registry_repo_path} "
                    f"CASE {definition['test_case_id']} "
                    f"PATH {definition_path}\n"
                )
                + (
                    f"CONSUMER-BLOB tracked.txt MODE "
                    f"{baseline_consumer_anchor['mode']} SHA256 "
                    f"{baseline_consumer_anchor['sha256']}\n"
                )
            )
            executions.append(
                {
                    "group_id": group_id,
                    "test_case_id": definition["test_case_id"],
                    "target_commit": self.baseline_commit,
                    "target_tree": self.baseline_tree,
                    "started_at": "2026-07-21T18:00:00Z",
                    "ended_at": "2026-07-21T18:00:01Z",
                    "executable": (
                        make_executable
                        if definition["runner_kind"] == "make-wrapper"
                        else python_executable
                    ),
                    "result": "PRE-FIX-NEGATIVE-REPRODUCED",
                    "exit_code": 0,
                    "sandbox": sandbox,
                    "semantic_anchors": ["pre-fix-negative-reproduced"],
                    "consumer_anchors_at_baseline": [
                        baseline_consumer_anchor
                    ],
                    "log": self._write_log(
                        f"logs/pre-fix-{group_id}.log",
                        pre_fix_log,
                    ),
                }
            )
        pre_fix = {
            "schema_version": 1,
            "baseline_commit": self.baseline_commit,
            "baseline_tree": self.baseline_tree,
            "test_definition_commit": self.final_commit,
            "test_definition_tree": self.final_tree,
            "test_definition_registry_at_final_commit": (
                self._git_blob_descriptor(
                    self.final_commit,
                    self.pre_fix_registry_repo_path,
                )
            ),
            "detached_head": True,
            "worktree_clean": True,
            "forbidden_access": {"live": False, "docker": False, "network": False, "secrets": False},
            "executions": executions,
            "summary": {
                "fix_group_count": 77,
                "reproduced_count": 77,
            },
        }
        self._write_json(self.inputs / "pre-fix-negative.json", pre_fix)

        closures = []
        for item_id in BASELINE_LOCAL_BLOCKERS:
            special = validator_module.EXTERNAL_PENDING_LOCAL_SUPPORT.get(item_id)
            row = {
                "schema_version": 1,
                "id": item_id,
                "status": (
                    "LOCAL-SUPPORT-READY-EXTERNAL-PENDING"
                    if special is not None
                    else "CLOSED-LOCAL"
                ),
                "candidate_final_commit": self.final_commit,
                "final_commit": self.final_commit,
                "test_receipt_ids": ["TEST-FULL-SUITE", "TEST-DOCUMENTATION-VALIDATION"],
                "evidence": ["docs.md"],
            }
            if special is not None:
                row.update(
                    {
                        "local_support_kind": special["local_support_kind"],
                        "external_residual_id": special["external_residual_id"],
                        "condition_ids": [f"COND-{item_id}"],
                    }
                )
            closures.append(row)
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

        governance_blockers = sorted(validator_module.EXTERNAL_PENDING_LOCAL_SUPPORT)
        all_external_blockers = [
            *REQUIRED_LIVE_RESIDUALS,
            *REQUIRED_PROVIDER_RESIDUALS,
            *governance_blockers,
        ]
        verdicts = {
            "schema_version": 1,
            "candidate_final_commit": self.final_commit,
            "evidence_cutoff_at": "2026-07-21T20:00:00Z",
            "candidate_security": {"value": "PASS", "reason_ids": []},
            "merge": {"value": "BLOCKED", "reason_ids": list(REQUIRED_PROVIDER_RESIDUALS)},
            "go_to_deploy": {"value": "NO-GO", "reason_ids": sorted(all_external_blockers)},
            "full_production_go": {"value": "NO-GO", "reason_ids": sorted(all_external_blockers)},
            "ready_for_commit_push_deploy_authorization": "NO",
        }
        self._write_json(self.inputs / "four-verdicts.json", verdicts)

        residuals = []
        for item_id in [*REQUIRED_LIVE_RESIDUALS, *REQUIRED_PROVIDER_RESIDUALS]:
            is_provider = item_id in REQUIRED_PROVIDER_RESIDUALS
            residuals.append(
                {
                    "schema_version": 1,
                    "id": item_id,
                    "locus": "PROVIDER-EXTERNAL" if is_provider else "LIVE-RUNTIME",
                    "verification_status": "NOT-VERIFIED",
                    "candidate_final_commit": self.final_commit,
                    "classification_ids": [item_id],
                    "condition_ids": [f"COND-{item_id}"],
                    "blocks": (
                        ["merge", "go_to_deploy", "full_production_go"]
                        if is_provider
                        else ["go_to_deploy", "full_production_go"]
                    ),
                    "required_evidence": ["direct live execution receipt"],
                    "owner": "platform operations",
                }
            )
        for item_id, special in validator_module.EXTERNAL_PENDING_LOCAL_SUPPORT.items():
            residuals.append(
                {
                    "schema_version": 1,
                    "id": special["external_residual_id"],
                    "locus": "GOVERNANCE-EXTERNAL",
                    "verification_status": "EXTERNAL-VALIDATION-REQUIRED",
                    "candidate_final_commit": self.final_commit,
                    "classification_ids": [item_id],
                    "condition_ids": [f"COND-{item_id}"],
                    "blocks": ["go_to_deploy", "full_production_go"],
                    "required_evidence": [special["required_evidence"]],
                    "owner": "external governance owner",
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
            matrix_number = int(matrix["id"][1:3])
            primary_ids = {
                1: [f"INV-{number:03d}" for number in range(1, 135)],
                2: [f"T{number:02d}" for number in range(1, 24)],
                11: list(validator_module.CI_CHECK_IDS),
                12: [f"T{number:02d}" for number in range(18, 24)],
                13: list(validator_module.T23_BLOCKER_SLUGS),
                14: [REQUIRED_LIVE_RESIDUALS[0]],
                15: self.reportable_ids,
            }.get(matrix_number)
            for index in range(count):
                if matrix["id"].startswith("M15-"):
                    values = [self.reportable_ids[index], f"Title {self.reportable_ids[index]}", "NEW-FINDING", "candidate", "Medium", "fixed", "test registry"]
                else:
                    identity = primary_ids[index] if primary_ids is not None else f"ROW-{index + 1:03d}"
                    values = [identity, "verified"]
                lines.append("| " + " | ".join(values) + " |")
            lines.append("")
        path.write_text("\n".join(lines), encoding="utf-8")

    def _make_handoff_manifest(self) -> None:
        names = {
            "postfix_classification_ledger": "inputs/classification.jsonl",
            "fix_group_ledger": "inputs/fix-groups.jsonl",
            "test_receipt_registry": "inputs/test-receipts.jsonl",
            "pre_fix_negative_receipt": "inputs/pre-fix-negative.json",
            "pre_fix_test_definition_registry": (
                self.pre_fix_definition_input_name
            ),
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
            "cohort_handoffs": {
                key: {"path": relative, "sha256": sha256(self.handoff_root / relative)}
                for key, relative in self.cohort_handoff_names.items()
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

    def refresh_cohort_handoff_hash(self, key: str) -> None:
        manifest = json.loads(self.handoff.read_text(encoding="utf-8"))
        relative = manifest["cohort_handoffs"][key]["path"]
        manifest["cohort_handoffs"][key]["sha256"] = sha256(
            self.handoff_root / relative
        )
        self._write_json(self.handoff, manifest)

    def load_cohort_handoff(self, key: str) -> list[dict[str, object]]:
        return self.load_jsonl(self.cohort_handoff_names[key])

    def write_cohort_handoff(
        self,
        key: str,
        rows: list[dict[str, object]],
    ) -> None:
        self.write_jsonl(self.cohort_handoff_names[key], rows)
        self.refresh_cohort_handoff_hash(key)

    def conflict_resolution_receipt(
        self,
        cohort_commit: str,
        final_commit: str,
        boundary_paths: list[str],
    ) -> dict[str, object]:
        cohort_rows = {
            row["path"]: row
            for row in common_module.commit_delta_records(self.repo, cohort_commit)
        }
        final_rows = {
            row["path"]: row
            for row in common_module.commit_delta_records(self.repo, final_commit)
        }
        files = []
        for path in sorted(boundary_paths):
            cohort = cohort_rows[path]
            final = final_rows[path]
            files.append(
                {
                    "path": path,
                    "before": {
                        "mode": final["old_mode"],
                        "sha256": final["old_content_sha256"],
                    },
                    "cohort": {
                        "mode": cohort["new_mode"],
                        "sha256": cohort["new_content_sha256"],
                    },
                    "final": {
                        "mode": final["new_mode"],
                        "sha256": final["new_content_sha256"],
                    },
                    "control_preserved": True,
                }
            )
        return {
            "schema_version": 1,
            "reason": "overlapping integration changed the same semantic boundary",
            "final_integration_commit": final_commit,
            "boundary_paths": sorted(boundary_paths),
            "files": files,
            "no_control_omitted": True,
            "test_receipt_ids": [
                "TEST-NEGATIVE",
                "TEST-POSITIVE",
                "TEST-HOSTILE",
                "TEST-INDEPENDENT-QA",
            ],
        }

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
        for path in sorted(
            item
            for item in root.rglob("*")
            if item.is_file() and item.relative_to(root).as_posix() != "MANIFEST.sha256"
        ):
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

    def configure_reconciled_group(self) -> dict[str, object]:
        rows = self.fixture.load_jsonl("inputs/fix-groups.jsonl")
        target = next(row for row in rows if row["group_id"] == "FG-001")
        target["integration_mode"] = "reconciled"
        target["cohort_commit"] = self.fixture.cohort_semantic_commit
        target["final_commit"] = self.fixture.final_semantic_commit
        target["boundary_paths"] = ["semantic.yml", "support.txt"]
        target["consumer_evidence"] = ["semantic.yml:1"]
        target["support_commits"] = [
            self.fixture.cohort_semantic_commit,
            self.fixture.cohort_support_commit,
        ]
        target["support_commit_mappings"][0] = {
            "cohort_commit": self.fixture.cohort_semantic_commit,
            "final_commit": self.fixture.final_semantic_commit,
            "integration_mode": "reconciled",
            "boundary_paths": ["semantic.yml"],
            "conflict_resolution_receipt": self.fixture.conflict_resolution_receipt(
                self.fixture.cohort_semantic_commit,
                self.fixture.final_semantic_commit,
                ["semantic.yml"],
            ),
        }
        self.fixture.write_jsonl("inputs/fix-groups.jsonl", rows)
        self.fixture.refresh_handoff_hash("fix_group_ledger")

        raw_rows = self.fixture.load_cohort_handoff("hosted")
        raw_target = next(row for row in raw_rows if row["group_id"] == "FG-001")
        raw_target["cohort_commit"] = self.fixture.cohort_semantic_commit
        raw_target["support_commits"] = [self.fixture.cohort_support_commit]
        raw_target["final_commit"] = self.fixture.final_semantic_commit
        raw_target["integration_mode"] = "reconciled"
        self.fixture.write_cohort_handoff("hosted", raw_rows)
        receipts = self.fixture.load_jsonl("inputs/test-receipts.jsonl")
        semantic_anchor = self.fixture._git_blob_descriptor(
            self.fixture.final_commit,
            "semantic.yml",
            kind="consumer",
        )
        for receipt in receipts:
            if receipt["phase"] in {
                "negative",
                "positive",
                "regression",
                "hostile",
                "independent-qa",
            }:
                receipt["artifact_anchors"].append(copy.deepcopy(semantic_anchor))
        self.fixture.write_jsonl("inputs/test-receipts.jsonl", receipts)
        self.fixture.refresh_handoff_hash("test_receipt_registry")
        return target

    def test_two_replay_build_is_byte_identical_and_valid(self) -> None:
        receipt = self.build()
        self.assertTrue(receipt["ok"])
        for replay_id, relative in validator_module.REPLAY_RECEIPT_PATHS.items():
            replay = json.loads(
                (self.fixture.output / relative).read_text(encoding="utf-8")
            )
            self.assertEqual(replay["replay_id"], replay_id)
            self.assertEqual(replay["execution_model"], "fresh-process")
            self.assertTrue(replay["fresh_source_validation"])
            self.assertTrue(replay["fresh_core_render"])
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
        verdicts = json.loads(
            (self.fixture.output / "four_verdicts_v1.json").read_text(encoding="utf-8")
        )
        self.assertEqual(verdicts["merge"], {"value": "BLOCKED", "reason_ids": ["PROVIDER-003"]})
        build_receipt = json.loads(
            (self.fixture.output / "receipts/build_receipt.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(build_receipt["validated_replay_ids"], ["A", "B"])
        self.assertEqual(
            {
                key.removeprefix("cohort_handoff:")
                for key in build_receipt["input_sha256"]
                if key.startswith("cohort_handoff:")
            },
            set(validator_module.COHORT_HANDOFF_KEYS),
        )
        for key, archived in validator_module.COHORT_HANDOFF_ARCHIVE_PATHS.items():
            source = self.fixture.handoff_root / self.fixture.cohort_handoff_names[key]
            self.assertEqual(
                (self.fixture.output / archived).read_bytes(),
                source.read_bytes(),
            )

    def test_independent_publications_have_the_same_byte_index(self) -> None:
        first = self.fixture.root / "package-a"
        second = self.fixture.root / "package-b"
        self.build(output=first)
        self.build(output=second)
        self.assertEqual(tree_index(first), tree_index(second))

    def test_replay_b_validation_failure_prevents_publication(self) -> None:
        original_validator = builder_module._run_package_validator

        def sabotaged_validator(
            replay_id: str,
            package: Path,
            **kwargs: object,
        ) -> dict[str, object]:
            if replay_id == "B":
                (package / "SABOTAGE.txt").write_text(
                    "unmanifested replay mutation\n",
                    encoding="utf-8",
                )
            return original_validator(replay_id, package, **kwargs)

        with mock.patch.object(
            builder_module,
            "_run_package_validator",
            side_effect=sabotaged_validator,
        ):
            with self.assertRaisesRegex(
                ContractError,
                "replay B package validation",
            ):
                self.build()
        self.assertFalse(self.fixture.output.exists())
        self.assertEqual(
            list(self.fixture.output.parent.glob(".postfix-replay-*")),
            [],
        )

    def test_atomic_publish_refuses_destination_created_after_validation(
        self,
    ) -> None:
        original_publish = builder_module._atomic_publish_directory_no_replace

        def raced_publish(
            parent_fd: int,
            source_name: str,
            destination_name: str,
        ) -> None:
            self.fixture.output.mkdir()
            (self.fixture.output / "OWNER.txt").write_text(
                "pre-existing concurrent owner\n",
                encoding="utf-8",
            )
            original_publish(parent_fd, source_name, destination_name)

        with mock.patch.object(
            builder_module,
            "_atomic_publish_directory_no_replace",
            side_effect=raced_publish,
        ):
            with self.assertRaisesRegex(
                ContractError,
                "destination appeared",
            ):
                self.build()
        self.assertEqual(
            (self.fixture.output / "OWNER.txt").read_text(encoding="utf-8"),
            "pre-existing concurrent owner\n",
        )
        self.assertEqual(
            list(self.fixture.output.parent.glob(".postfix-replay-*")),
            [],
        )

    def test_output_parent_swap_cannot_redirect_publication_into_candidate(
        self,
    ) -> None:
        publish_parent = self.fixture.root / "stable-publish-parent"
        publish_parent.mkdir()
        moved_parent = self.fixture.root / "moved-publish-parent"
        output = publish_parent / "package"
        baseline_before = tree_index(self.fixture.baseline)
        original_publish = builder_module._atomic_publish_directory_no_replace

        def swapped_parent_publish(
            parent_fd: int,
            source_name: str,
            destination_name: str,
        ) -> None:
            publish_parent.rename(moved_parent)
            publish_parent.symlink_to(
                self.fixture.repo,
                target_is_directory=True,
            )
            original_publish(parent_fd, source_name, destination_name)

        with mock.patch.object(
            builder_module,
            "_atomic_publish_directory_no_replace",
            side_effect=swapped_parent_publish,
        ):
            with self.assertRaisesRegex(
                ContractError,
                "parent identity changed",
            ):
                self.build(output=output)
        self.assertFalse((self.fixture.repo / "package").exists())
        self.assertFalse((moved_parent / "package").exists())
        self.assertEqual(
            list(moved_parent.glob(".postfix-replay-*")),
            [],
        )
        self.assertEqual(tree_index(self.fixture.baseline), baseline_before)

    def test_candidate_mutation_after_atomic_rename_removes_the_package(
        self,
    ) -> None:
        original_publish = builder_module._atomic_publish_directory_no_replace

        def publish_then_mutate(
            parent_fd: int,
            source_name: str,
            destination_name: str,
        ) -> None:
            original_publish(parent_fd, source_name, destination_name)
            (self.fixture.repo / "tracked.txt").write_text(
                "late hostile mutation\n",
                encoding="utf-8",
            )

        with mock.patch.object(
            builder_module,
            "_atomic_publish_directory_no_replace",
            side_effect=publish_then_mutate,
        ):
            with self.assertRaisesRegex(
                ContractError,
                "worktree changed during package build",
            ):
                self.build()
        self.assertFalse(self.fixture.output.exists())
        self.assertEqual(
            list(self.fixture.output.parent.glob(".postfix-replay-*")),
            [],
        )

    def test_worker_stdout_overflow_cleans_via_stable_parent_fd(self) -> None:
        publish_parent = self.fixture.root / "overflow-parent"
        publish_parent.mkdir()
        moved_parent = self.fixture.root / "overflow-parent-moved"
        output = publish_parent / "package"

        def overflowing_worker(*args: object, **kwargs: object) -> dict[str, object]:
            publish_parent.rename(moved_parent)
            publish_parent.symlink_to(
                self.fixture.repo,
                target_is_directory=True,
            )
            common_module.run_process_bounded(
                [
                    sys.executable,
                    "-c",
                    "import os\nwhile True: os.write(1, b'x'*65536)\n",
                ],
                label="hostile replay overflow",
                cwd=self.fixture.root,
                env={"PATH": os.defpath},
                timeout=10,
                max_stdout_bytes=64 * 1024,
                max_stderr_bytes=64 * 1024,
                max_total_output_bytes=96 * 1024,
                max_stdin_bytes=1024,
            )
            raise AssertionError("overflowing worker unexpectedly returned")

        with mock.patch.object(
            builder_module,
            "_run_replay_worker",
            side_effect=overflowing_worker,
        ):
            with self.assertRaisesRegex(
                ContractError,
                "subprocess output byte budget exceeded",
            ):
                self.build(output=output)
        self.assertFalse((self.fixture.repo / "package").exists())
        self.assertFalse((moved_parent / "package").exists())
        self.assertEqual(list(moved_parent.glob(".postfix-replay-*")), [])

    def test_worker_timeout_removes_every_temporary_directory(self) -> None:
        def timing_out_worker(*args: object, **kwargs: object) -> dict[str, object]:
            common_module.run_process_bounded(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                label="hostile replay timeout",
                cwd=self.fixture.root,
                env={"PATH": os.defpath},
                timeout=0.1,
                max_stdout_bytes=64 * 1024,
                max_stderr_bytes=64 * 1024,
                max_total_output_bytes=96 * 1024,
                max_stdin_bytes=1024,
            )
            raise AssertionError("timing-out worker unexpectedly returned")

        with mock.patch.object(
            builder_module,
            "_run_replay_worker",
            side_effect=timing_out_worker,
        ):
            with self.assertRaisesRegex(ContractError, "subprocess timed out"):
                self.build()
        self.assertFalse(self.fixture.output.exists())
        self.assertEqual(
            list(self.fixture.output.parent.glob(".postfix-replay-*")),
            [],
        )

    def test_cleanup_unlinks_a_replay_symlink_without_following_it(self) -> None:
        candidate_before = tree_index(self.fixture.repo)

        def symlink_worker(
            replay_id: str,
            destination: Path,
            **kwargs: object,
        ) -> dict[str, object]:
            shutil.rmtree(destination)
            destination.symlink_to(
                self.fixture.repo,
                target_is_directory=True,
            )
            raise ContractError("hostile replay symlink")

        with mock.patch.object(
            builder_module,
            "_run_replay_worker",
            side_effect=symlink_worker,
        ):
            with self.assertRaisesRegex(ContractError, "hostile replay symlink"):
                self.build()
        self.assertFalse(self.fixture.output.exists())
        self.assertEqual(
            list(self.fixture.output.parent.glob(".postfix-replay-*")),
            [],
        )
        self.assertEqual(tree_index(self.fixture.repo), candidate_before)

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

    def test_pre_fix_receipt_requires_exactly_77_unique_groups(self) -> None:
        receipt = self.fixture.load_json("inputs/pre-fix-negative.json")
        receipt["executions"][-1]["group_id"] = "FG-001"
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

    def test_pre_fix_definition_registry_is_a_required_handoff_root(self) -> None:
        manifest = self.fixture.load_json("handoff.json")
        del manifest["files"]["pre_fix_test_definition_registry"]
        self.fixture._write_json(self.fixture.handoff, manifest)
        with self.assertRaisesRegex(ContractError, "handoff"):
            self.build()

    def test_pre_fix_definition_registry_bytes_must_equal_final_head(self) -> None:
        rows = self.fixture.load_jsonl(
            self.fixture.pre_fix_definition_input_name
        )
        rows[0]["test_case_id"] = "PRE-FIX-TAMPERED"
        self.fixture.write_jsonl(
            self.fixture.pre_fix_definition_input_name,
            rows,
        )
        self.fixture.refresh_handoff_hash(
            "pre_fix_test_definition_registry"
        )
        with self.assertRaisesRegex(ContractError, "differ from final HEAD"):
            self.build()

    def test_pre_fix_receipt_cannot_fall_back_to_script_at_commit(self) -> None:
        receipt = self.fixture.load_json("inputs/pre-fix-negative.json")
        execution = receipt["executions"][0]
        execution["script_at_commit"] = {
            "path": "Makefile",
            "mode": "100644",
            "sha256": "0" * 64,
        }
        self.fixture.write_json("inputs/pre-fix-negative.json", receipt)
        self.fixture.refresh_handoff_hash("pre_fix_negative_receipt")
        with self.assertRaisesRegex(ContractError, "pre-fix execution|keys"):
            self.build()

    def test_pre_fix_consumer_anchors_must_equal_the_final_registry(self) -> None:
        receipt = self.fixture.load_json("inputs/pre-fix-negative.json")
        execution = receipt["executions"][0]
        execution["consumer_anchors_at_baseline"] = [
            self.fixture._git_blob_descriptor(
                self.fixture.baseline_commit,
                "docs.md",
                kind="consumer",
            )
        ]
        self.fixture.write_json("inputs/pre-fix-negative.json", receipt)
        self.fixture.refresh_handoff_hash("pre_fix_negative_receipt")
        with self.assertRaisesRegex(ContractError, "differ from the final registry"):
            self.build()

    def test_pre_fix_registry_rejects_make_environment_injection(self) -> None:
        rows = copy.deepcopy(self.fixture.pre_fix_definition_rows)
        rows[0]["argv"].append("MAKEFLAGS=--eval")
        registry_path = self.fixture.repo / self.fixture.pre_fix_registry_repo_path
        self.fixture._write_jsonl(registry_path, rows)
        commit = self.fixture._git_commit("unsafe registry fixture")
        baseline = validator_module._validate_baseline(self.fixture.baseline)
        with self.assertRaisesRegex(ContractError, "unsafe Make variable"):
            validator_module._validate_pre_fix_definition_registry(
                rows,
                registry_path.read_bytes(),
                self.fixture._git_blob_descriptor(
                    commit,
                    self.fixture.pre_fix_registry_repo_path,
                ),
                baseline=baseline,
                group_ids={f"FG-{number:03d}" for number in range(1, 78)},
                repo=self.fixture.repo,
                final_commit=commit,
            )

    def test_pre_fix_registry_requires_unique_group_execution_identity(self) -> None:
        rows = copy.deepcopy(self.fixture.pre_fix_definition_rows)
        rows[1]["argv"] = copy.deepcopy(rows[0]["argv"])
        registry_path = self.fixture.repo / self.fixture.pre_fix_registry_repo_path
        self.fixture._write_jsonl(registry_path, rows)
        commit = self.fixture._git_commit("duplicate registry fixture")
        baseline = validator_module._validate_baseline(self.fixture.baseline)
        with self.assertRaisesRegex(ContractError, "one-to-one"):
            validator_module._validate_pre_fix_definition_registry(
                rows,
                registry_path.read_bytes(),
                self.fixture._git_blob_descriptor(
                    commit,
                    self.fixture.pre_fix_registry_repo_path,
                ),
                baseline=baseline,
                group_ids={f"FG-{number:03d}" for number in range(1, 78)},
                repo=self.fixture.repo,
                final_commit=commit,
            )

    def test_baseline_has_no_makefile_but_final_definitions_are_git_bound(
        self,
    ) -> None:
        baseline_paths = run_git(
            self.fixture.repo,
            "ls-tree",
            "-r",
            "--name-only",
            self.fixture.baseline_commit,
        ).splitlines()
        self.assertEqual(
            [path for path in baseline_paths if Path(path).name == "Makefile"],
            [],
        )
        self.assertTrue(
            run_git(
                self.fixture.repo,
                "ls-tree",
                self.fixture.final_commit,
                "--",
                self.fixture.pre_fix_registry_repo_path,
            )
        )

    def test_every_baseline_local_blocker_requires_an_explicit_closure_row(self) -> None:
        rows = self.fixture.load_jsonl("inputs/local-closures.jsonl")
        rows = [row for row in rows if row["id"] != "DOC-EVD-001"]
        self.fixture.write_jsonl("inputs/local-closures.jsonl", rows)
        self.fixture.refresh_handoff_hash("local_condition_closure")
        with self.assertRaisesRegex(ContractError, "required proof rows missing"):
            self.build()

    def test_external_owner_and_drill_conditions_cannot_be_claimed_closed_local(self) -> None:
        rows = self.fixture.load_jsonl("inputs/local-closures.jsonl")
        target = next(row for row in rows if row["id"] == "DOC-EVD-001")
        target["status"] = "CLOSED-LOCAL"
        self.fixture.write_jsonl("inputs/local-closures.jsonl", rows)
        self.fixture.refresh_handoff_hash("local_condition_closure")
        with self.assertRaisesRegex(ContractError, "invalid identity or status|falsely closed"):
            self.build()

    def test_local_support_requires_exact_go_blocking_external_residual(self) -> None:
        rows = self.fixture.load_jsonl("inputs/provider-live-residuals.jsonl")
        target = next(row for row in rows if row["id"] == "GOV-DOC-EVD-002")
        target["required_evidence"] = ["self-authored local assertion"]
        self.fixture.write_jsonl("inputs/provider-live-residuals.jsonl", rows)
        self.fixture.refresh_handoff_hash("provider_live_residuals")
        with self.assertRaisesRegex(ContractError, "exact GO-blocking external condition mapping"):
            self.build()

    def test_cohort_only_final_commit_mapping_is_rejected(self) -> None:
        rows = self.fixture.load_jsonl("inputs/fix-groups.jsonl")
        for row in rows:
            row["final_commit"] = row["cohort_commit"]
            row["support_commit_mappings"][0]["final_commit"] = row["cohort_commit"]
        self.fixture.write_jsonl("inputs/fix-groups.jsonl", rows)
        self.fixture.refresh_handoff_hash("fix_group_ledger")
        with self.assertRaisesRegex(ContractError, "cohort-only"):
            self.build()

    def test_reachable_but_non_equivalent_final_mapping_is_rejected(self) -> None:
        rows = self.fixture.load_jsonl("inputs/fix-groups.jsonl")
        for row in rows:
            row["final_commit"] = self.fixture.unrelated_commit
            row["boundary_paths"] = ["integration-note.txt", "support.txt"]
            row["consumer_evidence"] = ["integration-note.txt:1"]
            row["support_commit_mappings"][0]["final_commit"] = self.fixture.unrelated_commit
            row["support_commit_mappings"][0]["boundary_paths"] = ["integration-note.txt"]
        self.fixture.write_jsonl("inputs/fix-groups.jsonl", rows)
        self.fixture.refresh_handoff_hash("fix_group_ledger")
        with self.assertRaisesRegex(ContractError, "exact tree delta|path/mode/content"):
            self.build()

    def test_direct_final_cannot_point_all_groups_at_the_authoritative_baseline(self) -> None:
        rows = self.fixture.load_jsonl("inputs/fix-groups.jsonl")
        for row in rows:
            row["integration_mode"] = "direct-final"
            row["cohort_commit"] = self.fixture.baseline_commit
            row["final_commit"] = self.fixture.baseline_commit
        self.fixture.write_jsonl("inputs/fix-groups.jsonl", rows)
        self.fixture.refresh_handoff_hash("fix_group_ledger")
        with self.assertRaisesRegex(ContractError, "post-baseline|boundary diff"):
            self.build()

    def test_patch_id_cannot_equate_semantically_different_yaml_content(self) -> None:
        cohort_patch = run_git(
            self.fixture.repo,
            "show",
            "--pretty=format:",
            self.fixture.cohort_semantic_commit,
        ).encode("utf-8")
        final_patch = run_git(
            self.fixture.repo,
            "show",
            "--pretty=format:",
            self.fixture.final_semantic_commit,
        ).encode("utf-8")
        cohort_patch_id = subprocess.run(
            ["git", "patch-id", "--stable"], input=cohort_patch, stdout=subprocess.PIPE, check=True
        ).stdout.split()[0]
        final_patch_id = subprocess.run(
            ["git", "patch-id", "--stable"], input=final_patch, stdout=subprocess.PIPE, check=True
        ).stdout.split()[0]
        self.assertEqual(cohort_patch_id, final_patch_id)
        rows = self.fixture.load_jsonl("inputs/fix-groups.jsonl")
        rows[0]["cohort_commit"] = self.fixture.cohort_semantic_commit
        rows[0]["final_commit"] = self.fixture.final_semantic_commit
        rows[0]["boundary_paths"] = ["semantic.yml", "support.txt"]
        rows[0]["consumer_evidence"] = ["semantic.yml:1"]
        rows[0]["support_commits"][0] = self.fixture.cohort_semantic_commit
        rows[0]["support_commit_mappings"][0] = {
            "cohort_commit": self.fixture.cohort_semantic_commit,
            "final_commit": self.fixture.final_semantic_commit,
            "integration_mode": "cherry-pick",
            "boundary_paths": ["semantic.yml"],
        }
        self.fixture.write_jsonl("inputs/fix-groups.jsonl", rows)
        self.fixture.refresh_handoff_hash("fix_group_ledger")
        raw_rows = self.fixture.load_cohort_handoff("hosted")
        raw_rows[0]["cohort_commit"] = self.fixture.cohort_semantic_commit
        self.fixture.write_cohort_handoff("hosted", raw_rows)
        with self.assertRaisesRegex(ContractError, "exact tree delta|path/mode/content"):
            self.build()

    def test_explicit_direct_final_identity_is_accepted(self) -> None:
        rows = self.fixture.load_jsonl("inputs/fix-groups.jsonl")
        rows[0]["integration_mode"] = "direct-final"
        rows[0]["cohort_commit"] = self.fixture.final_commit
        rows[0]["final_commit"] = self.fixture.final_commit
        rows[0]["support_commits"][0] = self.fixture.final_commit
        rows[0]["support_commit_mappings"][0] = {
            "cohort_commit": self.fixture.final_commit,
            "final_commit": self.fixture.final_commit,
            "integration_mode": "direct-final",
            "boundary_paths": ["tracked.txt"],
        }
        self.fixture.write_jsonl("inputs/fix-groups.jsonl", rows)
        self.fixture.refresh_handoff_hash("fix_group_ledger")
        raw_rows = self.fixture.load_cohort_handoff("hosted")
        raw_rows[0]["cohort_commit"] = self.fixture.final_commit
        self.fixture.write_cohort_handoff("hosted", raw_rows)
        self.assertTrue(self.build()["ok"])

    def test_declared_support_commit_cannot_be_omitted_from_mappings(self) -> None:
        rows = self.fixture.load_jsonl("inputs/fix-groups.jsonl")
        rows[0]["support_commit_mappings"].pop()
        self.fixture.write_jsonl("inputs/fix-groups.jsonl", rows)
        self.fixture.refresh_handoff_hash("fix_group_ledger")
        with self.assertRaisesRegex(ContractError, "support commit references are not exactly mapped"):
            self.build()

    def test_stale_support_commit_mapping_is_rejected(self) -> None:
        rows = self.fixture.load_jsonl("inputs/fix-groups.jsonl")
        rows[0]["boundary_paths"] = ["tracked.txt", "integration-note.txt"]
        rows[0]["support_commit_mappings"][1]["final_commit"] = self.fixture.unrelated_commit
        rows[0]["support_commit_mappings"][1]["boundary_paths"] = ["integration-note.txt"]
        self.fixture.write_jsonl("inputs/fix-groups.jsonl", rows)
        self.fixture.refresh_handoff_hash("fix_group_ledger")
        with self.assertRaisesRegex(ContractError, "exact tree delta|path/mode/content"):
            self.build()

    def test_manifest_requires_all_six_raw_cohort_handoff_trust_roots(self) -> None:
        manifest = self.fixture.load_json("handoff.json")
        del manifest["cohort_handoffs"]["release"]
        self.fixture._write_json(self.fixture.handoff, manifest)
        with self.assertRaisesRegex(ContractError, "raw cohort handoffs|release"):
            self.build()

    def test_raw_cohort_handoff_stale_hash_is_rejected(self) -> None:
        rows = self.fixture.load_cohort_handoff("hosted")
        rows[0]["source"] = "changed after manifest hashing"
        self.fixture.write_jsonl(self.fixture.cohort_handoff_names["hosted"], rows)
        with self.assertRaisesRegex(ContractError, "raw cohort handoff hosted: stale SHA-256"):
            self.build()

    def test_raw_cohort_authoritative_slug_and_can_projection_are_exact(self) -> None:
        rows = self.fixture.load_cohort_handoff("hosted")
        rows[0]["slug"] = "invented-slug"
        self.fixture.write_cohort_handoff("hosted", rows)
        with self.assertRaisesRegex(ContractError, "authoritative slug"):
            self.build()

        self.tearDown()
        self.setUp()
        rows = self.fixture.load_cohort_handoff("hosted")
        rows[0]["canonical_ids"] = list(reversed(rows[0]["canonical_ids"]))
        self.fixture.write_cohort_handoff("hosted", rows)
        with self.assertRaisesRegex(ContractError, "canonical ID projection"):
            self.build()

    def test_raw_cohort_exact_group_coverage_rejects_omission_and_duplication(self) -> None:
        rows = self.fixture.load_cohort_handoff("hosted")
        omitted = rows.pop()
        self.fixture.write_cohort_handoff("hosted", rows)
        with self.assertRaisesRegex(ContractError, "exact 77-group coverage"):
            self.build()

        self.tearDown()
        self.setUp()
        hosted = self.fixture.load_cohort_handoff("hosted")
        release = self.fixture.load_cohort_handoff("release")
        release.append(copy.deepcopy(hosted[0]))
        self.fixture.write_cohort_handoff("release", release)
        with self.assertRaisesRegex(ContractError, "duplicate fix group"):
            self.build()

    def test_raw_to_ledger_to_support_mapping_is_exact_in_both_directions(self) -> None:
        rows = self.fixture.load_cohort_handoff("hosted")
        rows[0]["support_commits"] = []
        self.fixture.write_cohort_handoff("hosted", rows)
        with self.assertRaisesRegex(ContractError, "raw handoff to ledger support SHA"):
            self.build()

        self.tearDown()
        self.setUp()
        ledger = self.fixture.load_jsonl("inputs/fix-groups.jsonl")
        ledger[0]["support_commits"].pop()
        self.fixture.write_jsonl("inputs/fix-groups.jsonl", ledger)
        self.fixture.refresh_handoff_hash("fix_group_ledger")
        with self.assertRaisesRegex(ContractError, "raw handoff to ledger support SHA"):
            self.build()

    def test_cross_cohort_dependency_is_attributed_to_the_owner_group(self) -> None:
        hosted = self.fixture.load_cohort_handoff("hosted")
        source = next(row for row in hosted if row["group_id"] == "FG-001")
        source["cross_cohort_dependencies"] = [
            {
                "group_id": "FG-010",
                "commit": self.fixture.cohort_support_commit,
                "reason": "release-owned support consumed by hosted admission",
            }
        ]
        self.fixture.write_cohort_handoff("hosted", hosted)
        release = self.fixture.load_cohort_handoff("release")
        owner = next(row for row in release if row["group_id"] == "FG-010")
        owner["support_commits"] = []
        self.fixture.write_cohort_handoff("release", release)
        validated = validator_module.validate_source_inputs(
            baseline=self.fixture.baseline,
            group_map=self.fixture.group_map,
            handoff=self.fixture.handoff,
            candidate_repo=self.fixture.repo,
            semantic_receipt_sha256=self.fixture.semantic_sha256(),
        )
        self.assertEqual(
            validated.cohort_expectations["FG-010"]["support_commits"],
            sorted(
                {
                    self.fixture.cohort_commit,
                    self.fixture.cohort_support_commit,
                }
            ),
        )

    def test_reconciled_mapping_with_complete_receipt_and_tests_is_accepted(self) -> None:
        self.configure_reconciled_group()
        validated = validator_module.validate_source_inputs(
            baseline=self.fixture.baseline,
            group_map=self.fixture.group_map,
            handoff=self.fixture.handoff,
            candidate_repo=self.fixture.repo,
            semantic_receipt_sha256=self.fixture.semantic_sha256(),
        )
        record = next(
            row for row in validated.equivalence_records if row["group_id"] == "FG-001"
        )
        self.assertEqual(record["integration_mode"], "reconciled")
        self.assertEqual(
            record["accepted_by"],
            "conflict-reconciliation-receipt-and-final-head-tests",
        )

    def test_reconciled_mapping_without_receipt_or_complete_tests_fails_closed(self) -> None:
        target = self.configure_reconciled_group()
        del target["support_commit_mappings"][0]["conflict_resolution_receipt"]
        rows = self.fixture.load_jsonl("inputs/fix-groups.jsonl")
        rows[0] = target
        self.fixture.write_jsonl("inputs/fix-groups.jsonl", rows)
        self.fixture.refresh_handoff_hash("fix_group_ledger")
        with self.assertRaisesRegex(ContractError, "conflict_resolution_receipt|wrong keys"):
            self.build()

        self.tearDown()
        self.setUp()
        target = self.configure_reconciled_group()
        target["support_commit_mappings"][0]["conflict_resolution_receipt"][
            "test_receipt_ids"
        ].remove("TEST-INDEPENDENT-QA")
        rows = self.fixture.load_jsonl("inputs/fix-groups.jsonl")
        rows[0] = target
        self.fixture.write_jsonl("inputs/fix-groups.jsonl", rows)
        self.fixture.refresh_handoff_hash("fix_group_ledger")
        with self.assertRaisesRegex(ContractError, "negative/positive/hostile/independent"):
            self.build()

    def test_reconciled_mapping_rejects_stale_hashes_and_nonconflicting_delta(self) -> None:
        target = self.configure_reconciled_group()
        target["support_commit_mappings"][0]["conflict_resolution_receipt"]["files"][0][
            "final"
        ]["sha256"] = "0" * 64
        rows = self.fixture.load_jsonl("inputs/fix-groups.jsonl")
        rows[0] = target
        self.fixture.write_jsonl("inputs/fix-groups.jsonl", rows)
        self.fixture.refresh_handoff_hash("fix_group_ledger")
        with self.assertRaisesRegex(ContractError, "before/cohort/final hashes"):
            self.build()

        self.tearDown()
        self.setUp()
        rows = self.fixture.load_jsonl("inputs/fix-groups.jsonl")
        target = rows[0]
        target["integration_mode"] = "reconciled"
        target["support_commit_mappings"][0]["integration_mode"] = "reconciled"
        target["support_commit_mappings"][0]["conflict_resolution_receipt"] = (
            self.fixture.conflict_resolution_receipt(
                self.fixture.cohort_commit,
                self.fixture.final_commit,
                ["tracked.txt"],
            )
        )
        self.fixture.write_jsonl("inputs/fix-groups.jsonl", rows)
        self.fixture.refresh_handoff_hash("fix_group_ledger")
        with self.assertRaisesRegex(ContractError, "only for a real conflicting delta"):
            self.build()

    def test_dirty_final_candidate_is_rejected(self) -> None:
        (self.fixture.repo / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaisesRegex(ContractError, "clean"):
            self.build()

    def test_source_validation_bounds_duplicate_immutable_git_queries(self) -> None:
        original_runner = common_module.run_process_bounded
        git_commands: list[tuple[str, ...]] = []

        def counted_runner(command: list[str], **kwargs: object) -> object:
            if Path(command[0]).name == "git":
                git_commands.append(tuple(command))
            return original_runner(command, **kwargs)

        with mock.patch.object(
            common_module,
            "run_process_bounded",
            side_effect=counted_runner,
        ):
            validated = validator_module.validate_source_inputs(
                baseline=self.fixture.baseline,
                group_map=self.fixture.group_map,
                handoff=self.fixture.handoff,
                candidate_repo=self.fixture.repo,
                semantic_receipt_sha256=self.fixture.semantic_sha256(),
            )
        self.assertEqual(validated.counts["fix_groups"], 77)
        self.assertLessEqual(
            len(git_commands),
            200,
            "one source validation repeated immutable Git object queries",
        )

    def test_git_query_cache_never_hides_worktree_drift(self) -> None:
        cache_scope = getattr(
            common_module,
            "with_immutable_git_query_cache",
            None,
        )
        self.assertIsNotNone(cache_scope, "scoped immutable Git cache is missing")

        @cache_scope
        def observe_status_transition() -> tuple[str, str]:
            before = common_module.git_text(
                self.fixture.repo,
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            )
            (self.fixture.repo / "cache-race.txt").write_text(
                "late drift\n",
                encoding="utf-8",
            )
            after = common_module.git_text(
                self.fixture.repo,
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            )
            return before, after

        before, after = observe_status_transition()
        self.assertEqual(before, "")
        self.assertIn("cache-race.txt", after)

    def test_executing_tool_checkout_must_equal_candidate_final_head(self) -> None:
        alternate_root = (
            self.fixture.root / "tool-checkout-b" / "scripts" / "postfix_evidence"
        )
        alternate_root.mkdir(parents=True)
        source_root = Path(validator_module.__file__).parent
        for name in validator_module.TOOL_SOURCE_NAMES:
            shutil.copy2(source_root / name, alternate_root / name)
        (alternate_root / "common.py").write_bytes(
            (alternate_root / "common.py").read_bytes()
            + b"\n# divergent tool checkout\n"
        )
        with mock.patch.object(
            validator_module,
            "_current_tool_source_root",
            return_value=alternate_root,
        ):
            with self.assertRaisesRegex(
                ContractError,
                "executing bytes differ from final HEAD",
            ):
                validator_module.validate_source_inputs(
                    baseline=self.fixture.baseline,
                    group_map=self.fixture.group_map,
                    handoff=self.fixture.handoff,
                    candidate_repo=self.fixture.repo,
                    semantic_receipt_sha256=self.fixture.semantic_sha256(),
                )

    def test_git_replace_ref_is_rejected_before_history_validation(self) -> None:
        run_git(
            self.fixture.repo,
            "replace",
            self.fixture.final_commit,
            self.fixture.unrelated_commit,
        )
        with self.assertRaisesRegex(ContractError, "replace refs"):
            self.build()

    def test_legacy_git_graft_is_rejected_before_history_validation(self) -> None:
        grafts = self.fixture.repo / ".git" / "info" / "grafts"
        grafts.parent.mkdir(parents=True, exist_ok=True)
        grafts.write_text(
            f"{self.fixture.final_commit} {self.fixture.baseline_commit}\n",
            encoding="ascii",
        )
        with self.assertRaisesRegex(ContractError, "grafts"):
            self.build()

    def test_git_subprocess_ignores_inherited_repository_and_config_overrides(
        self,
    ) -> None:
        poisoned = {
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/nonexistent/objects",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_VALUE_0": "/nonexistent/monitor",
            "GIT_CONFIG_GLOBAL": "/nonexistent/config",
            "GIT_CONFIG_SYSTEM": "/nonexistent/config",
            "GIT_DIR": "/nonexistent/git-dir",
            "GIT_EXEC_PATH": "/nonexistent/git-exec",
            "GIT_NO_REPLACE_OBJECTS": "0",
            "GIT_OBJECT_DIRECTORY": "/nonexistent/objects",
            "GIT_REPLACE_REF_BASE": "refs/poison",
            "GIT_WORK_TREE": "/nonexistent/worktree",
            "PATH": "/nonexistent/bin",
        }
        with mock.patch.dict(os.environ, poisoned, clear=False):
            self.assertEqual(
                common_module.git_head(self.fixture.repo),
                self.fixture.final_commit,
            )

    def test_local_fsmonitor_config_cannot_execute_during_validation(self) -> None:
        marker = self.fixture.root / "FS-MONITOR-RAN"
        monitor = self.fixture.root / "malicious-fsmonitor.sh"
        monitor.write_text(
            "#!/bin/sh\n"
            f": > {marker}\n"
            "printf '2\\n'\n",
            encoding="utf-8",
        )
        monitor.chmod(0o755)
        run_git(
            self.fixture.repo,
            "config",
            "core.fsmonitor",
            str(monitor),
        )
        validator_module.validate_source_inputs(
            baseline=self.fixture.baseline,
            group_map=self.fixture.group_map,
            handoff=self.fixture.handoff,
            candidate_repo=self.fixture.repo,
            semantic_receipt_sha256=self.fixture.semantic_sha256(),
        )
        self.assertFalse(marker.exists())

    def test_local_core_worktree_alias_cannot_change_candidate_root(self) -> None:
        alternate = self.fixture.root / "alternate-worktree"
        alternate.mkdir()
        run_git(
            self.fixture.repo,
            "config",
            "core.worktree",
            str(alternate),
        )
        self.assertEqual(
            Path(
                common_module.git_text(
                    self.fixture.repo,
                    "rev-parse",
                    "--show-toplevel",
                )
            ).resolve(strict=True),
            self.fixture.repo.resolve(strict=True),
        )
        validator_module.validate_source_inputs(
            baseline=self.fixture.baseline,
            group_map=self.fixture.group_map,
            handoff=self.fixture.handoff,
            candidate_repo=self.fixture.repo,
            semantic_receipt_sha256=self.fixture.semantic_sha256(),
        )

    def test_git_info_exclude_cannot_hide_an_untracked_candidate_file(self) -> None:
        exclude = self.fixture.repo / ".git" / "info" / "exclude"
        with exclude.open("a", encoding="utf-8") as handle:
            handle.write("\nhidden-runtime.env\n")
        (self.fixture.repo / "hidden-runtime.env").write_text(
            "runtime-only\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ContractError, "info/exclude patterns"):
            self.build()

    def test_assume_unchanged_cannot_hide_a_tracked_mutation(self) -> None:
        run_git(
            self.fixture.repo,
            "update-index",
            "--assume-unchanged",
            "tracked.txt",
        )
        (self.fixture.repo / "tracked.txt").write_text(
            "hidden mutation\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ContractError, "index flags"):
            self.build()

    def test_skip_worktree_cannot_hide_a_tracked_mutation(self) -> None:
        run_git(
            self.fixture.repo,
            "update-index",
            "--skip-worktree",
            "tracked.txt",
        )
        (self.fixture.repo / "tracked.txt").write_text(
            "hidden mutation\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ContractError, "index flags"):
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
        with self.assertRaisesRegex(ContractError, "derived|go_to_deploy"):
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

    def test_residual_classification_coverage_is_an_exact_non_overlapping_partition(self) -> None:
        residuals = self.fixture.load_jsonl("inputs/provider-live-residuals.jsonl")
        duplicate = copy.deepcopy(residuals[0])
        duplicate["id"] = "DUPLICATE-LIVE-COVERAGE"
        residuals.append(duplicate)
        self.fixture.write_jsonl("inputs/provider-live-residuals.jsonl", residuals)
        self.fixture.refresh_handoff_hash("provider_live_residuals")
        with self.assertRaisesRegex(ContractError, "duplicate classification coverage"):
            self.build()

    def test_pass_log_cannot_substitute_for_a_script_present_at_final_commit(self) -> None:
        rows = self.fixture.load_jsonl("inputs/test-receipts.jsonl")
        rows[0]["argv"] = ["python3", "missing-fixture.py", rows[0]["phase"]]
        rows[0]["script_at_commit"]["path"] = "missing-fixture.py"
        self.fixture.write_jsonl("inputs/test-receipts.jsonl", rows)
        self.fixture.refresh_handoff_hash("test_receipt_registry")
        with self.assertRaisesRegex(ContractError, "script-at-commit|script at final commit"):
            self.build()

    def test_receipt_log_must_bind_head_tree_phase_result_and_semantic_anchor(self) -> None:
        rows = self.fixture.load_jsonl("inputs/test-receipts.jsonl")
        target = rows[0]
        log_path = self.fixture.handoff_root / target["log"]["path"]
        log_path.write_text("PASS\n", encoding="utf-8")
        target["log"]["sha256"] = sha256(log_path)
        self.fixture.write_jsonl("inputs/test-receipts.jsonl", rows)
        self.fixture.refresh_handoff_hash("test_receipt_registry")
        with self.assertRaisesRegex(ContractError, "log lacks execution identity|semantic anchor"):
            self.build()

    def test_receipt_sandbox_and_executable_are_current_trust_roots(self) -> None:
        rows = self.fixture.load_jsonl("inputs/test-receipts.jsonl")
        rows[0]["sandbox"]["network"] = True
        rows[0]["executable"]["sha256"] = "0" * 64
        self.fixture.write_jsonl("inputs/test-receipts.jsonl", rows)
        self.fixture.refresh_handoff_hash("test_receipt_registry")
        with self.assertRaisesRegex(ContractError, "executable|sandbox"):
            self.build()

    def test_documentation_validation_receipt_anchors_every_document_blob(self) -> None:
        rows = self.fixture.load_jsonl("inputs/test-receipts.jsonl")
        target = next(row for row in rows if row["phase"] == "documentation-validation")
        target["artifact_anchors"] = [
            anchor for anchor in target["artifact_anchors"] if anchor["kind"] != "documentation"
        ]
        self.fixture.write_jsonl("inputs/test-receipts.jsonl", rows)
        self.fixture.refresh_handoff_hash("test_receipt_registry")
        with self.assertRaisesRegex(
            ContractError,
            "local support is not anchored|documentation blobs",
        ):
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

    def test_open_fd_snapshot_defeats_lstat_read_restore_path_swap(self) -> None:
        target = self.fixture.root / "swap-target.txt"
        target.write_bytes(b"ORIGINAL")
        original_reader = Path.read_bytes

        def hostile_reader(path: Path) -> bytes:
            if path != target:
                return original_reader(path)
            backup = target.with_suffix(".saved")
            target.rename(backup)
            target.write_bytes(b"HOSTILE!")
            try:
                return original_reader(target)
            finally:
                target.unlink()
                backup.rename(target)

        with mock.patch.object(Path, "read_bytes", hostile_reader):
            payload = common_module.read_regular_bytes(
                target,
                label="swap PoC",
                max_bytes=1024,
            )
        self.assertEqual(payload, b"ORIGINAL")

    def test_bounded_reader_rejects_a_huge_sparse_file_before_allocation(
        self,
    ) -> None:
        sparse = self.fixture.root / "huge-sparse-input"
        with sparse.open("wb") as handle:
            handle.truncate(8 * 1024 * 1024 * 1024)
        with self.assertRaisesRegex(ContractError, "byte limit"):
            common_module.read_regular_bytes(
                sparse,
                label="sparse hostile input",
                max_bytes=1024,
            )

    def test_cumulative_reader_budget_rejects_before_the_second_read(
        self,
    ) -> None:
        first = self.fixture.root / "budget-a"
        second = self.fixture.root / "budget-b"
        first.write_bytes(b"a" * 6)
        second.write_bytes(b"b" * 6)
        budget = common_module.ByteBudget("aggregate input", 10)
        self.assertEqual(
            common_module.read_regular_bytes(
                first,
                label="first aggregate input",
                max_bytes=8,
                budget=budget,
            ),
            b"a" * 6,
        )
        with self.assertRaisesRegex(ContractError, "cumulative byte budget"):
            common_module.read_regular_bytes(
                second,
                label="second aggregate input",
                max_bytes=8,
                budget=budget,
            )

    def test_bounded_process_kills_the_group_on_stdout_flood(self) -> None:
        secret_marker = "DO-NOT-REFLECT-THIS-FLOOD"
        parent_process_group = os.getpgrp()
        original_killer = common_module._kill_process_group
        killed_pids: list[int] = []

        def guarded_killer(
            process: subprocess.Popen[bytes],
            isolated_pgid: int,
        ) -> None:
            self.assertNotEqual(process.pid, os.getpid())
            self.assertNotEqual(process.pid, parent_process_group)
            self.assertEqual(isolated_pgid, process.pid)
            killed_pids.append(process.pid)
            try:
                child_process_group = os.getpgid(process.pid)
            except ProcessLookupError:
                child_process_group = process.pid
            self.assertEqual(child_process_group, process.pid)
            original_killer(process, isolated_pgid)

        with mock.patch.object(
            common_module,
            "_kill_process_group",
            side_effect=guarded_killer,
        ) as killer:
            with self.assertRaisesRegex(
                ContractError,
                "subprocess output byte budget exceeded",
            ) as raised:
                common_module.run_process_bounded(
                    [
                        sys.executable,
                        "-c",
                        (
                            "import os\n"
                            f"chunk={secret_marker!r}.encode()*8192\n"
                            "while True: os.write(1, chunk)\n"
                        ),
                    ],
                    label="stdout flood",
                    cwd=self.fixture.root,
                    env={"PATH": os.defpath},
                    timeout=10,
                    max_stdout_bytes=64 * 1024,
                    max_stderr_bytes=64 * 1024,
                    max_total_output_bytes=96 * 1024,
                    max_stdin_bytes=1024,
                )
        self.assertGreaterEqual(killer.call_count, 1)
        self.assertNotIn(secret_marker, str(raised.exception))
        for child_pid in killed_pids:
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)

    def test_bounded_process_uses_a_session_outside_the_parent_group(self) -> None:
        completed = common_module.run_process_bounded(
            [
                sys.executable,
                "-c",
                "import os; print(os.getpgrp())",
            ],
            label="process-group identity",
            cwd=self.fixture.root,
            env={"PATH": os.defpath},
            timeout=10,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
            max_total_output_bytes=2048,
            max_stdin_bytes=1024,
        )
        self.assertEqual(completed.returncode, 0)
        child_process_group = int(completed.stdout.decode("ascii").strip())
        self.assertNotEqual(child_process_group, os.getpgrp())

    def test_bounded_process_kills_a_descendant_after_leader_exit(self) -> None:
        marker = self.fixture.root / "DESCENDANT-SURVIVED"
        descendant = (
            "import time\n"
            "from pathlib import Path\n"
            "time.sleep(0.75)\n"
            f"Path({str(marker)!r}).write_text('survived')\n"
        )
        leader = (
            "import subprocess, sys\n"
            "child=subprocess.Popen("
            f"[sys.executable, '-c', {descendant!r}], "
            "stdin=subprocess.DEVNULL, "
            "stdout=subprocess.DEVNULL, "
            "stderr=subprocess.DEVNULL)\n"
            "print(child.pid, flush=True)\n"
        )
        completed = common_module.run_process_bounded(
            [sys.executable, "-c", leader],
            label="descendant containment",
            cwd=self.fixture.root,
            env={"PATH": os.defpath},
            timeout=10,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
            max_total_output_bytes=2048,
            max_stdin_bytes=1024,
        )
        self.assertEqual(completed.returncode, 0)
        descendant_pid = int(completed.stdout.decode("ascii").strip())
        deadline = time.monotonic() + 1.5
        descendant_alive = True
        while time.monotonic() < deadline and not marker.exists():
            try:
                os.kill(descendant_pid, 0)
            except ProcessLookupError:
                descendant_alive = False
                break
            time.sleep(0.05)
        self.assertFalse(marker.exists())
        self.assertFalse(descendant_alive)

    def test_bounded_process_timeout_kills_the_isolated_group(self) -> None:
        with mock.patch.object(
            common_module,
            "_kill_process_group",
            wraps=common_module._kill_process_group,
        ) as killer:
            with self.assertRaisesRegex(ContractError, "subprocess timed out"):
                common_module.run_process_bounded(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    label="timeout probe",
                    cwd=self.fixture.root,
                    env={"PATH": os.defpath},
                    timeout=0.1,
                    max_stdout_bytes=1024,
                    max_stderr_bytes=1024,
                    max_total_output_bytes=2048,
                    max_stdin_bytes=1024,
                )
        self.assertGreaterEqual(killer.call_count, 1)
        timed_out_process = killer.call_args_list[0].args[0]
        with self.assertRaises(ProcessLookupError):
            os.kill(timed_out_process.pid, 0)

    def test_process_group_termination_does_not_silence_eperm(self) -> None:
        original_killpg = os.killpg
        denied = False

        def deny_once(process_group: int, signal_number: int) -> None:
            nonlocal denied
            if not denied:
                denied = True
                raise PermissionError(errno.EPERM, "denied")
            original_killpg(process_group, signal_number)

        with mock.patch.object(
            os,
            "killpg",
            side_effect=deny_once,
        ):
            with self.assertRaisesRegex(
                ContractError,
                "could not be terminated",
            ):
                common_module.run_process_bounded(
                    [sys.executable, "-c", "pass"],
                    label="termination denial",
                    cwd=self.fixture.root,
                    env={"PATH": os.defpath},
                    timeout=10,
                    max_stdout_bytes=1024,
                    max_stderr_bytes=1024,
                    max_total_output_bytes=2048,
                    max_stdin_bytes=1024,
                )

    def test_bounded_process_rejects_cumulative_stdout_stderr_flood(self) -> None:
        with self.assertRaisesRegex(
            ContractError,
            "subprocess output byte budget exceeded",
        ):
            common_module.run_process_bounded(
                [
                    sys.executable,
                    "-c",
                    (
                        "import os\n"
                        "for _ in range(4096):\n"
                        " os.write(1, b'a'*1024)\n"
                        " os.write(2, b'b'*1024)\n"
                    ),
                ],
                label="combined flood",
                cwd=self.fixture.root,
                env={"PATH": os.defpath},
                timeout=10,
                max_stdout_bytes=128 * 1024,
                max_stderr_bytes=128 * 1024,
                max_total_output_bytes=96 * 1024,
                max_stdin_bytes=1024,
            )

    def test_git_blob_size_gate_rejects_a_sparse_blob_before_read(self) -> None:
        sparse = self.fixture.root / "oversized-git-blob"
        with sparse.open("wb") as handle:
            handle.truncate(validator_module.TOOL_SOURCE_MAX_BYTES + 1)
        object_id = run_git(
            self.fixture.repo,
            "hash-object",
            "-w",
            str(sparse),
        )
        with mock.patch.object(
            common_module,
            "git",
            wraps=common_module.git,
        ) as git_reader:
            with self.assertRaisesRegex(ContractError, "Git blob exceeds"):
                common_module.git_blob(
                    self.fixture.repo,
                    object_id,
                    label="sparse hostile Git blob",
                    max_bytes=validator_module.TOOL_SOURCE_MAX_BYTES,
                )
        blob_reads = [
            call
            for call in git_reader.call_args_list
            if len(call.args) >= 3
            and call.args[1:3] == ("cat-file", "blob")
        ]
        self.assertEqual(blob_reads, [])

    def test_worker_environment_does_not_inherit_tmpdir(self) -> None:
        hostile_tmp = self.fixture.repo / "hostile-tmp"
        with mock.patch.dict(
            os.environ,
            {"TMPDIR": str(hostile_tmp)},
            clear=False,
        ):
            environment = builder_module._subprocess_environment()
        self.assertNotIn("TMPDIR", environment)

    def test_manifest_snapshot_enforces_a_cumulative_payload_budget(self) -> None:
        root = self.fixture.root / "bounded-manifest"
        root.mkdir()
        first = root / "a.bin"
        second = root / "b.bin"
        first.write_bytes(b"a" * 6)
        second.write_bytes(b"b" * 6)
        manifest = (
            f"{sha256(first)}  a.bin\n"
            f"{sha256(second)}  b.bin\n"
        ).encode("ascii")
        (root / "MANIFEST.sha256").write_bytes(manifest)
        with self.assertRaisesRegex(ContractError, "cumulative byte budget"):
            common_module.validate_manifest_snapshot(
                root,
                exact=True,
                max_manifest_bytes=1024,
                max_file_bytes=8,
                max_total_bytes=len(manifest) + 10,
                capture_all=True,
            )

    def test_tree_index_enforces_a_bounded_entry_count(self) -> None:
        root = self.fixture.root / "bounded-tree"
        root.mkdir()
        for index in range(4):
            (root / f"{index}.txt").write_text("x", encoding="ascii")
        with self.assertRaisesRegex(ContractError, "tree entry limit"):
            tree_index(root, max_entries=3)

    def test_manifest_snapshot_enforces_a_bounded_entry_count(self) -> None:
        root = self.fixture.root / "bounded-manifest-entries"
        root.mkdir()
        for name in ("a.bin", "b.bin"):
            (root / name).write_bytes(name.encode("ascii"))
        manifest = "".join(
            f"{sha256(root / name)}  {name}\n"
            for name in ("a.bin", "b.bin")
        )
        (root / "MANIFEST.sha256").write_text(manifest, encoding="ascii")
        with self.assertRaisesRegex(ContractError, "manifest: entry limit"):
            common_module.validate_manifest_snapshot(
                root,
                exact=True,
                max_manifest_bytes=1024,
                max_file_bytes=1024,
                max_total_bytes=4096,
                capture_all=True,
                max_entries=1,
            )

    def test_tree_index_does_not_follow_a_directory_swapped_to_a_symlink(
        self,
    ) -> None:
        root = self.fixture.root / "tree-swap-root"
        victim = root / "victim"
        victim.mkdir(parents=True)
        (victim / "inside.txt").write_text("inside\n", encoding="ascii")
        outside = self.fixture.root / "tree-swap-outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("outside\n", encoding="ascii")
        saved = root / "victim-saved"
        original_open = os.open
        swapped = False

        def swapping_open(
            path: object,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal swapped
            if path == "victim" and dir_fd is not None and not swapped:
                swapped = True
                victim.rename(saved)
                victim.symlink_to(outside, target_is_directory=True)
            return original_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(os, "open", side_effect=swapping_open):
            with self.assertRaisesRegex(
                ContractError,
                "unable to open directory",
            ):
                tree_index(root)
        self.assertTrue(swapped)

    def test_handoff_sparse_oversize_is_rejected_before_hash_or_parse(self) -> None:
        target = self.fixture.inputs / "classification.jsonl"
        with target.open("wb") as handle:
            handle.truncate(validator_module.HANDOFF_FILE_MAX_BYTES + 1)
        with self.assertRaisesRegex(ContractError, "byte limit"):
            self.build()
        self.assertFalse(self.fixture.output.exists())

    def test_handoff_classification_hash_parse_and_copy_use_one_snapshot(self) -> None:
        source = (self.fixture.inputs / "classification.jsonl").resolve(strict=True)
        original_bytes = source.read_bytes()
        original_loader = validator_module.load_jsonl_bytes

        def hostile_loader(payload: bytes, *, label: str) -> list[dict[str, object]]:
            if label != "post-fix classification":
                return original_loader(payload, label=label)
            hostile_rows = [json.loads(line) for line in original_bytes.splitlines()]
            target = next(row for row in hostile_rows if row["id"].startswith("AUX-"))
            target["title"] = "HOSTILE-SWAP-AFTER-SNAPSHOT"
            source.write_bytes(
                b"".join(canonical_json_bytes(row) for row in hostile_rows)
            )
            try:
                return original_loader(payload, label=label)
            finally:
                source.write_bytes(original_bytes)

        with mock.patch.object(
            validator_module,
            "load_jsonl_bytes",
            side_effect=hostile_loader,
        ):
            self.build()
        packaged = [
            json.loads(line)
            for line in (
                self.fixture.output / "evidence/remediation/finding_classification_ledger.jsonl"
            ).read_text(encoding="utf-8").splitlines()
        ]
        self.assertFalse(
            any(
                row["title"] == "HOSTILE-SWAP-AFTER-SNAPSHOT"
                for row in packaged
            )
        )

    def test_m01_rejects_134_fake_duplicate_inventory_rows(self) -> None:
        path = self.fixture.inputs / "required-matrices.md"
        lines = path.read_text(encoding="utf-8").splitlines()
        start = next(index for index, line in enumerate(lines) if line.startswith("## M01-"))
        end = next(index for index, line in enumerate(lines[start + 1 :], start + 1) if line.startswith("## M02-"))
        header_index = next(index for index in range(start + 1, end) if lines[index].startswith("|"))
        for index in range(header_index + 2, end):
            if lines[index].startswith("|"):
                cells = [cell.strip() for cell in lines[index].strip("|").split("|")]
                cells[0] = "FAKE"
                lines[index] = "| " + " | ".join(cells) + " |"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.fixture.refresh_handoff_hash("required_matrices")
        with self.assertRaisesRegex(ContractError, "M01|FAKE|duplicate"):
            self.build()

    def test_m02_through_m14_reject_fake_semantic_cells(self) -> None:
        path = self.fixture.inputs / "required-matrices.md"
        lines = path.read_text(encoding="utf-8").splitlines()
        for number in range(2, 15):
            start = next(index for index, line in enumerate(lines) if line.startswith(f"## M{number:02d}-"))
            header_index = next(index for index in range(start + 1, len(lines)) if lines[index].startswith("|"))
            row_index = next(index for index in range(header_index + 2, len(lines)) if lines[index].startswith("|"))
            cells = [cell.strip() for cell in lines[row_index].strip("|").split("|")]
            cells[-1] = "FAKE"
            lines[row_index] = "| " + " | ".join(cells) + " |"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.fixture.refresh_handoff_hash("required_matrices")
        with self.assertRaisesRegex(ContractError, "FAKE|semantic"):
            self.build()

    def test_matrix_fixed_sets_are_the_authoritative_ci_and_t23_sets(self) -> None:
        schema_path = self.fixture.baseline / "schemas/matrix-schema-v1.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        schema["fixed_sets"]["ci_check_ids"][0] = "invented-check"
        self.fixture._write_json(schema_path, schema)
        self.fixture._write_manifest(self.fixture.baseline)
        with self.assertRaisesRegex(ContractError, "fixed CI/T23 sets"):
            self.build()

    def test_matrix_semantic_identity_sets_reject_duplicates(self) -> None:
        path = self.fixture.inputs / "required-matrices.md"
        lines = path.read_text(encoding="utf-8").splitlines()
        start = next(index for index, line in enumerate(lines) if line.startswith("## M02-"))
        header_index = next(index for index in range(start + 1, len(lines)) if lines[index].startswith("|"))
        first_row = header_index + 2
        second_row = first_row + 1
        first_id = lines[first_row].strip("|").split("|", 1)[0].strip()
        cells = [cell.strip() for cell in lines[second_row].strip("|").split("|")]
        cells[0] = first_id
        lines[second_row] = "| " + " | ".join(cells) + " |"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.fixture.refresh_handoff_hash("required_matrices")
        with self.assertRaisesRegex(ContractError, "duplicate semantic identities"):
            self.build()

    def test_common_secret_scanner_covers_headers_tokens_and_private_keys(self) -> None:
        scanner = getattr(common_module, "scan_secret_bytes", None)
        self.assertIsNotNone(scanner, "common builder/validator secret scanner is missing")
        for payload in (
            b"Authorization: Bearer abcdefghijklmnopqrstuvwxyz\n",
            b"Cookie: session=super-secret-cookie\n",
            b"Set-Cookie: session=super-secret-cookie; HttpOnly\n",
            b"-----BEGIN PGP PRIVATE KEY BLOCK-----\nprivate\n",
            b'const password = "unsafe-value-12345";\n',
            b'let apiKey: string = "unsafe-value-12345";\n',
            b'connect(password="unsafe-value-12345")\n',
            b'password: str = "unsafe-value-12345"\n',
        ):
            with self.subTest(payload=payload[:20]):
                with self.assertRaises(ContractError):
                    scanner(payload, label="secret PoC")
        for payload in (
            b"const password = process.env.PASSWORD;\n",
            b"const password = await readSecret();\n",
            b"password = args.password\n",
            b'const password = "<redacted>";\n',
            b'const password = "${PASSWORD}";\n',
        ):
            with self.subTest(runtime_reference=payload):
                scanner(payload, label="non-secret control")

    def test_secret_scanner_rejects_prefixed_and_multiline_python_literals(self) -> None:
        scanner = common_module.scan_secret_bytes
        secret = "unsafe-value-12345"
        payloads = [
            f'password = {prefix}"{secret}"\n'.encode("ascii")
            for prefix in ("b", "r", "u", "f", "br", "rb", "fr", "rf")
        ]
        payloads.extend(
            (
                f"password = b'''{secret}'''\n".encode("ascii"),
                f'password = f"""{secret}"""\n'.encode("ascii"),
                f'password = r"""\n{secret}\n"""\n'.encode("ascii"),
            )
        )
        for payload in payloads:
            with self.subTest(payload_prefix=payload[:20]):
                with self.assertRaises(ContractError) as raised:
                    scanner(payload, label="secret prefix PoC")
                self.assertNotIn(secret, str(raised.exception))

    def test_secret_scanner_rejects_namespaced_and_parenthesized_literals(
        self,
    ) -> None:
        scanner = common_module.scan_secret_bytes
        secret = "unsafe-value-12345"
        token = "sk-proj-abcdefghijklmnopqrstuvwxyz"
        for payload, forbidden_value in (
            (f'password=("{secret}")\n'.encode("ascii"), secret),
            (
                f'password=(\n  f"""{secret}\ncontinued"""\n)\n'.encode(
                    "ascii"
                ),
                secret,
            ),
            (f'OPENAI_API_KEY="{token}"\n'.encode("ascii"), token),
            (f'DATABASE_PASSWORD="{secret}"\n'.encode("ascii"), secret),
            (f'AWS_SECRET_ACCESS_KEY="{secret}"\n'.encode("ascii"), secret),
            (f'CLOUDFLARE_API_TOKEN="{secret}"\n'.encode("ascii"), secret),
        ):
            with self.subTest(identifier=payload.split(b"=", 1)[0]):
                with self.assertRaises(ContractError) as raised:
                    scanner(payload, label="namespaced secret PoC")
                self.assertNotIn(forbidden_value, str(raised.exception))
        for payload in (
            b'OPENAI_API_KEY=os.environ["OPENAI_API_KEY"]\n',
            b"DATABASE_PASSWORD=process.env.DATABASE_PASSWORD\n",
            b"AWS_SECRET_ACCESS_KEY=args.aws_secret_access_key\n",
            b'CLOUDFLARE_API_TOKEN="<redacted>"\n',
        ):
            with self.subTest(runtime_reference=payload):
                scanner(payload, label="namespaced non-secret control")

    def test_builder_and_validator_reject_a_secret_in_a_receipt_log(self) -> None:
        rows = self.fixture.load_jsonl("inputs/test-receipts.jsonl")
        target = rows[0]
        log_path = self.fixture.handoff_root / target["log"]["path"]
        log_path.write_bytes(
            log_path.read_bytes()
            + b"Authorization: Bearer abcdefghijklmnopqrstuvwxyz\n"
        )
        target["log"]["sha256"] = sha256(log_path)
        self.fixture.write_jsonl("inputs/test-receipts.jsonl", rows)
        self.fixture.refresh_handoff_hash("test_receipt_registry")
        with self.assertRaisesRegex(ContractError, "authentication|credential"):
            self.build()

    def test_build_receipt_input_and_tool_hashes_are_recalculated(self) -> None:
        self.build()
        path = self.fixture.output / "receipts/build_receipt.json"
        receipt = json.loads(path.read_text(encoding="utf-8"))
        receipt["input_sha256"] = {key: "0" * 64 for key in receipt["input_sha256"]}
        receipt["tool_source_sha256"] = {key: "0" * 64 for key in receipt["tool_source_sha256"]}
        self.fixture._write_json(path, receipt)
        self.fixture._write_manifest(self.fixture.output)
        with self.assertRaisesRegex(ContractError, "trust root|tool source|input SHA"):
            validate_package(
                package=self.fixture.output,
                baseline=self.fixture.baseline,
                group_map=self.fixture.group_map,
                candidate_repo=self.fixture.repo,
                semantic_receipt_sha256=self.fixture.semantic_sha256(),
            )

    def test_manifest_cannot_authorize_an_extra_package_file(self) -> None:
        self.build()
        (self.fixture.output / "EXTRA.txt").write_text("not allowlisted\n", encoding="utf-8")
        core_index = tree_index(
            self.fixture.output,
            exclude={
                "MANIFEST.sha256",
                "receipts/build_receipt.json",
                *validator_module.REPLAY_RECEIPT_PATHS.values(),
            },
        )
        core_hash = hashlib.sha256(canonical_json_bytes(core_index)).hexdigest()
        for relative in validator_module.REPLAY_RECEIPT_PATHS.values():
            replay_path = self.fixture.output / relative
            replay = json.loads(replay_path.read_text(encoding="utf-8"))
            replay["core_index_sha256"] = core_hash
            replay["core_entry_count"] = len(core_index)
            self.fixture._write_json(replay_path, replay)
        build_path = self.fixture.output / "receipts/build_receipt.json"
        build = json.loads(build_path.read_text(encoding="utf-8"))
        build["core_index_sha256"] = core_hash
        build["replay_receipt_sha256"] = {
            replay_id: sha256(self.fixture.output / relative)
            for replay_id, relative in validator_module.REPLAY_RECEIPT_PATHS.items()
        }
        self.fixture._write_json(build_path, build)
        self.fixture._write_manifest(self.fixture.output)
        with self.assertRaisesRegex(ContractError, "allowlist|extra"):
            validate_package(
                package=self.fixture.output,
                baseline=self.fixture.baseline,
                group_map=self.fixture.group_map,
                candidate_repo=self.fixture.repo,
                semantic_receipt_sha256=self.fixture.semantic_sha256(),
            )


if __name__ == "__main__":
    unittest.main()
