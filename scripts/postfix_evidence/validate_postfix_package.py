#!/usr/bin/env python3
"""Validate Ultra post-fix source inputs or a published evidence package."""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scripts.postfix_evidence.common import (
    ContractError,
    SHA1_RE,
    SHA256_RE,
    UTC_SECOND_RE,
    canonical_json_bytes,
    commit_equivalence,
    ensure_ancestor,
    ensure_path_at_commit,
    exact_keys,
    git_head,
    git_text,
    git_tree,
    load_json,
    load_jsonl,
    nonempty_string,
    read_regular_bytes,
    resolve_commit,
    resolve_regular,
    safe_relative,
    sha256_bytes,
    sha256_file,
    string_list,
    tree_index,
    validate_manifest,
)


HANDOFF_FILE_KEYS = (
    "postfix_classification_ledger",
    "fix_group_ledger",
    "test_receipt_registry",
    "pre_fix_negative_receipt",
    "local_condition_closure",
    "documentation_alignment_receipt",
    "semantic_completion_receipt",
    "required_matrices",
    "four_verdicts",
    "provider_live_residuals",
)

REQUIRED_LOCAL_CLOSURES = frozenset(
    {
        "DOC-EVD-004",
        "DOC-EVD-005",
        "ULTRA-GAP-027",
        "ULTRA-GAP-037",
        "ULTRA-GAP-040",
        "ULTRA-GAP-041",
        "ULTRA-GAP-042",
    }
)

REQUIRED_LIVE_RESIDUALS = frozenset(
    {"LIVE-BKP-006", "LIVE-OPS-001", "LIVE-OPS-002", "LIVE-OPS-004"}
)

DOCUMENTATION_TOPICS = frozenset(
    {
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
    }
)

REPORTABLE_IMMUTABLE_FIELDS = (
    "schema_version",
    "id",
    "record_type",
    "title",
    "severity",
    "component",
    "corrected_in_t1_t23",
    "t1_t23_task_ids",
    "is_new",
    "newness_status",
    "newness_basis",
    "source_input_ids",
    "source_hashes",
    "canonical_candidate_ids",
    "validation_receipt_ids",
    "attack_path_receipt_ids",
    "scenario",
    "prerequisites",
    "impact",
    "blast_radius",
    "remediation",
    "rollback",
    "closure_test",
    "owner",
)

GROUP_RECEIPT_FIELDS = {
    "negative_test_receipt_ids": "negative",
    "positive_test_receipt_ids": "positive",
    "regression_test_receipt_ids": "regression",
    "hostile_test_receipt_ids": "hostile",
    "independent_qa_receipt_ids": "independent-qa",
}

GLOBAL_TEST_PHASES = frozenset(
    {"full-suite", "differential-scan", "adversarial-qa", "documentation-validation"}
)

PACKAGE_REQUIRED_FILES = frozenset(
    {
        "README.md",
        "MANIFEST.sha256",
        "baseline/baseline_binding.json",
        "baseline/security_fix_groups_v1.jsonl",
        "evidence/remediation/finding_classification_ledger.jsonl",
        "evidence/remediation/fix_group_ledger_v1.jsonl",
        "evidence/remediation/finding_fix_commit_test_v1.jsonl",
        "evidence/remediation/local_condition_closure.jsonl",
        "evidence/remediation/documentation_alignment_receipt.json",
        "evidence/test/test_receipt_registry_v1.jsonl",
        "evidence/test/pre_fix_negative_receipt.json",
        "evidence/validation/canonical_candidate_registry.jsonl",
        "evidence/validation/semantic_completion_receipt.json",
        "evidence/validation/provider_live_residuals.jsonl",
        "required_matrices.md",
        "four_verdicts_v1.json",
        "schemas/matrix-schema-v1.json",
        "schemas/handoff-v1.schema.json",
        "receipts/candidate_identity.json",
        "receipts/replay_receipt.json",
        "receipts/build_receipt.json",
    }
)


@dataclass(frozen=True)
class Baseline:
    root: Path
    rows: list[dict[str, Any]]
    by_id: dict[str, dict[str, Any]]
    registry: list[dict[str, Any]]
    reportable_ids: frozenset[str]
    suppressed_ids: frozenset[str]
    candidate_commit: str
    candidate_tree: str
    matrix_schema: dict[str, Any]
    inventory_count: int
    manifest_sha256: str
    classification_sha256: str
    registry_sha256: str
    inventory_sha256: str
    matrix_schema_sha256: str


@dataclass
class ValidatedInputs:
    baseline: Baseline
    group_map_path: Path
    group_map_rows: list[dict[str, Any]]
    group_map_sha256: str
    handoff_path: Path
    handoff_sha256: str
    handoff_file_paths: dict[str, Path]
    handoff_file_sha256: dict[str, str]
    evidence_cutoff_at: str
    candidate_repo: Path
    candidate_final_commit: str
    candidate_final_tree: str
    classification_rows: list[dict[str, Any]]
    fix_group_rows: list[dict[str, Any]]
    test_receipt_rows: list[dict[str, Any]]
    pre_fix_receipt: dict[str, Any]
    local_closure_rows: list[dict[str, Any]]
    documentation_receipt: dict[str, Any]
    semantic_receipt: dict[str, Any]
    matrices_bytes: bytes
    verdicts: dict[str, Any]
    residual_rows: list[dict[str, Any]]
    equivalence_records: list[dict[str, Any]]
    test_log_sources: dict[str, Path]
    pre_fix_log_sources: dict[str, Path]
    counts: dict[str, int]


def _unique_rows(rows: list[dict[str, Any]], key: str, *, label: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(rows, start=1):
        value = row.get(key)
        if not isinstance(value, str) or not value:
            raise ContractError(f"{label}:{index}: invalid {key}")
        if value in result:
            raise ContractError(f"{label}: duplicate {key} {value}")
        result[value] = row
    return result


def _validate_baseline(root: Path) -> Baseline:
    required = {
        "finding_classification_ledger.jsonl",
        "inventory_ledger.jsonl",
        "evidence/validation/canonical_candidate_registry.jsonl",
        "schemas/matrix-schema-v1.json",
    }
    validate_manifest(root, exact=False, required=required)
    classification_path = resolve_regular(root, "finding_classification_ledger.jsonl", label="baseline classification")
    registry_path = resolve_regular(
        root,
        "evidence/validation/canonical_candidate_registry.jsonl",
        label="baseline canonical registry",
    )
    inventory_path = resolve_regular(root, "inventory_ledger.jsonl", label="baseline inventory")
    matrix_path = resolve_regular(root, "schemas/matrix-schema-v1.json", label="baseline matrix schema")
    rows = load_jsonl(classification_path, label="baseline classification")
    by_id = _unique_rows(rows, "id", label="baseline classification")
    if len(rows) != 341:
        raise ContractError("baseline: authoritative classification cardinality is not 341")

    registry = load_jsonl(registry_path, label="baseline canonical registry")
    registry_by_id = _unique_rows(registry, "id", label="baseline canonical registry")
    if len(registry_by_id) != 240:
        raise ContractError("baseline: canonical candidate cardinality is not 240")
    reportable_ids: set[str] = set()
    suppressed_ids: set[str] = set()
    commits: set[str] = set()
    trees: set[str] = set()
    classification_ids: set[str] = set()
    for item_id, row in registry_by_id.items():
        if row.get("canonical_candidate_id") != item_id or row.get("status") != "CANONICAL":
            raise ContractError("baseline: canonical registry identity is invalid")
        decision = row.get("policy_decision")
        if decision == "reportable":
            reportable_ids.add(item_id)
        elif decision == "ignore":
            suppressed_ids.add(item_id)
        else:
            raise ContractError("baseline: unknown canonical policy decision")
        item_ids = string_list(row.get("classification_item_ids"), label=f"baseline registry {item_id} classification IDs")
        classification_ids.update(item_ids)
        commit = row.get("candidate_commit")
        tree = row.get("candidate_tree")
        if not isinstance(commit, str) or SHA1_RE.fullmatch(commit) is None:
            raise ContractError("baseline: invalid candidate commit")
        if not isinstance(tree, str) or SHA1_RE.fullmatch(tree) is None:
            raise ContractError("baseline: invalid candidate tree")
        commits.add(commit)
        trees.add(tree)
    if len(reportable_ids) != 135 or len(suppressed_ids) != 105:
        raise ContractError("baseline: reportable/suppressed policy cardinalities are not 135/105")
    if classification_ids != reportable_ids | suppressed_ids:
        raise ContractError("baseline: canonical registry projection is incomplete or overlapping")
    if not classification_ids.issubset(by_id):
        raise ContractError("baseline: canonical classification rows are missing")
    for item_id in reportable_ids:
        row = by_id[item_id]
        if row.get("record_type") != "security-finding" or row.get("is_new") is not True:
            raise ContractError("baseline: reportable CAN semantics are invalid")
    if len(commits) != 1 or len(trees) != 1:
        raise ContractError("baseline: canonical registry has mixed candidate identities")

    inventory = load_jsonl(inventory_path, label="baseline inventory")
    if len(inventory) != 134:
        raise ContractError("baseline: inventory cardinality is not 134")
    matrix_schema = load_json(matrix_path, label="baseline matrix schema")
    _validate_matrix_schema(matrix_schema)
    return Baseline(
        root=root,
        rows=rows,
        by_id=by_id,
        registry=registry,
        reportable_ids=frozenset(reportable_ids),
        suppressed_ids=frozenset(suppressed_ids),
        candidate_commit=next(iter(commits)),
        candidate_tree=next(iter(trees)),
        matrix_schema=matrix_schema,
        inventory_count=len(inventory),
        manifest_sha256=sha256_file(root / "MANIFEST.sha256", label="baseline manifest"),
        classification_sha256=sha256_file(classification_path),
        registry_sha256=sha256_file(registry_path),
        inventory_sha256=sha256_file(inventory_path),
        matrix_schema_sha256=sha256_file(matrix_path),
    )


def _validate_matrix_schema(value: Any) -> None:
    if not isinstance(value, dict) or value.get("matrix_schema_version") != 1:
        raise ContractError("matrix schema: unsupported version")
    matrices = value.get("matrices")
    if not isinstance(matrices, list) or len(matrices) != 15:
        raise ContractError("matrix schema: expected exactly M01 through M15")
    expected_numbers = list(range(1, 16))
    actual_numbers: list[int] = []
    for row in matrices:
        if not isinstance(row, dict):
            raise ContractError("matrix schema: malformed row")
        matrix_id = row.get("id")
        if not isinstance(matrix_id, str) or re.fullmatch(r"M[0-9]{2}-[A-Z0-9-]+", matrix_id) is None:
            raise ContractError("matrix schema: invalid matrix ID")
        actual_numbers.append(int(matrix_id[1:3]))
        columns = row.get("columns")
        if not isinstance(columns, list) or not columns or any(not isinstance(item, str) for item in columns):
            raise ContractError(f"matrix schema: invalid columns for {matrix_id}")
        if len(set(columns)) != len(columns):
            raise ContractError(f"matrix schema: duplicate columns for {matrix_id}")
        boolean_columns = row.get("boolean_columns")
        if not isinstance(boolean_columns, list) or not set(boolean_columns).issubset(columns):
            raise ContractError(f"matrix schema: invalid boolean columns for {matrix_id}")
        if row.get("exact_count") is not None and type(row.get("exact_count")) is not int:
            raise ContractError(f"matrix schema: invalid exact count for {matrix_id}")
        if type(row.get("minimum_count")) is not int or row["minimum_count"] < 0:
            raise ContractError(f"matrix schema: invalid minimum count for {matrix_id}")
    if actual_numbers != expected_numbers:
        raise ContractError("matrix schema: matrix IDs are not ordered M01 through M15")


def _validate_group_map(path: Path, reportable_ids: frozenset[str]) -> tuple[list[dict[str, Any]], str]:
    rows = load_jsonl(path, label="fix-group map")
    by_id = _unique_rows(rows, "group_id", label="fix-group map")
    expected = {f"FG-{number:03d}" for number in range(1, 78)}
    if set(by_id) != expected:
        raise ContractError("fix-group map: expected exact FG-001 through FG-077 set")
    projection: list[str] = []
    for group_id in sorted(by_id):
        row = by_id[group_id]
        ids = string_list(row.get("canonical_ids"), label=f"fix-group map {group_id} canonical IDs")
        projection.extend(ids)
        for key in ("slug", "root_control", "remediation", "test_boundary"):
            nonempty_string(row.get(key), label=f"fix-group map {group_id} {key}")
    if len(projection) != 135 or len(set(projection)) != 135 or set(projection) != set(reportable_ids):
        raise ContractError("fix-group map: reportable projection is not an exact one-to-one 135-CAN cover")
    return [by_id[group_id] for group_id in sorted(by_id)], sha256_file(path, label="fix-group map")


def _validate_candidate(repo: Path, baseline: Baseline, final_commit_value: Any) -> tuple[str, str]:
    final_commit = resolve_commit(repo, final_commit_value, label="handoff final commit")
    head = git_head(repo)
    if head != final_commit:
        raise ContractError("candidate: handoff final commit does not equal HEAD")
    status = git_text(repo, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise ContractError("candidate: final worktree must be clean")
    baseline_commit = resolve_commit(repo, baseline.candidate_commit, label="baseline commit")
    if git_tree(repo, baseline_commit) != baseline.candidate_tree:
        raise ContractError("candidate: baseline commit tree disagrees with authoritative registry")
    ensure_ancestor(repo, baseline_commit, final_commit, label="candidate baseline ancestry")
    return final_commit, git_tree(repo, final_commit)


def _validate_handoff_manifest(path: Path) -> tuple[dict[str, Any], dict[str, Path], dict[str, str]]:
    handoff = load_json(path, label="handoff manifest")
    exact_keys(
        handoff,
        {"schema_version", "evidence_cutoff_at", "candidate_final_commit", "files"},
        label="handoff manifest",
    )
    if handoff["schema_version"] != 1:
        raise ContractError("handoff manifest: unsupported version")
    if not isinstance(handoff["evidence_cutoff_at"], str) or UTC_SECOND_RE.fullmatch(handoff["evidence_cutoff_at"]) is None:
        raise ContractError("handoff manifest: invalid evidence cutoff")
    if not isinstance(handoff["candidate_final_commit"], str) or SHA1_RE.fullmatch(handoff["candidate_final_commit"]) is None:
        raise ContractError("handoff manifest: invalid final commit")
    files = exact_keys(handoff["files"], HANDOFF_FILE_KEYS, label="handoff files")
    resolved: dict[str, Path] = {}
    hashes: dict[str, str] = {}
    for key in HANDOFF_FILE_KEYS:
        entry = exact_keys(files[key], {"path", "sha256"}, label=f"handoff file {key}")
        if not isinstance(entry["sha256"], str) or SHA256_RE.fullmatch(entry["sha256"]) is None:
            raise ContractError(f"handoff file {key}: invalid SHA-256")
        target = resolve_regular(path.parent, entry["path"], label=f"handoff file {key}")
        actual = sha256_file(target, label=f"handoff file {key}")
        if actual != entry["sha256"]:
            raise ContractError(f"handoff file {key}: stale SHA-256")
        resolved[key] = target
        hashes[key] = actual
    return handoff, resolved, hashes


def _validate_classification(
    rows: list[dict[str, Any]], baseline: Baseline, final_commit: str
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    by_id = _unique_rows(rows, "id", label="post-fix classification")
    if len(rows) != 341 or set(by_id) != set(baseline.by_id):
        raise ContractError("post-fix classification: exact 341-row baseline universe was not preserved")
    for item_id in baseline.suppressed_ids:
        if by_id[item_id] != baseline.by_id[item_id]:
            raise ContractError(f"post-fix classification: suppressed row changed: {item_id}")
    for item_id in baseline.reportable_ids:
        row = by_id[item_id]
        prior = baseline.by_id[item_id]
        for field in REPORTABLE_IMMUTABLE_FIELDS:
            if row.get(field) != prior.get(field):
                raise ContractError(f"post-fix classification: reportable lineage changed for {item_id} ({field})")
        if row.get("category") != "NEW-FINDING" or row.get("is_new") is not True:
            raise ContractError(f"post-fix classification: new-work semantics changed for {item_id}")
        if row.get("corrected_in_t1_t23") is not False or row.get("t1_t23_task_ids") != []:
            raise ContractError(f"post-fix classification: {item_id} was falsely attributed to T1-T23")
        if row.get("candidate_affected") is not False or "candidate" in row.get("affected_scope", []):
            raise ContractError(f"post-fix classification: candidate finding remains affected: {item_id}")
        if any(row.get(field) is not False for field in ("blocks_merge", "blocks_deploy", "blocks_go_to_deploy")):
            raise ContractError(f"post-fix classification: local blocker remains for {item_id}")
        evidence = row.get("fix_evidence")
        if not isinstance(evidence, list) or not evidence or final_commit not in " ".join(str(item) for item in evidence):
            raise ContractError(f"post-fix classification: fix evidence is not bound to final HEAD for {item_id}")
        if "OPEN" in str(row.get("final_state", "")).upper():
            raise ContractError(f"post-fix classification: final state remains open for {item_id}")

    external_or_live: set[str] = set()
    for item_id, row in by_id.items():
        if item_id in baseline.reportable_ids or item_id in baseline.suppressed_ids:
            continue
        if row.get("candidate_affected") is True or row.get("blocks_merge") is True:
            raise ContractError(f"post-fix classification: local candidate/merge blocker remains: {item_id}")
        if row.get("live_affected") is True or row.get("blocks_deploy") is True or row.get("blocks_go_to_deploy") is True:
            external_or_live.add(item_id)
    return by_id, external_or_live


def _validate_log_reference(root: Path, value: Any, *, label: str) -> Path:
    entry = exact_keys(value, {"path", "sha256"}, label=label)
    if not isinstance(entry["sha256"], str) or SHA256_RE.fullmatch(entry["sha256"]) is None:
        raise ContractError(f"{label}: invalid SHA-256")
    path = resolve_regular(root, entry["path"], label=label)
    if sha256_file(path, label=label) != entry["sha256"]:
        raise ContractError(f"{label}: stale log SHA-256")
    return path


def _validate_test_receipts(
    rows: list[dict[str, Any]], artifact_root: Path, final_commit: str, valid_groups: set[str]
) -> tuple[dict[str, dict[str, Any]], dict[str, Path]]:
    by_id = _unique_rows(rows, "receipt_id", label="test receipt registry")
    logs: dict[str, Path] = {}
    seen_global: set[str] = set()
    allowed_phases = set(GROUP_RECEIPT_FIELDS.values()) | set(GLOBAL_TEST_PHASES)
    for receipt_id, row in by_id.items():
        exact_keys(
            row,
            {
                "schema_version",
                "receipt_id",
                "phase",
                "scope",
                "group_ids",
                "candidate_final_commit",
                "command",
                "exit_code",
                "result",
                "log",
            },
            label=f"test receipt {receipt_id}",
        )
        if row["schema_version"] != 1 or row["phase"] not in allowed_phases:
            raise ContractError(f"test receipt {receipt_id}: invalid schema or phase")
        if row["candidate_final_commit"] != final_commit:
            raise ContractError(f"test receipt {receipt_id}: not bound to final HEAD")
        if row["exit_code"] != 0 or row["result"] != "PASS":
            raise ContractError(f"test receipt {receipt_id}: result is not PASS/0")
        nonempty_string(row["scope"], label=f"test receipt {receipt_id} scope")
        command = string_list(row["command"], label=f"test receipt {receipt_id} command")
        if any("\n" in item or "\x00" in item for item in command):
            raise ContractError(f"test receipt {receipt_id}: unsafe command encoding")
        groups = string_list(row["group_ids"], label=f"test receipt {receipt_id} groups", allow_empty=True)
        if not set(groups).issubset(valid_groups):
            raise ContractError(f"test receipt {receipt_id}: unknown fix group")
        if row["phase"] in GLOBAL_TEST_PHASES:
            if row["scope"] != "candidate" or groups:
                raise ContractError(f"test receipt {receipt_id}: global phase must have candidate scope")
            seen_global.add(row["phase"])
        elif not groups:
            raise ContractError(f"test receipt {receipt_id}: group phase has empty group coverage")
        logs[receipt_id] = _validate_log_reference(artifact_root, row["log"], label=f"test receipt {receipt_id} log")
    if seen_global != set(GLOBAL_TEST_PHASES):
        raise ContractError("test receipt registry: full-suite/differential/adversarial/documentation receipts are incomplete")
    return by_id, logs


def _validate_fix_groups(
    rows: list[dict[str, Any]],
    group_map_rows: list[dict[str, Any]],
    receipts: dict[str, dict[str, Any]],
    repo: Path,
    final_head: str,
) -> list[dict[str, Any]]:
    by_id = _unique_rows(rows, "group_id", label="fix-group ledger")
    source_by_id = {row["group_id"]: row for row in group_map_rows}
    if set(by_id) != set(source_by_id):
        raise ContractError("fix-group ledger: missing or extra fix-group rows")
    cache: dict[tuple[str, str], dict[str, Any]] = {}
    equivalence_by_group: list[dict[str, Any]] = []
    for group_id in sorted(by_id):
        row = by_id[group_id]
        exact_keys(
            row,
            {
                "schema_version",
                "group_id",
                "canonical_ids",
                "cohort",
                "cohort_commit",
                "final_commit",
                "source",
                "control",
                "sink",
                "remediation_boundary",
                "status",
                "consumer_evidence",
                *GROUP_RECEIPT_FIELDS,
            },
            label=f"fix-group ledger {group_id}",
        )
        if row["schema_version"] != 1 or row["status"] != "PASS":
            raise ContractError(f"fix-group ledger {group_id}: status is not PASS")
        if row["canonical_ids"] != source_by_id[group_id]["canonical_ids"]:
            raise ContractError(f"fix-group ledger {group_id}: canonical ID projection changed")
        nonempty_string(row["cohort"], label=f"fix-group ledger {group_id} cohort")
        for field in ("source", "control", "sink"):
            string_list(row[field], label=f"fix-group ledger {group_id} {field}")
        nonempty_string(row["remediation_boundary"], label=f"fix-group ledger {group_id} remediation boundary")
        consumer_evidence = string_list(row["consumer_evidence"], label=f"fix-group ledger {group_id} consumer evidence")
        for evidence in consumer_evidence:
            ensure_path_at_commit(repo, final_head, evidence)
        cohort = resolve_commit(repo, row["cohort_commit"], label=f"fix-group ledger {group_id} cohort commit")
        final = resolve_commit(repo, row["final_commit"], label=f"fix-group ledger {group_id} final commit")
        if cohort == final:
            raise ContractError(
                f"fix-group ledger {group_id}: cohort-only SHA is not a final integration mapping"
            )
        ensure_ancestor(repo, final, final_head, label=f"fix-group ledger {group_id} final mapping")
        pair = (cohort, final)
        if pair not in cache:
            cache[pair] = commit_equivalence(repo, cohort, final)
        equivalence_by_group.append({"group_id": group_id, **cache[pair]})
        for field, phase in GROUP_RECEIPT_FIELDS.items():
            receipt_ids = string_list(row[field], label=f"fix-group ledger {group_id} {field}")
            for receipt_id in receipt_ids:
                receipt = receipts.get(receipt_id)
                if receipt is None or receipt["phase"] != phase or group_id not in receipt["group_ids"]:
                    raise ContractError(f"fix-group ledger {group_id}: invalid {phase} receipt binding")
    return equivalence_by_group


def _validate_pre_fix_receipt(
    receipt: dict[str, Any], artifact_root: Path, baseline: Baseline, group_ids: set[str]
) -> dict[str, Path]:
    exact_keys(
        receipt,
        {
            "schema_version",
            "baseline_commit",
            "baseline_tree",
            "detached_head",
            "worktree_clean",
            "forbidden_access",
            "executions",
            "summary",
        },
        label="pre-fix negative receipt",
    )
    if receipt["schema_version"] != 1:
        raise ContractError("pre-fix negative receipt: unsupported version")
    if receipt["baseline_commit"] != baseline.candidate_commit or receipt["baseline_tree"] != baseline.candidate_tree:
        raise ContractError("pre-fix negative receipt: baseline commit/tree mismatch")
    if receipt["detached_head"] is not True or receipt["worktree_clean"] is not True:
        raise ContractError("pre-fix negative receipt: baseline was not detached and clean")
    exact_keys(receipt["forbidden_access"], {"live", "docker", "network", "secrets"}, label="pre-fix forbidden access")
    if any(receipt["forbidden_access"][key] is not False for key in ("live", "docker", "network", "secrets")):
        raise ContractError("pre-fix negative receipt: forbidden live/Docker/network/secret access occurred")
    executions = receipt["executions"]
    if not isinstance(executions, list) or len(executions) != 77:
        raise ContractError("pre-fix negative receipt: expected exactly 77 executions")
    seen: set[str] = set()
    counts = {"make-wrapper": 0, "manual-harness": 0}
    logs: dict[str, Path] = {}
    log_paths: set[str] = set()
    for index, row in enumerate(executions, start=1):
        exact_keys(row, {"group_id", "runner_kind", "command", "result", "exit_code", "log"}, label=f"pre-fix execution {index}")
        group_id = row["group_id"]
        if group_id not in group_ids or group_id in seen:
            raise ContractError("pre-fix negative receipt: missing or duplicate fix-group execution")
        seen.add(group_id)
        runner_kind = row["runner_kind"]
        if runner_kind not in counts:
            raise ContractError(f"pre-fix negative receipt: invalid runner kind for {group_id}")
        counts[runner_kind] += 1
        command = string_list(row["command"], label=f"pre-fix execution {group_id} command")
        executable = Path(command[0]).name
        if runner_kind == "make-wrapper" and executable not in {"make", "gmake"}:
            raise ContractError(f"pre-fix negative receipt: {group_id} is not a Make wrapper")
        if runner_kind == "manual-harness" and executable not in {"python3", "node", "bash", "sh"}:
            raise ContractError(f"pre-fix negative receipt: {group_id} manual harness executable is not allowed")
        if executable in {"docker", "ssh", "curl", "wget", "nc", "ncat"}:
            raise ContractError(f"pre-fix negative receipt: forbidden executable for {group_id}")
        if row["result"] != "PRE-FIX-NEGATIVE-REPRODUCED" or row["exit_code"] != 0:
            raise ContractError(f"pre-fix negative receipt: {group_id} was not reproduced")
        log_entry = row["log"]
        log_path_text = exact_keys(log_entry, {"path", "sha256"}, label=f"pre-fix execution {group_id} log")["path"]
        if log_path_text in log_paths:
            raise ContractError("pre-fix negative receipt: execution logs are not one-to-one")
        log_paths.add(log_path_text)
        logs[group_id] = _validate_log_reference(artifact_root, log_entry, label=f"pre-fix execution {group_id} log")
    if seen != group_ids or counts != {"make-wrapper": 72, "manual-harness": 5}:
        raise ContractError("pre-fix negative receipt: exact 77-FG/72-Make/5-manual contract failed")
    summary = exact_keys(
        receipt["summary"],
        {"fix_group_count", "make_wrapper_count", "manual_harness_count", "reproduced_count"},
        label="pre-fix negative summary",
    )
    expected_summary = {
        "fix_group_count": 77,
        "make_wrapper_count": 72,
        "manual_harness_count": 5,
        "reproduced_count": 77,
    }
    if summary != expected_summary:
        raise ContractError("pre-fix negative receipt: summary is inconsistent")
    return logs


def _validate_local_closures(
    rows: list[dict[str, Any]],
    baseline: Baseline,
    classification: dict[str, dict[str, Any]],
    final_commit: str,
    repo: Path,
    receipts: dict[str, dict[str, Any]],
) -> None:
    by_id = _unique_rows(rows, "id", label="local condition closure")
    external_categories = {
        "PROVIDER-EXTERNAL",
        "LIVE-OPERATIONAL-FINDING",
        "HARDWARE-MAINTENANCE",
        "DEPLOYMENT-PROCEDURE-FINDING",
    }
    baseline_local_blockers = {
        item_id
        for item_id, row in baseline.by_id.items()
        if item_id not in baseline.reportable_ids
        and item_id not in baseline.suppressed_ids
        and row.get("category") not in external_categories
        and any(
            row.get(field) is True
            for field in ("candidate_affected", "blocks_merge", "blocks_deploy", "blocks_go_to_deploy")
        )
    }
    available_required = (REQUIRED_LOCAL_CLOSURES & set(baseline.by_id)) | baseline_local_blockers
    if not available_required.issubset(by_id):
        raise ContractError(f"local condition closure: required proof rows missing: {sorted(available_required - set(by_id))}")
    for item_id, row in by_id.items():
        exact_keys(
            row,
            {"schema_version", "id", "status", "candidate_final_commit", "final_commit", "test_receipt_ids", "evidence"},
            label=f"local condition closure {item_id}",
        )
        if item_id not in baseline.by_id or row["schema_version"] != 1 or row["status"] != "CLOSED-LOCAL":
            raise ContractError(f"local condition closure {item_id}: invalid identity or status")
        if row["candidate_final_commit"] != final_commit:
            raise ContractError(f"local condition closure {item_id}: not bound to final HEAD")
        integration = resolve_commit(repo, row["final_commit"], label=f"local condition closure {item_id} final commit")
        ensure_ancestor(repo, integration, final_commit, label=f"local condition closure {item_id}")
        test_ids = string_list(row["test_receipt_ids"], label=f"local condition closure {item_id} tests")
        if any(test_id not in receipts for test_id in test_ids):
            raise ContractError(f"local condition closure {item_id}: unknown test receipt")
        for evidence in string_list(row["evidence"], label=f"local condition closure {item_id} evidence"):
            ensure_path_at_commit(repo, final_commit, evidence)
        post = classification[item_id]
        if post.get("candidate_affected") is not False or post.get("blocks_merge") is not False:
            raise ContractError(f"local condition closure {item_id}: post-fix classification is not closed")


def _validate_documentation(
    receipt: dict[str, Any], final_commit: str, repo: Path, test_receipts: dict[str, dict[str, Any]]
) -> None:
    exact_keys(
        receipt,
        {"schema_version", "candidate_final_commit", "status", "topics", "test_receipt_ids"},
        label="documentation alignment receipt",
    )
    if receipt["schema_version"] != 1 or receipt["status"] != "PASS" or receipt["candidate_final_commit"] != final_commit:
        raise ContractError("documentation alignment receipt: status/identity mismatch")
    topics = receipt["topics"]
    if not isinstance(topics, dict) or set(topics) != DOCUMENTATION_TOPICS:
        raise ContractError("documentation alignment receipt: required topic set is incomplete")
    for topic, paths in topics.items():
        for evidence in string_list(paths, label=f"documentation topic {topic}"):
            ensure_path_at_commit(repo, final_commit, evidence)
    receipt_ids = string_list(receipt["test_receipt_ids"], label="documentation alignment tests")
    if not any(test_receipts.get(item, {}).get("phase") == "documentation-validation" for item in receipt_ids):
        raise ContractError("documentation alignment receipt: documentation validation test is missing")


def _validate_semantic(receipt: dict[str, Any], final_commit: str, path: Path, expected_sha256: str) -> None:
    if SHA256_RE.fullmatch(expected_sha256) is None:
        raise ContractError("semantic completion: caller trust root is not a SHA-256")
    if sha256_file(path, label="semantic completion receipt") != expected_sha256:
        raise ContractError("semantic completion: receipt does not match caller-supplied current SHA-256")
    exact_keys(
        receipt,
        {"schema_version", "candidate_final_commit", "terminal_round", "modes", "summary", "saturated", "cap_reached"},
        label="semantic completion receipt",
    )
    if receipt["schema_version"] != 1 or receipt["candidate_final_commit"] != final_commit:
        raise ContractError("semantic completion: version or final HEAD mismatch")
    if type(receipt["terminal_round"]) is not int or receipt["terminal_round"] <= 0:
        raise ContractError("semantic completion: invalid terminal round")
    modes = exact_keys(receipt["modes"], {"require_terminal", "max_round"}, label="semantic completion modes")
    summary = exact_keys(receipt["summary"], {"novel_findings", "terminal_decision"}, label="semantic completion summary")
    if (
        modes != {"require_terminal": True, "max_round": None}
        or summary != {"novel_findings": 0, "terminal_decision": "SATURATED/STOP"}
        or receipt["saturated"] is not True
        or receipt["cap_reached"] is not False
    ):
        raise ContractError("semantic completion: only zero-novelty SATURATED/STOP terminal evidence is accepted")


def _split_markdown_row(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        raise ContractError("matrix: malformed Markdown table row")
    cells: list[str] = []
    current: list[str] = []
    escaped = False
    for character in stripped[1:-1]:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
            current.append(character)
        elif character == "|":
            cells.append("".join(current).strip().replace("\\|", "|"))
            current = []
        else:
            current.append(character)
    if escaped:
        current.append("\\")
    cells.append("".join(current).strip().replace("\\|", "|"))
    return cells


def _validate_matrices(payload: bytes, baseline: Baseline) -> None:
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ContractError("matrices: required_matrices.md is not UTF-8") from error
    heading_rows: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        match = re.fullmatch(r"## (M[0-9]{2}-[A-Z0-9-]+)", line.strip())
        if match:
            heading_rows.append((index, match.group(1)))
    expected_matrices = baseline.matrix_schema["matrices"]
    expected_ids = [row["id"] for row in expected_matrices]
    if [item[1] for item in heading_rows] != expected_ids:
        missing_m15 = not any(item[1].startswith("M15-") for item in heading_rows)
        suffix = " (M15 missing)" if missing_m15 else ""
        raise ContractError(f"matrices: exact ordered M01 through M15 set is required{suffix}")
    reportable_projection: set[str] = set()
    for matrix_index, ((start, matrix_id), schema) in enumerate(zip(heading_rows, expected_matrices)):
        end = heading_rows[matrix_index + 1][0] if matrix_index + 1 < len(heading_rows) else len(lines)
        section = [line for line in lines[start + 1 : end] if line.strip()]
        if len(section) < 2:
            raise ContractError(f"matrices: missing table for {matrix_id}")
        header = _split_markdown_row(section[0])
        separator = _split_markdown_row(section[1])
        if header != schema["columns"] or len(separator) != len(header) or any(re.fullmatch(r":?-{3,}:?", cell) is None for cell in separator):
            raise ContractError(f"matrices: header/separator mismatch for {matrix_id}")
        data_lines = [line for line in section[2:] if line.strip().startswith("|")]
        rows = [_split_markdown_row(line) for line in data_lines]
        if any(len(row) != len(header) for row in rows):
            raise ContractError(f"matrices: row width mismatch for {matrix_id}")
        exact_count = schema["exact_count"]
        minimum_count = schema["minimum_count"]
        if exact_count is not None and len(rows) != exact_count:
            raise ContractError(f"matrices: exact row count mismatch for {matrix_id}")
        if len(rows) < minimum_count:
            raise ContractError(f"matrices: minimum row count mismatch for {matrix_id}")
        if matrix_id.startswith("M01-") and len(rows) != baseline.inventory_count:
            raise ContractError("matrices: M01 must project all 134 inventory rows")
        for boolean_column in schema["boolean_columns"]:
            offset = header.index(boolean_column)
            if any(row[offset] not in {"true", "false"} for row in rows):
                raise ContractError(f"matrices: invalid boolean value in {matrix_id}.{boolean_column}")
        if matrix_id.startswith("M15-"):
            if header[0] != "finding_id":
                raise ContractError("matrices: M15 first column is not finding_id")
            finding_ids = [row[0] for row in rows]
            if len(finding_ids) != len(set(finding_ids)):
                raise ContractError("matrices: M15 contains duplicate finding IDs")
            reportable_projection = set(finding_ids)
    if reportable_projection != set(baseline.reportable_ids):
        raise ContractError("matrices: M15 is not the exact 135-reportable-CAN projection")


def _validate_residuals(
    rows: list[dict[str, Any]],
    classification: dict[str, dict[str, Any]],
    external_or_live: set[str],
    final_commit: str,
) -> tuple[dict[str, dict[str, Any]], dict[str, set[str]]]:
    by_id = _unique_rows(rows, "id", label="provider/live residuals")
    covered: set[str] = set()
    blockers = {axis: set() for axis in ("candidate_security", "merge", "go_to_deploy", "full_production_go")}
    for residual_id, row in by_id.items():
        exact_keys(
            row,
            {
                "schema_version",
                "id",
                "locus",
                "verification_status",
                "candidate_final_commit",
                "classification_ids",
                "blocks",
                "required_evidence",
                "owner",
            },
            label=f"provider/live residual {residual_id}",
        )
        if row["schema_version"] != 1 or row["candidate_final_commit"] != final_commit:
            raise ContractError(f"provider/live residual {residual_id}: identity mismatch")
        if row["locus"] not in {"PROVIDER-EXTERNAL", "LIVE-RUNTIME", "POST-DEPLOY", "HARDWARE-MAINTENANCE"}:
            raise ContractError(f"provider/live residual {residual_id}: invalid locus")
        if row["verification_status"] not in {"NOT-VERIFIED", "EXTERNAL-VALIDATION-REQUIRED", "POST-DEPLOY-REQUIRED"}:
            raise ContractError(f"provider/live residual {residual_id}: invalid or falsely positive status")
        ids = string_list(row["classification_ids"], label=f"provider/live residual {residual_id} classification IDs")
        if any(item not in classification for item in ids):
            raise ContractError(f"provider/live residual {residual_id}: unknown classification ID")
        covered.update(ids)
        axes = string_list(row["blocks"], label=f"provider/live residual {residual_id} blocker axes", allow_empty=True)
        if not set(axes).issubset(blockers):
            raise ContractError(f"provider/live residual {residual_id}: invalid blocker axis")
        for axis in axes:
            blockers[axis].add(residual_id)
        string_list(row["required_evidence"], label=f"provider/live residual {residual_id} required evidence")
        nonempty_string(row["owner"], label=f"provider/live residual {residual_id} owner")
    if not external_or_live.issubset(covered):
        raise ContractError(f"provider/live residuals: unreported live/external classification rows: {sorted(external_or_live - covered)}")
    required_live = REQUIRED_LIVE_RESIDUALS & set(classification)
    if not required_live.issubset(covered):
        raise ContractError("provider/live residuals: required High live operational rows were hidden")
    return by_id, blockers


def _validate_verdicts(
    verdicts: dict[str, Any],
    final_commit: str,
    evidence_cutoff: str,
    blockers: dict[str, set[str]],
    residual_count: int,
) -> None:
    exact_keys(
        verdicts,
        {
            "schema_version",
            "candidate_final_commit",
            "evidence_cutoff_at",
            "candidate_security",
            "merge",
            "go_to_deploy",
            "full_production_go",
            "ready_for_commit_push_deploy_authorization",
        },
        label="four verdicts",
    )
    if verdicts["schema_version"] != 1 or verdicts["candidate_final_commit"] != final_commit or verdicts["evidence_cutoff_at"] != evidence_cutoff:
        raise ContractError("four verdicts: version/final identity/cutoff mismatch")
    axes = {
        "candidate_security": {"PASS", "FAIL"},
        "merge": {"READY", "BLOCKED"},
        "go_to_deploy": {"GO", "NO-GO"},
        "full_production_go": {"GO", "NO-GO"},
    }
    values: dict[str, str] = {}
    reasons: dict[str, set[str]] = {}
    for axis, allowed in axes.items():
        value = exact_keys(verdicts[axis], {"value", "reason_ids"}, label=f"four verdicts {axis}")
        if value["value"] not in allowed:
            raise ContractError(f"four verdicts: invalid {axis} value")
        values[axis] = value["value"]
        reasons[axis] = set(string_list(value["reason_ids"], label=f"four verdicts {axis} reasons", allow_empty=True))
    if values["candidate_security"] != "PASS" or values["merge"] != "READY":
        raise ContractError("four verdicts: a complete post-fix package requires candidate PASS and merge READY")
    positive = {"candidate_security": "PASS", "merge": "READY", "go_to_deploy": "GO", "full_production_go": "GO"}
    for axis, blocking_ids in blockers.items():
        if blocking_ids and values[axis] == positive[axis]:
            raise ContractError(f"four verdicts: positive {axis} hides blocking provider/live residuals")
        if blocking_ids and not blocking_ids.issubset(reasons[axis]):
            raise ContractError(f"four verdicts: {axis} reasons omit blocking residual IDs")
    if residual_count and values["full_production_go"] == "GO":
        raise ContractError("four verdicts: full production GO cannot coexist with unverified residuals")
    expected_ready = "YES" if values["go_to_deploy"] == "GO" else "NO"
    if verdicts["ready_for_commit_push_deploy_authorization"] != expected_ready:
        raise ContractError("four verdicts: authorization readiness is inconsistent with go_to_deploy")


def _derive_finding_map(
    group_rows: list[dict[str, Any]], test_receipts: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for group in sorted(group_rows, key=lambda row: row["group_id"]):
        receipt_ids: list[str] = []
        for field in GROUP_RECEIPT_FIELDS:
            receipt_ids.extend(group[field])
        receipt_ids = sorted(set(receipt_ids))
        if any(item not in test_receipts for item in receipt_ids):
            raise ContractError("finding map: fix-group references an unknown test receipt")
        for canonical_id in group["canonical_ids"]:
            result.append(
                {
                    "schema_version": 1,
                    "canonical_id": canonical_id,
                    "group_id": group["group_id"],
                    "cohort_commit": group["cohort_commit"],
                    "final_commit": group["final_commit"],
                    "test_receipt_ids": receipt_ids,
                }
            )
    return sorted(result, key=lambda row: row["canonical_id"])


def _validate_dataset(
    *,
    baseline: Baseline,
    group_map_rows: list[dict[str, Any]],
    classification_rows: list[dict[str, Any]],
    fix_group_rows: list[dict[str, Any]],
    test_receipt_rows: list[dict[str, Any]],
    pre_fix_receipt: dict[str, Any],
    local_closure_rows: list[dict[str, Any]],
    documentation_receipt: dict[str, Any],
    semantic_receipt: dict[str, Any],
    semantic_path: Path,
    matrices_bytes: bytes,
    verdicts: dict[str, Any],
    residual_rows: list[dict[str, Any]],
    artifact_root: Path,
    candidate_repo: Path,
    final_commit: str,
    evidence_cutoff: str,
    semantic_receipt_sha256: str,
) -> tuple[list[dict[str, Any]], dict[str, Path], dict[str, Path], dict[str, int]]:
    classification, external_or_live = _validate_classification(classification_rows, baseline, final_commit)
    group_ids = {row["group_id"] for row in group_map_rows}
    receipts, test_logs = _validate_test_receipts(test_receipt_rows, artifact_root, final_commit, group_ids)
    equivalence = _validate_fix_groups(fix_group_rows, group_map_rows, receipts, candidate_repo, final_commit)
    pre_fix_logs = _validate_pre_fix_receipt(pre_fix_receipt, artifact_root, baseline, group_ids)
    _validate_local_closures(local_closure_rows, baseline, classification, final_commit, candidate_repo, receipts)
    _validate_documentation(documentation_receipt, final_commit, candidate_repo, receipts)
    _validate_semantic(semantic_receipt, final_commit, semantic_path, semantic_receipt_sha256)
    _validate_matrices(matrices_bytes, baseline)
    _, blockers = _validate_residuals(residual_rows, classification, external_or_live, final_commit)
    _validate_verdicts(verdicts, final_commit, evidence_cutoff, blockers, len(residual_rows))
    counts = {
        "classification_rows": len(classification_rows),
        "canonical_candidates": len(baseline.registry),
        "reportable": len(baseline.reportable_ids),
        "suppressed": len(baseline.suppressed_ids),
        "fix_groups": len(fix_group_rows),
        "inventory_rows": baseline.inventory_count,
        "provider_live_residuals": len(residual_rows),
    }
    return equivalence, test_logs, pre_fix_logs, counts


def validate_source_inputs(
    *,
    baseline: Path,
    group_map: Path,
    handoff: Path,
    candidate_repo: Path,
    semantic_receipt_sha256: str,
) -> ValidatedInputs:
    baseline_data = _validate_baseline(baseline)
    group_rows, group_hash = _validate_group_map(group_map, baseline_data.reportable_ids)
    handoff_value, files, hashes = _validate_handoff_manifest(handoff)
    final_commit, final_tree = _validate_candidate(candidate_repo, baseline_data, handoff_value["candidate_final_commit"])
    classification_rows = load_jsonl(files["postfix_classification_ledger"], label="post-fix classification")
    fix_group_rows = load_jsonl(files["fix_group_ledger"], label="fix-group ledger")
    test_rows = load_jsonl(files["test_receipt_registry"], label="test receipt registry")
    pre_fix = load_json(files["pre_fix_negative_receipt"], label="pre-fix negative receipt")
    closures = load_jsonl(files["local_condition_closure"], label="local condition closure")
    documentation = load_json(files["documentation_alignment_receipt"], label="documentation alignment receipt")
    semantic = load_json(files["semantic_completion_receipt"], label="semantic completion receipt")
    matrices_bytes = read_regular_bytes(files["required_matrices"], label="required matrices")
    verdicts = load_json(files["four_verdicts"], label="four verdicts")
    residuals = load_jsonl(files["provider_live_residuals"], label="provider/live residuals")
    equivalence, test_logs, pre_fix_logs, counts = _validate_dataset(
        baseline=baseline_data,
        group_map_rows=group_rows,
        classification_rows=classification_rows,
        fix_group_rows=fix_group_rows,
        test_receipt_rows=test_rows,
        pre_fix_receipt=pre_fix,
        local_closure_rows=closures,
        documentation_receipt=documentation,
        semantic_receipt=semantic,
        semantic_path=files["semantic_completion_receipt"],
        matrices_bytes=matrices_bytes,
        verdicts=verdicts,
        residual_rows=residuals,
        artifact_root=handoff.parent,
        candidate_repo=candidate_repo,
        final_commit=final_commit,
        evidence_cutoff=handoff_value["evidence_cutoff_at"],
        semantic_receipt_sha256=semantic_receipt_sha256,
    )
    return ValidatedInputs(
        baseline=baseline_data,
        group_map_path=group_map,
        group_map_rows=group_rows,
        group_map_sha256=group_hash,
        handoff_path=handoff,
        handoff_sha256=sha256_file(handoff, label="handoff manifest"),
        handoff_file_paths=files,
        handoff_file_sha256=hashes,
        evidence_cutoff_at=handoff_value["evidence_cutoff_at"],
        candidate_repo=candidate_repo,
        candidate_final_commit=final_commit,
        candidate_final_tree=final_tree,
        classification_rows=classification_rows,
        fix_group_rows=fix_group_rows,
        test_receipt_rows=test_rows,
        pre_fix_receipt=pre_fix,
        local_closure_rows=closures,
        documentation_receipt=documentation,
        semantic_receipt=semantic,
        matrices_bytes=matrices_bytes,
        verdicts=verdicts,
        residual_rows=residuals,
        equivalence_records=equivalence,
        test_log_sources=test_logs,
        pre_fix_log_sources=pre_fix_logs,
        counts=counts,
    )


def expected_baseline_binding(data: Baseline, group_map_sha256: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "authoritative_candidate_commit": data.candidate_commit,
        "authoritative_candidate_tree": data.candidate_tree,
        "sha256": {
            "baseline_manifest": data.manifest_sha256,
            "finding_classification_ledger": data.classification_sha256,
            "canonical_candidate_registry": data.registry_sha256,
            "inventory_ledger": data.inventory_sha256,
            "matrix_schema": data.matrix_schema_sha256,
            "security_fix_group_map": group_map_sha256,
        },
        "cardinalities": {
            "classification_rows": 341,
            "canonical_candidates": 240,
            "reportable": 135,
            "suppressed": 105,
            "fix_groups": 77,
            "inventory_rows": 134,
            "matrices": 15,
        },
    }


def validate_package(
    *,
    package: Path,
    baseline: Path,
    group_map: Path,
    candidate_repo: Path,
    semantic_receipt_sha256: str,
) -> dict[str, Any]:
    manifest = validate_manifest(package, exact=True, required=PACKAGE_REQUIRED_FILES - {"MANIFEST.sha256"})
    baseline_data = _validate_baseline(baseline)
    group_rows, group_hash = _validate_group_map(group_map, baseline_data.reportable_ids)
    final_commit, final_tree = _validate_candidate(
        candidate_repo,
        baseline_data,
        load_json(package / "receipts/candidate_identity.json", label="candidate identity").get("final_commit"),
    )
    binding = load_json(package / "baseline/baseline_binding.json", label="baseline binding")
    if binding != expected_baseline_binding(baseline_data, group_hash):
        raise ContractError("package: baseline binding is stale")
    packaged_group_map = load_jsonl(package / "baseline/security_fix_groups_v1.jsonl", label="packaged fix-group map")
    if packaged_group_map != group_rows:
        raise ContractError("package: packaged fix-group map differs from caller trust root")
    packaged_registry = load_jsonl(
        package / "evidence/validation/canonical_candidate_registry.jsonl",
        label="packaged canonical registry",
    )
    if packaged_registry != baseline_data.registry:
        raise ContractError("package: canonical registry differs from baseline")
    packaged_matrix_schema = load_json(package / "schemas/matrix-schema-v1.json", label="packaged matrix schema")
    if packaged_matrix_schema != baseline_data.matrix_schema:
        raise ContractError("package: matrix schema differs from baseline")

    classification_rows = load_jsonl(
        package / "evidence/remediation/finding_classification_ledger.jsonl",
        label="packaged classification",
    )
    fix_rows = load_jsonl(package / "evidence/remediation/fix_group_ledger_v1.jsonl", label="packaged fix groups")
    test_rows = load_jsonl(package / "evidence/test/test_receipt_registry_v1.jsonl", label="packaged test receipts")
    pre_fix = load_json(package / "evidence/test/pre_fix_negative_receipt.json", label="packaged pre-fix receipt")
    closure_rows = load_jsonl(
        package / "evidence/remediation/local_condition_closure.jsonl",
        label="packaged local closures",
    )
    documentation = load_json(
        package / "evidence/remediation/documentation_alignment_receipt.json",
        label="packaged documentation receipt",
    )
    semantic_path = package / "evidence/validation/semantic_completion_receipt.json"
    semantic = load_json(semantic_path, label="packaged semantic receipt")
    matrices_bytes = read_regular_bytes(package / "required_matrices.md", label="packaged matrices")
    verdicts = load_json(package / "four_verdicts_v1.json", label="packaged four verdicts")
    residuals = load_jsonl(
        package / "evidence/validation/provider_live_residuals.jsonl",
        label="packaged residuals",
    )
    evidence_cutoff = verdicts.get("evidence_cutoff_at")
    if not isinstance(evidence_cutoff, str):
        raise ContractError("package: verdict cutoff is missing")
    equivalence, _, _, counts = _validate_dataset(
        baseline=baseline_data,
        group_map_rows=group_rows,
        classification_rows=classification_rows,
        fix_group_rows=fix_rows,
        test_receipt_rows=test_rows,
        pre_fix_receipt=pre_fix,
        local_closure_rows=closure_rows,
        documentation_receipt=documentation,
        semantic_receipt=semantic,
        semantic_path=semantic_path,
        matrices_bytes=matrices_bytes,
        verdicts=verdicts,
        residual_rows=residuals,
        artifact_root=package,
        candidate_repo=candidate_repo,
        final_commit=final_commit,
        evidence_cutoff=evidence_cutoff,
        semantic_receipt_sha256=semantic_receipt_sha256,
    )

    finding_map = load_jsonl(
        package / "evidence/remediation/finding_fix_commit_test_v1.jsonl",
        label="packaged finding map",
    )
    receipts_by_id = _unique_rows(test_rows, "receipt_id", label="packaged test receipts")
    if finding_map != _derive_finding_map(fix_rows, receipts_by_id):
        raise ContractError("package: finding-to-fix-to-commit-to-test map is stale")
    if len(finding_map) != 135 or {row["canonical_id"] for row in finding_map} != set(baseline_data.reportable_ids):
        raise ContractError("package: finding map is not the exact reportable projection")

    candidate_identity = load_json(package / "receipts/candidate_identity.json", label="candidate identity")
    exact_keys(
        candidate_identity,
        {"schema_version", "final_commit", "final_tree", "worktree_clean", "cohort_final_equivalence"},
        label="candidate identity",
    )
    expected_equivalence = sorted(equivalence, key=lambda row: row["group_id"])
    if (
        candidate_identity["schema_version"] != 1
        or candidate_identity["final_commit"] != final_commit
        or candidate_identity["final_tree"] != final_tree
        or candidate_identity["worktree_clean"] is not True
        or candidate_identity["cohort_final_equivalence"] != expected_equivalence
    ):
        raise ContractError("package: candidate identity/equivalence receipt is stale")

    core_excluded = {"MANIFEST.sha256", "receipts/build_receipt.json", "receipts/replay_receipt.json"}
    core_index = tree_index(package, exclude=core_excluded)
    core_hash = sha256_bytes(canonical_json_bytes(core_index))
    replay = load_json(package / "receipts/replay_receipt.json", label="replay receipt")
    if replay != {
        "schema_version": 1,
        "replay_count": 2,
        "byte_identical": True,
        "core_index_sha256": core_hash,
    }:
        raise ContractError("package: replay receipt is inconsistent")
    build = load_json(package / "receipts/build_receipt.json", label="build receipt")
    if not isinstance(build, dict):
        raise ContractError("package: build receipt is malformed")
    if (
        build.get("schema_version") != 1
        or build.get("tool") != "ultra-postfix-evidence-builder"
        or build.get("candidate_final_commit") != final_commit
        or build.get("candidate_final_tree") != final_tree
        or build.get("evidence_cutoff_at") != evidence_cutoff
        or build.get("semantic_receipt_sha256") != semantic_receipt_sha256
        or build.get("core_index_sha256") != core_hash
        or build.get("counts") != counts
    ):
        raise ContractError("package: build receipt is inconsistent")
    return {
        "ok": True,
        "package_manifest_sha256": sha256_file(package / "MANIFEST.sha256", label="package manifest"),
        "manifest_entries": len(manifest),
        "candidate_final_commit": final_commit,
        "candidate_final_tree": final_tree,
        "counts": counts,
        "semantic_completion": "SATURATED/STOP",
        "replay_count": 2,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--group-map", type=Path, required=True)
    parser.add_argument("--candidate-repo", type=Path, required=True)
    parser.add_argument("--semantic-receipt-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        result = validate_package(
            package=arguments.package,
            baseline=arguments.baseline,
            group_map=arguments.group_map,
            candidate_repo=arguments.candidate_repo,
            semantic_receipt_sha256=arguments.semantic_receipt_sha256,
        )
    except ContractError as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
