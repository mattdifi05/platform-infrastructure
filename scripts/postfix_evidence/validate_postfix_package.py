#!/usr/bin/env python3
"""Validate Ultra post-fix source inputs or a published evidence package."""

from __future__ import annotations

import argparse
import copy
import json
import re
import shutil
import sys
from datetime import datetime, timezone
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
    commit_delta_records,
    evidence_repo_path,
    ensure_ancestor,
    ensure_path_at_commit,
    exact_keys,
    git,
    git_head,
    git_text,
    git_tree,
    load_json_bytes,
    load_jsonl_bytes,
    nonempty_string,
    read_regular_bytes,
    read_regular_under,
    scan_secret_bytes,
    resolve_commit,
    safe_relative,
    sha256_bytes,
    sha256_file,
    string_list,
    validate_manifest_snapshot,
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

HANDOFF_ARCHIVE_PATHS = {
    "postfix_classification_ledger": "receipts/input/handoff/postfix_classification_ledger.jsonl",
    "fix_group_ledger": "receipts/input/handoff/fix_group_ledger.jsonl",
    "test_receipt_registry": "receipts/input/handoff/test_receipt_registry.jsonl",
    "pre_fix_negative_receipt": "receipts/input/handoff/pre_fix_negative_receipt.json",
    "local_condition_closure": "receipts/input/handoff/local_condition_closure.jsonl",
    "documentation_alignment_receipt": "receipts/input/handoff/documentation_alignment_receipt.json",
    "semantic_completion_receipt": "receipts/input/handoff/semantic_completion_receipt.json",
    "required_matrices": "receipts/input/handoff/required_matrices.md",
    "four_verdicts": "receipts/input/handoff/four_verdicts.json",
    "provider_live_residuals": "receipts/input/handoff/provider_live_residuals.jsonl",
}

BASELINE_MANIFEST_ARCHIVE_PATH = "receipts/input/baseline/MANIFEST.sha256"
GROUP_MAP_ARCHIVE_PATH = "receipts/input/security_fix_groups_v1.jsonl"
HANDOFF_MANIFEST_ARCHIVE_PATH = "receipts/input/handoff/handoff-v1.json"

TOOL_SOURCE_NAMES = (
    "build_postfix_package.py",
    "common.py",
    "validate_postfix_package.py",
    "handoff-v1.schema.json",
)
TOOL_SOURCE_PACKAGE_PATHS = {
    name: f"validators/{name}" for name in TOOL_SOURCE_NAMES
}

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

REQUIRED_PROVIDER_RESIDUALS = frozenset({"PROVIDER-003"})

EXTERNAL_PENDING_LOCAL_SUPPORT = {
    "DOC-EVD-001": {
        "local_support_kind": "inventory-ownership-matrix",
        "external_residual_id": "GOV-DOC-EVD-001",
        "required_evidence": "named owner and substitute acknowledgement",
    },
    "DOC-EVD-002": {
        "local_support_kind": "versioned-runbook-catalog",
        "external_residual_id": "GOV-DOC-EVD-002",
        "required_evidence": "independent operator drill receipts bound to exact approved artifacts",
    },
}

EXTERNAL_CATEGORIES = frozenset(
    {
        "PROVIDER-EXTERNAL",
        "LIVE-OPERATIONAL-FINDING",
        "HARDWARE-MAINTENANCE",
        "DEPLOYMENT-PROCEDURE-FINDING",
    }
)

CI_CHECK_IDS = (
    "four-required-checks",
    "actionlint",
    "governance",
    "supply-chain",
    "action-lock",
    "static-scan",
    "secret-scan",
    "coverage",
    "portability",
    "maintainability",
    "testing",
    "ha",
    "readiness",
    "functional",
    "provider-auth",
    "status",
    "catalog",
    "sse",
    "wrapper-allowlist",
    "hard-037-binding",
)

T23_BLOCKER_SLUGS = (
    "vps-bootstrap-applied",
    "vps-hardening-applied",
    "vps-host-readiness",
    "pre-go-live-evidence-complete",
    "runtime-fingerprint-exact",
    "github-actions-run-success",
    "secret-rotation-evidence",
    "disaster-recovery-rpo-rto-offsite",
    "real-alert-delivery",
    "external-uptime-provider",
    "public-load-benchmark",
    "release-evidence-and-rollback",
    "cloudflare-access-admin-verified",
)

MATRIX_FIRST_COLUMNS = (
    "inventory_id",
    "task_id",
    "component_id",
    "component",
    "container_name",
    "store_id",
    "record_id",
    "identity_id",
    "secret_id",
    "backup_id",
    "check_id",
    "task_id",
    "blocker_slug",
    "finding_id",
    "finding_id",
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

PHASE_SEMANTIC_ANCHOR = {
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

OFFLINE_SANDBOX = {
    "mode": "offline-read-only",
    "network": False,
    "docker": False,
    "live": False,
    "provider": False,
    "secrets": False,
    "filesystem_write": False,
}

SAFE_RECEIPT_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9._-]{0,127}$")
SECRET_COMMAND_RE = re.compile(
    r"(?i)(?:password|passwd|api[_-]?key|access[_-]?token|private[_-]?key)\s*=\s*.+"
)

PACKAGE_STATIC_FILES = frozenset(
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
        BASELINE_MANIFEST_ARCHIVE_PATH,
        GROUP_MAP_ARCHIVE_PATH,
        HANDOFF_MANIFEST_ARCHIVE_PATH,
        *HANDOFF_ARCHIVE_PATHS.values(),
        *TOOL_SOURCE_PACKAGE_PATHS.values(),
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
    inventory_ids: frozenset[str]
    manifest_bytes: bytes
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
    group_map_bytes: bytes
    handoff_path: Path
    handoff_sha256: str
    handoff_bytes: bytes
    handoff_file_paths: dict[str, Path]
    handoff_file_sha256: dict[str, str]
    handoff_file_bytes: dict[str, bytes]
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
    test_log_bytes: dict[str, bytes]
    pre_fix_log_bytes: dict[str, bytes]
    counts: dict[str, int]


def expected_package_payload_paths(
    test_receipt_rows: list[dict[str, Any]],
    pre_fix_receipt: dict[str, Any],
) -> frozenset[str]:
    paths = set(PACKAGE_STATIC_FILES)
    paths.discard("MANIFEST.sha256")
    for index, row in enumerate(test_receipt_rows, start=1):
        receipt_id = row.get("receipt_id") if isinstance(row, dict) else None
        if not isinstance(receipt_id, str) or SAFE_RECEIPT_ID_RE.fullmatch(receipt_id) is None:
            raise ContractError(f"package allowlist: unsafe test receipt identity at row {index}")
        paths.add(f"evidence/test/logs/{receipt_id}.log")
    executions = pre_fix_receipt.get("executions") if isinstance(pre_fix_receipt, dict) else None
    if not isinstance(executions, list):
        raise ContractError("package allowlist: pre-fix executions are missing")
    for index, row in enumerate(executions, start=1):
        group_id = row.get("group_id") if isinstance(row, dict) else None
        if not isinstance(group_id, str) or re.fullmatch(r"FG-[0-9]{3}", group_id) is None:
            raise ContractError(f"package allowlist: unsafe pre-fix group identity at row {index}")
        paths.add(f"evidence/test/pre-fix/{group_id}.log")
    return frozenset(paths)


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
    if root.is_symlink() or not root.is_dir():
        raise ContractError("baseline: trust root must be a real directory")
    required = {
        "finding_classification_ledger.jsonl",
        "inventory_ledger.jsonl",
        "evidence/validation/canonical_candidate_registry.jsonl",
        "schemas/matrix-schema-v1.json",
    }
    snapshot = validate_manifest_snapshot(root, exact=False, required=required)
    classification_bytes = snapshot.files["finding_classification_ledger.jsonl"]
    registry_bytes = snapshot.files["evidence/validation/canonical_candidate_registry.jsonl"]
    inventory_bytes = snapshot.files["inventory_ledger.jsonl"]
    matrix_bytes = snapshot.files["schemas/matrix-schema-v1.json"]
    rows = load_jsonl_bytes(classification_bytes, label="baseline classification")
    by_id = _unique_rows(rows, "id", label="baseline classification")
    if len(rows) != 341:
        raise ContractError("baseline: authoritative classification cardinality is not 341")

    registry = load_jsonl_bytes(registry_bytes, label="baseline canonical registry")
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

    inventory = load_jsonl_bytes(inventory_bytes, label="baseline inventory")
    if len(inventory) != 134:
        raise ContractError("baseline: inventory cardinality is not 134")
    inventory_ids: list[str] = []
    for index, row in enumerate(inventory, start=1):
        nested = row.get("inventory")
        inventory_id = nested.get("id") if isinstance(nested, dict) else row.get("id")
        if not isinstance(inventory_id, str) or not inventory_id:
            raise ContractError(f"baseline inventory:{index}: missing inventory identity")
        inventory_ids.append(inventory_id)
    if len(set(inventory_ids)) != 134:
        raise ContractError("baseline: inventory identities are not unique")
    matrix_schema = load_json_bytes(matrix_bytes, label="baseline matrix schema")
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
        inventory_ids=frozenset(inventory_ids),
        manifest_bytes=snapshot.manifest_bytes,
        manifest_sha256=sha256_bytes(snapshot.manifest_bytes),
        classification_sha256=sha256_bytes(classification_bytes),
        registry_sha256=sha256_bytes(registry_bytes),
        inventory_sha256=sha256_bytes(inventory_bytes),
        matrix_schema_sha256=sha256_bytes(matrix_bytes),
    )


def _validate_matrix_schema(value: Any) -> None:
    exact_keys(value, {"matrix_schema_version", "fixed_sets", "matrices"}, label="matrix schema")
    if value.get("matrix_schema_version") != 1:
        raise ContractError("matrix schema: unsupported version")
    fixed_sets = exact_keys(
        value["fixed_sets"],
        {"ci_check_ids", "t23_blocker_slugs"},
        label="matrix schema fixed sets",
    )
    ci_ids = string_list(fixed_sets["ci_check_ids"], label="matrix schema CI check IDs")
    blocker_slugs = string_list(
        fixed_sets["t23_blocker_slugs"], label="matrix schema T23 blocker slugs"
    )
    if ci_ids != list(CI_CHECK_IDS) or blocker_slugs != list(T23_BLOCKER_SLUGS):
        raise ContractError("matrix schema: fixed CI/T23 sets differ from the authoritative contract")
    matrices = value.get("matrices")
    if not isinstance(matrices, list) or len(matrices) != 15:
        raise ContractError("matrix schema: expected exactly M01 through M15")
    expected_numbers = list(range(1, 16))
    actual_numbers: list[int] = []
    for matrix_index, row in enumerate(matrices):
        exact_keys(
            row,
            {"id", "columns", "boolean_columns", "exact_count", "minimum_count"},
            label="matrix schema row",
        )
        matrix_id = row.get("id")
        if not isinstance(matrix_id, str) or re.fullmatch(r"M[0-9]{2}-[A-Z0-9-]+", matrix_id) is None:
            raise ContractError("matrix schema: invalid matrix ID")
        actual_numbers.append(int(matrix_id[1:3]))
        columns = row.get("columns")
        if not isinstance(columns, list) or not columns or any(not isinstance(item, str) for item in columns):
            raise ContractError(f"matrix schema: invalid columns for {matrix_id}")
        if len(set(columns)) != len(columns):
            raise ContractError(f"matrix schema: duplicate columns for {matrix_id}")
        if columns[0] != MATRIX_FIRST_COLUMNS[matrix_index]:
            raise ContractError(f"matrix schema: wrong semantic identity column for {matrix_id}")
        boolean_columns = row.get("boolean_columns")
        if not isinstance(boolean_columns, list) or not set(boolean_columns).issubset(columns):
            raise ContractError(f"matrix schema: invalid boolean columns for {matrix_id}")
        if row.get("exact_count") is not None and type(row.get("exact_count")) is not int:
            raise ContractError(f"matrix schema: invalid exact count for {matrix_id}")
        if type(row.get("minimum_count")) is not int or row["minimum_count"] < 0:
            raise ContractError(f"matrix schema: invalid minimum count for {matrix_id}")
        required_exact = {2: 23, 5: 34, 12: 6, 13: 13}.get(matrix_index + 1)
        if required_exact is not None and row["exact_count"] != required_exact:
            raise ContractError(f"matrix schema: authoritative exact count changed for {matrix_id}")
        if matrix_index + 1 == 11 and row["minimum_count"] < len(CI_CHECK_IDS):
            raise ContractError("matrix schema: M11 minimum does not cover the fixed CI set")
    if actual_numbers != expected_numbers:
        raise ContractError("matrix schema: matrix IDs are not ordered M01 through M15")


def _validate_group_map(
    path: Path,
    reportable_ids: frozenset[str],
) -> tuple[list[dict[str, Any]], str, bytes]:
    payload = read_regular_bytes(path, label="fix-group map")
    rows = load_jsonl_bytes(payload, label="fix-group map")
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
    return [by_id[group_id] for group_id in sorted(by_id)], sha256_bytes(payload), payload


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


def _validate_handoff_manifest(
    path: Path,
) -> tuple[dict[str, Any], dict[str, Path], dict[str, str], dict[str, bytes], bytes]:
    handoff_bytes = read_regular_bytes(path, label="handoff manifest")
    scan_secret_bytes(handoff_bytes, label="handoff manifest")
    handoff = load_json_bytes(handoff_bytes, label="handoff manifest")
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
    snapshots: dict[str, bytes] = {}
    root = path.parent.resolve(strict=True)
    for key in HANDOFF_FILE_KEYS:
        entry = exact_keys(files[key], {"path", "sha256"}, label=f"handoff file {key}")
        if not isinstance(entry["sha256"], str) or SHA256_RE.fullmatch(entry["sha256"]) is None:
            raise ContractError(f"handoff file {key}: invalid SHA-256")
        relative = safe_relative(entry["path"], label=f"handoff file {key}")
        payload = read_regular_under(path.parent, relative.as_posix(), label=f"handoff file {key}")
        actual = sha256_bytes(payload)
        if actual != entry["sha256"]:
            raise ContractError(f"handoff file {key}: stale SHA-256")
        scan_secret_bytes(payload, label=f"handoff file {key}")
        resolved[key] = root / Path(*relative.parts)
        hashes[key] = actual
        snapshots[key] = payload
    return handoff, resolved, hashes, snapshots, handoff_bytes


def _validate_classification(
    rows: list[dict[str, Any]], baseline: Baseline, final_commit: str
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    by_id = _unique_rows(rows, "id", label="post-fix classification")
    if len(rows) != 341 or set(by_id) != set(baseline.by_id):
        raise ContractError("post-fix classification: exact 341-row baseline universe was not preserved")
    boolean_fields = (
        "candidate_affected",
        "live_affected",
        "corrected_in_t1_t23",
        "is_new",
        "blocks_merge",
        "blocks_deploy",
        "blocks_go_to_deploy",
        "blocks_only_production_go",
    )
    for item_id, row in by_id.items():
        prior = baseline.by_id[item_id]
        if set(row) != set(prior):
            raise ContractError(f"post-fix classification: schema surface changed for {item_id}")
        if row.get("schema_version") != 2:
            raise ContractError(f"post-fix classification: unsupported schema version for {item_id}")
        if any(type(row.get(field)) is not bool for field in boolean_fields):
            raise ContractError(f"post-fix classification: invalid boolean field for {item_id}")
        if not isinstance(row.get("affected_scope"), list) or any(
            not isinstance(scope, str) for scope in row["affected_scope"]
        ):
            raise ContractError(f"post-fix classification: invalid affected scope for {item_id}")
        prior = baseline.by_id[item_id]
        if prior.get("category") in EXTERNAL_CATEGORIES or prior.get("live_affected") is True:
            for field in (
                "category",
                "candidate_affected",
                "live_affected",
                "blocks_merge",
                "blocks_deploy",
                "blocks_go_to_deploy",
                "blocks_only_production_go",
                "affected_scope",
            ):
                if row.get(field) != prior.get(field):
                    raise ContractError(
                        f"post-fix classification: external/live boundary was weakened for {item_id} ({field})"
                    )
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
        if row.get("candidate_affected") is True:
            raise ContractError(f"post-fix classification: local candidate/merge blocker remains: {item_id}")
        if row.get("blocks_merge") is True and row.get("category") not in EXTERNAL_CATEGORIES:
            raise ContractError(f"post-fix classification: local candidate/merge blocker remains: {item_id}")
        if (
            row.get("category") in EXTERNAL_CATEGORIES
            or row.get("live_affected") is True
            or row.get("blocks_merge") is True
            or row.get("blocks_deploy") is True
            or row.get("blocks_go_to_deploy") is True
            or row.get("blocks_only_production_go") is True
        ):
            external_or_live.add(item_id)
    return by_id, external_or_live


def _validate_log_reference(
    root: Path,
    value: Any,
    *,
    label: str,
    artifact_snapshots: dict[str, bytes] | None = None,
) -> bytes:
    entry = exact_keys(value, {"path", "sha256"}, label=label)
    if not isinstance(entry["sha256"], str) or SHA256_RE.fullmatch(entry["sha256"]) is None:
        raise ContractError(f"{label}: invalid SHA-256")
    relative = safe_relative(entry["path"], label=f"{label} path").as_posix()
    if artifact_snapshots is None:
        payload = read_regular_under(root, relative, label=label)
    else:
        try:
            payload = artifact_snapshots[relative]
        except KeyError as error:
            raise ContractError(f"{label}: log is absent from the package snapshot") from error
    if sha256_bytes(payload) != entry["sha256"]:
        raise ContractError(f"{label}: stale log SHA-256")
    scan_secret_bytes(payload, label=label)
    return payload


def _parse_utc_second(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or UTC_SECOND_RE.fullmatch(value) is None:
        raise ContractError(f"{label}: expected a UTC timestamp with second precision")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise ContractError(f"{label}: invalid UTC timestamp") from error
    return parsed


def _git_object_anchor(
    repo: Path,
    commit: str,
    value: Any,
    *,
    label: str,
    allowed_kinds: set[str] | None = None,
) -> tuple[str, str | None]:
    expected_keys = {"path", "mode", "sha256"}
    if allowed_kinds is not None:
        expected_keys.add("kind")
    entry = exact_keys(value, expected_keys, label=label)
    path = safe_relative(entry["path"], label=f"{label} path").as_posix()
    if not isinstance(entry["mode"], str) or re.fullmatch(r"[0-7]{6}", entry["mode"]) is None:
        raise ContractError(f"{label}: invalid Git mode")
    if not isinstance(entry["sha256"], str) or SHA256_RE.fullmatch(entry["sha256"]) is None:
        raise ContractError(f"{label}: invalid blob SHA-256")
    if allowed_kinds is not None and entry["kind"] not in allowed_kinds:
        raise ContractError(f"{label}: invalid anchor kind")
    listing = git_text(repo, "ls-tree", commit, "--", path)
    match = re.fullmatch(r"([0-7]{6}) (?:blob|commit) [0-9a-f]+\t.+", listing)
    if match is None or match.group(1) != entry["mode"]:
        raise ContractError(f"{label}: path/mode is absent at commit")
    payload = git(repo, "show", f"{commit}:{path}")
    if sha256_bytes(payload) != entry["sha256"]:
        raise ContractError(f"{label}: content does not match script-at-commit/blob anchor")
    return path, entry.get("kind")


def _validate_cwd_at_commit(repo: Path, commit: str, value: Any, *, label: str) -> str:
    cwd = nonempty_string(value, label=label)
    if cwd == ".":
        return cwd
    path = safe_relative(cwd, label=label).as_posix()
    object_type = git_text(repo, "cat-file", "-t", f"{commit}:{path}")
    if object_type != "tree":
        raise ContractError(f"{label}: cwd is not a directory at commit")
    return path


def _validate_executable(value: Any, argv: list[str], *, label: str) -> None:
    entry = exact_keys(value, {"argv0", "resolved_path", "sha256"}, label=label)
    argv0 = nonempty_string(entry["argv0"], label=f"{label} argv0")
    if argv[0] != argv0:
        raise ContractError(f"{label}: argv[0] does not match executable identity")
    resolved_value = nonempty_string(entry["resolved_path"], label=f"{label} resolved path")
    if not isinstance(entry["sha256"], str) or SHA256_RE.fullmatch(entry["sha256"]) is None:
        raise ContractError(f"{label}: invalid executable SHA-256")
    located = shutil.which(argv0)
    if located is None:
        raise ContractError(f"{label}: executable is unavailable")
    resolved = Path(located).resolve(strict=True)
    if str(resolved) != resolved_value or sha256_file(resolved, label=label) != entry["sha256"]:
        raise ContractError(f"{label}: executable path/hash trust root changed")


def _validate_execution_proof(
    row: dict[str, Any],
    *,
    receipt_id: str,
    phase: str,
    repo: Path,
    commit: str,
    tree: str,
    log_bytes: bytes,
    label: str,
) -> set[tuple[str, str]]:
    if row["head_commit"] != commit or row["head_tree"] != tree:
        raise ContractError(f"{label}: execution head/tree does not match the required commit")
    started = _parse_utc_second(row["started_at"], label=f"{label} start")
    ended = _parse_utc_second(row["ended_at"], label=f"{label} end")
    if ended < started:
        raise ContractError(f"{label}: execution ended before it started")
    _validate_cwd_at_commit(repo, commit, row["cwd"], label=f"{label} cwd")
    argv = string_list(row["argv"], label=f"{label} argv")
    if any("\n" in item or "\x00" in item or SECRET_COMMAND_RE.search(item) for item in argv):
        raise ContractError(f"{label}: unsafe or credential-like argv")
    _validate_executable(row["executable"], argv, label=f"{label} executable")
    script_path, _ = _git_object_anchor(
        repo,
        commit,
        row["script_at_commit"],
        label=f"{label} script-at-commit",
    )
    executable_name = Path(argv[0]).name
    if executable_name in {"python", "python3", "node", "bash", "sh"}:
        if script_path not in argv[1:]:
            raise ContractError(f"{label}: interpreter argv does not execute script-at-commit")
    elif executable_name in {"make", "gmake"}:
        script_name = Path(script_path).name
        explicit_makefile = any(
            item == script_path or item == script_name
            for index, item in enumerate(argv)
            if index > 0 and argv[index - 1] in {"-f", "--file", "--makefile"}
        )
        if script_name != "Makefile" and not explicit_makefile:
            raise ContractError(f"{label}: Make argv is not bound to script-at-commit")
    else:
        raise ContractError(f"{label}: unsupported receipt executable")
    if row["sandbox"] != OFFLINE_SANDBOX:
        raise ContractError(f"{label}: sandbox does not prove offline read-only execution")
    expected_semantic = PHASE_SEMANTIC_ANCHOR.get(phase, "pre-fix-negative-reproduced")
    semantic_anchors = string_list(row["semantic_anchors"], label=f"{label} semantic anchors")
    if semantic_anchors != [expected_semantic]:
        raise ContractError(f"{label}: semantic anchor is not exact for phase")
    artifact_rows = row["artifact_anchors"]
    if not isinstance(artifact_rows, list) or not artifact_rows:
        raise ContractError(f"{label}: artifact anchors are missing")
    artifacts: set[tuple[str, str]] = set()
    for index, anchor in enumerate(artifact_rows, start=1):
        path, kind = _git_object_anchor(
            repo,
            commit,
            anchor,
            label=f"{label} artifact anchor {index}",
            allowed_kinds={"test-script", "consumer", "documentation"},
        )
        pair = (str(kind), path)
        if pair in artifacts:
            raise ContractError(f"{label}: duplicate artifact anchor")
        artifacts.add(pair)
    if ("test-script", script_path) not in artifacts:
        raise ContractError(f"{label}: script-at-commit lacks a test-script artifact anchor")
    try:
        log_lines = log_bytes.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ContractError(f"{label}: log is not UTF-8") from error
    identity_line = (
        f"RECEIPT {receipt_id} HEAD {commit} TREE {tree} PHASE {phase} RESULT PASS"
    )
    if identity_line not in log_lines or f"ANCHOR {expected_semantic}" not in log_lines:
        raise ContractError(f"{label}: log lacks execution identity or semantic anchor")
    return artifacts


def _validate_test_receipts(
    rows: list[dict[str, Any]],
    artifact_root: Path,
    repo: Path,
    final_commit: str,
    final_tree: str,
    valid_groups: set[str],
    artifact_snapshots: dict[str, bytes] | None = None,
) -> tuple[dict[str, dict[str, Any]], dict[str, bytes]]:
    by_id = _unique_rows(rows, "receipt_id", label="test receipt registry")
    logs: dict[str, bytes] = {}
    seen_global: set[str] = set()
    allowed_phases = set(GROUP_RECEIPT_FIELDS.values()) | set(GLOBAL_TEST_PHASES)
    for receipt_id, row in by_id.items():
        if SAFE_RECEIPT_ID_RE.fullmatch(receipt_id) is None:
            raise ContractError(f"test receipt {receipt_id}: unsafe receipt ID")
        exact_keys(
            row,
            {
                "schema_version",
                "receipt_id",
                "phase",
                "scope",
                "group_ids",
                "head_commit",
                "head_tree",
                "started_at",
                "ended_at",
                "cwd",
                "argv",
                "executable",
                "script_at_commit",
                "exit_code",
                "result",
                "sandbox",
                "semantic_anchors",
                "artifact_anchors",
                "log",
            },
            label=f"test receipt {receipt_id}",
        )
        if row["schema_version"] != 1 or row["phase"] not in allowed_phases:
            raise ContractError(f"test receipt {receipt_id}: invalid schema or phase")
        if row["exit_code"] != 0 or row["result"] != "PASS":
            raise ContractError(f"test receipt {receipt_id}: result is not PASS/0")
        nonempty_string(row["scope"], label=f"test receipt {receipt_id} scope")
        groups = string_list(row["group_ids"], label=f"test receipt {receipt_id} groups", allow_empty=True)
        if not set(groups).issubset(valid_groups):
            raise ContractError(f"test receipt {receipt_id}: unknown fix group")
        if row["phase"] in GLOBAL_TEST_PHASES:
            if row["scope"] != "candidate" or groups:
                raise ContractError(f"test receipt {receipt_id}: global phase must have candidate scope")
            seen_global.add(row["phase"])
        elif not groups:
            raise ContractError(f"test receipt {receipt_id}: group phase has empty group coverage")
        logs[receipt_id] = _validate_log_reference(
            artifact_root,
            row["log"],
            label=f"test receipt {receipt_id} log",
            artifact_snapshots=artifact_snapshots,
        )
        _validate_execution_proof(
            row,
            receipt_id=receipt_id,
            phase=row["phase"],
            repo=repo,
            commit=final_commit,
            tree=final_tree,
            log_bytes=logs[receipt_id],
            label=f"test receipt {receipt_id}",
        )
    if seen_global != set(GLOBAL_TEST_PHASES):
        raise ContractError("test receipt registry: full-suite/differential/adversarial/documentation receipts are incomplete")
    return by_id, logs


def _validate_fix_groups(
    rows: list[dict[str, Any]],
    group_map_rows: list[dict[str, Any]],
    receipts: dict[str, dict[str, Any]],
    repo: Path,
    final_head: str,
    baseline_commit: str,
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
                "integration_mode",
                "cohort_commit",
                "final_commit",
                "source",
                "control",
                "sink",
                "remediation_boundary",
                "boundary_paths",
                "support_commits",
                "support_commit_mappings",
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
        integration_mode = row["integration_mode"]
        if integration_mode not in {"cherry-pick", "direct-final"}:
            raise ContractError(f"fix-group ledger {group_id}: invalid integration mode")
        for field in ("source", "control", "sink"):
            string_list(row[field], label=f"fix-group ledger {group_id} {field}")
        nonempty_string(row["remediation_boundary"], label=f"fix-group ledger {group_id} remediation boundary")
        boundary_paths = string_list(
            row["boundary_paths"],
            label=f"fix-group ledger {group_id} boundary paths",
        )
        boundary_set = {
            safe_relative(path, label=f"fix-group ledger {group_id} boundary path").as_posix()
            for path in boundary_paths
        }
        consumer_evidence = string_list(row["consumer_evidence"], label=f"fix-group ledger {group_id} consumer evidence")
        for evidence in consumer_evidence:
            ensure_path_at_commit(repo, final_head, evidence)
        consumer_paths = {evidence_repo_path(item) for item in consumer_evidence}
        if not consumer_paths.issubset(boundary_set):
            raise ContractError(
                f"fix-group ledger {group_id}: consumer evidence is outside the declared remediation boundary"
            )
        cohort = resolve_commit(repo, row["cohort_commit"], label=f"fix-group ledger {group_id} cohort commit")
        final = resolve_commit(repo, row["final_commit"], label=f"fix-group ledger {group_id} final commit")
        if final == baseline_commit:
            raise ContractError(
                f"fix-group ledger {group_id}: final commit must be post-baseline with a nonempty boundary diff"
            )
        ensure_ancestor(repo, baseline_commit, final, label=f"fix-group ledger {group_id} post-baseline final")
        if cohort == baseline_commit:
            raise ContractError(
                f"fix-group ledger {group_id}: cohort/direct commit must be post-baseline"
            )
        ensure_ancestor(repo, baseline_commit, cohort, label=f"fix-group ledger {group_id} post-baseline cohort")
        if integration_mode == "direct-final" and cohort != final:
            raise ContractError(
                f"fix-group ledger {group_id}: direct-final mode requires identical commit fields"
            )
        if integration_mode == "cherry-pick" and cohort == final:
            raise ContractError(
                f"fix-group ledger {group_id}: cohort-only SHA is not a final integration mapping"
            )
        ensure_ancestor(repo, final, final_head, label=f"fix-group ledger {group_id} final mapping")
        final_delta = commit_delta_records(repo, final)
        changed_paths = {item["path"] for item in final_delta}
        if not (changed_paths & boundary_set):
            raise ContractError(
                f"fix-group ledger {group_id}: final commit has no nonempty diff on boundary paths"
            )
        declared_supports = string_list(
            row["support_commits"],
            label=f"fix-group ledger {group_id} support commits",
        )
        resolved_supports = {
            resolve_commit(
                repo,
                value,
                label=f"fix-group ledger {group_id} support commit",
            )
            for value in declared_supports
        }
        mapping_rows = row["support_commit_mappings"]
        if not isinstance(mapping_rows, list) or not mapping_rows:
            raise ContractError(f"fix-group ledger {group_id}: support commit mappings are missing")
        support_records: list[dict[str, Any]] = []
        mapped_cohorts: set[str] = set()
        mapped_boundaries: set[str] = set()
        primary_record: dict[str, Any] | None = None
        for mapping_index, mapping in enumerate(mapping_rows, start=1):
            exact_keys(
                mapping,
                {"cohort_commit", "final_commit", "integration_mode", "boundary_paths"},
                label=f"fix-group ledger {group_id} support mapping {mapping_index}",
            )
            mapping_mode = mapping["integration_mode"]
            if mapping_mode not in {"cherry-pick", "direct-final"}:
                raise ContractError(
                    f"fix-group ledger {group_id}: invalid support integration mode"
                )
            mapping_cohort = resolve_commit(
                repo,
                mapping["cohort_commit"],
                label=f"fix-group ledger {group_id} mapped cohort commit",
            )
            mapping_final = resolve_commit(
                repo,
                mapping["final_commit"],
                label=f"fix-group ledger {group_id} mapped final commit",
            )
            if mapping_cohort in mapped_cohorts:
                raise ContractError(
                    f"fix-group ledger {group_id}: duplicate support commit mapping"
                )
            mapped_cohorts.add(mapping_cohort)
            ensure_ancestor(
                repo,
                baseline_commit,
                mapping_cohort,
                label=f"fix-group ledger {group_id} support post-baseline cohort",
            )
            ensure_ancestor(
                repo,
                baseline_commit,
                mapping_final,
                label=f"fix-group ledger {group_id} support post-baseline final",
            )
            ensure_ancestor(
                repo,
                mapping_final,
                final_head,
                label=f"fix-group ledger {group_id} support final reachability",
            )
            if mapping_cohort == baseline_commit or mapping_final == baseline_commit:
                raise ContractError(
                    f"fix-group ledger {group_id}: support mapping points at the baseline"
                )
            mapping_boundary_list = string_list(
                mapping["boundary_paths"],
                label=f"fix-group ledger {group_id} support mapping boundary",
            )
            mapping_boundary = {
                safe_relative(
                    value,
                    label=f"fix-group ledger {group_id} support mapping boundary path",
                ).as_posix()
                for value in mapping_boundary_list
            }
            if not mapping_boundary.issubset(boundary_set):
                raise ContractError(
                    f"fix-group ledger {group_id}: support mapping escapes remediation boundary"
                )
            mapping_delta = commit_delta_records(repo, mapping_final)
            mapping_changed = {item["path"] for item in mapping_delta}
            if mapping_changed != mapping_boundary:
                raise ContractError(
                    f"fix-group ledger {group_id}: support mapping boundary is not the exact nonempty final delta"
                )
            mapped_boundaries.update(mapping_boundary)
            if mapping_mode == "direct-final":
                if mapping_cohort != mapping_final:
                    raise ContractError(
                        f"fix-group ledger {group_id}: direct support mapping is not identical"
                    )
                mapping_record = {
                    "cohort_commit": mapping_cohort,
                    "final_commit": mapping_final,
                    "integration_mode": mapping_mode,
                    "boundary_paths": sorted(mapping_boundary),
                    "tree_delta_sha256": sha256_bytes(canonical_json_bytes(mapping_delta)),
                    "accepted_by": "direct-final-identity",
                }
            else:
                if mapping_cohort == mapping_final:
                    raise ContractError(
                        f"fix-group ledger {group_id}: cohort-only support SHA lacks final mapping"
                    )
                pair = (mapping_cohort, mapping_final)
                if pair not in cache:
                    cache[pair] = commit_equivalence(repo, mapping_cohort, mapping_final)
                mapping_record = {
                    "integration_mode": mapping_mode,
                    "boundary_paths": sorted(mapping_boundary),
                    **cache[pair],
                }
            support_records.append(mapping_record)
            if (
                mapping_cohort == cohort
                and mapping_final == final
                and mapping_mode == integration_mode
            ):
                primary_record = mapping_record
        if mapped_cohorts != resolved_supports:
            raise ContractError(
                f"fix-group ledger {group_id}: support commit references are not exactly mapped"
            )
        if mapped_boundaries != boundary_set:
            raise ContractError(
                f"fix-group ledger {group_id}: support mappings do not exactly cover remediation boundary paths"
            )
        if primary_record is None:
            raise ContractError(
                f"fix-group ledger {group_id}: primary cohort/final mapping is absent from support mappings"
            )
        equivalence_by_group.append(
            {
                "group_id": group_id,
                "integration_mode": integration_mode,
                "cohort_commit": cohort,
                "final_commit": final,
                "accepted_by": primary_record["accepted_by"],
                "support_commit_mappings": sorted(
                    support_records,
                    key=lambda item: (item["cohort_commit"], item["final_commit"]),
                ),
            }
        )
        for field, phase in GROUP_RECEIPT_FIELDS.items():
            receipt_ids = string_list(row[field], label=f"fix-group ledger {group_id} {field}")
            for receipt_id in receipt_ids:
                receipt = receipts.get(receipt_id)
                if receipt is None or receipt["phase"] != phase or group_id not in receipt["group_ids"]:
                    raise ContractError(f"fix-group ledger {group_id}: invalid {phase} receipt binding")
                anchored_consumers = {
                    anchor["path"]
                    for anchor in receipt["artifact_anchors"]
                    if anchor["kind"] == "consumer"
                }
                required_consumers = {evidence_repo_path(item) for item in consumer_evidence}
                if not required_consumers.issubset(anchored_consumers):
                    raise ContractError(
                        f"fix-group ledger {group_id}: {phase} receipt lacks consumer blob anchors"
                    )
    return equivalence_by_group


def _validate_pre_fix_receipt(
    receipt: dict[str, Any],
    artifact_root: Path,
    baseline: Baseline,
    group_ids: set[str],
    repo: Path,
    artifact_snapshots: dict[str, bytes] | None = None,
) -> dict[str, bytes]:
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
    logs: dict[str, bytes] = {}
    log_paths: set[str] = set()
    for index, row in enumerate(executions, start=1):
        exact_keys(
            row,
            {
                "group_id",
                "runner_kind",
                "head_commit",
                "head_tree",
                "started_at",
                "ended_at",
                "cwd",
                "argv",
                "executable",
                "script_at_commit",
                "result",
                "exit_code",
                "sandbox",
                "semantic_anchors",
                "artifact_anchors",
                "log",
            },
            label=f"pre-fix execution {index}",
        )
        group_id = row["group_id"]
        if group_id not in group_ids or group_id in seen:
            raise ContractError("pre-fix negative receipt: missing or duplicate fix-group execution")
        seen.add(group_id)
        runner_kind = row["runner_kind"]
        if runner_kind not in counts:
            raise ContractError(f"pre-fix negative receipt: invalid runner kind for {group_id}")
        counts[runner_kind] += 1
        argv = string_list(row["argv"], label=f"pre-fix execution {group_id} argv")
        executable = Path(argv[0]).name
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
        logs[group_id] = _validate_log_reference(
            artifact_root,
            log_entry,
            label=f"pre-fix execution {group_id} log",
            artifact_snapshots=artifact_snapshots,
        )
        _validate_execution_proof(
            row,
            receipt_id=group_id,
            phase="pre-fix-negative",
            repo=repo,
            commit=baseline.candidate_commit,
            tree=baseline.candidate_tree,
            log_bytes=logs[group_id],
            label=f"pre-fix execution {group_id}",
        )
        if runner_kind == "make-wrapper":
            script_path = row["script_at_commit"]["path"]
            script_payload = git(repo, "show", f"{baseline.candidate_commit}:{script_path}")
            targets = [
                item
                for item in argv[1:]
                if not item.startswith("-") and item not in {script_path, Path(script_path).name}
            ]
            if not targets:
                raise ContractError(f"pre-fix negative receipt: {group_id} Make target is missing")
            target = targets[-1]
            try:
                makefile_text = script_payload.decode("utf-8")
            except UnicodeDecodeError as error:
                raise ContractError(f"pre-fix negative receipt: {group_id} Makefile is not UTF-8") from error
            if re.search(rf"(?m)^{re.escape(target)}\s*:", makefile_text) is None:
                raise ContractError(
                    f"pre-fix negative receipt: {group_id} Make target is absent at baseline commit"
                )
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
) -> dict[str, dict[str, Any]]:
    by_id = _unique_rows(rows, "id", label="local condition closure")
    baseline_local_blockers = {
        item_id
        for item_id, row in baseline.by_id.items()
        if item_id not in baseline.reportable_ids
        and item_id not in baseline.suppressed_ids
        and row.get("category") not in EXTERNAL_CATEGORIES
        and any(
            row.get(field) is True
            for field in ("candidate_affected", "blocks_merge", "blocks_deploy", "blocks_go_to_deploy")
        )
    }
    available_required = (REQUIRED_LOCAL_CLOSURES & set(baseline.by_id)) | baseline_local_blockers
    if not available_required.issubset(by_id):
        raise ContractError(f"local condition closure: required proof rows missing: {sorted(available_required - set(by_id))}")
    pending_external: dict[str, dict[str, Any]] = {}
    base_keys = {
        "schema_version",
        "id",
        "status",
        "candidate_final_commit",
        "final_commit",
        "test_receipt_ids",
        "evidence",
    }
    for item_id, row in by_id.items():
        special = EXTERNAL_PENDING_LOCAL_SUPPORT.get(item_id)
        exact_keys(
            row,
            base_keys
            | (
                {"local_support_kind", "external_residual_id", "condition_ids"}
                if special is not None
                else set()
            ),
            label=f"local condition closure {item_id}",
        )
        expected_status = (
            "LOCAL-SUPPORT-READY-EXTERNAL-PENDING" if special is not None else "CLOSED-LOCAL"
        )
        if (
            item_id not in baseline.by_id
            or row["schema_version"] != 1
            or row["status"] != expected_status
        ):
            raise ContractError(f"local condition closure {item_id}: invalid identity or status")
        if row["candidate_final_commit"] != final_commit:
            raise ContractError(f"local condition closure {item_id}: not bound to final HEAD")
        integration = resolve_commit(repo, row["final_commit"], label=f"local condition closure {item_id} final commit")
        ensure_ancestor(repo, integration, final_commit, label=f"local condition closure {item_id}")
        test_ids = string_list(row["test_receipt_ids"], label=f"local condition closure {item_id} tests")
        if any(test_id not in receipts for test_id in test_ids):
            raise ContractError(f"local condition closure {item_id}: unknown test receipt")
        evidence_rows = string_list(row["evidence"], label=f"local condition closure {item_id} evidence")
        for evidence in evidence_rows:
            ensure_path_at_commit(repo, final_commit, evidence)
        post = classification[item_id]
        if special is None:
            if post.get("candidate_affected") is not False or any(
                post.get(field) is not False
                for field in (
                    "blocks_merge",
                    "blocks_deploy",
                    "blocks_go_to_deploy",
                    "blocks_only_production_go",
                )
            ):
                raise ContractError(f"local condition closure {item_id}: post-fix classification is not closed")
            continue

        baseline_conditions = string_list(
            baseline.by_id[item_id].get("condition_ids"),
            label=f"local condition closure {item_id} baseline conditions",
        )
        conditions = string_list(
            row["condition_ids"],
            label=f"local condition closure {item_id} conditions",
        )
        if (
            row["local_support_kind"] != special["local_support_kind"]
            or row["external_residual_id"] != special["external_residual_id"]
            or conditions != baseline_conditions
            or post.get("condition_ids") != baseline_conditions
        ):
            raise ContractError(
                f"local condition closure {item_id}: local support/residual/condition mapping is not exact"
            )
        if (
            post.get("candidate_affected") is not False
            or post.get("blocks_merge") is not False
            or post.get("blocks_deploy") is not True
            or post.get("blocks_go_to_deploy") is not True
            or post.get("blocks_only_production_go") is not False
            or not set(post.get("affected_scope", []))
            or not any(token in str(post.get("final_state", "")).upper() for token in ("PENDING", "EXTERNAL"))
        ):
            raise ContractError(
                f"local condition closure {item_id}: external acknowledgement/drill was falsely closed"
            )
        documentation_receipts = [
            receipts[test_id]
            for test_id in test_ids
            if receipts[test_id].get("phase") == "documentation-validation"
        ]
        anchored_documents = {
            anchor["path"]
            for receipt in documentation_receipts
            for anchor in receipt["artifact_anchors"]
            if anchor["kind"] == "documentation"
        }
        if not documentation_receipts or not {
            evidence_repo_path(evidence) for evidence in evidence_rows
        }.issubset(anchored_documents):
            raise ContractError(
                f"local condition closure {item_id}: local support is not anchored by documentation validation"
            )
        pending_external[item_id] = {
            "external_residual_id": row["external_residual_id"],
            "condition_ids": conditions,
            "required_evidence": special["required_evidence"],
        }
    return pending_external


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
    documentation_receipts = [
        test_receipts[item]
        for item in receipt_ids
        if item in test_receipts and test_receipts[item].get("phase") == "documentation-validation"
    ]
    if not documentation_receipts:
        raise ContractError("documentation alignment receipt: documentation validation test is missing")
    required_paths = {
        evidence_repo_path(evidence)
        for paths in topics.values()
        for evidence in paths
    }
    anchored_paths = {
        anchor["path"]
        for test_receipt in documentation_receipts
        for anchor in test_receipt["artifact_anchors"]
        if anchor["kind"] == "documentation"
    }
    if anchored_paths != required_paths:
        raise ContractError(
            "documentation alignment receipt: documentation blobs are not exactly anchored by the runner"
        )


def _validate_semantic(
    receipt: dict[str, Any],
    final_commit: str,
    payload: bytes,
    expected_sha256: str,
) -> None:
    if SHA256_RE.fullmatch(expected_sha256) is None:
        raise ContractError("semantic completion: caller trust root is not a SHA-256")
    if sha256_bytes(payload) != expected_sha256:
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
        if any(not cell.strip() for row in rows for cell in row):
            raise ContractError(f"matrices: empty semantic cell in {matrix_id}")
        if any(cell.strip().upper() == "FAKE" for row in rows for cell in row):
            raise ContractError(f"matrices: FAKE semantic cell in {matrix_id}")
        exact_count = schema["exact_count"]
        minimum_count = schema["minimum_count"]
        if exact_count is not None and len(rows) != exact_count:
            raise ContractError(f"matrices: exact row count mismatch for {matrix_id}")
        if len(rows) < minimum_count:
            raise ContractError(f"matrices: minimum row count mismatch for {matrix_id}")
        if matrix_id.startswith("M01-") and len(rows) != baseline.inventory_count:
            raise ContractError("matrices: M01 must project all 134 inventory rows")
        primary_ids = [row[0] for row in rows]
        if len(primary_ids) != len(set(primary_ids)):
            raise ContractError(f"matrices: duplicate semantic identities in {matrix_id}")
        for boolean_column in schema["boolean_columns"]:
            offset = header.index(boolean_column)
            if any(row[offset] not in {"true", "false"} for row in rows):
                raise ContractError(f"matrices: invalid boolean value in {matrix_id}.{boolean_column}")
        matrix_number = matrix_index + 1
        expected_primary: set[str] | None = None
        if matrix_number == 1:
            expected_primary = set(baseline.inventory_ids)
        elif matrix_number == 2:
            expected_primary = {f"T{number:02d}" for number in range(1, 24)}
        elif matrix_number == 11:
            expected_primary = set(CI_CHECK_IDS)
        elif matrix_number == 12:
            expected_primary = {f"T{number:02d}" for number in range(18, 24)}
        elif matrix_number == 13:
            expected_primary = set(T23_BLOCKER_SLUGS)
        elif matrix_number == 14:
            if not set(primary_ids).issubset(baseline.by_id):
                raise ContractError("matrices: M14 references unknown classification IDs")
        elif matrix_number == 15:
            expected_primary = set(baseline.reportable_ids)
            reportable_projection = set(primary_ids)
        if expected_primary is not None and set(primary_ids) != expected_primary:
            raise ContractError(f"matrices: {matrix_id} does not match its exact semantic identity set")
    if reportable_projection != set(baseline.reportable_ids):
        raise ContractError("matrices: M15 is not the exact 135-reportable-CAN projection")


def _validate_residuals(
    rows: list[dict[str, Any]],
    classification: dict[str, dict[str, Any]],
    external_or_live: set[str],
    final_commit: str,
    pending_local_support: dict[str, dict[str, Any]],
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
                "condition_ids",
                "blocks",
                "required_evidence",
                "owner",
            },
            label=f"provider/live residual {residual_id}",
        )
        if row["schema_version"] != 1 or row["candidate_final_commit"] != final_commit:
            raise ContractError(f"provider/live residual {residual_id}: identity mismatch")
        if row["locus"] not in {
            "PROVIDER-EXTERNAL",
            "LIVE-RUNTIME",
            "POST-DEPLOY",
            "HARDWARE-MAINTENANCE",
            "GOVERNANCE-EXTERNAL",
        }:
            raise ContractError(f"provider/live residual {residual_id}: invalid locus")
        if row["verification_status"] not in {"NOT-VERIFIED", "EXTERNAL-VALIDATION-REQUIRED", "POST-DEPLOY-REQUIRED"}:
            raise ContractError(f"provider/live residual {residual_id}: invalid or falsely positive status")
        ids = string_list(row["classification_ids"], label=f"provider/live residual {residual_id} classification IDs")
        if any(item not in classification for item in ids):
            raise ContractError(f"provider/live residual {residual_id}: unknown classification ID")
        conditions = string_list(
            row["condition_ids"],
            label=f"provider/live residual {residual_id} condition IDs",
            allow_empty=True,
        )
        expected_conditions = sorted(
            {
                condition
                for item_id in ids
                for condition in string_list(
                    classification[item_id].get("condition_ids"),
                    label=f"provider/live residual {residual_id} classification conditions",
                    allow_empty=True,
                )
            }
        )
        if conditions != expected_conditions:
            raise ContractError(
                f"provider/live residual {residual_id}: classification condition mapping is not exact"
            )
        overlap = covered & set(ids)
        if overlap:
            raise ContractError(
                f"provider/live residuals: duplicate classification coverage: {sorted(overlap)}"
            )
        covered.update(ids)
        axes = string_list(row["blocks"], label=f"provider/live residual {residual_id} blocker axes", allow_empty=True)
        if not set(axes).issubset(blockers):
            raise ContractError(f"provider/live residual {residual_id}: invalid blocker axis")
        derived_axes: set[str] = {"full_production_go"}
        for item_id in ids:
            classification_row = classification[item_id]
            if classification_row.get("candidate_affected") is True:
                derived_axes.add("candidate_security")
            if classification_row.get("blocks_merge") is True:
                derived_axes.add("merge")
            if (
                classification_row.get("blocks_deploy") is True
                or classification_row.get("blocks_go_to_deploy") is True
            ):
                derived_axes.add("go_to_deploy")
        if set(axes) != derived_axes:
            raise ContractError(
                f"provider/live residual {residual_id}: blocks are not the exact residual axes derived from classification"
            )
        for axis in derived_axes:
            blockers[axis].update(ids)
        string_list(row["required_evidence"], label=f"provider/live residual {residual_id} required evidence")
        nonempty_string(row["owner"], label=f"provider/live residual {residual_id} owner")
    if covered != external_or_live:
        raise ContractError(
            "provider/live residuals: coverage is not the exact live/external classification partition"
        )
    required_external = (REQUIRED_LIVE_RESIDUALS | REQUIRED_PROVIDER_RESIDUALS) & set(classification)
    if not required_external.issubset(covered):
        raise ContractError("provider/live residuals: required High/provider blocking rows were hidden")
    for item_id, mapping in pending_local_support.items():
        residual = by_id.get(mapping["external_residual_id"])
        if (
            residual is None
            or residual["locus"] != "GOVERNANCE-EXTERNAL"
            or residual["verification_status"] != "EXTERNAL-VALIDATION-REQUIRED"
            or residual["classification_ids"] != [item_id]
            or residual["condition_ids"] != mapping["condition_ids"]
            or residual["blocks"] != ["go_to_deploy", "full_production_go"]
            or residual["required_evidence"] != [mapping["required_evidence"]]
        ):
            raise ContractError(
                f"provider/live residuals: {item_id} lacks its exact GO-blocking external condition mapping"
            )
    return by_id, blockers


def _derive_verdicts(
    classification: dict[str, dict[str, Any]],
    final_commit: str,
    evidence_cutoff: str,
    residual_classification_ids: set[str],
) -> dict[str, Any]:
    candidate_reasons = sorted(
        item_id for item_id, row in classification.items() if row.get("candidate_affected") is True
    )
    merge_reasons = sorted(
        item_id for item_id, row in classification.items() if row.get("blocks_merge") is True
    )
    deploy_reasons = sorted(
        item_id
        for item_id, row in classification.items()
        if row.get("blocks_deploy") is True or row.get("blocks_go_to_deploy") is True
    )
    production_reasons = sorted(
        residual_classification_ids
        | {
            item_id
            for item_id, row in classification.items()
            if row.get("blocks_only_production_go") is True
        }
    )
    candidate_value = "FAIL" if candidate_reasons else "PASS"
    merge_value = "BLOCKED" if merge_reasons else "READY"
    deploy_value = "NO-GO" if deploy_reasons else "GO"
    production_value = "NO-GO" if production_reasons else "GO"
    ready = "YES" if candidate_value == "PASS" and merge_value == "READY" and deploy_value == "GO" else "NO"
    return {
        "schema_version": 1,
        "candidate_final_commit": final_commit,
        "evidence_cutoff_at": evidence_cutoff,
        "candidate_security": {"value": candidate_value, "reason_ids": candidate_reasons},
        "merge": {"value": merge_value, "reason_ids": merge_reasons},
        "go_to_deploy": {"value": deploy_value, "reason_ids": deploy_reasons},
        "full_production_go": {"value": production_value, "reason_ids": production_reasons},
        "ready_for_commit_push_deploy_authorization": ready,
    }


def _validate_verdicts(
    verdicts: dict[str, Any],
    derived: dict[str, Any],
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
    for axis in ("candidate_security", "merge", "go_to_deploy", "full_production_go"):
        exact_keys(verdicts[axis], {"value", "reason_ids"}, label=f"four verdicts {axis}")
        string_list(verdicts[axis]["reason_ids"], label=f"four verdicts {axis} reasons", allow_empty=True)
    if verdicts != derived:
        raise ContractError("four verdicts: values and reasons are not derived from the full classification ledger")


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
                    "integration_mode": group["integration_mode"],
                    "cohort_commit": group["cohort_commit"],
                    "final_commit": group["final_commit"],
                    "support_commit_mappings": group["support_commit_mappings"],
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
    semantic_bytes: bytes,
    matrices_bytes: bytes,
    verdicts: dict[str, Any],
    residual_rows: list[dict[str, Any]],
    artifact_root: Path,
    candidate_repo: Path,
    final_commit: str,
    evidence_cutoff: str,
    semantic_receipt_sha256: str,
    artifact_snapshots: dict[str, bytes] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, bytes], dict[str, bytes], dict[str, int]]:
    classification, external_or_live = _validate_classification(classification_rows, baseline, final_commit)
    group_ids = {row["group_id"] for row in group_map_rows}
    final_tree = git_tree(candidate_repo, final_commit)
    receipts, test_logs = _validate_test_receipts(
        test_receipt_rows,
        artifact_root,
        candidate_repo,
        final_commit,
        final_tree,
        group_ids,
        artifact_snapshots,
    )
    equivalence = _validate_fix_groups(
        fix_group_rows,
        group_map_rows,
        receipts,
        candidate_repo,
        final_commit,
        baseline.candidate_commit,
    )
    pre_fix_logs = _validate_pre_fix_receipt(
        pre_fix_receipt,
        artifact_root,
        baseline,
        group_ids,
        candidate_repo,
        artifact_snapshots,
    )
    pending_local_support = _validate_local_closures(
        local_closure_rows,
        baseline,
        classification,
        final_commit,
        candidate_repo,
        receipts,
    )
    _validate_documentation(documentation_receipt, final_commit, candidate_repo, receipts)
    _validate_semantic(semantic_receipt, final_commit, semantic_bytes, semantic_receipt_sha256)
    _validate_matrices(matrices_bytes, baseline)
    _, blockers = _validate_residuals(
        residual_rows,
        classification,
        external_or_live,
        final_commit,
        pending_local_support,
    )
    residual_classification_ids = set().union(*blockers.values()) if blockers else set()
    derived_verdicts = _derive_verdicts(
        classification,
        final_commit,
        evidence_cutoff,
        residual_classification_ids,
    )
    _validate_verdicts(verdicts, derived_verdicts)
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
    group_rows, group_hash, group_bytes = _validate_group_map(group_map, baseline_data.reportable_ids)
    handoff_value, files, hashes, snapshots, handoff_bytes = _validate_handoff_manifest(handoff)
    final_commit, final_tree = _validate_candidate(candidate_repo, baseline_data, handoff_value["candidate_final_commit"])
    classification_rows = load_jsonl_bytes(
        snapshots["postfix_classification_ledger"], label="post-fix classification"
    )
    fix_group_rows = load_jsonl_bytes(snapshots["fix_group_ledger"], label="fix-group ledger")
    test_rows = load_jsonl_bytes(snapshots["test_receipt_registry"], label="test receipt registry")
    pre_fix = load_json_bytes(snapshots["pre_fix_negative_receipt"], label="pre-fix negative receipt")
    closures = load_jsonl_bytes(snapshots["local_condition_closure"], label="local condition closure")
    documentation = load_json_bytes(
        snapshots["documentation_alignment_receipt"], label="documentation alignment receipt"
    )
    semantic_bytes = snapshots["semantic_completion_receipt"]
    semantic = load_json_bytes(semantic_bytes, label="semantic completion receipt")
    matrices_bytes = snapshots["required_matrices"]
    verdicts = load_json_bytes(snapshots["four_verdicts"], label="four verdicts")
    residuals = load_jsonl_bytes(snapshots["provider_live_residuals"], label="provider/live residuals")
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
        semantic_bytes=semantic_bytes,
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
        group_map_bytes=group_bytes,
        handoff_path=handoff,
        handoff_sha256=sha256_bytes(handoff_bytes),
        handoff_bytes=handoff_bytes,
        handoff_file_paths=files,
        handoff_file_sha256=hashes,
        handoff_file_bytes=snapshots,
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
        test_log_bytes=test_logs,
        pre_fix_log_bytes=pre_fix_logs,
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


def _validate_packaged_trust_roots(
    *,
    package_files: dict[str, bytes],
    baseline: Baseline,
    group_map_rows: list[dict[str, Any]],
    group_map_sha256: str,
    final_commit: str,
    evidence_cutoff: str,
    classification_rows: list[dict[str, Any]],
    fix_rows: list[dict[str, Any]],
    test_rows: list[dict[str, Any]],
    pre_fix: dict[str, Any],
    closure_rows: list[dict[str, Any]],
    documentation: dict[str, Any],
    semantic_bytes: bytes,
    matrices_bytes: bytes,
    verdicts: dict[str, Any],
    residuals: list[dict[str, Any]],
) -> tuple[dict[str, str], dict[str, str]]:
    def archived(relative: str, *, label: str) -> bytes:
        try:
            return package_files[relative]
        except KeyError as error:
            raise ContractError(f"package trust root: missing {label}") from error

    baseline_manifest = archived(
        BASELINE_MANIFEST_ARCHIVE_PATH,
        label="baseline manifest snapshot",
    )
    if baseline_manifest != baseline.manifest_bytes:
        raise ContractError("package trust root: baseline manifest snapshot is not authoritative")

    group_map_bytes = archived(GROUP_MAP_ARCHIVE_PATH, label="fix-group map snapshot")
    if sha256_bytes(group_map_bytes) != group_map_sha256:
        raise ContractError("package trust root: fix-group map snapshot hash changed")
    archived_group_rows = load_jsonl_bytes(group_map_bytes, label="archived fix-group map")
    if archived_group_rows != group_map_rows:
        raise ContractError("package trust root: fix-group map snapshot content changed")

    handoff_bytes = archived(HANDOFF_MANIFEST_ARCHIVE_PATH, label="handoff manifest snapshot")
    handoff = load_json_bytes(handoff_bytes, label="archived handoff manifest")
    exact_keys(
        handoff,
        {"schema_version", "evidence_cutoff_at", "candidate_final_commit", "files"},
        label="archived handoff manifest",
    )
    if (
        handoff["schema_version"] != 1
        or handoff["candidate_final_commit"] != final_commit
        or handoff["evidence_cutoff_at"] != evidence_cutoff
    ):
        raise ContractError("package trust root: archived handoff identity/cutoff changed")
    handoff_entries = exact_keys(handoff["files"], HANDOFF_FILE_KEYS, label="archived handoff files")
    handoff_payloads: dict[str, bytes] = {}
    handoff_hashes: dict[str, str] = {}
    for key in HANDOFF_FILE_KEYS:
        entry = exact_keys(
            handoff_entries[key],
            {"path", "sha256"},
            label=f"archived handoff file {key}",
        )
        safe_relative(entry["path"], label=f"archived handoff file {key} path")
        if not isinstance(entry["sha256"], str) or SHA256_RE.fullmatch(entry["sha256"]) is None:
            raise ContractError(f"package trust root: invalid archived SHA-256 for {key}")
        payload = archived(HANDOFF_ARCHIVE_PATHS[key], label=f"handoff file {key}")
        digest = sha256_bytes(payload)
        if digest != entry["sha256"]:
            raise ContractError(f"package trust root: archived handoff file hash changed for {key}")
        handoff_payloads[key] = payload
        handoff_hashes[key] = digest

    source_classification = load_jsonl_bytes(
        handoff_payloads["postfix_classification_ledger"],
        label="archived classification",
    )
    if sorted(source_classification, key=lambda row: row["id"]) != classification_rows:
        raise ContractError("package trust root: classification is not projected from archived input")
    source_fix = load_jsonl_bytes(handoff_payloads["fix_group_ledger"], label="archived fix groups")
    if sorted(source_fix, key=lambda row: row["group_id"]) != fix_rows:
        raise ContractError("package trust root: fix groups are not projected from archived input")

    source_tests = load_jsonl_bytes(
        handoff_payloads["test_receipt_registry"],
        label="archived test receipts",
    )
    source_test_by_id = _unique_rows(source_tests, "receipt_id", label="archived test receipts")
    packaged_test_by_id = _unique_rows(test_rows, "receipt_id", label="packaged test receipts")
    if set(source_test_by_id) != set(packaged_test_by_id):
        raise ContractError("package trust root: test receipt identity projection changed")
    normalized_tests: list[dict[str, Any]] = []
    for receipt_id in sorted(source_test_by_id):
        row = copy.deepcopy(source_test_by_id[receipt_id])
        row["log"]["path"] = f"evidence/test/logs/{receipt_id}.log"
        normalized_tests.append(row)
    if normalized_tests != test_rows:
        raise ContractError("package trust root: test receipts are not projected from archived input")

    source_pre_fix = load_json_bytes(
        handoff_payloads["pre_fix_negative_receipt"],
        label="archived pre-fix receipt",
    )
    source_pre_fix = copy.deepcopy(source_pre_fix)
    source_pre_fix["executions"] = sorted(
        source_pre_fix["executions"], key=lambda row: row["group_id"]
    )
    for row in source_pre_fix["executions"]:
        row["log"]["path"] = f"evidence/test/pre-fix/{row['group_id']}.log"
    if source_pre_fix != pre_fix:
        raise ContractError("package trust root: pre-fix receipt is not projected from archived input")

    source_closures = load_jsonl_bytes(
        handoff_payloads["local_condition_closure"],
        label="archived local closures",
    )
    if sorted(source_closures, key=lambda row: row["id"]) != closure_rows:
        raise ContractError("package trust root: local closures are not projected from archived input")
    source_documentation = load_json_bytes(
        handoff_payloads["documentation_alignment_receipt"],
        label="archived documentation receipt",
    )
    if source_documentation != documentation:
        raise ContractError("package trust root: documentation receipt projection changed")
    if handoff_payloads["semantic_completion_receipt"] != semantic_bytes:
        raise ContractError("package trust root: semantic receipt bytes changed")
    if handoff_payloads["required_matrices"] != matrices_bytes:
        raise ContractError("package trust root: required matrix bytes changed")
    source_verdicts = load_json_bytes(handoff_payloads["four_verdicts"], label="archived verdicts")
    if source_verdicts != verdicts:
        raise ContractError("package trust root: verdict projection changed")
    source_residuals = load_jsonl_bytes(
        handoff_payloads["provider_live_residuals"],
        label="archived provider/live residuals",
    )
    if sorted(source_residuals, key=lambda row: row["id"]) != residuals:
        raise ContractError("package trust root: provider/live residual projection changed")

    expected_inputs = {
        "baseline_manifest": baseline.manifest_sha256,
        "security_fix_group_map": group_map_sha256,
        "handoff_manifest": sha256_bytes(handoff_bytes),
        **{f"handoff:{key}": digest for key, digest in sorted(handoff_hashes.items())},
    }

    tool_root = Path(__file__).parent
    expected_tools: dict[str, str] = {}
    for name in TOOL_SOURCE_NAMES:
        current = read_regular_bytes(tool_root / name, label=f"current tool source {name}")
        packaged = archived(TOOL_SOURCE_PACKAGE_PATHS[name], label=f"tool source {name}")
        if packaged != current:
            raise ContractError(f"package trust root: packaged tool source differs for {name}")
        expected_tools[name] = sha256_bytes(packaged)
    if package_files["schemas/handoff-v1.schema.json"] != package_files[
        TOOL_SOURCE_PACKAGE_PATHS["handoff-v1.schema.json"]
    ]:
        raise ContractError("package trust root: handoff schema copies differ")
    return expected_inputs, expected_tools


def validate_package(
    *,
    package: Path,
    baseline: Path,
    group_map: Path,
    candidate_repo: Path,
    semantic_receipt_sha256: str,
) -> dict[str, Any]:
    if package.is_symlink() or not package.is_dir():
        raise ContractError("package: trust root must be a real directory")
    package_root = package.resolve(strict=True)
    candidate_root = candidate_repo.resolve(strict=True)
    baseline_root = baseline.resolve(strict=True)
    for forbidden_root, label in (
        (candidate_root, "candidate repository"),
        (baseline_root, "authoritative baseline"),
    ):
        try:
            package_root.relative_to(forbidden_root)
        except ValueError:
            pass
        else:
            raise ContractError(f"package: package must be external to the {label}")
    package_snapshot = validate_manifest_snapshot(
        package,
        exact=True,
        required=PACKAGE_STATIC_FILES - {"MANIFEST.sha256"},
    )
    manifest = package_snapshot.rows
    package_files = package_snapshot.files
    for relative, payload in sorted(package_files.items()):
        scan_secret_bytes(payload, label=f"package file {relative}")

    def json_at(relative: str, *, label: str) -> Any:
        try:
            payload = package_files[relative]
        except KeyError as error:
            raise ContractError(f"{label}: file is absent from the package snapshot") from error
        return load_json_bytes(payload, label=label)

    def jsonl_at(relative: str, *, label: str) -> list[dict[str, Any]]:
        try:
            payload = package_files[relative]
        except KeyError as error:
            raise ContractError(f"{label}: file is absent from the package snapshot") from error
        return load_jsonl_bytes(payload, label=label)

    baseline_data = _validate_baseline(baseline)
    group_rows, group_hash, _ = _validate_group_map(group_map, baseline_data.reportable_ids)
    candidate_identity = json_at("receipts/candidate_identity.json", label="candidate identity")
    final_commit, final_tree = _validate_candidate(
        candidate_repo,
        baseline_data,
        candidate_identity.get("final_commit"),
    )
    binding = json_at("baseline/baseline_binding.json", label="baseline binding")
    if binding != expected_baseline_binding(baseline_data, group_hash):
        raise ContractError("package: baseline binding is stale")
    packaged_group_map = jsonl_at(
        "baseline/security_fix_groups_v1.jsonl", label="packaged fix-group map"
    )
    if packaged_group_map != group_rows:
        raise ContractError("package: packaged fix-group map differs from caller trust root")
    packaged_registry = jsonl_at(
        "evidence/validation/canonical_candidate_registry.jsonl",
        label="packaged canonical registry",
    )
    if packaged_registry != baseline_data.registry:
        raise ContractError("package: canonical registry differs from baseline")
    packaged_matrix_schema = json_at("schemas/matrix-schema-v1.json", label="packaged matrix schema")
    if packaged_matrix_schema != baseline_data.matrix_schema:
        raise ContractError("package: matrix schema differs from baseline")

    classification_rows = jsonl_at(
        "evidence/remediation/finding_classification_ledger.jsonl",
        label="packaged classification",
    )
    fix_rows = jsonl_at("evidence/remediation/fix_group_ledger_v1.jsonl", label="packaged fix groups")
    test_rows = jsonl_at("evidence/test/test_receipt_registry_v1.jsonl", label="packaged test receipts")
    pre_fix = json_at("evidence/test/pre_fix_negative_receipt.json", label="packaged pre-fix receipt")
    expected_paths = set(expected_package_payload_paths(test_rows, pre_fix))
    if set(manifest) != expected_paths:
        missing = sorted(expected_paths - set(manifest))
        extra = sorted(set(manifest) - expected_paths)
        raise ContractError(
            f"package allowlist: missing or extra files (missing={missing}, extra={extra})"
        )
    closure_rows = jsonl_at(
        "evidence/remediation/local_condition_closure.jsonl",
        label="packaged local closures",
    )
    documentation = json_at(
        "evidence/remediation/documentation_alignment_receipt.json",
        label="packaged documentation receipt",
    )
    semantic_bytes = package_files["evidence/validation/semantic_completion_receipt.json"]
    semantic = load_json_bytes(semantic_bytes, label="packaged semantic receipt")
    matrices_bytes = package_files["required_matrices.md"]
    verdicts = json_at("four_verdicts_v1.json", label="packaged four verdicts")
    residuals = jsonl_at(
        "evidence/validation/provider_live_residuals.jsonl",
        label="packaged residuals",
    )
    evidence_cutoff = verdicts.get("evidence_cutoff_at")
    if not isinstance(evidence_cutoff, str):
        raise ContractError("package: verdict cutoff is missing")
    expected_input_hashes, expected_tool_hashes = _validate_packaged_trust_roots(
        package_files=package_files,
        baseline=baseline_data,
        group_map_rows=group_rows,
        group_map_sha256=group_hash,
        final_commit=final_commit,
        evidence_cutoff=evidence_cutoff,
        classification_rows=classification_rows,
        fix_rows=fix_rows,
        test_rows=test_rows,
        pre_fix=pre_fix,
        closure_rows=closure_rows,
        documentation=documentation,
        semantic_bytes=semantic_bytes,
        matrices_bytes=matrices_bytes,
        verdicts=verdicts,
        residuals=residuals,
    )
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
        semantic_bytes=semantic_bytes,
        matrices_bytes=matrices_bytes,
        verdicts=verdicts,
        residual_rows=residuals,
        artifact_root=package,
        candidate_repo=candidate_repo,
        final_commit=final_commit,
        evidence_cutoff=evidence_cutoff,
        semantic_receipt_sha256=semantic_receipt_sha256,
        artifact_snapshots=package_files,
    )

    finding_map = jsonl_at(
        "evidence/remediation/finding_fix_commit_test_v1.jsonl",
        label="packaged finding map",
    )
    receipts_by_id = _unique_rows(test_rows, "receipt_id", label="packaged test receipts")
    if finding_map != _derive_finding_map(fix_rows, receipts_by_id):
        raise ContractError("package: finding-to-fix-to-commit-to-test map is stale")
    if len(finding_map) != 135 or {row["canonical_id"] for row in finding_map} != set(baseline_data.reportable_ids):
        raise ContractError("package: finding map is not the exact reportable projection")

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
    core_index = {
        relative: {"sha256": manifest[relative], "size": len(payload)}
        for relative, payload in sorted(package_files.items())
        if relative not in core_excluded
    }
    core_hash = sha256_bytes(canonical_json_bytes(core_index))
    replay = json_at("receipts/replay_receipt.json", label="replay receipt")
    if replay != {
        "schema_version": 1,
        "replay_count": 2,
        "byte_identical": True,
        "core_index_sha256": core_hash,
    }:
        raise ContractError("package: replay receipt is inconsistent")
    build = json_at("receipts/build_receipt.json", label="build receipt")
    exact_keys(
        build,
        {
            "schema_version",
            "tool",
            "candidate_final_commit",
            "candidate_final_tree",
            "evidence_cutoff_at",
            "semantic_receipt_sha256",
            "core_index_sha256",
            "counts",
            "input_sha256",
            "tool_source_sha256",
        },
        label="build receipt",
    )
    if (
        build.get("schema_version") != 1
        or build.get("tool") != "ultra-postfix-evidence-builder"
        or build.get("candidate_final_commit") != final_commit
        or build.get("candidate_final_tree") != final_tree
        or build.get("evidence_cutoff_at") != evidence_cutoff
        or build.get("semantic_receipt_sha256") != semantic_receipt_sha256
        or build.get("core_index_sha256") != core_hash
        or build.get("counts") != counts
        or build.get("input_sha256") != expected_input_hashes
        or build.get("tool_source_sha256") != expected_tool_hashes
    ):
        raise ContractError("package: build receipt trust root/input SHA/tool source is inconsistent")
    return {
        "ok": True,
        "package_manifest_sha256": sha256_bytes(package_snapshot.manifest_bytes),
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
