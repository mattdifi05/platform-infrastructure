#!/usr/bin/env python3
"""Build a deterministic two-replay Ultra post-fix evidence package."""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from scripts.postfix_evidence.common import (
    ContractError,
    canonical_json_bytes,
    read_regular_bytes,
    sha256_bytes,
    sha256_file,
    tree_index,
    write_bytes,
    write_json,
    write_jsonl,
    write_manifest,
)
from scripts.postfix_evidence.validate_postfix_package import (
    ValidatedInputs,
    _derive_finding_map,
    expected_baseline_binding,
    validate_package,
    validate_source_inputs,
)


SENSITIVE_LOG_RE = re.compile(
    rb"(?i)(?:password|passwd|api[_-]?key|access[_-]?token|private[_-]?key)\s*[:=]\s*[^\s]{4,}|-----BEGIN [A-Z ]*PRIVATE KEY-----"
)


def _copy_verified_log(payload: bytes, expected_sha256: str, destination: Path) -> None:
    if len(payload) > 10 * 1024 * 1024:
        raise ContractError("evidence log: file exceeds the 10 MiB package limit")
    if sha256_bytes(payload) != expected_sha256:
        raise ContractError("evidence log: source changed after validation")
    if SENSITIVE_LOG_RE.search(payload):
        raise ContractError("evidence log: credential-like value detected; sanitize before packaging")
    write_bytes(destination, payload)


def _rewrite_test_receipts(data: ValidatedInputs, destination: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for original in sorted(data.test_receipt_rows, key=lambda row: row["receipt_id"]):
        row = copy.deepcopy(original)
        receipt_id = row["receipt_id"]
        relative = f"evidence/test/logs/{receipt_id}.log"
        expected = row["log"]["sha256"]
        _copy_verified_log(data.test_log_bytes[receipt_id], expected, destination / relative)
        row["log"] = {"path": relative, "sha256": expected}
        rows.append(row)
    return rows


def _rewrite_pre_fix_receipt(data: ValidatedInputs, destination: Path) -> dict[str, Any]:
    receipt = copy.deepcopy(data.pre_fix_receipt)
    executions = []
    for original in sorted(receipt["executions"], key=lambda row: row["group_id"]):
        row = copy.deepcopy(original)
        group_id = row["group_id"]
        relative = f"evidence/test/pre-fix/{group_id}.log"
        expected = row["log"]["sha256"]
        _copy_verified_log(data.pre_fix_log_bytes[group_id], expected, destination / relative)
        row["log"] = {"path": relative, "sha256": expected}
        executions.append(row)
    receipt["executions"] = executions
    return receipt


def _render_readme(data: ValidatedInputs) -> bytes:
    verdicts = data.verdicts
    lines = [
        "# Ultra post-fix evidence package",
        "",
        "This package is a deterministic, two-replay evidence assembly bound to one clean final candidate HEAD.",
        "It does not modify or supersede the authoritative pre-fix baseline.",
        "",
        f"- Candidate security verdict: `{verdicts['candidate_security']['value']}`",
        f"- Merge verdict: `{verdicts['merge']['value']}`",
        f"- GO-to-deploy verdict: `{verdicts['go_to_deploy']['value']}`",
        f"- Full production-go verdict: `{verdicts['full_production_go']['value']}`",
        f"- Ready for commit/push/deploy authorization: `{verdicts['ready_for_commit_push_deploy_authorization']}`",
        "",
        "No push, merge, deploy, provider mutation, Docker operation, network operation, or live mutation was performed by the builder.",
        "Provider/live residuals remain explicit under `evidence/validation/provider_live_residuals.jsonl`.",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _render_core(destination: Path, data: ValidatedInputs) -> None:
    write_bytes(destination / "README.md", _render_readme(data))
    write_json(
        destination / "baseline/baseline_binding.json",
        expected_baseline_binding(data.baseline, data.group_map_sha256),
    )
    write_jsonl(destination / "baseline/security_fix_groups_v1.jsonl", data.group_map_rows)
    write_jsonl(
        destination / "evidence/validation/canonical_candidate_registry.jsonl",
        data.baseline.registry,
    )
    write_json(destination / "schemas/matrix-schema-v1.json", data.baseline.matrix_schema)
    schema_path = Path(__file__).with_name("handoff-v1.schema.json")
    write_bytes(
        destination / "schemas/handoff-v1.schema.json",
        read_regular_bytes(schema_path, label="handoff schema"),
    )

    write_jsonl(
        destination / "evidence/remediation/finding_classification_ledger.jsonl",
        sorted(data.classification_rows, key=lambda row: row["id"]),
    )
    fix_rows = sorted(data.fix_group_rows, key=lambda row: row["group_id"])
    write_jsonl(destination / "evidence/remediation/fix_group_ledger_v1.jsonl", fix_rows)
    rewritten_tests = _rewrite_test_receipts(data, destination)
    write_jsonl(destination / "evidence/test/test_receipt_registry_v1.jsonl", rewritten_tests)
    receipt_index = {row["receipt_id"]: row for row in rewritten_tests}
    write_jsonl(
        destination / "evidence/remediation/finding_fix_commit_test_v1.jsonl",
        _derive_finding_map(fix_rows, receipt_index),
    )
    write_jsonl(
        destination / "evidence/remediation/local_condition_closure.jsonl",
        sorted(data.local_closure_rows, key=lambda row: row["id"]),
    )
    write_json(
        destination / "evidence/remediation/documentation_alignment_receipt.json",
        data.documentation_receipt,
    )
    write_json(
        destination / "evidence/test/pre_fix_negative_receipt.json",
        _rewrite_pre_fix_receipt(data, destination),
    )

    semantic_bytes = data.handoff_file_bytes["semantic_completion_receipt"]
    if sha256_bytes(semantic_bytes) != data.handoff_file_sha256["semantic_completion_receipt"]:
        raise ContractError("semantic completion receipt changed after source validation")
    write_bytes(destination / "evidence/validation/semantic_completion_receipt.json", semantic_bytes)
    write_jsonl(
        destination / "evidence/validation/provider_live_residuals.jsonl",
        sorted(data.residual_rows, key=lambda row: row["id"]),
    )
    matrices_bytes = data.handoff_file_bytes["required_matrices"]
    if sha256_bytes(matrices_bytes) != data.handoff_file_sha256["required_matrices"]:
        raise ContractError("required matrices changed after source validation")
    write_bytes(destination / "required_matrices.md", matrices_bytes)
    write_json(destination / "four_verdicts_v1.json", data.verdicts)
    write_json(
        destination / "receipts/candidate_identity.json",
        {
            "schema_version": 1,
            "final_commit": data.candidate_final_commit,
            "final_tree": data.candidate_final_tree,
            "worktree_clean": True,
            "cohort_final_equivalence": sorted(data.equivalence_records, key=lambda row: row["group_id"]),
        },
    )


def _tool_source_hashes() -> dict[str, str]:
    names = (
        "build_postfix_package.py",
        "common.py",
        "validate_postfix_package.py",
        "handoff-v1.schema.json",
    )
    root = Path(__file__).parent
    return {name: sha256_file(root / name, label=f"tool source {name}") for name in names}


def _build_receipt(data: ValidatedInputs, core_hash: str, semantic_sha256: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "tool": "ultra-postfix-evidence-builder",
        "candidate_final_commit": data.candidate_final_commit,
        "candidate_final_tree": data.candidate_final_tree,
        "evidence_cutoff_at": data.evidence_cutoff_at,
        "semantic_receipt_sha256": semantic_sha256,
        "core_index_sha256": core_hash,
        "counts": data.counts,
        "input_sha256": {
            "baseline_manifest": data.baseline.manifest_sha256,
            "security_fix_group_map": data.group_map_sha256,
            "handoff_manifest": data.handoff_sha256,
            **{f"handoff:{key}": value for key, value in sorted(data.handoff_file_sha256.items())},
        },
        "tool_source_sha256": _tool_source_hashes(),
    }


def build_package(
    *,
    baseline: Path,
    group_map: Path,
    handoff: Path,
    candidate_repo: Path,
    output: Path,
    semantic_receipt_sha256: str,
) -> dict[str, Any]:
    if output.exists() or output.is_symlink():
        raise ContractError("output: destination already exists; overwrite is forbidden")
    try:
        candidate_root = candidate_repo.resolve(strict=True)
        baseline_root = baseline.resolve(strict=True)
        output_absolute = output.resolve(strict=False)
        output_absolute.relative_to(candidate_root)
    except ValueError:
        pass
    except OSError as error:
        raise ContractError("output: candidate or baseline trust root is unavailable") from error
    else:
        raise ContractError("output: package must be external to the candidate repository")
    try:
        output_absolute.relative_to(baseline_root)
    except ValueError:
        pass
    else:
        raise ContractError("output: package must not be created inside the authoritative baseline")
    output.parent.mkdir(parents=True, exist_ok=True)
    data = validate_source_inputs(
        baseline=baseline,
        group_map=group_map,
        handoff=handoff,
        candidate_repo=candidate_repo,
        semantic_receipt_sha256=semantic_receipt_sha256,
    )
    replay_a = Path(tempfile.mkdtemp(prefix=".postfix-replay-a-", dir=output.parent))
    replay_b = Path(tempfile.mkdtemp(prefix=".postfix-replay-b-", dir=output.parent))
    published = False
    try:
        _render_core(replay_a, data)
        _render_core(replay_b, data)
        index_a = tree_index(replay_a)
        index_b = tree_index(replay_b)
        if index_a != index_b:
            raise ContractError("replay: independent core builds are not byte-identical")
        core_hash = sha256_bytes(canonical_json_bytes(index_a))
        replay_receipt = {
            "schema_version": 1,
            "replay_count": 2,
            "byte_identical": True,
            "core_index_sha256": core_hash,
        }
        build_receipt = _build_receipt(data, core_hash, semantic_receipt_sha256)
        for replay in (replay_a, replay_b):
            write_json(replay / "receipts/replay_receipt.json", replay_receipt)
            write_json(replay / "receipts/build_receipt.json", build_receipt)
            write_manifest(replay)
        if tree_index(replay_a) != tree_index(replay_b):
            raise ContractError("replay: complete package builds are not byte-identical")
        if output.exists() or output.is_symlink():
            raise ContractError("output: destination appeared during build")
        replay_a.rename(output)
        published = True
        try:
            validation = validate_package(
                package=output,
                baseline=baseline,
                group_map=group_map,
                candidate_repo=candidate_repo,
                semantic_receipt_sha256=semantic_receipt_sha256,
            )
        except Exception:
            shutil.rmtree(output, ignore_errors=True)
            published = False
            raise
        return validation
    finally:
        if replay_a.exists():
            shutil.rmtree(replay_a, ignore_errors=True)
        if replay_b.exists():
            shutil.rmtree(replay_b, ignore_errors=True)
        if not published and output.exists() and output.name.startswith(".postfix-replay-"):
            shutil.rmtree(output, ignore_errors=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--group-map", type=Path, required=True)
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--candidate-repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--semantic-receipt-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        result = build_package(
            baseline=arguments.baseline,
            group_map=arguments.group_map,
            handoff=arguments.handoff,
            candidate_repo=arguments.candidate_repo,
            output=arguments.output,
            semantic_receipt_sha256=arguments.semantic_receipt_sha256,
        )
    except ContractError as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
