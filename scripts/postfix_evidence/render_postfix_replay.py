#!/usr/bin/env python3
"""Fresh-process source validation and core render for one package replay."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scripts.postfix_evidence.build_postfix_package import (
    _package_tree_index,
    _render_core,
    _replay_attestation,
    _scan_validated_inputs,
)
from scripts.postfix_evidence.common import ContractError, scan_secret_bytes
from scripts.postfix_evidence.validate_postfix_package import validate_source_inputs


def render_replay(
    *,
    baseline: Path,
    group_map: Path,
    handoff: Path,
    candidate_repo: Path,
    destination: Path,
    semantic_receipt_sha256: str,
) -> dict[str, object]:
    if destination.is_symlink() or not destination.is_dir():
        raise ContractError("replay worker: destination must be a real directory")
    if any(destination.iterdir()):
        raise ContractError("replay worker: destination must start empty")
    data = validate_source_inputs(
        baseline=baseline,
        group_map=group_map,
        handoff=handoff,
        candidate_repo=candidate_repo,
        semantic_receipt_sha256=semantic_receipt_sha256,
    )
    _scan_validated_inputs(data)
    tool_sources = data.tool_source_bytes
    for name, payload in sorted(tool_sources.items()):
        scan_secret_bytes(payload, label=f"tool source {name}")
    _render_core(destination, data, tool_sources)
    return _replay_attestation(
        data,
        semantic_receipt_sha256=semantic_receipt_sha256,
        core_index=_package_tree_index(destination, data.pre_fix_mode),
        tool_sources=tool_sources,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--group-map", type=Path, required=True)
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--candidate-repo", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--semantic-receipt-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        result = render_replay(
            baseline=arguments.baseline,
            group_map=arguments.group_map,
            handoff=arguments.handoff,
            candidate_repo=arguments.candidate_repo,
            destination=arguments.destination,
            semantic_receipt_sha256=arguments.semantic_receipt_sha256,
        )
    except ContractError as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, **result}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
