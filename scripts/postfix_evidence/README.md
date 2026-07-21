# Post-fix Ultra evidence package

This directory contains the versioned, fail-closed builder and validator for the
post-fix Ultra package.  It does not modify the authoritative pre-fix package,
the candidate repository, Docker, the network, a provider, or a live host.

## Trust roots

The builder accepts four trust roots:

1. an immutable baseline package (`--baseline`);
2. the authoritative 77-row fix-group map (`--group-map`);
3. a hash-bound handoff manifest (`--handoff`); and
4. the final candidate Git worktree (`--candidate-repo`).

The caller must additionally provide the SHA-256 of the current saturated
semantic-completion receipt with `--semantic-receipt-sha256`.  There is no
count-dependent or historical snapshot hash in the code.

The candidate worktree must be clean.  Its exact `HEAD` and tree must match the
handoff.  Every fix-group row has distinct `cohort_commit` and `final_commit`
fields.  The final commit must resolve, be reachable from final `HEAD`, and be
patch-equivalent to the cohort commit (stable patch-id or exact Git tree delta).
A cohort-only SHA, an unreachable integration SHA, or a stale mapping is a hard
failure.

## Handoff manifest

The manifest is JSON with this closed top-level shape:

```json
{
  "schema_version": 1,
  "evidence_cutoff_at": "2026-07-21T20:00:00Z",
  "candidate_final_commit": "<40 lower-case hex>",
  "files": {
    "postfix_classification_ledger": {"path": "inputs/classification.jsonl", "sha256": "<sha256>"},
    "fix_group_ledger": {"path": "inputs/fix-groups.jsonl", "sha256": "<sha256>"},
    "test_receipt_registry": {"path": "inputs/test-receipts.jsonl", "sha256": "<sha256>"},
    "pre_fix_negative_receipt": {"path": "inputs/pre-fix-negative.json", "sha256": "<sha256>"},
    "local_condition_closure": {"path": "inputs/local-closures.jsonl", "sha256": "<sha256>"},
    "documentation_alignment_receipt": {"path": "inputs/documentation.json", "sha256": "<sha256>"},
    "semantic_completion_receipt": {"path": "inputs/semantic-completion.json", "sha256": "<sha256>"},
    "required_matrices": {"path": "inputs/required-matrices.md", "sha256": "<sha256>"},
    "four_verdicts": {"path": "inputs/four-verdicts.json", "sha256": "<sha256>"},
    "provider_live_residuals": {"path": "inputs/provider-live-residuals.jsonl", "sha256": "<sha256>"}
  }
}
```

All paths are regular, non-symlink files below the manifest directory.  Unknown
keys, missing keys, duplicate JSON keys, stale hashes, unsafe paths, and
non-finite JSON values fail closed.

`pre_fix_negative_receipt` is the execution receipt for negative tests against
the detached authoritative baseline commit/tree.  It must enumerate every
FG-001 through FG-077 exactly once: exactly 72 `make-wrapper` executions and 5
`manual-harness` executions.  It records that live, Docker, network, and secret
access were all disabled.  Every execution binds a regular log by SHA-256.

Each fix-group ledger row preserves the canonical IDs from the group map and
records source, control, sink, remediation boundary, cohort/final commits,
consumer evidence, and receipt IDs for negative, positive, regression, hostile,
and independent-QA tests.  Test receipts bind final `HEAD` and hash-bound logs.
The registry also needs candidate-wide receipts for the full suite,
differential scan, adversarial QA, and documentation validation.

The semantic receipt is accepted only when it proves `SATURATED/STOP`, zero
novel findings, terminal mode enabled, no max-round cap, and the exact final
candidate commit.  `MAX_ROUND_REACHED/STOP` is never accepted as completion.

## Preserved cardinalities and recomputed state

The builder preserves the baseline universe: 341 classification rows, 240
canonical candidates, 135 reportable CAN rows, 105 suppressed CAN rows, 77 fix
groups, and M01 through M15.  These are identity/cardinality invariants, not a
claim that the old pre-fix state is current.  Candidate/open/blocker state and
all four verdicts are validated from the supplied post-fix evidence.

The 105 suppressed rows must be logically byte-equivalent to the baseline after
canonical JSON serialization.  The 135 reportable CAN rows keep their lineage
and `is_new=true` semantics but must carry post-fix closure evidence.  The
builder never rewrites them to historical T1-T23 fixes.

## Output and replay

The output is a sibling package created through two independent temporary
builds.  Their complete byte indexes must match before publication.  The
package includes a replay receipt, build receipt, baseline binding, candidate
identity, all ledgers and matrices, explicit provider/live residuals, four
verdicts, and `MANIFEST.sha256`.  Existing output directories are never
overwritten.

Run the tests with:

```sh
python3 -m unittest discover -s scripts/postfix_evidence/tests -v
```
