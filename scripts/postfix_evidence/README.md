# Post-fix Ultra evidence package

This directory contains the versioned, fail-closed builder and validator for the
post-fix Ultra package.  It does not modify the authoritative pre-fix package,
the candidate repository, Docker, the network, a provider, or a live host.

## Trust roots

The builder accepts four trust-root classes:

1. an immutable baseline package (`--baseline`);
2. the authoritative 77-row fix-group map (`--group-map`);
3. a hash-bound handoff manifest (`--handoff`) that names both the eleven final
   assembly inputs and all six raw cohort handoffs; and
4. the final candidate Git worktree (`--candidate-repo`).

The caller must additionally provide the SHA-256 of the current saturated
semantic-completion receipt with `--semantic-receipt-sha256`.  There is no
count-dependent or historical snapshot hash in the code.

The candidate worktree must be clean.  Its exact `HEAD` and tree must match the
handoff. Git is invoked through a closed environment with replacement objects
disabled and safe command-line overrides for the worktree, fsmonitor, hooks,
credentials, attributes, and global excludes. The reported top-level,
worktree Git directory, and common Git directory must match canonical
repository metadata. Replace refs, legacy grafts, shallow/sparse history,
assume-unchanged, skip-worktree, and non-comment `.git/info/exclude` entries are
rejected.

Ignored files selected by a tracked final-HEAD `.gitignore` remain outside the
evidence boundary: they are neither read nor scanned nor treated as candidate
inputs. Global excludes and `.git/info/exclude` patterns cannot expand that
boundary. All non-ignored untracked files still make the candidate dirty.
`build_postfix_package.py`, `common.py`, `render_postfix_replay.py`,
`validate_postfix_package.py`, and `handoff-v1.schema.json` must each be a
regular blob under `scripts/postfix_evidence/` at that exact final HEAD. The
executing bytes, committed bytes, and packaged validator bytes must match
exactly. File snapshots, Git blob reads, evidence-log aggregates, manifests,
package trees, and child-process stdout/stderr all have explicit per-item and
cumulative byte ceilings. Git blob content is not read until `cat-file -s`
passes its size gate; overflow or timeout kills the isolated child process
group (which is verified distinct from the parent process group) and never
includes captured output in the error. A fixed supervisor remains the session
leader, reports the target exit code over a four-byte control pipe, and keeps
the certified PGID alive until the whole group is terminated; group
termination therefore happens before leader reap, including when a target
exits after spawning a descendant with closed pipes. `EPERM` and every
termination error other than an already-absent group fail closed. Replay
overflow or timeout is handled inside the stable-parent-dirfd cleanup boundary,
so neither temporary replay directories nor an output package survive.
Cleanup itself is entry/depth bounded, dirfd-relative, and never follows a
symlink; a cleanup error fails the build and also removes any already-published
package before the trusted parent descriptor is closed.

Worker and Git commands are fixed by the tool: validated paths and hashes are
passed only as data arguments, receipt `argv` values are inspected but never
executed, hooks/fsmonitor are disabled, and no validated input selects an
executable or invokes `setsid`. Therefore a valid input cannot escape the
certified child process group. Any future feature that executes input-selected
commands or permits a second session must fail closed until it is placed in an
independent external sandbox; process-group containment alone would not be a
sufficient boundary for that expanded model.

The raw `control_auth`, `control_services`, `hosted`, `runtime`,
`backup_evidence`, and `release` JSONL files are immutable manifest inputs,
archived in the package, and revalidated independently. Their exact FG-001
through FG-077 projection must preserve the authoritative slugs and canonical
CAN IDs. The validator derives each FG's complete support-commit set from its
raw cohort commit, raw support commits, and incoming cross-cohort dependencies;
the final ledger and every support mapping must equal that set in both
directions.

Every fix-group row declares `integration_mode`. For `cherry-pick`,
`cohort_commit` and `final_commit` must be distinct; the final commit must
resolve, be reachable from final `HEAD`, and be patch-equivalent to the cohort
commit (stable patch-id or exact Git tree delta).  For `direct-final`, the two
fields must be the same reachable commit because the fix was authored directly
on the final candidate branch.

`reconciled` is reserved for a real overlapping/conflicting integration whose
exact tree delta cannot truthfully equal the cohort delta. Each reconciled
support mapping must name a distinct reachable final integration commit, cover
the exact closed path set changed by both commits, and carry a conflict
resolution receipt with exact before/cohort/final blob hashes and modes. The
receipt must attest no omitted control and bind the exact final-HEAD negative,
positive, hostile, and independent-QA receipts. An equivalent non-conflicting
delta, a missing or stale receipt, an incomplete test set, or an expanded path
boundary fails closed. A cohort-only SHA mislabeled as `cherry-pick`, an
unreachable integration SHA, or a stale mapping is also a hard failure.

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
    "pre_fix_test_definition_registry": {"path": "inputs/pre-fix-test-definitions.jsonl", "sha256": "<sha256>"},
    "local_condition_closure": {"path": "inputs/local-closures.jsonl", "sha256": "<sha256>"},
    "documentation_alignment_receipt": {"path": "inputs/documentation.json", "sha256": "<sha256>"},
    "semantic_completion_receipt": {"path": "inputs/semantic-completion.json", "sha256": "<sha256>"},
    "required_matrices": {"path": "inputs/required-matrices.md", "sha256": "<sha256>"},
    "four_verdicts": {"path": "inputs/four-verdicts.json", "sha256": "<sha256>"},
    "provider_live_residuals": {"path": "inputs/provider-live-residuals.jsonl", "sha256": "<sha256>"}
  },
  "cohort_handoffs": {
    "control_auth": {"path": "cohorts/control-auth.jsonl", "sha256": "<sha256>"},
    "control_services": {"path": "cohorts/control-services.jsonl", "sha256": "<sha256>"},
    "hosted": {"path": "cohorts/hosted.jsonl", "sha256": "<sha256>"},
    "runtime": {"path": "cohorts/runtime.jsonl", "sha256": "<sha256>"},
    "backup_evidence": {"path": "cohorts/backup-evidence.jsonl", "sha256": "<sha256>"},
    "release": {"path": "cohorts/release.jsonl", "sha256": "<sha256>"}
  }
}
```

All paths are regular, non-symlink files below the manifest directory.  Unknown
keys, missing keys, duplicate JSON keys, stale hashes, unsafe paths, and
non-finite JSON values fail closed.

`DOC-EVD-001` and `DOC-EVD-002` remain a deliberate split state:
`LOCAL-SUPPORT-READY-EXTERNAL-PENDING`. Local inventory/runbook support may be
complete, but named-owner acknowledgement and independent operator drill
receipts remain exact GO-blocking governance residuals. Raw cohort text cannot
promote either condition to a local PASS.

`pre_fix_negative_receipt` is the execution receipt for negative tests against
the detached authoritative baseline commit/tree. The separately supplied
`pre_fix_test_definition_registry` must itself be an exact regular Git blob at
the final candidate HEAD. It maps FG-001 through FG-077 one-to-one to a
nontrivial final-HEAD test definition, closed `argv`/`cwd`, and the exact
regular consumer blobs exercised at the baseline. Each execution log binds
both identities: the baseline commit/tree and consumer blobs being tested, and
the final-HEAD registry/test definition used to test them.

The receipt must enumerate all 77 groups exactly once and record that live,
Docker, network, and secret access were disabled. Every execution binds a
regular log by SHA-256. Runner-kind counts are intentionally not an
authoritative invariant. In particular, an external or generated PoC suite
that cannot prove an antecedent Git identity is neither a trust root nor a
package input, and test definitions are never represented as though they had
existed at the baseline commit.

Each fix-group ledger row preserves the canonical IDs from the group map and
records source, control, sink, remediation boundary, integration mode,
cohort/final commits,
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
builds. Replay A and replay B each run in a fresh OS process, independently
reload and validate every source trust root, scan inputs and tool sources for
credential material, and render the core package. The builder then adds
distinct A/B replay receipts and manifests and runs the complete package
validator against both temporary copies. Publication is allowed only after
both validations return the same result and the complete byte indexes match.
A failure or mutation of either replay leaves no output package. Final
publication uses the platform's dirfd-relative atomic no-replace rename
primitive while retaining an open descriptor for an owner-controlled,
non-group/world-writable parent. The parent inode and publication boundary are
rechecked before and after rename; a file, directory, or symlink that appears
at the destination during the build is never overwritten. The candidate
HEAD/tree, clean status, Git topology, and exact tool-source hashes are also
revalidated immediately before and after publication. Any late drift removes
the just-published package through the retained parent descriptor.

The package includes both replay receipts, the build receipt, baseline binding,
candidate identity, the six byte-exact raw cohort handoffs, the eleven
byte-exact final handoff inputs, all ledgers and matrices, explicit
provider/live residuals, four verdicts, and `MANIFEST.sha256`. The build receipt
binds the complete source snapshot, every input SHA, every packaged validator
source SHA, and both replay-receipt SHAs. Existing output directories are never
overwritten.

The credential scanner rejects key/token material and static credential
assignments, including Python byte/raw/Unicode/f-string prefixes and
triple-quoted or multiline literals. Runtime secret references and explicit
redaction placeholders remain accepted; rejection messages never echo the
matched credential value.

Run the tests with:

```sh
python3 -m unittest discover -s scripts/postfix_evidence/tests -v
```

Build only after every handoff hash and the current semantic trust root are
known:

```sh
python3 -m scripts.postfix_evidence.build_postfix_package \
  --baseline /absolute/path/to/outputs \
  --group-map /absolute/path/to/security_fix_groups_v1.jsonl \
  --handoff /absolute/path/to/handoff.json \
  --candidate-repo /absolute/path/to/final-candidate \
  --output /absolute/path/to/postfix-package \
  --semantic-receipt-sha256 CURRENT_64_HEX_SHA256
```

Revalidate the published sibling package independently with:

```sh
python3 -m scripts.postfix_evidence.validate_postfix_package \
  --package /absolute/path/to/postfix-package \
  --baseline /absolute/path/to/outputs \
  --group-map /absolute/path/to/security_fix_groups_v1.jsonl \
  --candidate-repo /absolute/path/to/final-candidate \
  --semantic-receipt-sha256 CURRENT_64_HEX_SHA256
```

Both commands return structured JSON and a nonzero exit status on failure.  The
output directory must not already exist and must be external to both candidate
and baseline.
