# Integration handoff

## Isolation and scope

- Worktree: `/Users/matthew/Documents/Codex/2026-07-11/ss/work/postfix-package-builder`
- Branch: `tooling/postfix-package-builder`
- Base: `68cd05895b8d479ffb8167344282e7d922958bfc`
- Authoritative baseline: unchanged
- Candidate and all cohort worktrees: unchanged by this worktree
- Push, merge, deploy, Docker, network, provider, secret, and live operations: not performed

The builder only publishes to a previously nonexistent directory external to
both candidate and baseline.  It removes a newly created output if final
validation fails.

## Commit order

Cherry-pick the complete ordered branch range
`5791f61^..tooling/postfix-package-builder`. Do not copy only the builder
without its negative tests, schema, later adversarial hardening, or raw-cohort
trust-root validation.

## Final-assembly obligations

The final assembler must create one hash-bound handoff directory matching
`handoff-v1.schema.json`. The builder will fail until all eleven declared final
inputs and all six raw cohort handoffs are present, SHA-bound, and complete. In
particular:

- the post-fix classification ledger must preserve the exact 341-row universe,
  240 CAN projection, 135 reportable CAN rows, and 105 unchanged suppressed CAN
  rows;
- the fix ledger must contain exactly FG-001 through FG-077 and cover the 135
  reportable CAN IDs once each;
- raw control-auth, control-services, hosted, runtime, backup-evidence, and
  release handoffs must preserve the authoritative slug/CAN projection and
  cover FG-001 through FG-077 exactly once;
- every executing builder/validator/replay/schema source must be a regular blob
  at the exact final HEAD, byte-identical to both `git show` and the copy
  archived in the package;
- all trust-root reads, Git blobs, manifests, evidence-log aggregates, package
  trees, and child stdout/stderr are subject to explicit per-item and
  cumulative byte limits; oversized Git blobs fail at the object-size gate
  before content is loaded;
- worker executables/modules are fixed tool code, receipt commands are
  validation-only data and are never run, and validated inputs cannot create a
  second session; adding input-selected execution requires a separate external
  sandbox rather than relying on process-group containment;
- the candidate repository must have complete native history without replace
  refs or legacy grafts; all Git subprocesses run with a closed environment and
  replacement objects disabled;
- canonical Git top-level/git-dir/common-dir identities must agree; local
  fsmonitor/hooks/worktree aliases are neutralized; sparse checkout,
  assume-unchanged, skip-worktree, and non-comment `.git/info/exclude` patterns
  are forbidden;
- ignored runtime data selected by a tracked final-HEAD `.gitignore` remains
  expressly outside the evidence package and is not read or scanned;
- every raw cohort/support SHA, including an incoming cross-cohort dependency
  attributed to its owner FG, must appear exactly once in that FG's final
  support mapping set; invented and omitted mappings fail closed;
- `integration_mode: cherry-pick` requires distinct cohort/final SHAs plus
  stable patch-id or exact tree-delta equivalence;
- `integration_mode: direct-final` requires identical cohort/final SHAs and a
  commit reachable from final HEAD (used only for fixes authored directly on
  the final candidate branch);
- `integration_mode: reconciled` is allowed only for an actually different
  conflicting delta and requires a distinct final integration commit, exact
  closed changed-path set, before/cohort/final blob hashes and modes, a
  no-control-omitted attestation, and exact final-HEAD negative, positive,
  hostile, and independent-QA receipt bindings;
- every group needs final-HEAD negative, positive, regression, hostile, and
  independent-QA receipts;
- candidate-wide full-suite, differential-scan, adversarial-QA, and
  documentation-validation receipts are mandatory;
- the detached-baseline pre-fix receipt must enumerate FG-001 through FG-077
  exactly once and attest no live, Docker, network, or secret access;
- the separate 77-row pre-fix test-definition registry must be byte-identical
  to a regular blob at final HEAD and map every group one-to-one to a
  nontrivial Git-bound test definition, closed runner command, and exact
  regular baseline consumer paths;
- each pre-fix log must bind the detached baseline target/tree and consumer
  blobs as well as the final-HEAD registry and test-definition identity. No
  external/generated PoC suite without antecedent Git provenance is accepted
  as a trust root, and no test definition is retroactively attributed to the
  baseline;
- every baseline local blocker requires an explicit closure row; against the
  real baseline this is a 15-ID set;
- semantic completion must be current caller-pinned zero-novelty
  `SATURATED/STOP`; max-round STOP is rejected;
- M01 through M15 must match the fixed schema, including M01=134 and exact
  M15=135 reportable IDs;
- the four verdicts must not hide blocking provider/live residuals.  The four
  High live rows `LIVE-BKP-006`, `LIVE-OPS-001`, `LIVE-OPS-002`, and
  `LIVE-OPS-004` cannot be removed without direct evidence.
- `DOC-EVD-001` and `DOC-EVD-002` remain
  `LOCAL-SUPPORT-READY-EXTERNAL-PENDING`; local support cannot replace the
  exact named-owner acknowledgement or independent operator drill residual.

No real post-fix package was generated in this branch because the integrated
final-HEAD handoff does not yet exist.  Generating a green package from partial
cohort evidence would violate the fail-closed contract.

## Verification performed

The Python sources compile under the host Python 3 runtime. The adversarial
unit suite covers successful two-process replay publication, complete
pre-publication validation of both copies, replay-B sabotage, all six raw
cohort trust roots, authoritative slug/CAN identity, support-SHA equality in
both directions, incoming dependency ownership, reconciled conflict receipts
and missing/stale variants, missing/duplicate groups, final-HEAD
test-definition registry binding, baseline consumer anchors, runner-command
injection, baseline identity drift, missing local closures, cohort-only and
non-equivalent mappings, explicit direct-final identity, dirty worktree,
in-repository output, suppressed-row mutation, missing/stale handoff inputs,
path-escape receipt IDs, M15 omission, hidden live blockers, retired snapshot
pinning, max-round STOP, credential-scanner positive/negative controls,
Python literal-prefix and multiline-secret variants, divergent tool checkouts,
Git replace/graft and local-config overrides, hidden index flags,
`.git/info/exclude` bypass, atomic no-replace publication races, manifest
tampering, sparse oversized filesystem and Git blobs, stdout/stderr flood
termination, certified supervisor PGID and pre-reap descendant cleanup,
non-suppressed termination denial, replay
overflow/timeout cleanup through a stable parent descriptor, late candidate
mutation with post-rename package removal, and extra-file injection.

The validator was also run read-only against the real authoritative baseline:

```text
classification=341 canonical=240 reportable=135 suppressed=105
inventory=134 fix_groups=77 matrices=M01..M15 PASS
group_map_sha256=82eb9a2f436afaf521b2d73a91537612f5f543e05af0dd35f2af494fcc26a725
baseline_commit=68cd05895b8d479ffb8167344282e7d922958bfc
baseline_tree=70031b30316fbaecbb23249491d6ff4e364d65d5
```

Use the module-form build and validation commands in `README.md`; both emit
structured JSON and return nonzero on failure.
