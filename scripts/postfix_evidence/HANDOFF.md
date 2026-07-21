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

1. `5791f61` — negative tests and closed handoff contract
2. `bf27d9b` — deterministic builder and independent validator
3. the commit containing this handoff — final adversarial hardening and QA notes

Cherry-pick in that order.  Do not copy only the builder without its negative
tests and schema.

## Final-assembly obligations

The final assembler must create one hash-bound handoff directory matching
`handoff-v1.schema.json`.  The builder will fail until all ten declared files
are present and complete.  In particular:

- the post-fix classification ledger must preserve the exact 341-row universe,
  240 CAN projection, 135 reportable CAN rows, and 105 unchanged suppressed CAN
  rows;
- the fix ledger must contain exactly FG-001 through FG-077 and cover the 135
  reportable CAN IDs once each;
- `integration_mode: cherry-pick` requires distinct cohort/final SHAs plus
  stable patch-id or exact tree-delta equivalence;
- `integration_mode: direct-final` requires identical cohort/final SHAs and a
  commit reachable from final HEAD (used only for fixes authored directly on
  the final candidate branch);
- every group needs final-HEAD negative, positive, regression, hostile, and
  independent-QA receipts;
- candidate-wide full-suite, differential-scan, adversarial-QA, and
  documentation-validation receipts are mandatory;
- the detached-baseline pre-fix receipt must enumerate 77 groups exactly, with
  72 Make wrappers and 5 manual harnesses, and attest no live, Docker, network,
  or secret access;
- every baseline local blocker requires an explicit closure row; against the
  real baseline this is a 15-ID set;
- semantic completion must be current caller-pinned zero-novelty
  `SATURATED/STOP`; max-round STOP is rejected;
- M01 through M15 must match the fixed schema, including M01=134 and exact
  M15=135 reportable IDs;
- the four verdicts must not hide blocking provider/live residuals.  The four
  High live rows `LIVE-BKP-006`, `LIVE-OPS-001`, `LIVE-OPS-002`, and
  `LIVE-OPS-004` cannot be removed without direct evidence.

No real post-fix package was generated in this branch because the integrated
final-HEAD handoff does not yet exist.  Generating a green package from partial
cohort evidence would violate the fail-closed contract.

## Verification performed

The Python sources compile under the host Python 3 runtime.  The adversarial
unit suite covers successful two-replay publication and independent validation,
plus missing/duplicate groups, 72+5 drift, baseline identity drift, missing
local closures, cohort-only and non-equivalent mappings, explicit direct-final
identity, dirty worktree, in-repository output, suppressed-row mutation,
missing/stale handoff inputs, path-escape receipt IDs, M15 omission, hidden live
blockers, retired snapshot pinning, max-round STOP, and manifest tampering.

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
