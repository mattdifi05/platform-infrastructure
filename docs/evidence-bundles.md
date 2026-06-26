# Evidence Bundles

Evidence bundles package non-sensitive proof for review.

## Paths

- `reports/`: generated reports, ignored by Git.
- `.tmp/evidence-bundles/`: generated bundles, ignored by Git.

## Scripts

```sh
sh ./scripts/evidence-bundle.sh
sh ./scripts/evidence-bundle-verify.sh --requireComplete
```

## Contents

Bundles may include:

- manifest
- SHA256 checksums
- release evidence
- readiness evidence
- restore evidence
- uptime evidence
- alert evidence

They must exclude secrets, `.env`, backups, dumps and tokens.

## When to generate

Generate after pre-go-live evidence and before production go/no-go signoff.
