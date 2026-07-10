# Test Evidence Index

| Evidence ID | Task | Boundary | Command or artifact | Result | Freshness |
| --- | --- | --- | --- | --- | --- |
| EV-T00-001 | T00 | Git/runtime baseline | `/home/platform_infrastructure/remediation-work/20260710T034801Z-t00-baseline` | PASS: 22 dirty paths accounted for | 2026-07-10 |
| EV-T00-002 | T00 | Archive integrity | `sha256sum -c manifest-sha256.txt` | PASS | 2026-07-10 |
| EV-T00-003 | T00 | Dirty file recovery | extract `dirty-files.tar`, verify per-file SHA-256 | PASS | 2026-07-10 |
| EV-T00-004 | T00 | Runtime overlays | extract `runtime-overlays.tar`, verify per-file SHA-256 | PASS | 2026-07-10 |
| EV-T00-005 | T00 | Functional edge | local-CA HTTPS probes for registered application hosts | PASS for seven registered apps; public FAIL 404 | 2026-07-10 |
| EV-T01-NEG-001 | T01 | Admin authorization | anonymous GET `/control/applications` | FAIL expected security invariant: HTTP 200 proves fail-open | 2026-07-10 |
| EV-MAP-DB-001 | T00/T04 | DB catalog | PostgreSQL and MariaDB read-only catalog queries | PASS inventory; drift recorded | 2026-07-10 |
| EV-MAP-BKP-001 | T00/T07 | Backup catalog | filesystem and Control Center backup summary | PARTIAL: fresh local artifacts, full portability unproven | 2026-07-10 |

Every later entry must record positive, negative, regression and behavior-preservation evidence. Secret values must never be embedded.
