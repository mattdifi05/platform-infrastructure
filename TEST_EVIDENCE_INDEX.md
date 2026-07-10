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
| EV-T11-001 | T11 | Compose render | old active runtime versus tracked runtime, normalized for worktree paths | PASS: all 32 shared services identical; registry is the only added service | 2026-07-10 |
| EV-T11-002 | T11 | Runtime ownership | replace registry and project-router, preserve registry volume | PASS: both owned by `platform_infra_vps`; catalog unchanged | 2026-07-10 |
| EV-T11-003 | T11 | Behavior preservation | compare eight HTTPS host status codes before/after | PASS: exact match | 2026-07-10 |
| EV-T11-004 | T11 | Blast-radius control | compare IDs for every container except the two selected replacements | PASS: all unchanged | 2026-07-10 |
| EV-T11-005 | T11 | Data pre-change gate | fresh signed local backups plus two new OneDrive/Restic snapshots | PASS with OPEN T07 warnings: rclone config update and ephemeral Restic host grouping | 2026-07-10 |
| EV-T11-006 | T11 | Registry rollback | private 218947584-byte volume archive plus SHA-256 and catalog snapshot | PASS | 2026-07-10 |

Every later entry must record positive, negative, regression and behavior-preservation evidence. Secret values must never be embedded.
