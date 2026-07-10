# Test Evidence Index

| Evidence ID | Task | Boundary | Command or artifact | Result | Freshness |
| --- | --- | --- | --- | --- | --- |
| EV-T00-001 | T00 | Git/runtime baseline | `/home/platform_infrastructure/remediation-work/20260710T034801Z-t00-baseline` | PASS: 22 dirty paths accounted for | 2026-07-10 |
| EV-T00-002 | T00 | Archive integrity | `sha256sum -c manifest-sha256.txt` | PASS | 2026-07-10 |
| EV-T00-003 | T00 | Dirty file recovery | extract `dirty-files.tar`, verify per-file SHA-256 | PASS | 2026-07-10 |
| EV-T00-004 | T00 | Runtime overlays | extract `runtime-overlays.tar`, verify per-file SHA-256 | PASS | 2026-07-10 |
| EV-T00-005 | T00 | Functional edge | local-CA HTTPS probes for registered application hosts | PASS for seven registered apps; public FAIL 404 | 2026-07-10 |
| EV-T01-NEG-001 | T01 | Admin authorization | anonymous GET `/control/applications` | FAIL expected security invariant: HTTP 200 proves fail-open | 2026-07-10 |
| EV-T01-001 | T01 | Auth behavior | `npm test` in pinned Node container | PASS 9/9: anonymous denial, no password path, PKCE/nonce, passkey ACR/AMR, RBAC, one-time state and logout revocation | 2026-07-10 |
| EV-T01-002 | T01 | PostgreSQL session store | PostgreSQL 18 tmpfs sandbox plus `001_auth_sessions.sql` and `postgres-auth-store.integration.mjs` | PASS: migration, atomic transaction consumption, session lookup and post-revocation replay denial | 2026-07-10 |
| EV-T01-003 | T01 | Immutable image | build `docker/control-center.Dockerfile`, run with network disabled and loopback health probe | PASS; test image removed after smoke | 2026-07-10 |
| EV-T01-004 | T01 | Production render | canonical VPS Compose JSON invariant extraction | PASS: `oidc-passkey`, PostgreSQL store, database secret present, password verifier absent, source bind absent | 2026-07-10 |
| EV-T01-005 | T01 | Global static gate | `static-security-check --infra-only` | BLOCKED by pre-existing T20 CSS border assertion; no T01 auth assertion failure observed before stop | 2026-07-10 |
| EV-T02-001 | T02 | Browser mutation boundary | cryptographic OIDC integration test | PASS: missing/sibling Origin rejected, same-origin CSRF accepted, oversized body 413, stale passkey auth 428 | 2026-07-10 |
| EV-T02-002 | T02 | Shared session security | both auth migrations plus PostgreSQL 18 tmpfs integration | PASS: throttle lock/reset, CSRF/session columns, transaction replay and logout revocation | 2026-07-10 |
| EV-T02-003 | T02 | Keycloak policy | pinned Keycloak 26.6.3 first-boot import in tmpfs | PASS: brute force, no password recovery, required UV, discoverable passkey, passwordless-only flow, PKCE and AMR mapper | 2026-07-10 |
| EV-T02-004 | T02 | Runtime readiness negative | `scripts/keycloak-passkey-readiness.sh` against live realm | EXPECTED FAIL: brute-force protection is disabled; live cutover correctly blocked | 2026-07-10 |
| EV-T02-005 | T02 | Alert rules | pinned Prometheus `promtool check rules` | PASS: 21 rules including Keycloak login-failure and admin-lockout alerts | 2026-07-10 |
| EV-T02-006 | T02 | Effective VPS config | canonical Compose JSON invariant extraction | PASS: exact portal origin, 300-second fresh auth, shared throttle, Keycloak event metrics and identity upstream | 2026-07-10 |
| EV-T03-001 | T03 | Versioned Vault keyring | official Control Center runner and `control-center/tests/vault-keyring.test.mjs` | PASS 12/12 overall: stable key ID, reorder, rotation, missing key, tamper and legacy migration | 2026-07-10 |
| EV-T03-002 | T03 | Backup preview confidentiality | API fixture with PostgreSQL COPY row in `.sql.gz` | PASS: `.sql`, `.sql.gz` and `.dump` are metadata-only with empty content | 2026-07-10 |
| EV-T03-003 | T03 | Migration safety | `scripts/control-center-vault-reencrypt.mjs` against synthetic legacy state | PASS: dry-run no write; unconfirmed apply denied; confirmed fixture apply backed up state, escrowed both key files at mode 0600 and preserved decrypt round-trip | 2026-07-10 |
| EV-T03-004 | T03 | State integrity | corrupt JSON and normal Vault mutation fixtures | PASS: corrupt bytes preserved with HTTP 500; normal writes atomic with no temporary artifact left | 2026-07-10 |
| EV-T03-005 | T03 | Secret/Compose contract | isolated Infra Secret Manager init/verify plus canonical VPS render | PASS: dedicated keyring generated mode 0600; no session-key fallback; explicit legacy source only | 2026-07-10 |
| EV-T03-006 | T03 | Private evidence integrity | `/home/platform_infrastructure/remediation-work/20260710T060352Z-t03-vault/manifest-sha256.txt` | PASS: all evidence hashes verified; no real key or Vault state read | 2026-07-10 |
| EV-T03-007 | T03 | Global static gate | `static-security-check --infraOnly` | BLOCKED only after T03 assertions by pre-existing T20 CSS border assertion | 2026-07-10 |
| EV-T04-001 | T04 | Ownership policy/API | official Control Center runner | PASS 16/16: generated principal, protected DB, foreign binding, immutable owner, atomic/fail-closed state | 2026-07-10 |
| EV-T04-002 | T04 | MariaDB sandbox | `scripts/database-ownership-sandbox-test.sh` with pinned disposable MariaDB | PASS: existing foreign principal unchanged, no collision database created, managed create/rotate works, tampered binding rejected | 2026-07-10 |
| EV-T04-003 | T04 | PostgreSQL sandbox | same disposable test with pinned PostgreSQL 18 | PASS: privileged foreign role unchanged, no collision database created, managed create/rotate works | 2026-07-10 |
| EV-T04-004 | T04 | Legacy rollout plan | `scripts/database-principal-migration-plan.mjs` against current metadata read-only | PASS: 5 total, 5 migration-required, 0 mutations; apply mode denied | 2026-07-10 |
| EV-T04-005 | T04 | Candidate/live configuration | canonical VPS render plus redacted live runtime flag | PARTIAL: candidate can render live apply false and registry path; current old live Control Center still reports live apply true | 2026-07-10 |
| EV-T04-006 | T04 | Private evidence integrity | `/home/platform_infrastructure/remediation-work/20260710T110657Z-t04-db-ownership/manifest-sha256.txt` | PASS: all evidence hashes verified; disposable resources cleaned | 2026-07-10 |
| EV-T04-007 | T04 | Global static gate | `static-security-check --infraOnly` | BLOCKED only after T04 assertions by pre-existing T20 CSS border assertion | 2026-07-10 |
| EV-MAP-DB-001 | T00/T04 | DB catalog | PostgreSQL and MariaDB read-only catalog queries | PASS inventory; drift recorded | 2026-07-10 |
| EV-MAP-BKP-001 | T00/T07 | Backup catalog | filesystem and Control Center backup summary | PARTIAL: fresh local artifacts, full portability unproven | 2026-07-10 |
| EV-T11-001 | T11 | Compose render | old active runtime versus tracked runtime, normalized for worktree paths | PASS: all 32 shared services identical; registry is the only added service | 2026-07-10 |
| EV-T11-002 | T11 | Runtime ownership | replace registry and project-router, preserve registry volume | PASS: both owned by `platform_infra_vps`; catalog unchanged | 2026-07-10 |
| EV-T11-003 | T11 | Behavior preservation | compare eight HTTPS host status codes before/after | PASS: exact match | 2026-07-10 |
| EV-T11-004 | T11 | Blast-radius control | compare IDs for every container except the two selected replacements | PASS: all unchanged | 2026-07-10 |
| EV-T11-005 | T11 | Data pre-change gate | fresh signed local backups plus two new OneDrive/Restic snapshots | PASS with OPEN T07 warnings: rclone config update and ephemeral Restic host grouping | 2026-07-10 |
| EV-T11-006 | T11 | Registry rollback | private 218947584-byte volume archive plus SHA-256 and catalog snapshot | PASS | 2026-07-10 |

Every later entry must record positive, negative, regression and behavior-preservation evidence. Secret values must never be embedded.
