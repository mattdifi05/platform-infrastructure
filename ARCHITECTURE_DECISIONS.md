# Architecture Decisions

Status values: ACCEPTED, OPEN, BLOCKED-STAGING, BLOCKED-EXTERNAL.

| ID | Decision | Status | Consequence |
| --- | --- | --- | --- |
| ADR-001 | Keycloak/OIDC is the central identity provider. Platform administrators use passkey/WebAuthn only, with no password fallback. | ACCEPTED | T01 implements PKCE, signed-token/nonce/ACR/AMR validation, RBAC and PostgreSQL-backed revocable sessions; T02 owns realm flow, lockout, CSRF and fresh re-auth. |
| ADR-015 | The OIDC client is public and uses PKCE S256; no Control Center client secret exists. Browser tokens are never persisted and session cookies are opaque hashes in PostgreSQL. | ACCEPTED | Future Control Center replicas can share session/revocation state without sharing process memory or local signing keys. |
| ADR-016 | Browser mutations require exact portal Origin, same-origin Fetch Metadata and a session-bound double-submit CSRF token; sensitive actions require passkey auth no older than five minutes. | ACCEPTED | Sibling origins and stale sessions cannot invoke Control Center mutations; all replicas enforce one PostgreSQL-backed policy. |
| ADR-017 | Keycloak login/lockout events are exported as bounded-cardinality Prometheus metrics and retained as realm audit events for seven days. | ACCEPTED | T09 must prove the configured alert reaches a real receiver; configuration alone is not delivery evidence. |
| ADR-002 | PostgreSQL dedicated to the control plane is the final primary state store. JSON files are migration input, not final authority. | ACCEPTED | T19 owns versioned schema, transactional migration and rollback. |
| ADR-003 | Release classification is enterprise single-node candidate, HA-prepared but not HA. | ACCEPTED | No same-host replica may be described as HA. |
| ADR-004 | Stexor business backend, web and workers belong to the hosted Stexor project, not platform core. | ACCEPTED | T18 must replace platform-specific naming and external build coupling with generic workload contracts. |
| ADR-005 | Initial RPO is 8 hours and RTO is 4 hours. Later target is RPO 1 hour and RTO 2 hours. | ACCEPTED | Claims require measured empty-host restore evidence. |
| ADR-006 | First release uses a local encrypted Vault with offline encrypted escrow and a provider interface for future KMS. | ACCEPTED | Vault and session keys must be separate and key IDs stable. |
| ADR-007 | Network target uses trust-zone/application bridges plus host enforcement where Docker bridges are insufficient. | ACCEPTED | T12 must include negative connectivity tests and preserve SSH. |
| ADR-008 | Resource ceilings follow the baseline in the remediation program and are calibrated with real metrics. | ACCEPTED | T10 and T13 own limits and capacity headroom. |
| ADR-009 | Destructive staging must be a separate disposable Ubuntu host. The Mac is not staging. | BLOCKED-STAGING | T08 and destructive/failure tests cannot be marked complete on production. |
| ADR-010 | Public edge requires a real domain and scoped Cloudflare configuration. | BLOCKED-EXTERNAL | T17 and public parts of T23 remain blocked until provider inputs exist. |
| ADR-011 | Work happens in a separate server worktree with short-lived remediation branches. The live checkout stays recoverable. | ACCEPTED | No reset, clean or destructive checkout operation on live. |
| ADR-012 | phpMyAdmin/phpPgAdmin become temporary, admin-network-only tools with scoped credentials and auto-shutdown. | ACCEPTED | Persistent current services remain an open T12/T15/T20 issue. |
| ADR-013 | Redis cache, transient NATS, Prometheus samples and Loki logs are rebuildable unless durable use is found. Grafana/Alertmanager configuration is versioned. | OPEN | T07-T08 must confirm whether Redis durability or JetStream is enabled before finalizing. |
| ADR-014 | Production should use Ethernet, deterministic addressing and UPS/NUT. | OPEN | Hardware availability and out-of-band access need verification in T21. |
