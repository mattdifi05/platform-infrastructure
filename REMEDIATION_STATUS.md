# Remediation Status

Baseline UTC: 2026-07-10T03:48:01Z
Baseline live commit: `5d926f356ea40083856d921a0cfd9ffccc9da785`
Preserved-state commit: `885196ed417de94d70ee1d327f879132181edf06`
Live checkout remains unchanged and dirty by design.

| Task | State | Dependencies | Branch/commit | Evidence | Rollout | Rollback | Residual risk | HA impact |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T00 | CLOSED-VERIFIED | none | `remediation/t00-baseline`, `885196e` | private baseline directory, verified manifest, verified dirty archive, verified overlay archive, runtime/application map | no live mutation | restore archived files/patch; live checkout untouched | map has unresolved public and legacy DB resources | establishes portable identity inventory |
| T01 | IMPLEMENTED-VERIFIED-SANDBOX | T00,T11 design | `remediation/t01-auth`, `30fd2f9`, `86f99e7` | 9/9 Node tests; cryptographic mock IdP; PostgreSQL 18 tmpfs integration; immutable image smoke; secure VPS render | live cutover gated on Keycloak client/flow, dedicated DB secret and two enrolled passkeys | keep portal route offline or LAN-only; restore prior image only behind that restriction | live portal remains fail-open until controlled cutover; current realm has zero users/passkeys | OIDC transactions and opaque revocable sessions use a shared PostgreSQL contract |
| T02 | IMPLEMENTED-VERIFIED-SANDBOX | T01,T09 | `remediation/t02-session-security`, `e92fa99`, `3f123e6` | CSRF/fresh-auth/throttle tests; PostgreSQL tmpfs; Keycloak 26.6.3 import; promtool; secure Compose render | live policy, identity route and Control Center restart gated on two passkeys per admin | keep current runtime unchanged; do not bind passkey flow before enrollment | live realm still has brute-force protection disabled and zero users; alert delivery remains T09 | CSRF, policy version and throttle state use PostgreSQL; Keycloak config is reproducible |
| T03 | OPEN | T01,T08 design | pending | pending | pending | pending | Vault recoverability | key-provider interface required |
| T04 | OPEN | T01 | pending | DB catalog and principal drift recorded | pending | pending | cross-app principal risk | managed endpoint compatible principals |
| T05 | OPEN | T01,T04,T06,T07 | pending | pending | pending | pending | destructive DB workflow | idempotent state machine required |
| T06 | OPEN | T00,T11 | pending | current jobs are global/fuzzy | pending | pending | incorrect resource association | typed portable manifests |
| T07 | OPEN | T03,T04,T06,T15 | pending | fresh local backups; incomplete identity/control coverage | pending | pending | incomplete recovery | portable off-site catalog |
| T08 | BLOCKED-STAGING | T03,T07,T11,T18 | pending | no empty Ubuntu host | none | none | no measured full restore | required for node migration |
| T09 | OPEN | T00,T11 | pending | pending | pending | pending | alert delivery not proven | replaceable receiver contract |
| T10 | OPEN | T00,T11 | pending | pending | pending | pending | workload metrics not truthful | replica-aware metrics labels |
| T11 | DEPLOYED-LIVE | T00 | `remediation/t11-runtime`, `5bcc4ce`, `551a945` | tracked render matches all 32 prior active services; project-router and registry adopted by `platform_infra_vps`; route/catalog/DB/container-ID checks pass | two stateless containers replaced; registry volume retained | automatic rollback commands plus verified registry archive and T00 config | unchanged containers retain historical config-file labels until later per-service rollout; live checkout is still dirty | canonical tracked stack removes future `.tmp` dependency and physical-IP bind is configurable |
| T12-T22 | OPEN | see master plan | pending | see TEST_EVIDENCE_INDEX.md | pending | pending | see master plan | must preserve future multi-node path |
| T23 | BLOCKED-EXTERNAL | T01-T22 | pending | staging/domain/provider evidence absent | none | none | final candidate verdict unavailable | true HA explicitly out of scope |

Do not use DONE. Each row advances only with the evidence required by the master plan.
