# Remediation Status

Baseline UTC: 2026-07-10T03:48:01Z
Baseline live commit: `5d926f356ea40083856d921a0cfd9ffccc9da785`
Preserved-state commit: `885196ed417de94d70ee1d327f879132181edf06`
Live checkout remains unchanged and dirty by design.

| Task | State | Dependencies | Branch/commit | Evidence | Rollout | Rollback | Residual risk | HA impact |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T00 | CLOSED-VERIFIED | none | `remediation/t00-baseline`, `885196e` | private baseline directory, verified manifest, verified dirty archive, verified overlay archive, runtime/application map | no live mutation | restore archived files/patch; live checkout untouched | map has unresolved public and legacy DB resources | establishes portable identity inventory |
| T01 | OPEN | T00,T11 design | pending | unauthenticated `/control/applications` returned HTTP 200 | pending | pending | fail-open admin surface | auth state must become shared/revocable |
| T02 | OPEN | T01,T09 | pending | pending | pending | pending | CSRF/session/Keycloak gaps | shared session contract required |
| T03 | OPEN | T01,T08 design | pending | pending | pending | pending | Vault recoverability | key-provider interface required |
| T04 | OPEN | T01 | pending | DB catalog and principal drift recorded | pending | pending | cross-app principal risk | managed endpoint compatible principals |
| T05 | OPEN | T01,T04,T06,T07 | pending | pending | pending | pending | destructive DB workflow | idempotent state machine required |
| T06 | OPEN | T00,T11 | pending | current jobs are global/fuzzy | pending | pending | incorrect resource association | typed portable manifests |
| T07 | OPEN | T03,T04,T06,T15 | pending | fresh local backups; incomplete identity/control coverage | pending | pending | incomplete recovery | portable off-site catalog |
| T08 | BLOCKED-STAGING | T03,T07,T11,T18 | pending | no empty Ubuntu host | none | none | no measured full restore | required for node migration |
| T09 | OPEN | T00,T11 | pending | pending | pending | pending | alert delivery not proven | replaceable receiver contract |
| T10 | OPEN | T00,T11 | pending | pending | pending | pending | workload metrics not truthful | replica-aware metrics labels |
| T11 | IN-PROGRESS | T00 | pending | two ignored runtime overlays and mixed Compose ownership recorded | pending | baseline bundle and current live config | recreate not yet deterministic | removes node-specific runtime drift |
| T12-T22 | OPEN | see master plan | pending | see TEST_EVIDENCE_INDEX.md | pending | pending | see master plan | must preserve future multi-node path |
| T23 | BLOCKED-EXTERNAL | T01-T22 | pending | staging/domain/provider evidence absent | none | none | final candidate verdict unavailable | true HA explicitly out of scope |

Do not use DONE. Each row advances only with the evidence required by the master plan.
