# HA Preparedness

## Verdict

The platform is single-node and is not highly available. A host, power, storage or network failure can stop the entire platform. Same-host replicas are not failover.

## Current singleton and state inventory

| Component | Current state location | Singleton reason | Future direction |
| --- | --- | --- | --- |
| Traefik/WAF | host Compose and local configuration | one ingress node | external load balancer and replicated stateless edge |
| Control Center | application metadata remains in JSON; T01 auth transactions and revocable sessions target PostgreSQL | application state migration is still pending T19 | migrate all authority to PostgreSQL, then run multiple stateless instances |
| project-router | one process and local source discovery | host-mounted registry/source | service registry with immutable workload IDs and replicated routers |
| PostgreSQL | one local Docker volume | single-node release | managed or replicated PostgreSQL endpoint |
| MariaDB | one local Docker volume | single-node release | managed or replicated MariaDB endpoint |
| MinIO | one local Docker volume | single-node release | distributed MinIO or managed object storage |
| Redis | one local Docker volume | standalone deployment | clustered/managed Redis if durable/shared state requires it |
| NATS | one local Docker volume | standalone deployment | clustered NATS/JetStream with explicit durability policy |
| Backup scheduler | one Docker-socket executor | local cron/executor model | leased idempotent jobs and replaceable isolated executor |
| Prometheus/Loki/Alertmanager | local volumes/configuration | single observability node | remote or replicated observability as required |

## Node dependencies to remove

- effective runtime depends on ignored `.tmp` overlays;
- application and control services depend on fixed host paths;
- project-router and PHP services receive host-parent mounts;
- Control Center application state is JSON/file based; auth session state has a PostgreSQL contract but is not live yet;
- local images are not yet tied to immutable release provenance;
- all services share one Docker network;
- local Docker socket is an execution boundary;
- backup host identity and restore manifests are incomplete.

## Stateless replication contract

Before a service is called HA-prepared it must keep no authoritative state in the container filesystem, support graceful shutdown, expose distinct liveness/readiness/functional health, use idempotent jobs and avoid implicit leadership. Shared session/revocation/job state must move to PostgreSQL/Redis with explicit contracts.

## Stateful future options

- PostgreSQL and MariaDB: configurable DNS endpoints, separate runtime/migration/backup principals, managed or replicated target.
- MinIO: S3-compatible endpoint abstraction, per-application policies, distributed or managed target.
- Redis/NATS: explicit durable versus rebuildable classification, clustered endpoints and distributed lease/deduplication.
- Control plane: PostgreSQL-backed state, replicated stateless Control Center and project-router behind a load balancer.
- Edge: DNS/load-balancer failover without application dependency on the current physical IP.

## Gaps before true HA

A second failure domain, replicated or managed stateful services, redundant ingress, external load balancer, quorum/fencing, tested failover, replicated backup credentials/escrow and measured continuity are absent. Therefore the only permitted label is: PRODUCTION-READY ENTERPRISE SINGLE-NODE CANDIDATE, HA-PREPARED MA NON HA, and only after T23 evidence.
