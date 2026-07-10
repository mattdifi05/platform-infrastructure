# HA Single-Node Risk Acceptance

This document is non-secret governance evidence for the current platform phase.
It does not claim high availability or multi-node production readiness.

## Scope

- Platform: `platform-infrastructure`.
- Runtime phase: single Ubuntu LTS host on LAN/home VPS.
- Current decision: single-node operation is accepted for this phase.
- Excluded claim: no HA, failover, quorum, multi-node storage or multi-AZ
  availability is claimed.

## Accepted Risk

The platform owner accepts the single-node risk until a public production target
or multi-node provider is introduced. The accepted risk is:

- the host is a single failure domain;
- maintenance can cause downtime;
- local network or power failure can make the platform unavailable;
- stateful services are not automatically failed over to another node.

## Compensating Controls

- Docker healthchecks and `infra-health` verify the running stack.
- Backup scheduler and restore evidence cover recovery from data loss.
- Off-site Restic backup/restore evidence covers remote recovery when current.
- Runbooks document rollback, restore and post-deploy checks.
- The Control Center reports the environment as single-node, not HA.

## Exit Criteria

This acceptance must be replaced by real HA evidence before claiming HA:

- at least two production nodes or a managed HA provider;
- load balancer or provider edge failover;
- tested stateful backup/restore or managed database HA;
- documented failover drill with non-secret report;
- public monitoring that proves availability during failover.

## Approval

- Approved scope: platform-infrastructure only.
- Approved status: single-node risk accepted for the current phase.
- HA claimed: no.
- Multi-node claimed: no.
- Review cadence: before public production go-live and after any provider change.
