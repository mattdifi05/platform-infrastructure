# Service and Asset Ownership Scope

Status: `LOCAL-SUPPORT-READY-EXTERNAL-PENDING`.

This artifact defines the repository-side accountability scope used by
`governance/service-asset-ownership.json`. It does not name or infer a person,
prove a live estate, accept risk, or authorize a rollout. The role identifiers
in the catalog are unbound human-accountability slots until authenticated
primary and substitute acknowledgements are produced and independently
verified outside the local validator.

Every catalog asset requires four distinct roles: primary, substitute,
approval, and escalation. Before a material change, those roles must preserve
the exact prior state and evidence, approve a bounded rollback, review the
artifact after material changes, and keep unresolved external conditions
GO-blocking.

## Hardware scope

Catalog anchor: asset-scope:hardware

The hardware domain covers capacity and recoverability of the reference host,
including compute, storage, network interface, boot path, console or rescue
path, and power dependencies. The local catalog provides only the
`host-capacity` and `host-recovery` accountability slots. Current topology,
custody, health, recovery access, and controlled recovery evidence remain live
or externally verified facts.

## Network scope

Catalog anchor: asset-scope:network

The network domain covers trust zones, internal and edge routing, ingress,
egress, name resolution, origin boundaries, and recovery connectivity. The
catalog assigns `network-segmentation` and `edge-routing`; it does not claim
that live routes, DNS, firewall state, or provider controls match repository
intent.

## Applications scope

Catalog anchor: asset-scope:applications

The applications domain covers lifecycle controls for infrastructure services
and the boundary that keeps hosted project workloads outside the platform
control plane. The catalog assigns `platform-service-lifecycle` and
`hosted-workload-boundary`. It does not make hosted business applications part
of infrastructure readiness or attest their runtime state.

## Data scope

Catalog anchor: asset-scope:data

The data domain covers platform database storage and object-storage
namespaces, including preservation before change and bounded rollback. The
catalog assigns `database-storage` and `object-storage`; record completeness,
live durability, and restore correctness require separate runtime evidence.

## Backup scope

Catalog anchor: asset-scope:backups

The backups domain covers creation, retention, custody, recovery selection,
and verification of backups. The catalog assigns `backup` and `restore`.
Configuration or a local rehearsal is not proof of a successful off-site
backup or independent restore drill.

## Secrets scope

Catalog anchor: asset-scope:secrets

The secrets domain covers approved materialization, rotation, revocation,
recovery, and evidence that never exposes secret values. The catalog assigns
`secret-lifecycle` and `key-recovery`. Runtime principals are not accountable
owners, and repository documentation cannot prove secret custody.

## Observability scope

Catalog anchor: asset-scope:observability

The observability domain covers metrics, logs, alert rules, and authenticated
alert delivery. The catalog assigns `metrics`, `logs`, and `alerting`.
Dashboards and local test fixtures do not prove live ingestion, retention, or
provider delivery.

## CI scope

Catalog anchor: asset-scope:ci

The CI domain covers repository governance and immutable release provenance.
The catalog assigns `source-governance` and `release-provenance`. Local files
cannot prove provider-side branch protection, workflow execution, reviewer
identity, or attestation custody.

## Providers scope

Catalog anchor: asset-scope:providers

The providers domain covers DNS and edge controls, identity services, and
notification delivery. The catalog assigns `dns-edge-provider`,
`identity-provider`, and `notification-provider`. Provider state and
authenticated evidence remain external and must be refreshed against the
exact approved deployment.
