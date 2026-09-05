# Network Segmentation and Router Boundary

## Candidate scope

`compose.networks.yaml` is the T12 trust-zone overlay for the canonical VPS
runtime. It is loaded last by `scripts/compose-vps.sh`. The old external
`enterprise_net` remains declared by the base file for compatibility with
non-canonical profiles, but no service in the candidate runtime is attached to
it.

This is a candidate only. Applying it recreates Docker network attachments and
must happen in an approved maintenance window after backup evidence. T12 does
not change the live networks.

## LOCAL_PRIVATE FIP dedicated egress

This section is separate from the Hosted candidate above. The active Dell V1.1
is the **no-hosted** `LOCAL_PRIVATE` source-lock render; do not activate a
Hosted workload, use its helper, or attach FIP to shared `platform_egress`.

The approved opt-in projection is one new logical network,
`fiplatform_egress`, with the physical name
`platform_infra_greenfield_platform_fiplatform_egress` in the active release. It is a
non-internal IPv4 bridge with only `php-fiplatform` attached:

| Property | Fixed value |
| --- | --- |
| bridge interface | `lpe-fiplatform` |
| IPv4 subnet / gateway | `172.31.240.0/28` / `172.31.240.1` |
| IPv6 | disabled |
| consumer | only `php-fiplatform` |
| retained FIP networks | `enterprise_net`, `platform_routing`, `platform_db_admin` |
| rendered labels | `com.platform.trust-zone=isolated-application-egress`; `com.platform.egress-owner=fiplatform` |

`php-fiplatform` drops `NET_RAW`; it must not add `NET_RAW` or `ALL`. The
network/compiler policy rejects an additional non-internal FIP network, any
other member, a changed bridge/CIDR/name, or a route inventory that overlaps
the proposed subnet. A later application needs its own explicit policy record
and an exact consumer list. Each consumer declares its own
`requiredInternalNetworks`; the compiler preserves that exact internal set,
including for previously admitted owners when another application opts in.
This declaration does not make egress available to every LOCAL_PRIVATE service.

The root-owned LOCAL_PRIVATE guard must derive the Engine bridge and CIDR from
the accepted render/inventory, not from operator arguments. Its `input` hook
drops **all** traffic arriving through `iifname "lpe-fiplatform"`, before any
source-address condition. Its dedicated `forward` hook first drops spoofed
traffic matching `iifname "lpe-fiplatform" ip saddr != 172.31.240.0/28`; only
then may rules match that same interface plus the accepted source CIDR and
apply the reviewed public-destination policy. Those rules deny private,
metadata, link-local, CGNAT, documentation, multicast and reserved ranges. A
CIDR-only rule is invalid: it could capture traffic from a different bridge,
while an interface-plus-CIDR input drop could be bypassed with a spoofed source.
The guard must not modify UFW, Docker `DOCKER-USER`, or any Hosted firewall
chain.

The controller creates the FIP replacement stopped, verifies the exact Engine
inventory, installs and verifies its own firewall state, then starts only FIP.
Inventory v3 distinguishes a never-started `configured-unmaterialized` join
(created container, actual named network key, absent Engine IDs) from a
full-ID `configured-stopped` join and an `active-endpoint`. It never invents a
container NetworkID before Docker allocates it. The controller separately
captures the real empty network's full ID, labels and IPAM, then rechecks both
that identity and the created container's exact physical network names just
before start. Post-start admission still requires full network/endpoint IDs.
Its systemd guard reapplies the admitted nftables program before Docker can
restart containers after a host/Docker restart. This is boot-time firewall
restoration, not a continuous Engine identity monitor: the helper does not
query Docker before the daemon starts. Root/Docker-admin topology changes
require fresh render/inventory admission; application containers and the typed
backup broker cannot perform those changes. The interface/source/destination
guard remains independent of Docker's network ID. Record actual runtime
activation separately from reboot, daemon-restart and UFW-reload validation;
do not claim those disruptive lifecycle checks from unit syntax or namespace
tests alone. Rollback stops only FIP, restores its
prior reviewed attachment and the prior private firewall state, then restarts
that prior FIP container. Never use `docker network connect`, `compose down`,
or a hand-written firewall command for this boundary.

## Core trust zones

| Network | Members/purpose | Internet route |
| --- | --- | --- |
| `platform_edge` | WAF to Traefik only | No |
| `platform_routing` | Traefik to router/control/backend/admin HTTP targets | No |
| `platform_db_admin` | Control Center and DB admin tools to MariaDB/PostgreSQL | No |
| `platform_postgres` | Platform services that require PostgreSQL | No |
| `platform_cache` | Platform services that require Redis | No |
| `platform_bus` | Platform services that require NATS | No |
| `platform_storage` | Platform services that require MinIO | No |
| `platform_observability` | Prometheus, Loki, Alertmanager, Grafana and approved scrape/receiver targets | No |
| `platform_egress` | Trusted platform services with ACME/provider/SMTP/off-site needs | Yes |

Every hosted application receives separate ingress and egress networks. An
application with a database also receives a separate data network containing
only that application and its database service. The project-router is present
only on ingress networks; it does not share database or observability networks.
Application egress networks contain exactly one workload, preventing egress
networks from becoming a second east-west application network.

Traefik uses the trusted platform egress zone for ACME. The Control Center uses
it for approved provider/repository operations. Neither service is attached to
an application egress network, and the project-router has no Internet-routed
network.

## Router destination contract

The project-router accepts only internal HTTP origins whose exact
`service-id:port` appears in `PROJECT_ROUTER_ALLOWED_UPSTREAMS`.

The following are rejected before an outbound request:

- IP literals, including loopback, RFC1918 and link-local/metadata addresses;
- `localhost`, `host.docker.internal` and hostnames containing dots;
- protocols other than `http`;
- URL credentials, query, fragment or base path;
- services not in the exact allowlist;
- absolute-form and scheme-relative client request targets.

Loopback is available only when both `NODE_ENV=test` and
`PROJECT_ROUTER_TEST_ALLOW_LOOPBACK=true`, allowing deterministic unit tests
without weakening production. Redirect responses are relayed to the client but
never followed by the router.

## Verification

Policy/render check, no live network mutation:

```bash
sh ./scripts/network-segmentation-check.sh \
  --envFile /home/platform_infrastructure/platform-infrastructure/.env
```

Disposable Docker network connectivity test:

```bash
sh ./scripts/network-segmentation-sandbox-test.sh
```

The policy check renders through the same `scripts/compose-vps.sh` wrapper used
for deployment. A configured, verified `HOSTED_WORKLOAD_LOCK` is therefore part
of the checked graph; the evidence records the complete render digest and every
hosted workload identity.

The sandbox proves router-to-app and app-to-database connectivity, then proves
router-to-database, router/app-to-observability, cross-app and unrelated
app-to-database denial. It removes all disposable containers and networks on
exit.

Review the destination-aware IPv4 egress policy without changing the host:

```bash
sh ./scripts/workload-egress-firewall.sh \
  --plan \
  --lock /absolute/deployment-private/hosted-workloads.lock.json \
  --project-name platform_infra_vps
```

The production deploy gate creates containers without starting them, verifies
the exact Engine network ownership from that same lock, applies and verifies
the firewall, repeats both read-only verifications, and only then starts the
containers. Apply requires root and the exact
`APPLY-WORKLOAD-EGRESS-FIREWALL` confirmation; it never discovers networks by
prefix or accepts a caller-supplied subnet. A replacement chain is populated
and verified before it becomes the first `DOCKER-USER` rule, so the previous
chain remains enforcing until the complete replacement is active. The dedicated
`PLATFORM-WORKLOAD-EGRESS` chain is reached from `DOCKER-USER` and blocks
loopback, RFC1918, link-local/metadata, CGNAT and reserved IPv4 ranges. The
Compose egress networks explicitly disable IPv6. Rollback has a different
strong confirmation and removes only the dedicated chain.

## Rollout and rollback

1. Archive fresh backup/restore and current `docker network inspect` evidence.
2. Render the canonical stack with `compose.networks.yaml` last.
3. Verify the policy and disposable sandbox, then review the egress firewall
   plan against the Docker-assigned candidate subnets.
4. Apply and verify the dedicated egress firewall before starting hosted
   workloads.
5. Recreate services in dependency groups, never with `docker compose down -v`.
6. Run route, OIDC, DB admin, alert delivery, workload metrics and application
   smoke tests after every group.
7. Preserve old `enterprise_net` until all services pass on the new networks.

Rollback re-applies the previous Compose revision and recreates only affected
containers on `enterprise_net`. It never removes volumes. Network deletion is
allowed only after no container is attached and rollback evidence is complete.

## Known follow-ups

- T13 removes broad mounts/socket exposure and applies resource controls.
- T14 narrows credentials and service policies inside allowed data paths.
- T17 controls public admin access and direct-origin traffic.
- T18 extracts the current application-specific runtime/network declarations
  into generic generated application contracts.
- Provider-specific destination allowlists and proxy policy remain a host/edge
  follow-up even after private/reserved destinations are denied.
