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

The sandbox proves router-to-app and app-to-database connectivity, then proves
router-to-database, router/app-to-observability, cross-app and unrelated
app-to-database denial. It removes all disposable containers and networks on
exit.

Review the destination-aware IPv4 egress policy without changing the host:

```bash
sh ./scripts/workload-egress-firewall.sh \
  --plan \
  --network-prefix platform_infra_vps
```

After candidate egress networks exist, apply requires root and the exact
`APPLY-WORKLOAD-EGRESS-FIREWALL` confirmation. The dedicated
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
