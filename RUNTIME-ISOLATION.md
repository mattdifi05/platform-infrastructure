# Runtime Isolation

Status: implemented and verified in disposable sandboxes on 2026-07-10. The
reference live containers were not recreated. This is a single-node hardening
contract; it does not provide high availability.

## Scope

`compose.runtime-isolation.yaml` is the final VPS overlay. It enforces:

- CPU quota and relative CPU priority for every rendered service;
- memory ceiling and reservation for every rendered service;
- PID, file-descriptor and block-I/O weight limits;
- read-only root filesystems for hosted applications and exposed control
  services where the image supports it;
- exact, read-only source mounts for each hosted application;
- no infrastructure repository, backup path, Control Center state or Docker
  socket inside hosted workloads;
- no shared gateway signing key or SMTP secret in PHP workloads;
- one digest-pinned Docker socket proxy on a dedicated internal network;
- a loopback-only host endpoint for the trusted ops runner.

The overlay is loaded after `compose.networks.yaml`. Earlier overlays remain
the rollback source, but the final render is authoritative.

## Resource Budget

The verified reference host has 12 logical CPUs and approximately 15 GiB RAM.
The rendered hard ceilings total 13,623,099,392 bytes, below the 14,155,776,000
byte admission limit. This leaves approximately 2 GiB for Ubuntu, Docker and
filesystem cache. CPU ceilings are intentionally overcommitted; `cpu_shares`
prioritizes control-plane and data services when workloads contend.

The budget is a starting production candidate, not a capacity forecast. T10
metrics must be collected through a representative load window before any
limit is reduced.

## Hosted Mount Model

PHP source directories are mounted below `/opt/platform-source/<slug>` as
read-only. `php-project-runtime.sh` validates the slug and paths, copies only
that application into a per-container tmpfs at `/var/www/projects`, and starts
the standard PHP image entrypoint. Runtime cache and log writes are ephemeral;
the host source cannot be altered by the PHP process. The `fireport` hostname
is an in-memory alias of the `fiplatform` runtime and does not add another host
source mount.

Node account/UI source is mounted read-only at `/workspace`. Production
runtime install/build commands are disabled; the containers start only the
prebuilt artifact. Runtime cache is a bounded tmpfs. T18 still owns replacing
the external prebuilt source dependency with immutable application images.

Control Center keeps read-only access to infrastructure documentation and the
external application catalog plus its dedicated writable state directory.
Project Router receives only read-only application and state catalogs. Neither
service receives the repository-parent mount.

## Docker Daemon Boundary

Only `docker-socket-proxy` receives `/var/run/docker.sock`. Its image is pinned
by digest. Auth, build, commit, secrets, services, swarm, system and task API
sections are disabled.

The backup scheduler reaches the proxy through the internal
`platform_docker_control` network. Hosted workloads are not members of this
network.

The host ops runner uses `127.0.0.1:2376`; no LAN or public address is bound.
When the persistent VPS proxy is absent, `infra-ops.sh` creates a disposable
digest-pinned proxy and private client network, runs the command with the SSH
user UID/GID, then removes both. Raw socket mode is denied unless an operator
sets both:

```sh
PLATFORM_OPS_DOCKER_MODE=raw \
PLATFORM_ALLOW_RAW_DOCKER_SOCKET=1 \
sh ./scripts/infra-ops.sh <command>
```

That mode is recovery-only and requires an approved maintenance record.

## Verification

Deterministic policy and Compose checks:

```sh
sh ./scripts/compose-runtime-check.sh
sh ./scripts/runtime-isolation-check.sh --env-file=.env.vps.example
sh ./scripts/network-segmentation-check.sh --env-file=.env.vps.example
sh ./scripts/supply-chain-lock-check.sh
```

Bounded cgroup/socket stress sandbox:

```sh
sh ./scripts/runtime-isolation-sandbox-test.sh
```

Hosted workload contract and combined render on Ubuntu:

```sh
HOSTED_WORKLOAD_CATALOG=/path/hosted-workloads.json \
HOSTED_WORKLOAD_ROOT=/path/applications \
HOSTED_WORKLOAD_LOCK=/path/private/hosted-workloads.lock.json \
COMPOSE_ENV_FILE=.env.vps \
sh ./scripts/prepare-hosted-workloads.sh
```

Preparation does not start containers or connect to a database. It validates
the external workload inputs, renders core and combined Compose models and
writes a permission-restricted SHA-256 lock. Runtime activation is a separate
approved maintenance action.

## Rollout Gate

Do not apply this overlay to the reference stack without:

1. fresh signed local and off-site backup evidence;
2. an approved maintenance window;
3. a saved pre-change Compose render and live container inventory;
4. T01/T02 identity readiness before exposing the new Control Center;
5. one-service-at-a-time recreation and functional probes;
6. T10 metrics confirming no OOM, PID or FD pressure.

Start with one PHP canary, then one Node canary, Project Router, scheduler and
finally shared control/data services. Database and edge recreation require a
separate stop point.

Never run `docker compose down -v` and never delete volumes during rollout.

## Rollback

Rollback uses the previous verified release and recreates only the affected
service. Preserve logs, `docker inspect`, resource events and the failed render
before rollback. Do not remove volumes or application sources.

For a per-app failure, restore the previous Compose revision and run the old
canonical wrapper with `up -d --no-deps --force-recreate <service>`. If the
socket proxy fails, stop new scheduler jobs, preserve queued job state, restore
the previous scheduler revision and leave the Docker socket unavailable to
hosted workloads.

## Residuals

- T14 scoped identity and MinIO contracts are implemented in sandbox; their
  application-specific rollout now belongs to each workload repository.
- T18 immutable hosted application builds and the external workload lock are
  implemented in candidate branches; live activation remains pending approval.
- T20 owns the existing Control Center CSS static-gate blocker.
- T21 owns disk/UPS telemetry and host I/O/power drills.
- T22 owns complete CI gate consolidation and dependency-runner cleanup.
- T08 still requires a clean-host restore on a disposable Ubuntu server.
