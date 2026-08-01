# Safe admission-control PoC

This PoC demonstrates that the exact pre-fix hosted-workload validator accepts
a workload-prefixed logical egress network that resolves to the protected
physical Docker-control network.

It is intentionally non-operational at the Docker boundary. It does not invoke
Docker or Compose; create, inspect, or join a network; open a socket; issue an
HTTP request; contact the socket proxy; deploy a workload; or read live state.
All validation objects are constructed in memory.

## Prerequisites

- Node.js 20 or later.
- Read-only access to the Git repository containing revision
  <code>68cd05895b8d479ffb8167344282e7d922958bfc</code>.
- No Docker daemon is required.

## Run

Start in the parent report directory:

```sh
snapshot="$(mktemp -d)"
REPOSITORY=${REPOSITORY:?set REPOSITORY to the platform-infrastructure Git repository}
git -C "$REPOSITORY" archive 68cd05895b8d479ffb8167344282e7d922958bfc \
  scripts/hosted-workload-contract.mjs \
  scripts/hosted-workload-contract.test.mjs \
  scripts/compose-vps.sh \
  compose.runtime-isolation.yaml |
  tar -x -C "$snapshot"

node poc/hosted-network-physical-ownership-poc.mjs --source-root "$snapshot"
poc_status=$?
rm -rf "$snapshot"
exit "$poc_status"
```

The <code>git archive</code> step avoids the working tree and supplies only the
files used by the PoC. The script refuses a source snapshot whose fingerprints
do not match the exact pre-fix files.

Expected output:

```text
[PASS] exact pre-fix source fingerprints verified
[PASS] repository hosted-workload tests pass 15/15
[PASS] dedicated workload egress baseline is accepted
[PASS] direct logical Docker-control key is rejected
[PASS] non-egress external alias shape is rejected
[PASS] workload-prefixed egress alias to protected physical network is accepted
[PASS] protected network and socket-proxy sink are present in frozen source
[SAFE] no Compose, Docker, network, socket, HTTP, or deployment action attempted
```

## What the result proves

The positive result comes from importing and calling the real
<code>validateRenderedWorkloads</code> implementation. It proves that the
pre-fix admission contract:

- recognizes the workload-prefixed logical key as owned;
- recognizes the <code>egress</code> suffix as an allowed zone;
- leaves <code>external</code> and the physical <code>name</code> unbound; and
- accepts the alias to
  <code>platform_infra_vps_platform_docker_control</code>.

The negative controls show that directly declaring the protected logical key
is rejected and that the same external alias does not pass through a
non-egress zone without the required internal attribute.

## What the result does not prove

The script does not attach a container to an Engine network or demonstrate
connectivity to port 2375. Docker documents that an external network with a
custom name selects the named existing platform network, but an Engine-backed
closure test remains appropriate after the admission fix.

That closure test should use a disposable Engine, a harmless protected fixture
network, and no Docker socket proxy. It should assert that admission rejects
the alias before any Compose activation or network attachment.
