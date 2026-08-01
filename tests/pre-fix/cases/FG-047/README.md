# Evidence-render deployment-equivalence PoC

This offline probe demonstrates `CAN-221` and `CAN-222` against exact pre-fix
revision `68cd05895b8d479ffb8167344282e7d922958bfc` (tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`). It requires a local Git checkout
that contains the revision, but it never reads or executes that checkout's
working tree.

Run:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper verifies the commit and tree, exports a clean Git archive into an
unpredictably named temporary directory, and runs the probe against that
archive. The probe verifies five source fingerprints before importing the
original hosted-workload contract plus the network and runtime policy
evaluators. It then proves three states:

1. both evidence commands hard-code the same nine core Compose files and omit
   the hosted-workload resolver used by the deployment wrapper;
2. a core-only render passes both policies with zero hosted workloads, while
   the exact render containing a directly hostile workload fails both;
3. a workload network can pass the hosted-workload contract with a dedicated
   logical egress name while aliasing the protected Docker-control physical
   network, and the pre-fix network policy still passes the combined render.

The probe does not invoke Docker or Compose. It does not access the network,
SSH, credentials, provider APIs, or live infrastructure. It writes nothing
inside the archived source. Cleanup removes only the sentinel-owned temporary
archive and fails closed if its ownership sentinel is missing or altered.

Representative output is included in the accompanying vulnerability report.
