# Redis workload-authorization PoC

This offline probe demonstrates `CAN-128` against exact pre-fix revision
`68cd05895b8d479ffb8167344282e7d922958bfc` (tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`). It requires a local Git checkout
that contains the revision, but it never reads or executes that checkout's
working tree.

Run:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper verifies the commit and tree and exports two clean Git archives
under one unpredictable, sentinel-owned temporary directory. The first is a
negative guard: the probe receives the wrong ownership token, must reject it,
and the wrapper confirms the archived `compose.yaml` stayed unchanged. The
second archive runs the positive probe.

The probe verifies four exact source fingerprints. It proves that Redis starts
with one `requirepass` secret and no ACL file, while the hosted-workload
contract permits two workloads to depend on the one Redis service through
separate logical cache networks. It also proves negative contract controls for
cross-workload network use and undeclared secrets.

The final step is an explicitly labeled offline authorization projection. It
uses fixture-only credentials and models the effective default-user policy
selected by `requirepass`: one authenticated identity can access all keys and
commands. The fixed control uses distinct identities, own-prefix permissions,
and a narrow command allowlist. This is not a Redis server emulator and does
not claim a live reproduction.

The PoC does not start Redis, Docker, or Compose. It does not access the
network, SSH, credentials, provider APIs, or live infrastructure. It writes
nothing inside the archived source. Cleanup removes only the wrapper-owned
temporary directory and fails closed if its sentinel is missing or altered.
