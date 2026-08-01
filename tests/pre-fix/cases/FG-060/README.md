# Trusted forwarded-client rate-key PoC

This offline probe demonstrates `CAN-171` against exact pre-fix revision
`68cd05895b8d479ffb8167344282e7d922958bfc` (tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`). It requires a local Git checkout
containing that revision, but it never reads or executes the checkout's working
tree.

Run:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper verifies the commit and tree and exports two clean `git archive`
snapshots under one unpredictable, sentinel-owned temporary directory. The
first is a negative ownership guard: the probe receives the wrong sentinel
token, must reject it, and the wrapper confirms that the archived rate-limit
configuration stayed unchanged. The second archive runs the positive probe.

The probe verifies eight exact source fingerprints. It proves that the VPS WAF
is the public peer immediately in front of Traefik, that both services share the
private edge network, and that the shared rate-limit definition has
`average: 120`, `burst: 60`, `period: 1m`, but no `sourceCriterion`. It also
counts eight router references, including one wildcard project router.

The final phase is an explicitly labeled in-memory policy projection. It shows
that two independent public clients map to the same pre-fix WAF peer key, so one
client's instantaneous burst exhausts the other client's bucket on that router.
The fixed control models a WAF that overwrites a dedicated client-identity
header and a Traefik boundary that accepts it only from the expected WAF peer.
It proves independent buckets and negative controls for spoofed, malformed,
untrusted-provider, and direct-to-Traefik identities.

This is not a Traefik or WAF emulator and does not claim a live denial of
service. It does not start Traefik, Nginx, ModSecurity, Docker, or Compose. It
does not access the network, SSH, credentials, provider APIs, or live
infrastructure. Cleanup removes only the wrapper-owned temporary directory and
fails closed if its sentinel, path, or ownership token is missing or altered.
