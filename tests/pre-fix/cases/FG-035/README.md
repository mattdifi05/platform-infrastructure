# Evidence-bundle trust-anchor PoC

This offline probe demonstrates `CAN-068` against exact revision
`68cd05895b8d479ffb8167344282e7d922958bfc` (tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`). It requires a local Git checkout
that contains the revision; it never uses the checkout's working tree.

Run:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper checks the commit and tree, exports a clean archive, and runs the
original JavaScript verifier inside that disposable copy. Before the positive
demonstration, it exports a separate guard archive, adds deterministic
pre-existing evidence, confirms that the probe rejects it, and compares the
evidence bytes afterward. The positive probe then confirms that a complete
bundle containing `status: "no-go"` is rejected, changes the report to `go`,
recalculates its unsigned manifest entry, and confirms that
`--requireComplete` accepts the coordinated tampering.

The probe uses only temporary files, standard local shell utilities, and the
local `git`, `tar`, and `node` executables. It does not access the network,
Docker, SSH, credentials, provider APIs, or live infrastructure.

The JavaScript entry point will not accept an ordinary source tree directly.
It requires the wrapper's `REPORT_FG035_*` ownership variables, verifies that
the real source path is exactly the non-symlink `source` child of an
unpredictably named wrapper root, validates a random `mktemp` sentinel and its
token, and rejects any pre-existing `reports/` or `.tmp` path before writing.
It performs no recursive cleanup. On exit, the shell wrapper removes only its
top-level temporary archive after validating that archive's independent
ownership sentinel; a missing or altered sentinel makes cleanup fail closed.
