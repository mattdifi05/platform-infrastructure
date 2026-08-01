# Safe API-socket admission probe

This PoC evaluates synthetic hosted-workload input in an archive of the pinned
vulnerable revision. It does not open a Docker socket, invoke Docker, start a
container, or contact a live service.

Run from this directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper verifies commit `68cd05895b8d479ffb8167344282e7d922958bfc`
and tree `70031b30316fbaecbb23249491d6ff4e364d65d5` and runs the probe only
inside its temporary archive. A successful demonstration reports
`VULNERABLE`; wrapper-owned temporary data is removed afterward.
