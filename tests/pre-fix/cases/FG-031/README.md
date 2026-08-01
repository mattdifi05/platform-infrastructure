# Safe interpolation-provenance probe

This PoC renders only synthetic Compose/environment input inside a clean
archive of the pinned vulnerable revision. It does not read deployment secrets,
invoke Docker Compose, start a container, or contact a network.

Run from this directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper verifies commit `68cd05895b8d479ffb8167344282e7d922958bfc`
and tree `70031b30316fbaecbb23249491d6ff4e364d65d5` before execution. A
successful safe demonstration ends with `VULNERABLE`.
