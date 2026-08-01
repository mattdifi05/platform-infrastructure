# Safe project-tree budget probe

This PoC builds a synthetic bounded directory tree inside a clean archive of
the pinned vulnerable revision. It does not traverse a real hosted project,
start a service, or contact Docker or the network.

Run from this directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper verifies commit `68cd05895b8d479ffb8167344282e7d922958bfc`
and tree `70031b30316fbaecbb23249491d6ff4e364d65d5`. Expected vulnerable
behavior is identified by a final `VULNERABLE` result.
