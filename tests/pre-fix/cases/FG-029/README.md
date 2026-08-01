# Safe release-gate ordering probe

This PoC uses local fakes and synthetic state in a clean archive to determine
whether release gates precede mutation boundaries. It does not build images,
invoke a real Docker daemon, deploy, or contact the production host.

Run from this directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper verifies commit `68cd05895b8d479ffb8167344282e7d922958bfc`
and tree `70031b30316fbaecbb23249491d6ff4e364d65d5` before running. A final
`VULNERABLE` result demonstrates the ordering defect using only fakes.
