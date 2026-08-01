# Safe project-metadata budget probe

This PoC creates only synthetic project metadata beneath a wrapper-owned
temporary archive. It does not inspect real project directories, start the
router, invoke Docker, or use the network.

Run from this directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper verifies commit `68cd05895b8d479ffb8167344282e7d922958bfc`
and tree `70031b30316fbaecbb23249491d6ff4e364d65d5` before executing the
probe. A successful demonstration reports `VULNERABLE` and leaves the source
checkout unchanged.
