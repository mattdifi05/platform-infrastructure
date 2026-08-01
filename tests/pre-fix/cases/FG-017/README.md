# Safe local-volume driver probe

This PoC uses synthetic Compose data inside a clean archive of the pinned
vulnerable revision. It demonstrates admission of dangerous local-driver
options without creating a Docker volume, mounting a host path, or invoking
Docker or a network service.

Run from this directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper verifies commit `68cd05895b8d479ffb8167344282e7d922958bfc`
and tree `70031b30316fbaecbb23249491d6ff4e364d65d5`, then runs only against
the exported snapshot. A successful demonstration ends with `VULNERABLE`.
