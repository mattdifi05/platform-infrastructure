# Safe backup-preview redaction probe

This PoC evaluates the vulnerable preview/redaction logic against synthetic
backup text in an archive of the pinned revision. It does not read a real
backup, call a live API, start a server, or use real credentials.

Run from this directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper verifies commit `68cd05895b8d479ffb8167344282e7d922958bfc`
and tree `70031b30316fbaecbb23249491d6ff4e364d65d5` before running in a
temporary archive. A successful demonstration ends with `VULNERABLE`.
