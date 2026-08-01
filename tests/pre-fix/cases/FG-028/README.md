# Safe approved-revision binding probe

This PoC analyzes and exercises only local synthetic release inputs inside an
archive of the pinned vulnerable revision. It does not fetch a remote branch,
push code, build an image, deploy, or mutate a live checkout.

Run from this directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper verifies commit `68cd05895b8d479ffb8167344282e7d922958bfc`
and tree `70031b30316fbaecbb23249491d6ff4e364d65d5`. A successful safe
demonstration reports `VULNERABLE`.
