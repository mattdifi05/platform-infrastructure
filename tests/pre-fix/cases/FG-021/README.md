# Safe WAF logging-pipeline probe

This PoC inspects the pinned configuration and processes only synthetic secret
markers inside a clean Git archive. It does not submit traffic, read real logs,
query Loki, or expose credentials.

Run from this directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper verifies commit `68cd05895b8d479ffb8167344282e7d922958bfc`
and tree `70031b30316fbaecbb23249491d6ff4e364d65d5`. A successful safe
demonstration reports `VULNERABLE`; all inputs are synthetic and temporary.
