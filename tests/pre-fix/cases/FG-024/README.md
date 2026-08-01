# Safe status-tail amplification probe

This PoC generates a synthetic status history inside an archived copy of the
pinned vulnerable revision and measures the one-shot read behavior. It does not
access production history, start the Control Center, or contact a network.

Run from this directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper verifies commit `68cd05895b8d479ffb8167344282e7d922958bfc`
and tree `70031b30316fbaecbb23249491d6ff4e364d65d5`. A successful bounded
fixture demonstration reports `VULNERABLE`; temporary data is removed.
