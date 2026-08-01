# Safe hosted-secret ownership probe

This PoC evaluates synthetic Compose secret aliases in an archived copy of the
pinned vulnerable revision. It does not read a real secret, invoke Docker,
start a service, or contact a network endpoint.

Run from this directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper verifies commit `68cd05895b8d479ffb8167344282e7d922958bfc`
and tree `70031b30316fbaecbb23249491d6ff4e364d65d5`. A successful
demonstration reports `VULNERABLE`; all secret values are synthetic.
