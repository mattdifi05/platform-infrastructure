# Safe raw-device admission probe

This PoC exports the pinned vulnerable revision into a wrapper-owned temporary
directory and exercises only synthetic Compose input. It does not access a real
device, invoke Docker, contact a network service, or modify the source checkout.

Run from this directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper verifies commit `68cd05895b8d479ffb8167344282e7d922958bfc`
and tree `70031b30316fbaecbb23249491d6ff4e364d65d5` before running the
probe against the clean archive. A successful demonstration ends with a
`VULNERABLE` result. Temporary files are removed by the wrapper.
