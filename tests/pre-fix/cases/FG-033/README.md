# Safe edge-evidence authenticity probe

This PoC evaluates synthetic provider/origin evidence inside a wrapper-owned
archive. It does not contact Cloudflare or the production origin, send traffic,
use credentials, or modify evidence outside the temporary fixture.

Run from this directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper verifies commit `68cd05895b8d479ffb8167344282e7d922958bfc`
and tree `70031b30316fbaecbb23249491d6ff4e364d65d5`. A successful
demonstration reports `VULNERABLE`; the wrapper removes its temporary archive.
