# Safe session-revocation probe

This PoC uses local synthetic session data and an archived copy of the pinned
vulnerable source. It does not contact an identity provider, replay a real
cookie, use credentials, or modify a live database or service.

Run from this directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper verifies commit `68cd05895b8d479ffb8167344282e7d922958bfc`
and tree `70031b30316fbaecbb23249491d6ff4e364d65d5` before executing the
probe in a temporary archive. Expected vulnerable behavior is identified by a
final `VULNERABLE` result.
