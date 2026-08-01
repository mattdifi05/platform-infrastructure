# Safe PoC execution

Run the probe through the archive wrapper:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper verifies commit
`68cd05895b8d479ffb8167344282e7d922958bfc` and tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`, exports that revision into a
temporary directory, and passes only the temporary archive to the Node probe.

The probe refuses to run if the supplied source already contains a `reports/`
directory. It also requires the source's real path to be the exact `source/`
child of the wrapper-owned temporary root. When `reports/` is absent, the
probe creates it with an unpredictable ownership sentinel and removes it only
when that exact sentinel is still present. These controls prevent direct
invocation from deleting pre-existing evidence. No network, provider, Docker,
SSH, credential, or live target is used.
