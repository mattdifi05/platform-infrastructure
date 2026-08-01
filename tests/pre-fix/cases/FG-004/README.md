# Authorization route probe

This source-aware probe reads `control-center/auth/oidc.mjs` and
`control-center/server.mjs` from a selected Git revision. It extracts and runs
the revision's real `authorize`, `isSensitivePath`, and
`normalizeControlApiParts` functions in a local VM context. It does not open a
socket, make an HTTP request, read a secret, or invoke an operation handler.

From this directory, reproduce the vulnerable matrix with:

```sh
make run SOURCE_ROOT=/path/to/platform-infrastructure \
  REVISION=68cd05895b8d479ffb8167344282e7d922958bfc \
  EXPECT=vulnerable
```

Supply a different checkout, revision, or expected result without editing the
probe:

```sh
make run SOURCE_ROOT=/path/to/platform-infrastructure REVISION=HEAD EXPECT=fixed
```

The vulnerable expectation requires both `/control` and `/control/v1` aliases
for all eight operations to authorize an admin and a stale owner. It also
requires the corresponding legacy action routes to deny admin with 403 and a
stale owner with 428. The fixed expectation reverses the API behavior while
retaining fresh-owner access.

Cleanup is unnecessary. The probe writes only to standard output.
