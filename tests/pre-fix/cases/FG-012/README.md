# SSH first-use host-key trust PoC

This safe probe demonstrates the two affected call sites without opening an
SSH connection. It exports the selected revision with `git archive`, checks
the affected source digests, and places a fake `ssh` executable first in
`PATH`.

For the deployment path, the real `scripts/deploy-vps.sh` builds its request
and invokes the fake client, which records the arguments and input. For the VPS
evidence path, the real request renderer creates the remote evidence script;
the fake client returns a harmless archive containing one forged report. The
probe lists that archive but does not extract or execute its content.

No network request, DNS lookup, SSH handshake, credential use, remote command,
or live-host mutation occurs. All capture files are placed in the disposable
archive and deleted on exit.

Requirements: Git, tar, Make, and Node.js 20 or newer.

Run from this directory:

```sh
make run REPOSITORY=/path/to/platform-infrastructure
```

The default revision is
`68cd05895b8d479ffb8167344282e7d922958bfc`, with
`EXPECT=vulnerable`. A coarse static post-fix check is also available:

```sh
make run \
  REPOSITORY=/path/to/platform-infrastructure \
  REVISION=<fixed-revision> \
  EXPECT=fixed
```

The fixed expectation requires both surfaces to use strict checking with an
explicit known-hosts file and no `accept-new`. Project integration tests should
also exercise a disposable SSH server with the approved, unknown, rotated, and
conflicting host keys.
