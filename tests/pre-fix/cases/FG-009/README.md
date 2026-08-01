# Safe transitive-lock probe

This probe reproduces the source-level lock/second-read primitive at revision
`68cd05895b8d479ffb8167344282e7d922958bfc`. It does not invoke Docker or the
Compose CLI and does not attempt container activation.

Requirements: POSIX `sh`, Git, tar, Make, and Node.js with ES-module support.
Run it from this directory and point `SOURCE_REPO` at a Git checkout containing
the vulnerable revision:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper exports the exact revision into a temporary directory, checks its
commit and tree identities, and removes the directory automatically. The Node
probe verifies four embedded source hashes, imports the vulnerable contract,
and creates a second temporary synthetic fixture. Three cases independently
exercise `extends.file`, top-level `include`, and service `env_file`.

Each case validates a benign in-memory rendered workload, changes only the
dependency omitted from `lock.files`, confirms the primary file is unchanged,
and shows that `verifyLockFiles` still succeeds before a minimal field-specific
second read observes the changed value. All temporary data is deleted on normal
exit. The wrapper also removes its archive directory on handled interruption;
as with most temporary test programs, an uncatchable process termination can
leave an operating-system temporary directory for routine cleanup.
