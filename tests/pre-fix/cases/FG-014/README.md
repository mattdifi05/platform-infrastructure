# Safe validator PoC

This PoC imports the hosted-workload validator from a clean `git archive` of
the pinned vulnerable revision. It creates only synthetic files in a temporary
directory and does not invoke Docker, Docker Compose, a network service, or a
live deployment.

## Requirements

- Git
- Node.js 20 or newer
- POSIX `sh`, `tar`, and either `sha256sum` or `shasum`

## Run

```sh
make run REPOSITORY=/path/to/platform-infrastructure
```

The wrapper resolves the revision, checks the exact commit, tree, and
`scripts/hosted-workload-contract.mjs` digest, exports that revision with
`git archive`, and runs the probe only against the exported snapshot.

Expected result on the pinned vulnerable revision:

```text
[+] absolute config source: ACCEPTED
[+] traversal config source: ACCEPTED
[+] symlink config source: ACCEPTED
[+] mutable config source: ACCEPTED
[+] pointed-to config bytes in workload lock: NO
[+] config bytes changed after lock resolution: YES
[+] workload lock verification after config mutation: ACCEPTED
[+] deployment-readable synthetic source: YES
[+] revision: 68cd05895b8d479ffb8167344282e7d922958bfc
[+] tree: 70031b30316fbaecbb23249491d6ff4e364d65d5
[+] result: VULNERABLE
```

Temporary artifacts are removed automatically. The PoC prints no sentinel
contents and does not need elevated privileges.
