# Safe check/use interleaving PoC

This PoC executes the archived `hosted-workload-lock.sh` verifier against a
temporary synthetic lock and Compose file. After the real `compose-files`
command verifies the approved digest and returns the pathname, the probe forces
each swap before simulating the later pathname reopen.

No Docker or Docker Compose command is run, and the synthetic Compose payload
is never executed.

## Requirements

- Git
- Node.js 20 or newer
- jq
- POSIX `sh`, `tar`, and `sha256sum`

## Run

```sh
make run REPOSITORY=/path/to/platform-infrastructure
```

The wrapper verifies the exact commit, tree, lock-verifier digest, and
activation-wrapper digest before running against a clean `git archive`.

Expected output on the pinned vulnerable revision:

```text
[+] in-place mutation: verified path reopened with unverified bytes
[+] in-place mutation: a later verification rejects the swapped source
[+] atomic replacement: verified path reopened with unverified bytes
[+] atomic replacement: a later verification rejects the swapped source
[+] symlink swap: verified path reopened with unverified bytes
[+] symlink swap: a later verification rejects the swapped source
[+] revision: 68cd05895b8d479ffb8167344282e7d922958bfc
[+] tree: 70031b30316fbaecbb23249491d6ff4e364d65d5
[+] Docker/Compose invoked: NO
[+] result: VULNERABLE
```

The later rejection lines are intentional counterevidence: the digest and
symlink checks work when run after a swap, but the activation sequence has no
such check after `compose-files` returns and before Compose opens the path.
Temporary files are removed automatically.
