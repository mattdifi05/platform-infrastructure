# Remote evidence revision-binding PoC

This offline PoC demonstrates `CAN-146` against exact revision
`68cd05895b8d479ffb8167344282e7d922958bfc` (tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`). It requires a local Git
checkout containing that revision, but it never reads the checkout's working
tree.

## Safety boundary

The wrapper verifies the exact commit and tree, exports clean snapshots with
`git archive`, and supplies only a wrapper-owned snapshot plus an empty
wrapper-owned laboratory to the JavaScript probe. The probe requires their
physical realpaths, an unpredictable ownership sentinel and matching token,
and the exact non-symlink `source` and `lab` children. It rejects direct
invocation against arbitrary directories.

Before the positive run, the wrapper presents a wrong ownership token to a
separate guard snapshot. That call must fail before the laboratory is touched,
and a pre-existing source marker must remain byte-for-byte unchanged. The
positive probe hashes the complete source snapshot before and after execution
and verifies that its sentinel keeps the same device, inode, and bytes.

The experiment creates only disposable local Git repositories beneath the lab.
Their `origin` uses Git's local `file` transport. It does not contact a network,
GitHub, SSH, a VPS, a credential provider, Docker, or another repository. It
does not execute the archived remote script, invoke `sudo`, run host-readiness
checks, create an evidence archive, or extract an archive. Cleanup removes only
the unpredictable top-level temporary root after revalidating its independent
sentinel. Missing or changed ownership evidence makes cleanup fail closed.

## Requirements

- Git
- Node.js 20 or newer
- POSIX `sh`, `tar`, `mktemp`, `grep`, `cmp`, `find`, and BSD or GNU `stat`

## Run

From this `poc` directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

`SOURCE_REPO` has no default. Uncommitted changes are ignored because the
wrapper exports the pinned revision from Git's object database.

## Expected result

```text
[GUARD] invalid_ownership_rejected=true preexisting_bytes_preserved=true lab_untouched=true
[+] archived revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5
[+] wrapper-owned source and lab boundaries verified
[+] verified 4 embedded vulnerable-source hashes
[TRACE] workflow_revision_forwarded=false expected_tree_forwarded=false remote_selection=main-fast-forward archive_binding=missing
[VULNERABLE] workflow_sha=A remote_head=B evidence_revision=B workflow_matches_remote=false
[CONTROL] mutable_main=rejected wrong_commit=rejected wrong_tree=rejected dirty_worktree=rejected exact_detached=accepted
[+] summary revision_mismatch_reproduced=true source_tree_unchanged=true
[+] no network, SSH, GitHub API, credential, sudo, host check, archive extraction, or live target was accessed
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

The PoC first verifies the exact missing fields and mutable-main commands in
the archived source. It then records synthetic workflow revision A, advances a
local bare `main` to revision B, and executes the four vulnerable Git
selection commands in a local clone. The evidence marker comes from B even
though the workflow identity remains A.

The control models the fixed invariant. It rejects a named `main` worktree, a
detached wrong commit, a wrong tree, and a dirty detached worktree; only the
exact expected commit and tree in a clean detached state is accepted.
