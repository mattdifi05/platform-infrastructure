# Privileged CI selected-ref trust PoC

This offline PoC demonstrates `CAN-227`, `CAN-229`, `CAN-230`, and
`CAN-231` against exact revision
`68cd05895b8d479ffb8167344282e7d922958bfc` (tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`). It requires a local Git
checkout containing that revision, but it never reads files from the
checkout's working tree.

## Safety boundary

The wrapper verifies the exact commit and tree, creates clean snapshots with
`git archive`, and supplies only a wrapper-owned snapshot to the JavaScript
probe. The probe requires a physical temporary path, an unpredictable
ownership sentinel with a matching token, and the exact non-symlink `source`
child. It refuses direct invocation against an arbitrary source directory.

Before the positive run, the wrapper gives an invalid token to a separate
guard snapshot. The probe must reject it, and a pre-existing synthetic file
must remain byte-for-byte unchanged. The positive probe hashes the entire
source snapshot before and after analysis and verifies that its sentinel keeps
the same device, inode, and bytes.

The PoC performs a source-pinned static workflow trace. It does not call the
GitHub API, dispatch a workflow, start an Actions runner, request an
environment approval, read a credential, connect with SSH, contact
Cloudflare, push a package, issue an attestation, invoke Docker, or access a
live target. All selected refs and the fixed-policy regression inputs are
synthetic in-memory values. Cleanup removes only the unpredictable top-level
temporary archive after revalidating its independent sentinel; missing or
changed ownership evidence makes cleanup fail closed.

## Requirements

- Git
- Node.js 20 or newer
- POSIX `sh`, `tar`, `mktemp`, `grep`, `cmp`, and BSD or GNU `stat`

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
[GUARD] invalid_ownership_rejected=true preexisting_bytes_preserved=true
[+] archived revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5
[+] wrapper-owned source boundary verified
[+] verified 10 embedded vulnerable-source hashes
[+] verified tracked production policy is provider-enforced and still requires live proof
[CONTROL] trusted-ref-policy protected_main=accepted attacker_branch=rejected pull_request_ref=rejected unapproved_tag=rejected approved_release_tag=accepted
[VULNERABLE] CAN-227 release-attestation selected_ref=refs/heads/researcher-controlled precheckout_ref_gate=missing checkout=event-ref authority=packages+attestations+oidc provider_precondition=write-dispatch-authority
[VULNERABLE] CAN-229 vps-evidence selected_ref=refs/heads/researcher-controlled precheckout_ref_gate=missing checkout=event-ref authority=production-ssh provider_precondition=production-environment-admits-ref
[VULNERABLE] CAN-230 live-evidence selected_ref=refs/heads/researcher-controlled precheckout_ref_gate=missing checkout=event-ref authority=cloudflare-provider-token provider_precondition=production-environment-admits-ref
[VULNERABLE] CAN-231 production-deploy selected_ref=refs/heads/researcher-controlled precheckout_ref_gate=missing checkout=event-ref authority=production-ssh-deploy provider_precondition=production-environment-admits-ref
[+] summary vulnerable_source_paths=4 provider_environment_status=not_queried source_tree_unchanged=true
[+] no GitHub API, Actions runner, credential, SSH, provider, registry, Docker, network, or live target was accessed
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

`VULNERABLE` means the pinned workflow admits manual selected-ref execution,
does not contain a trusted-ref condition before its default checkout, and
connects checked-out repository code to the listed authority. For the three
`production` environment jobs, actual credential release remains conditional
on the provider's environment branch and reviewer rules. The probe deliberately
does not claim that this external condition is satisfied.
