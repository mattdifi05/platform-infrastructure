# Hosted network-object invariant PoC

This offline PoC demonstrates `CAN-151`, `CAN-152`, `CAN-153`, and `CAN-160`
against exact revision `68cd05895b8d479ffb8167344282e7d922958bfc`
(tree `70031b30316fbaecbb23249491d6ff4e364d65d5`). It requires a local Git
checkout that contains the revision, but it never reads files from the
checkout's working tree.

## Safety boundary

The wrapper verifies the commit and tree, exports clean snapshots with
`git archive`, and passes only the positive snapshot to the probe. The
JavaScript entry point requires the wrapper's physical temporary path, a random
ownership sentinel and matching token, and an exact non-symlink `source` child.
It refuses direct invocation against an arbitrary directory.

Before the positive run, the wrapper supplies an invalid token to a separate
guard snapshot. That call must fail, and a pre-existing synthetic file must
remain byte-for-byte unchanged. The positive probe hashes the entire source
snapshot before and after analysis and verifies that its ownership sentinel
keeps the same device, inode, and bytes.

The PoC does not invoke Docker or Docker Compose, create or join an Engine
network, load a driver, send a packet, connect to a service, use SSH, access a
credential, or contact live infrastructure. All hostile network definitions
and topology fixtures exist only in JavaScript memory. Cleanup removes only the
unpredictable top-level temporary archive after revalidating its independent
sentinel. Missing or changed ownership evidence makes cleanup fail closed.

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

`SOURCE_REPO` has no default. Uncommitted working-tree changes are ignored
because the wrapper exports the pinned revision from the Git object database.

## Expected result

```text
[GUARD] invalid_ownership_rejected=true preexisting_bytes_preserved=true
[+] archived revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5
[+] wrapper-owned source boundary verified
[+] verified 5 embedded vulnerable-source hashes
[+] verified tracked database and routing physical network names
[+] verified admitted workload files reach the Compose activation command
[CONTROL] foreign-logical-key admission=rejected
[VULNERABLE] CAN-151 database-external-alias admission=accepted segmentation=passed external=true name=platform_infra_vps_db_admin
[VULNERABLE] CAN-152 routing-external-alias admission=accepted segmentation=passed external=true name=platform_infra_vps_routing
[VULNERABLE] CAN-153 sibling-external-alias admission=accepted segmentation=passed external=true name=platform_infra_vps_sibling_app_ingress
[VULNERABLE] CAN-160 custom-egress-driver admission=accepted segmentation=passed driver=macvlan parent=poc-parent0 subnet=192.0.2.0/24
[+] summary vulnerable=4 total=4 source_tree_unchanged=true
[+] no Docker, Compose, Engine network, packet, service, network, or live target was accessed
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

The negative control confirms that an obvious foreign logical key is rejected.
The four vulnerable cases retain an allowed workload key and change only the
physical network fields that the original policies omit. `VULNERABLE` means
both policy functions returned success; it does not claim that a named Engine
network or custom-driver topology was activated.
