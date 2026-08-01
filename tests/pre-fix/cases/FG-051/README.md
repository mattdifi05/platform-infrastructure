# Admin access-surface inventory PoC

This offline PoC demonstrates canonical findings `CAN-147`, `CAN-173`, and
`CAN-174` against exact revision
`68cd05895b8d479ffb8167344282e7d922958bfc` (tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`). It requires a local Git checkout
that contains the revision, but it never reads files from the checkout's
working tree.

## Safety boundary

The wrapper verifies the commit and tree, exports clean snapshots with
`git archive`, and passes only the positive snapshot to the probe. The
JavaScript entry point refuses direct invocation against an arbitrary
directory: it requires the wrapper's real temporary root, random ownership
sentinel, matching token, and exact non-symlink `source` child.

Before the positive run, the wrapper deliberately supplies an invalid token
to a separate guard snapshot. The probe must reject, and a pre-existing
synthetic file must remain byte-for-byte unchanged. The positive probe hashes
the complete archived source tree before and after analysis and rejects any
mutation.

The probe executes the original Cloudflare Access verifier only against
synthetic manifests and an imported `fetch` replacement. The child process
receives a minimal environment containing a fixed, explicitly synthetic token;
it receives no ambient credentials. Every attempted Cloudflare API request is
answered in memory, and an unexpected URL or method fails the run. Temporary
manifests and generated evidence stay under the wrapper-owned root.

The PoC does not use SSH, DNS, sockets, HTTP, a Cloudflare account, a real API
token, a browser, a deployment, or any live target. It does not modify the
source snapshot. Cleanup removes only the unpredictable top-level archive
after revalidating its ownership sentinel; if ownership cannot be proved,
cleanup fails closed and prints the retained path.

## Requirements

- Git
- Node.js 20 or newer
- POSIX `sh`, `tar`, `mktemp`, `grep`, and `cmp`

## Run

From this `poc` directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

`SOURCE_REPO` has no default. Uncommitted changes are ignored because the
wrapper reads the pinned objects through `git archive`.

## Expected result

```text
[GUARD] invalid_ownership_rejected=true preexisting_bytes_preserved=true
[+] archived revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5
[+] wrapper-owned source boundary verified
[+] verified 6 embedded vulnerable-source hashes
[+] tracked_manifest_apps=8 reconciled_expected_apps=9 required_route=phppgadmin.platform-infrastructure.com manifest_contains_route=false
[CONTROL] empty-manifest verifier=rejected mock_fetch_calls=0
[VULNERABLE] omitted-phppgadmin manifest_apps=8 expected_apps=9 verifier=passed evidence=passed access_gate=passed mock_fetch_calls=9
[VULNERABLE] duplicate-domain manifest_apps=2 unique_domains=1 duplicates=1 verifier=passed evidence=passed access_gate=passed mock_fetch_calls=3
[VULNERABLE] unknown-application manifest_apps=1 unknown_domains=1 verifier=passed evidence=passed access_gate=passed mock_fetch_calls=2
[+] summary vulnerable=3 controls=1 source_tree_unchanged=true temp_writes_confined=true
[+] no SSH, DNS, socket, HTTP, Cloudflare account, credential, deployment, or live target was accessed
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

`access_gate=passed` reproduces only the Cloudflare Access check inside the
go/no-go consumer. It does not claim that every other production gate passed
or that a full release was admitted. Likewise, the dedicated route becomes an
external bypass only if it is publicly routed and lacks an independent outer
control; the PoC does not test those deployment conditions.
