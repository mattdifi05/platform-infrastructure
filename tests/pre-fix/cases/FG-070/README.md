# Vault opaque-fingerprint PoC

This offline PoC demonstrates canonical finding `CAN-207` against exact
revision `68cd05895b8d479ffb8167344282e7d922958bfc` (tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`). It requires a local Git
checkout containing those objects, but it never reads the checkout's working
tree.

## Safety boundary

The wrapper verifies the commit and tree, exports a clean source snapshot with
`git archive`, and creates an unpredictable wrapper-owned lab. The JavaScript
probe refuses direct invocation against arbitrary directories. It requires the
wrapper's real source and lab children, random ownership sentinel, matching
token, and non-symlink paths.

Before the positive run, the wrapper supplies a wrong token to an isolated
guard lab. Rejection is mandatory and a pre-existing synthetic file must remain
byte-for-byte unchanged. Cleanup removes only the unpredictable top-level lab
after revalidating the wrapper sentinel. If ownership cannot be proved, cleanup
fails closed and retains the path for manual review.

The positive run executes the original archived secret-manager CLI with every
storage path redirected into the synthetic lab. It stores the deliberately
fake four-digit value `4821` under `demo_access_code`; the other required
manager values are freshly generated throwaways. It then copies only the
encrypted synthetic store and captured synthetic status output into an offline
artifact that has no master key. A five-entry synthetic dictionary recovers the
fake value from each exported SHA-256 prefix. A wrong dictionary must fail.

The fixed controls remove the plaintext-derived fingerprint from exported
metadata and demonstrate a domain-separated HMAC retained only inside an
authorized verifier. No real Vault, secret, backup, credential, network
service, live target, or candidate working-tree file is read or changed.

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
wrapper reads only pinned Git objects with `git archive`.

## Expected result

```text
[GUARD] invalid_ownership_rejected=true preexisting_bytes_preserved=true
[+] archived revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5
[+] wrapper-owned source and synthetic lab verified
[+] verified 4 embedded vulnerable-source hashes
[+] vulnerable policy vault_min_length_default=1 fingerprint=sha256-prefix-64
[+] synthetic store created scope=vault fingerprint_bits=64 ciphertext_present=true
[VULNERABLE] persisted_store dictionary_candidates=5 recovered=true offline_artifact_master_key=false
[VULNERABLE] exported_status dictionary_candidates=5 recovered=true offline_artifact_master_key=false
[CONTROL] wrong_dictionary candidates=4 recovered=false
[FIXED] migrated_metadata plaintext_derived_fingerprint_present=false offline_guess_oracle=false
[FIXED] keyed_internal_tag domain=infra-secret-manager/fingerprint/v2 wrong_key_matches=false authorized_match=true exported=false
[+] source_tree_unchanged=true synthetic_only=true
[+] no real Vault, secret, backup, credential, network, live target, or candidate working tree was read or changed
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

`recovered=true` means one dictionary candidate matched the exported 64-bit
SHA-256 prefix. It does not mean the PoC decrypted AES-GCM ciphertext or
recovered a real credential. The dictionary and target are public synthetic
fixtures chosen only to demonstrate the offline verification oracle.
