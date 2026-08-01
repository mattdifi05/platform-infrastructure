# Safe transport-scheme integrity PoC

This offline, source-pinned PoC demonstrates `CAN-123` without sending an HTTP
request, opening a socket, starting Docker or another service, using SSH,
reading a credential, or contacting a provider or live target.

The wrapper requires a caller-supplied local Git repository. It resolves commit
`68cd05895b8d479ffb8167344282e7d922958bfc`, verifies tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`, and exports only the eight source
files used by the probe into a private temporary directory. The probe verifies
the SHA-256 digest of every archived source file before analyzing it. The
current checkout may differ because all evidence comes from the pinned Git
object.

The probe reconstructs the effective VPS transport state from the archived
environment and Compose fragments. It proves that public port 80 is enabled,
the WAF redirect is disabled, the WAF-to-Traefik hop uses HTTP, both proxy layers
force `X-Forwarded-Proto: https`, and Keycloak is configured to trust forwarded
headers. It then traces absent and attacker-supplied forwarded-protocol values
and shows that every plaintext request reaches the backend labeled as HTTPS.

Two negative controls fail closed. First, an in-memory corrected configuration
turns the HTTP redirect on and proves that even a spoofed HTTPS header cannot
reach the backend. Second, a one-byte change to an archived source file fails
the pinned hash check. The probe also asks its cleanup routine to remove a
pre-existing sentinel-free directory; deletion must be refused and the marker's
device, inode, bytes, and hash must remain unchanged.

Run from this directory:

```sh
make check
make -n run SOURCE_REPO=/path/to/platform-infrastructure
make run SOURCE_REPO=/path/to/platform-infrastructure
```

Expected output includes:

```text
[+] unwrapped direct invocation rejected
[SOURCE] revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5 files=8 provenance=git-archive
[VULNERABLE CAN-123] public_http=0.0.0.0:80 redirect=off waf_backend=http://traefik:80 waf_forwarded_proto=https traefik_entrypoint=web:80 traefik_forwarded_proto=https application_trust=xforwarded
[TRACE] inbound_x_forwarded_proto=attacker-value waf_decision=forward backend_transport=plaintext-http backend_x_forwarded_proto=https backend_x_forwarded_port=443
[NEGATIVE CONTROL] redirect=on spoofed_forwarded_proto=https backend_reached=false verdict=safe
[NEGATIVE CONTROL] single_byte_source_change_rejected=true
[GUARD] unowned_cleanup_refused=true preexisting_sha256=<sha256>
[SAFE] network_attempts=0 credentials_read=0 services_started=0 source_mutations=0 live_mutations=0
[+] cleanup sentinel_owned_analysis_removed=true preexisting_marker_preserved=true
[+] result=VULNERABLE canonical_id=CAN-123
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

The only writes are the selected Git archive, synthetic receipt, and preservation
fixture under the wrapper-owned temporary root. Nested cleanup requires the
exact ownership sentinel. Outer cleanup independently revalidates the temporary
path, directory identity, sentinel identity, and unpredictable 256-bit token
before recursive removal. A mismatch refuses deletion and makes the run fail.

No cleanup is normally required. An uncatchable `SIGKILL` or power loss can
leave a directory named `transport-scheme-integrity.*` under `TMPDIR`; inspect
its `.transport-scheme-integrity-wrapper-owner` sentinel before removing it.
