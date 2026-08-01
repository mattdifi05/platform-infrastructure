# Safe origin-lock lifecycle probe

This source-pinned probe demonstrates `CAN-121`, `CAN-122`, and `CAN-149`
without invoking UFW, `sudo`, `curl`, Docker, Compose, SSH, HTTP, a service, a
credential, or the network.

It analyzes the exact vulnerable revision and proves that:

1. host hardening adds unrestricted web-port rules;
2. the origin-lock script only adds Cloudflare-scoped rules and leaves removal
   of broader rules to a later manual step;
3. both operator instructions restrict only port 80 while the production WAF
   overlay publishes ports 80 and 443;
4. host readiness does not reject unrestricted web-port rules;
5. the remote deploy path activates the public Compose stack without a prior
   origin-lock verification; and
6. a synthetic fixed lifecycle rejects an omitted port or a leftover IPv6 rule,
   permits both address families only through Cloudflare, and preserves the SSH
   recovery rule before allowing activation.

The wrapper requires a caller-supplied local Git repository. It verifies the
exact commit and tree, creates a private temporary root with an unpredictable
256-bit ownership sentinel, and archives the pinned source as that root's exact
physical `source` child. The probe verifies a SHA-256 digest for every source
file used in its decision.

The only generated result is a synthetic JSON receipt inside a token-bound
fixture. A separate pre-existing firewall snapshot must be rejected as a probe
target and preserved byte-for-byte. Cleanup revalidates the owned fixture's
physical path, directory and sentinel device/inode, type, and token before
deletion; the wrapper verifies the pre-existing snapshot again afterward.

Run from this directory:

```sh
make check
make -n run SOURCE_REPO=../../repository
make run SOURCE_REPO=../../repository
```

`SOURCE_REPO` has no default. It must be a local Git repository containing
commit `68cd05895b8d479ffb8167344282e7d922958bfc` and tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`. The current checkout may differ;
the wrapper archives the pinned object directly.

Expected output includes:

```text
[+] unwrapped direct invocation rejected
[+] archived revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5
[+] source hardening_generic_web_allows=80,443 origin_lock_default_ports=80,443 origin_lock_reconciliation=false
[+] documentation readme_ports=80 checklist_ports=80 public_waf_ports=80,443
[+] readiness ufw_active=true internal_port_check=true ssh_check=true generic_web_allow_check=false
[VULNERABLE] CAN-121 additive_origin_lock=true generic_rules_removed=false untrusted_ipv4_80=true untrusted_ipv4_443=true untrusted_ipv6_80=true untrusted_ipv6_443=true
[VULNERABLE] CAN-122 documented_ports=80 published_ports=80,443 cloudflare_scoped_443=false untrusted_ipv4_443=true untrusted_ipv6_443=true
[VULNERABLE] CAN-149 preactivation_origin_gate=false compose_activated=true public_bind_ipv4_80=true public_bind_ipv4_443=true readiness_accepts_generic_web_rules=true
[+] negative-control fixed_policy verified=true activated=true ssh_recovery_preserved=true untrusted_ipv4_80=false untrusted_ipv4_443=false untrusted_ipv6_80=false untrusted_ipv6_443=false cloudflare_dual_stack=true
[+] negative-control leftover_ipv6_443 verified=false activated=false fail_closed=true
[+] negative-control omitted_443 verified=false activated=false fail_closed=true
[+] safety ufw_calls=0 sudo_calls=0 curl_calls=0 http_requests=0 ssh_connections=0 docker_calls=0 compose_calls=0 firewall_changes=0 services_started=0 credentials_read=0 network_attempts=0
[+] result=VULNERABLE
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

The IPv6 branch is a dual-stack fixture: actual IPv6 exposure still requires
host IPv6 support, a route, a public listener, and an effective UFW IPv6 rule.
The source-only result does not assert the firewall state of any deployed host.

Normal completion, ordinary failures, and handled HUP, INT, or TERM use the
same token-checked cleanup. A SIGKILL or power failure cannot be trapped and may
leave a directory under `poc/.tmp`; inspect its
`.origin-lock-lifecycle-owner-*` sentinel before removing it manually.
