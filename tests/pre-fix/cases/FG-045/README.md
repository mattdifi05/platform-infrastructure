# Safe database-admin owner-gate probe

This source-pinned probe demonstrates `CAN-169` and `CAN-170` without sending an
HTTP request, invoking Traefik or the WAF, starting Docker or a service, reading
a credential, or connecting to a database or network.

It analyzes the exact vulnerable revision and proves that:

1. the dedicated phpMyAdmin and phpPgAdmin routers contain no fresh-owner
   ForwardAuth middleware;
2. the WAF deny rule exempts loopback, `10.0.0.0/8`, `172.16.0.0/12`, and
   `192.168.0.0/16` sources;
3. the final runtime overlay mounts the routes and enables both services;
4. the Control Center's intended bridge requires owner plus a 300-second fresh
   authentication and records successful bridge events; and
5. anonymous, viewer, admin, stale owner, and fresh owner all receive the same
   direct-route decision from an RFC1918 source, while a synthetic ForwardAuth
   negative control enforces the intended 401/403/403/428/200 matrix.

The wrapper requires a caller-supplied repository, verifies the exact commit
and tree, creates a private temporary root with an unpredictable 256-bit
ownership sentinel, and archives the pinned source as that root's exact
physical `source` child. The probe verifies hashes for every source file it
uses and writes only one synthetic fixed-policy receipt inside a token-bound
fixture.

As a preservation regression, the wrapper creates a separate pre-existing
route file. Fixture acquisition must reject that existing target before any
write. The probe preserves its directory listing, device, inode, bytes, and
hash; the wrapper checks the hash again after the probe returns. Fixture cleanup
revalidates the owned directory and sentinel physical path, device, inode, file
type, and token before deletion. Wrapper cleanup independently revalidates the
temporary parent, archive root, and wrapper sentinel identities before removal.

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
[+] activation admin_routes_mounted=true phpmyadmin_enabled=true phppgadmin_enabled=true runtime_overlay_after_vps=true
[+] intended-control sensitive_actions=true owner_required=true fresh_auth_seconds=300 audited_bridge=true
[VULNERABLE] CAN-169 router=enterprise-phpmyadmin owner_auth_middleware=false service=enterprise-phpmyadmin
[VULNERABLE] CAN-170 router=enterprise-phppgadmin owner_auth_middleware=false service=enterprise-phppgadmin
[+] waf private_source_exemptions=127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 public_admin_host_status=404
[VULNERABLE] CAN-169 private_identity=anonymous control_status=401 direct=ROUTED_TO_NATIVE_LOGIN
[VULNERABLE] CAN-169 private_identity=viewer control_status=403 direct=ROUTED_TO_NATIVE_LOGIN
[VULNERABLE] CAN-169 private_identity=admin control_status=403 direct=ROUTED_TO_NATIVE_LOGIN
[VULNERABLE] CAN-169 private_identity=stale-owner control_status=428 direct=ROUTED_TO_NATIVE_LOGIN
[VULNERABLE] CAN-169 private_identity=fresh-owner control_status=200 direct=ROUTED_TO_NATIVE_LOGIN
[VULNERABLE] CAN-170 private_identity=anonymous control_status=401 direct=ROUTED_TO_NATIVE_LOGIN
[VULNERABLE] CAN-170 private_identity=viewer control_status=403 direct=ROUTED_TO_NATIVE_LOGIN
[VULNERABLE] CAN-170 private_identity=admin control_status=403 direct=ROUTED_TO_NATIVE_LOGIN
[VULNERABLE] CAN-170 private_identity=stale-owner control_status=428 direct=ROUTED_TO_NATIVE_LOGIN
[VULNERABLE] CAN-170 private_identity=fresh-owner control_status=200 direct=ROUTED_TO_NATIVE_LOGIN
[+] negative-control synthetic_forwardauth anonymous=401 viewer=403 admin=403 stale_owner=428 fresh_owner=200
[+] safety http_requests=0 traefik_calls=0 waf_calls=0 docker_calls=0 database_logins=0 credentials_read=0 services_started=0 network_attempts=0
[+] result=VULNERABLE
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

Normal completion, ordinary failures, and handled HUP, INT, or TERM use the
same token-checked cleanup. A SIGKILL or power failure cannot be trapped and may
leave a directory under `poc/.tmp`; inspect its
`.database-admin-owner-gate-owner-*` sentinel before removing it manually.
