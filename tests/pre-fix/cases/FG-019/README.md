# Safe hosted egress discovery PoC

This PoC demonstrates that the exact pre-fix firewall script ignores valid
hosted-workload egress networks whose physical names do not contain the
literal <code>app_</code> segment expected by its discovery glob.

The PoC does not contact Docker or mutate firewall state. It creates temporary,
fail-closed executables named <code>docker</code> and <code>iptables</code>,
places them at the front of an isolated <code>PATH</code>, and runs the real
firewall script only in <code>--plan</code> mode. The fake Docker executable
returns a fixed three-network inventory; the fake iptables executable fails if
called. All temporary artifacts are removed before exit.

## Requirements

- Node.js 20 or later.
- Read-only access to the Git repository containing revision
  <code>68cd05895b8d479ffb8167344282e7d922958bfc</code>.
- A POSIX <code>/bin/sh</code>.
- No Docker Engine, Docker CLI, root access, or iptables installation is
  required.

## Run

Start in the parent report directory:

```sh
snapshot="$(mktemp -d)"
REPOSITORY=${REPOSITORY:?set REPOSITORY to the platform-infrastructure Git repository}
git -C "$REPOSITORY" archive 68cd05895b8d479ffb8167344282e7d922958bfc \
  scripts/workload-egress-firewall.sh \
  scripts/hosted-workload-contract.mjs \
  scripts/hosted-workload-contract.test.mjs \
  scripts/compose-vps.sh \
  NETWORK-SEGMENTATION.md \
  config/project-manifest.example.json |
  tar -x -C "$snapshot"

node poc/hosted-egress-network-discovery-poc.mjs --source-root "$snapshot"
poc_status=$?
rm -rf "$snapshot"
exit "$poc_status"
```

The archive step reads committed objects rather than the working tree. The PoC
checks every supplied file against its expected SHA-256 fingerprint and stops
if the snapshot differs.

Expected output:

```text
[PASS] exact pre-fix source fingerprints verified
[PASS] repository hosted-workload tests pass 15/15
[PASS] valid stexor and example-app egress networks pass admission
[PASS] exact discovery glob inspects only app_demo egress
[PASS] valid stexor and example-app physical networks are ignored
[PASS] partial discovery succeeds instead of reporting omitted networks
[PASS] firewall plan tracks 172.28.10.0/24 but not 172.28.20.0/24 or 172.28.30.0/24
[SAFE] fake Docker shim only; no Engine, network, iptables, HTTP, or live-state action attempted
```

## Demonstrated state

The fake inventory is:

| Physical network | Subnet | Result |
| --- | --- | --- |
| <code>platform_infra_vps_app_demo_egress</code> | <code>172.28.10.0/24</code> | Inspected and planned |
| <code>platform_infra_vps_stexor_egress</code> | <code>172.28.20.0/24</code> | Ignored |
| <code>platform_infra_vps_example_app_egress</code> | <code>172.28.30.0/24</code> | Ignored |

The PoC imports the actual hosted-workload contract first, proving that
<code>stexor_egress</code> and <code>example_app_egress</code> are accepted.
It then executes the actual firewall script. Because the matching App Demo
network contributes one subnet, the aggregate file is non-empty and the plan
succeeds despite the two omissions.

## Safety and limits

The PoC:

- never looks up or executes the system Docker binary;
- never creates, removes, lists, or inspects a real network;
- never executes a real iptables binary;
- never opens a socket or sends traffic;
- never reads candidate working-tree content; and
- removes its temporary directory in a <code>finally</code> block.

It proves the naming mismatch, partial-discovery success, and incomplete
planned subnet set. It does not prove that a particular private or metadata
endpoint is reachable from a live workload. That final boundary belongs in a
disposable Engine and firewall-namespace regression test after the fix.
