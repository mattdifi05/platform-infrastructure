# Safe PoC: broad Docker proxy authority

This PoC demonstrates that the exact pre-fix runtime policy accepts two distinct clients of the same broad Docker API authority:

- a host-local process reaching the loopback publication; and
- `backup-scheduler` reaching the proxy over `platform_docker_control`.

It is a static and in-memory check. It does **not** run Docker, connect to a Unix or TCP socket, send an HTTP request, create a container, open a port, or modify repository/deployment state.

## Requirements

- Git
- `tar`
- Node.js 18 or newer
- A local Git object containing revision `68cd05895b8d479ffb8167344282e7d922958bfc`

## Run

From the parent report directory:

```sh
REPO=/path/to/platform-infrastructure
mkdir -p specimen
git -C "$REPO" archive 68cd05895b8d479ffb8167344282e7d922958bfc | tar -x -C specimen
node poc/verify-docker-proxy-authority.mjs specimen
```

The script checks exact SHA-256 fingerprints before importing the affected policy. It exits nonzero if the supplied specimen differs from the validated revision.

Expected output:

```text
[PASS] exact pre-fix source fingerprints verified
[PASS] pre-fix runtime policy result: passed
[PASS] host-loopback boundary is accepted with broad Docker mutation families
[PASS] scheduler boundary is accepted with the same unauthenticated authority
[PASS] policy negative controls reject public binding and extra network membership
[PASS] sandbox omits denial probes for decisive mutation routes
[SAFE] no network connection, Docker command, socket access, or state change was attempted
```

## Interpretation and limits

The `passed` result is produced by the repository's own affected `evaluateRuntimeIsolation` implementation, not a reimplementation of that evaluator. The PoC also supplies negative controls so a disabled or bypassed evaluator cannot produce a false success.

The PoC proves the source-level policy gap. It does not claim that the proxy is deployed, that its configured port is reachable on a particular host, or that an attacker already controls a local process or the scheduler.

On a fixed revision, the source-fingerprint guard should fail first. For deliberate patch validation after updating those fingerprints, the supplied vulnerable fixture must be rejected by the fixed policy instead of producing `pre-fix runtime policy result: passed`.

Cleanup removes only the extracted specimen:

```sh
rm -rf specimen
```
