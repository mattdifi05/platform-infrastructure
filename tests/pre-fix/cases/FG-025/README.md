# Safe reproduction: project route ownership collisions

This harness demonstrates that project alias and host collisions resolve to
the first discovered project, while unrelated projects can reuse one verified
upstream identity. It operates on the exact affected source without starting
the project router.

The harness verifies every archived source fingerprint, runs the repository's
hosted-workload contract tests, and imports only the contract module. It
extracts the router's unexported discovery, verified-lock, normalization,
first-match, and upstream-selection functions directly from `server.mjs` and
evaluates them in isolated `node:vm` contexts. A narrow filesystem wrapper
returns two real temporary project directories in deterministic opposite
orders; every other filesystem operation uses Node's normal API.

No listener, socket, network connection, container, deployed project, or live
state is used. The fixture directory is private to the current user, files are
created with mode `0600`, and the complete fixture is removed in a `finally`
block.

## Requirements

- Git with `SOURCE_REPO` set to a checkout containing the affected revision
- Node.js 22 or newer; representative output was produced with Node.js 26
- `tar` and a POSIX-compatible shell

## Run

From the directory containing the vulnerability report, run exactly:

```sh
: "${SOURCE_REPO:?set SOURCE_REPO to a checkout containing the affected revision}"
test "$(git -C "$SOURCE_REPO" rev-parse '68cd05895b8d479ffb8167344282e7d922958bfc^{tree}')" = \
  "70031b30316fbaecbb23249491d6ff4e364d65d5" || exit 1
snapshot="$(mktemp -d)"
git -C "$SOURCE_REPO" archive 68cd05895b8d479ffb8167344282e7d922958bfc \
  project-router/server.mjs \
  project-router/tests/project-router.test.mjs \
  scripts/hosted-workload-contract.mjs \
  scripts/hosted-workload-contract.test.mjs \
  compose.yaml \
  compose.runtime.yaml \
  traefik/dynamic/project-routes.yml |
  tar -x -C "$snapshot"

node poc/project-route-global-ownership-poc.mjs --source-root "$snapshot"
poc_status=$?
rm -rf "$snapshot"
exit "$poc_status"
```

The tree assertion and embedded SHA-256 fingerprints make the harness fail
closed if the source snapshot differs from the tested revision.

## Expected output

```text
[PASS] exact pre-fix source fingerprints verified
[PASS] repository hosted-workload contract tests pass 15/15
[PASS] first-match routing and slug-only ownership controls verified
[PASS] two unique route slugs pass while alias, host, and upstream claims remain outside the contract
[TRACE] alias_collision first=attacker->http://attacker-app-web:4000/ reversed=victim->http://victim-app-web:3000/
[PASS] reversing discovery order flips alias ownership and selected upstream
[TRACE] host_collision first=attacker->http://attacker-app-web:4000/ reversed=victim->http://victim-app-web:3000/
[PASS] reversing discovery order flips explicit-host ownership and selected upstream
[TRACE] upstream_collision attacker=http://shared-app-web:8080/ victim=http://shared-app-web:8080/
[PASS] two project identities can claim the same verified upstream identity
[SAFE] exact functions, deterministic directory order, and temporary fixtures only; no listener, socket, network, container, or live-state access
```

## What the assertions establish

- The ordinary hosted-workload contract suite remains green and two unique
  route slugs pass catalog resolution.
- Project aliases, hosts, and upstream ownership are outside that admission
  record.
- Both colliding projects survive exact project discovery because only
  canonical slugs enter the `seen` set.
- Reversing the same two directory entries flips the owner and upstream for an
  alias collision.
- The same reversal flips an explicit-host collision.
- Two different project identities can resolve to one service and port from
  the verified lock's allowed set.

The harness does not claim that a particular operating system will enumerate
directories in either demonstrated order. It proves that both orders are
accepted and produce different security decisions. A corrected target should
reject the colliding fixture before a route index is created, independent of
input order.
