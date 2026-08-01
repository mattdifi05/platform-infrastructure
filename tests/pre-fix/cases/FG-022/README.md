# Safe reproduction: status SSE polling amplification

This harness reproduces the availability-cost primitive at the exact affected
revision without starting the Control Center or touching deployed state. It
extracts the unexported status SSE functions directly from the archived
`control-center/server.mjs`, evaluates them in isolated `node:vm` contexts,
and gives those contexts mock request, response, clock, and timer objects. The
functions use the revision's real `FileStateStore` against temporary JSONL
fixtures created by the harness.

The reproduction opens no listener, socket, or network connection. It does not
read or write live application state. Temporary files are created under the
operating system's temporary directory with mode `0600` and removed in a
`finally` block.

## Requirements

- Git with `SOURCE_REPO` set to a checkout containing the affected revision
- Node.js 20 or newer
- `tar` and a POSIX-compatible shell

## Run

From the directory containing the vulnerability report, run exactly:

```sh
: "${SOURCE_REPO:?set SOURCE_REPO to a checkout containing the affected revision}"
test "$(git -C "$SOURCE_REPO" rev-parse '68cd05895b8d479ffb8167344282e7d922958bfc^{tree}')" = \
  "70031b30316fbaecbb23249491d6ff4e364d65d5" || exit 1
snapshot="$(mktemp -d)"
git -C "$SOURCE_REPO" archive 68cd05895b8d479ffb8167344282e7d922958bfc \
  control-center/server.mjs \
  control-center/state/file-store.mjs \
  control-center/state/file-store.test.mjs \
  control-center/state/catalog.mjs \
  control-center/auth/oidc.mjs \
  traefik/dynamic/middlewares.yml \
  compose.runtime-isolation.yaml \
  compose.vps.yaml |
  tar -x -C "$snapshot"

node poc/status-sse-poll-amplification-poc.mjs --source-root "$snapshot"
poc_status=$?
rm -rf "$snapshot"
exit "$poc_status"
```

The source archive is pinned to commit
`68cd05895b8d479ffb8167344282e7d922958bfc` and tree
`70031b30316fbaecbb23249491d6ff4e364d65d5`. The harness verifies SHA-256
fingerprints for every archived input before executing the reproduction. It
also runs the archived file-store tests and requires all four to pass.

## Expected output

```text
[PASS] exact pre-fix source fingerprints verified
[PASS] repository file-store tests pass 4/4
[PASS] route, poll loop, full-file parser, viewer GET, and rate-limit controls verified
[PASS] exact unexported SSE functions extracted without importing the listening server
[METRIC] baseline history=2000 clients=1 polls=6 store_reads=6 parsed_records=12000 bytes_reprocessed=2801916 emitted_events=0 false_writes=0
[METRIC] large_history history=12000 clients=1 polls=6 store_reads=6 parsed_records=72000 bytes_reprocessed=16901928 emitted_events=0 false_writes=0
[METRIC] concurrent history=12000 clients=16 polls=6 store_reads=96 parsed_records=1152000 bytes_reprocessed=270430848 emitted_events=0 false_writes=0
[METRIC] backpressure history=2000 clients=1 polls=2 store_reads=2 parsed_records=4000 bytes_reprocessed=933972 emitted_events=2000 false_writes=2000
[PASS] sixfold history growth causes sixfold parsing at the same poll count
[PASS] 16 concurrent SSE streams cause 16-fold full-file parsing
[PASS] a valid nonexistent run ID holds streams with zero event output
[PASS] mock response backpressure is ignored and the next full poll still runs
[DERIVED] nominal_six_minute_polls_per_stream=2400 nominal_parsed_records=460800000
[SAFE] exact SSE functions, mock req/res, fake clock, and temporary JSONL only; no listener, socket, network, or live-state access
```

The deterministic assertions are structural work counters, not timing
thresholds:

- `store_reads` counts invocations of the real file-backed dataset reader.
- `parsed_records` is incremented by the real store's dataset validator after
  every JSONL record has been parsed.
- `bytes_reprocessed` is the fixture size multiplied by full store reads.
- `false_writes` counts mocked response writes whose return value requests
  backpressure.

The baseline and large-history cases prove linear amplification with retained
history. The concurrent case proves the independent per-stream multiplier.
The nonexistent-run case emits no status events but continues polling. The
backpressure case proves that a false `write()` return does not pause the next
full-file poll in the affected handler.
