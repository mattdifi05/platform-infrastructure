# Validator-only lifecycle-hook probe

This probe imports the target repository's
`scripts/hosted-workload-contract.mjs` and submits synthetic in-memory rendered
Compose objects. It does not invoke Docker or Compose, pull an image, write a
workload lock, or execute a lifecycle command.

From this directory, test the vulnerable revision with:

```sh
make syntax
node probe.mjs --candidate-root /path/to/platform-infrastructure --expect vulnerable
```

After applying a fix that rejects all hosted-workload lifecycle primitives,
test the same source tree with:

```sh
node probe.mjs --candidate-root /path/to/platform-infrastructure --expect fixed
```

`CANDIDATE_ROOT` may point to any checkout containing
`scripts/hosted-workload-contract.mjs`. Node.js 20 or later is recommended.
No cleanup is required because the probe keeps all fixtures in memory.
