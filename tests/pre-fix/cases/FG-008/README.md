# Protected core-resource immutability probe

This probe imports the target repository's real hosted-workload render
validator and submits in-memory models for four protected resource classes:
configs, secrets, volumes, and networks. Each test keeps the core service's
logical reference unchanged and replaces only the referenced top-level
definition.

It does not invoke Docker or Compose, read a secret file, create a volume or
network, change routes, write a workload lock, access a live host, or modify the
target checkout.

From this directory, test the vulnerable revision with:

```sh
make syntax
node probe.mjs --candidate-root /path/to/platform-infrastructure --expect vulnerable
```

After core top-level resource definitions are frozen, test with:

```sh
node probe.mjs --candidate-root /path/to/platform-infrastructure --expect fixed
```

Node.js 20 or later is recommended. The probe uses only the Node.js standard
library, keeps all fixtures in memory, and requires no cleanup.
