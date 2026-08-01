# Scheduler entrypoint contract probe

This probe reads the scheduler commands in `README.md` and `RUNBOOK.md`, the
base scheduler service, the runtime-isolation override, and the canonical
Compose wrapper. It does not invoke Docker or Compose, start a service, write to
the target repository, inspect a live host, or access the Docker socket.

From this directory, test the vulnerable revision with:

```sh
make syntax
node probe.mjs --candidate-root /path/to/platform-infrastructure --expect vulnerable
```

After both documented scheduler commands delegate to the safe wrapper, use:

```sh
node probe.mjs --candidate-root /path/to/platform-infrastructure --expect fixed
```

`CANDIDATE_ROOT` may point to any checkout containing the documented files and
Compose definitions. Node.js 20 or later is recommended. The probe is
read-only, uses only the Node.js standard library, and requires no cleanup.
