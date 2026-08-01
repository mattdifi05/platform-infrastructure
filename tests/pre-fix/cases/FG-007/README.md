# Hosted replica resource multiplier PoC

This safe probe demonstrates that the hosted-workload contract and runtime
isolation policy account for one service definition while accepting Compose
replica counts that make the effective aggregate resource declaration much
larger. It imports source only from a clean `git archive` of the requested
revision. It does not invoke Docker, activate a workload, access a provider, or
make network requests.

Requirements: Git, tar, Make, and Node.js 20 or newer.

From this directory, run:

```sh
make run REPOSITORY=/path/to/platform-infrastructure
```

The default revision is the affected commit
`68cd05895b8d479ffb8167344282e7d922958bfc`, and the default expectation is
`vulnerable`. The wrapper deletes its temporary archive on exit. It also checks
the vulnerable source files against embedded SHA-256 digests before evaluating
synthetic Compose objects.

For regression testing after a fix, run:

```sh
make run REPOSITORY=/path/to/platform-infrastructure REVISION=<fixed-revision> EXPECT=fixed
```

`EXPECT=fixed` accepts either supported remediation: rejecting replica counts
above one at the contract boundary, or multiplying the aggregate admission
budget by the effective replica count. `EXPECT=either` reports the observed
state without using it as the process exit criterion.
