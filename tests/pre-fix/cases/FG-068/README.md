# Offline egress-start ordering probe

This proof of concept demonstrates CAN-202 from an exact source archive. It
does not run deployment scripts or execute any firewall, network, Docker, SSH,
privileged, credential, or live-target operation.

## Requirements

- a local Git checkout whose `HEAD` is the affected revision;
- local `git`, `tar`, POSIX shell utilities, `make`, and Node.js;
- no network access and no service credentials.

The wrapper requires this exact source identity:

- commit `68cd05895b8d479ffb8167344282e7d922958bfc`;
- tree `70031b30316fbaecbb23249491d6ff4e364d65d5`.

It reads the commit with `git archive`, so unrelated working-tree edits are not
included. It also checks that the source checkout's `HEAD` and `HEAD^{tree}`
are unchanged after the run.

## Run

From this `poc/` directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

`make check` performs shell and JavaScript syntax checks. `make run` verifies
the commit and tree, extracts only that revision under a private wrapper-owned
temporary directory, checks embedded hashes for nine decisive source files,
and runs the offline probe with a minimal environment.

The probe performs two related experiments:

1. It locates the preflight, `compose up`, and postdeploy transitions in both
   canonical deployment paths and confirms that no egress firewall gate occurs
   before the workload start.
2. It exercises an in-memory fixed controller. The controller rejects a start
   before networks are staged, a missing or unverified policy, a stale lock,
   and the wrong subnet set. It accepts only the sequence
   `stage -> apply -> verify -> start` for the exact lock and subnets.

Representative successful output is:

```text
[GUARD] invalid_ownership_rejected=true preexisting_bytes_preserved=true lab_untouched=true
[+] archived revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5
[+] wrapper-owned source and lab boundaries verified
[+] verified 9 embedded vulnerable-source hashes
[TRACE] deploy_remote=preflight@50>compose-up@53>postdeploy@64 firewall_call=absent
[TRACE] go_live=preflight@401>compose-up@404>postdeploy@409 firewall_call=absent
[VULNERABLE] workload_started=true firewall_verified_at_start=false prestart_default_deny=false
[CONTROL] uncreated_networks=rejected missing_policy=rejected unverified_policy=rejected stale_lock=rejected wrong_subnets=rejected exact_verified_policy=accepted
[+] summary unsafe_order_reproduced=true fixed_gate_enforced=true source_tree_unchanged=true
[+] no firewall command, network socket, Docker, SSH, sudo, credential, or live target was accessed
[+] source_repository_head_unchanged=true source_repository_tree_unchanged=true
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

## Safety and cleanup

The JavaScript probe cannot be invoked directly: it requires wrapper-provided
ownership paths, an unpredictable ownership token, and a matching regular-file
sentinel. Before the real run, the wrapper deliberately supplies the wrong
token and proves that the probe rejects it without modifying pre-existing
source bytes or writing into the lab.

The probe reads only the archived source. Its sole artifact is a synthetic
JSON trace under the wrapper-owned lab. On exit, the wrapper revalidates the
temporary directory, parent directory, and sentinel device/inode/content
before removing only its own temporary root. If any ownership check fails, it
refuses cleanup and exits nonzero.

This is an ordering and policy-state demonstration. It deliberately does not
test packet reachability, modify host rules, start containers, or establish
the state of any deployed environment.

## Files

- `egress-ordering-probe.mjs` contains the source checks and in-memory models.
- `run-from-git-archive.sh` pins source identity, enforces ownership, and
  performs fail-closed cleanup.
- `Makefile` exposes the syntax and run targets.
