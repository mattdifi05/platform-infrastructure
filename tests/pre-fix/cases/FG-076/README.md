# Offline database-admin profile safety probe

This proof of concept demonstrates CAN-232 from an exact source archive. It
does not invoke Docker or Docker Compose, open a network socket, resolve DNS,
connect to a database, inspect credentials, or access any live environment.

## Requirements

- a local Git checkout whose `HEAD` is the affected revision;
- local `git`, `tar`, POSIX shell utilities, `make`, and Node.js;
- no database, Docker daemon, network access, or credentials.

The wrapper requires this exact source identity:

- commit `68cd05895b8d479ffb8167344282e7d922958bfc`;
- tree `70031b30316fbaecbb23249491d6ff4e364d65d5`.

It reads the commit with `git archive`, so unrelated working-tree edits are not
included. It checks that the source checkout's `HEAD` and `HEAD^{tree}` remain
unchanged after the run.

## Run

From this `poc/` directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

`make check` performs shell and JavaScript syntax checks. `make run` verifies
the commit and tree, extracts only that revision beneath a wrapper-owned
temporary directory, verifies twelve embedded source hashes, and launches the
probe with a minimal environment.

The probe performs these checks without executing the source:

1. It reconstructs the exact core overlay order from `scripts/compose-vps.sh`.
2. It reads only the focused `profiles` and `restart` properties for
   `phpmyadmin` and `phppgadmin`. It models Compose's `!reset []` semantics and
   scalar last-writer behavior.
3. It proves that the later runtime overlay clears `admin` and changes
   `restart: "no"` to `unless-stopped`, making both services active even though
   the canonical wrapper selects only the `backup` profile.
4. It checks the mounted routes, public WAF bind defaults, database-admin
   network attachment, and absence of an identity or source-allowlist
   middleware in the focused route configuration.
5. It exercises negative controls: the VPS-only order and runtime-before-VPS
   order remain disabled; removing the protected runtime overrides remains
   disabled by default; an explicit admin selection without an identity gate is
   rejected; explicit admin plus an identity gate is accepted.

Representative successful output is:

```text
[GUARD] invalid_ownership_rejected=true preexisting_bytes_preserved=true lab_untouched=true
[+] archived revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5
[+] wrapper-owned source and lab boundaries verified
[+] verified 12 embedded vulnerable-source hashes
[TRACE] overlay_order=compose.yaml>compose.secrets.yaml>compose.waf.yaml>compose.vps.yaml>compose.vps-waf.yaml>compose.backup-scheduler.yaml>compose.runtime.yaml>compose.networks.yaml>compose.runtime-isolation.yaml selected_profile=backup
[VULNERABLE] service=phpmyadmin profiles=[] restart=unless-stopped active_without_admin=true
[VULNERABLE] service=phppgadmin profiles=[] restart=unless-stopped active_without_admin=true
[ROUTES] public_edge_defaults=true portal_admin_paths=2 identity_middleware=false database_admin_network=true
[CONTROL] vps_gate_only=disabled runtime_before_vps=disabled fixed_default=disabled explicit_admin_without_identity=rejected explicit_authenticated_admin=accepted
[+] summary forced_default_activation_reproduced=true fixed_profile_gate_enforced=true source_tree_unchanged=true
[+] runtime_limit static_compose_semantics_only=true compose_binary=false database=false docker=false network=false live=false
[+] source_repository_head_unchanged=true source_repository_tree_unchanged=true
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

## Runtime limits

This is a focused static semantics model, not a general YAML parser and not a
replacement for `docker compose config`. It deliberately implements only the
properties needed for this finding: normal profile-list merging, `!reset []`,
and scalar restart replacement. The embedded hashes make the conclusion fail
closed if any decisive source bytes change.

The probe does not validate a particular Docker Compose binary or custom-tag
implementation. After remediation, CI should separately render the canonical
files with the production-pinned Compose version on a disposable runner and
assert the effective profiles and default service set. That runtime test must
not use a live database or production host.

Static route review proves configuration shape, not present DNS, edge, WAF,
container, or live reachability. The finding does not itself prove a database
authentication bypass or possession of database credentials.

## Safety and cleanup

The JavaScript probe requires wrapper-provided ownership paths, an unpredictable
ownership token, and a matching regular-file sentinel. Before the real run, the
wrapper supplies an invalid token and confirms that the probe rejects it before
writing to the lab, while pre-existing synthetic source bytes remain intact.

The positive probe reads only the archived source and writes one synthetic JSON
trace inside its wrapper-owned lab. On exit, the wrapper rechecks the temporary
root, parent, and sentinel path/device/inode/content before removing only its
own directory. If ownership cannot be proved, it refuses cleanup and exits
nonzero.

## Files

- `database-admin-profile-probe.mjs` contains the source checks and focused
  overlay-policy model.
- `run-from-git-archive.sh` pins source identity, enforces ownership, and
  performs fail-closed cleanup.
- `Makefile` exposes syntax and run targets.
