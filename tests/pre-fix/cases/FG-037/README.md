# FG-037 offline proof of concept

This PoC reproduces `CAN-072` from the exact affected Git object without using
a live server, Docker daemon, Restic binary, repository, password, or network.
It requires Node.js, Git, `tar`, and a checkout that contains commit
`68cd05895b8d479ffb8167344282e7d922958bfc`.

Run it from this directory:

```sh
make check
make run SOURCE_REPO=/path/to/platform-infrastructure
```

The wrapper verifies the commit and tree, exports a clean Git archive, and
passes only an exact physical child of its own temporary root to the probe. A
random ownership sentinel gates every recursive cleanup. Before the positive
case, a negative regression plants pre-existing report evidence, verifies that
the probe rejects that mutation target before execution, and confirms the
evidence remains byte-for-byte unchanged.

For the positive case, the probe supplies two synthetic values:

- a repository-URL userinfo canary; and
- a different password-file-content canary.

A fake `docker` executable records its exact child argument vector and returns
a deterministic failure. The probe verifies that the repository canary appears
in the Docker child argv, top-level stderr, and both generated failure reports,
while the password-file contents remain absent. The fake executable prevents a
real container or Restic process from starting. The reserved `.invalid` host is
never contacted.

Representative output:

```text
[GUARD] preexisting_reports_rejected=true evidence_preserved=true execution_started=false
[+] archived revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5
[+] safety wrapper-owned archive, synthetic canaries, fake Docker sink, no Restic or network
[+] confinement wrapper_realpath_exact=true source_exact_child=true sentinel_valid=true
[VULNERABLE] repository_canary_in_docker_child_argv=true
[VULNERABLE] repository_canary_in_stderr=true json_report=true markdown_report=true
[NEGATIVE] password_file_contents_exposed=false stdout_repository_canary=false
[REFERENCE] repository_file_argv_secret_free=true centralized_error_redaction=true
[+] safety fake_docker_calls=1 real_docker_calls=0 real_restic_executions=0 network_attempts=0
[+] result=VULNERABLE
[+] cleanup sentinel_owned_fixture_removed=true
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

All generated files stay below the sentinel-owned temporary archive and are
removed after the run. The source checkout supplied through `SOURCE_REPO` is
read only.
