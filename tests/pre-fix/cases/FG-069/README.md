# Safe privileged backup-queue backpressure probe

This source-pinned probe demonstrates `CAN-206` without sending an HTTP
request, starting the Control Center or backup scheduler, creating a backup-job
file, invoking a backup command, reading deployed state, or accessing a
network, database, storage service, credential, or Docker API.

It verifies the exact vulnerable source and then uses a bounded eight-item,
in-memory fixture to show that:

1. an authenticated `admin` is admitted on both modern backup API aliases,
   while the legacy backup action requires a fresh `owner`;
2. every repeated submission receives a distinct synthetic job identity and
   the source has no queue-depth, deduplication, rate, or concurrency admission
   control;
3. the scheduler consumes all durable files serially and invokes its typed,
   privileged executor; and
4. a synthetic fixed-policy oracle rejects duplicates, a full queue,
   cross-principal duplicates, per-principal excess, and excess concurrency,
   while allowing a deliberate retry after completion and retaining only four
   terminal records.

The fixed-policy oracle is a negative control, not a claim that the affected
revision contains a fix.

The wrapper requires a caller-supplied Git repository and archives commit
`68cd05895b8d479ffb8167344282e7d922958bfc`, whose tree must be
`70031b30316fbaecbb23249491d6ff4e364d65d5`. It does not trust the checkout's
working files. The probe verifies SHA-256 fingerprints for all nine source
inputs before evaluating them.

Before the positive run, the wrapper deliberately supplies a different valid
256-bit ownership token. The probe must reject it before reading source or
writing anything. The wrapper then verifies that both an archived source file
and a pre-existing preservation file are byte-identical and that the
laboratory is still empty.

Run from this directory:

```sh
make check
make -n run SOURCE_REPO=/path/to/platform-infrastructure
make run SOURCE_REPO=/path/to/platform-infrastructure
```

Expected positive output includes:

```text
[GUARD] invalid_ownership_rejected=true archived_source_preserved=true lab_untouched=true
[+] archived revision=68cd05895b8d479ffb8167344282e7d922958bfc tree=70031b30316fbaecbb23249491d6ff4e364d65d5
[+] exact_source_fingerprints_verified=9
[AUTH] modern_backup_aliases=2 admin=allow legacy_backup=deny owner_fresh_required=missing
[VULNERABLE] CAN-206 duplicate_requests=8 accepted=8 unique_jobs=8 queue_depth_bound=absent
[SCHEDULER] consumer=serial synthetic_queued=8 typed_privileged_execution=source_verified backpressure=absent
[FIXED-AUTH] modern_aliases=deny_admin database_backup=deny_admin owner_fresh=true
[FIXED-CONTROL] sequential_alias_dedupe_accepted=1/2 duplicate=duplicate_active full_queue=queue_full completion_then_retry=allow cross_principal=duplicate_active per_principal=principal_rate rate_after_expiry=allow concurrency=concurrency_full retention=4 atomic_race=NOT_TESTED
[SAFE] source_reads=9 synthetic_fixture=in_memory real_jobs_queued=0 real_jobs_executed=0 network_calls=0 service_starts=0 live_state_reads=0 lab_writes=0
[+] result=VULNERABLE
[+] wrapper_postcheck archived_server_unchanged=true lab_untouched=true sha256=0e660c3278ebe6d85c83e6852ef0afee6be10e7a434c3b37f0f33154969549b6
[+] cleanup wrapper_owned_temp_removed=true sentinel_verified=true
```

All synthetic job objects remain in Node.js memory. The `lab` directory must
stay empty through both runs. Cleanup revalidates the physical temporary parent
and root identities plus the unpredictable wrapper-sentinel path, identity,
token, and contents before removing only that wrapper-owned root. If those
checks fail, cleanup refuses deletion and reports the retained path. A SIGKILL
or power loss cannot be trapped; inspect an `.fg069-wrapper-owner-*` sentinel
before manually removing any abandoned temporary root.

The fixed reference batch is sequential. It validates alias-key deduplication,
not simultaneous-request atomicity. A post-fix closure test must race real
requests at the durable admission boundary and prove that exactly one job is
written; this PoC reports that property as `atomic_race=NOT_TESTED`.
