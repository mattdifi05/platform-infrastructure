#!/usr/bin/python3 -I
"""V1 GREENFIELD TRANSACTION STATE MACHINE (pure orchestration, delegated steps).

Exact order: PREPARE -> BACKUP_PRE -> BUILD -> CREATE_GREENFIELD_RESOURCES ->
RESTORE -> VERIFY -> START_ISOLATED -> FUNCTIONAL_VERIFY -> READY_FOR_FINAL_SYNC
-> QUIESCE_WRITERS -> FINAL_CAPTURE -> FINAL_RESTORE -> VERIFY_DELTA -> POST ->
CUTOVER -> OBSERVE -> SEAL -> GO.

Never talks to Docker, SSH, or any server.  Every state maps to one registered
step(context) -> receipt-dict callable that delegates through the injectable step
executor named by PLATFORM_GREENFIELD_STEP_EXECUTOR: it receives one JSON line
{"state", "context"} on stdin and must reply exactly one JSON line
{"outputs": {...}}.  Without a configured executor every step fails closed
(StepNotImplemented) before any journal mutation (exit 78).

Durability: append-only fsynced JSONL journal (PLATFORM_GREENFIELD_TRANSACTION_
JOURNAL, default <repo>/reports/greenfield/transaction/journal.jsonl); receipts
are atomically written BEFORE their RECEIPTED record; records {seq, tsUtc, state,
status, receiptSha256, prevRecordSha256} form a SHA-256 chain over canonical JSON
bytes (json.dumps sort_keys separators (",",":")); genesis prev is 64 zeros;
tampering fails closed with exit 79 everywhere.

PONR: immediately after the CUTOVER receipt durably commits.  Before it, rollback
is always legal (delegates state ROLLBACK, emits a rollback receipt listing
completed states, marks terminal ROLLED_BACK, zero destructive repair itself).
After it, rollback exits 86 with the cutover receipt digest as evidence and only
`reconcile` may proceed forward deterministically (idempotent re-runs with
context.attempt increments).  A hard crash leaves dangling ENTERED: `run`
refuses ambiguous auto-retry (exit 87); cleanly FAILED idempotent states may be
retried by `run`; non-idempotent CUTOVER always requires `reconcile`.

Authority: PLATFORM_RUNTIME_CANDIDATE_COMMIT/TREE (40-hex) are required for every
mutating command, bound once in authority.json plus inside every receipt; drift
on resume exits 88.  GO seals the journal (SEALED marker); later mutations exit
89.  Exit codes: 0 ok; 64 usage; 78 executor missing/fail-closed; 79 journal
corrupt/missing; 85 non-ROLLBACK-capable; 86 post-PONR refusal; 87 ambiguous
crash retry; 88 authority drift; 89 sealed.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone

RECEIPT_SCHEMA = "platform.v1-greenfield-transaction.receipt/v1"
STATUS_SCHEMA = "platform.v1-greenfield-transaction.status/v1"
CONTEXT_SCHEMA = "platform.v1-greenfield-transaction.context/v1"
AUTHORITY_SCHEMA = "platform.v1-greenfield-transaction.authority/v1"
RUN_SUMMARY_SCHEMA = "platform.v1-greenfield-transaction.run-summary/v1"
VERIFY_SCHEMA = "platform.v1-greenfield-transaction.verify/v1"

PROJECT_NAME = "platform_infra_greenfield"

STATES = (
    "PREPARE", "BACKUP_PRE", "BUILD", "CREATE_GREENFIELD_RESOURCES", "RESTORE",
    "VERIFY", "START_ISOLATED", "FUNCTIONAL_VERIFY", "READY_FOR_FINAL_SYNC",
    "QUIESCE_WRITERS", "FINAL_CAPTURE", "FINAL_RESTORE", "VERIFY_DELTA", "POST",
    "CUTOVER", "OBSERVE", "SEAL", "GO",
)
STATE_INDEX = {state: index for index, state in enumerate(STATES)}
PONR_STATE = "CUTOVER"
TERMINAL_STATE = "GO"
DEFAULT_FROM_STATE = "PREPARE"
DEFAULT_STOP_AFTER = "FUNCTIONAL_VERIFY"
ROLLBACK_STATE = "ROLLBACK"
SEALED_MARKER_STATE = "JOURNAL_SEALED"
NON_IDEMPOTENT_STATES = frozenset({"CUTOVER"})

STATUS_ENTERED, STATUS_RECEIPTED, STATUS_FAILED = "ENTERED", "RECEIPTED", "FAILED"
STATUS_ROLLED_BACK, STATUS_SEALED = "ROLLED_BACK", "SEALED"
RECORD_STATUSES = frozenset({
    STATUS_ENTERED, STATUS_RECEIPTED, STATUS_FAILED, STATUS_ROLLED_BACK, STATUS_SEALED,
})
DIGEST_RECORD_STATUSES = frozenset({STATUS_RECEIPTED, STATUS_ROLLED_BACK})

RECORD_KEYS = frozenset({"seq", "tsUtc", "state", "status", "receiptSha256", "prevRecordSha256"})
RECEIPT_KEYS = frozenset({
    "schema", "state", "runId", "authority", "startedUtc", "finishedUtc", "executor", "outputs",
})
AUTHORITY_KEYS = frozenset({"schema", "project", "topology", "candidateCommit", "candidateTree"})
REPLY_KEYS = frozenset({"outputs"})
GENESIS_PREV = "0" * 64

SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
GIT_OBJECT_RE = re.compile(r"^[a-f0-9]{40}$")
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
OUTPUT_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")

ENV_JOURNAL = "PLATFORM_GREENFIELD_TRANSACTION_JOURNAL"
ENV_STEP_EXECUTOR = "PLATFORM_GREENFIELD_STEP_EXECUTOR"
ENV_CANDIDATE_COMMIT = "PLATFORM_RUNTIME_CANDIDATE_COMMIT"
ENV_CANDIDATE_TREE = "PLATFORM_RUNTIME_CANDIDATE_TREE"
ENV_TOPOLOGY = "PLATFORM_GREENFIELD_TOPOLOGY"
ENV_ALLOW_FULL_RUN = "PLATFORM_GREENFIELD_ALLOW_FULL_RUN"
TOPOLOGIES = ("PARALLEL", "CUTOVER")

STEP_TIMEOUT_SECONDS = 300
MAX_REPLY_BYTES = 64 * 1024
MAX_JOURNAL_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_ENTRIES = 32
MAX_OUTPUT_VALUE_CHARS = 512

EXIT_USAGE, EXIT_EXECUTOR, EXIT_JOURNAL_CORRUPT = 64, 78, 79
EXIT_ROLLBACK_INCAPABLE, EXIT_PONR_REFUSAL, EXIT_AMBIGUOUS_CRASH = 85, 86, 87
EXIT_AUTHORITY_DRIFT, EXIT_SEALED = 88, 89

AUTHORITY_FILENAME = "authority.json"
ANCHOR_FILENAME = "chain-head.json"


class TransactionError(Exception):
    def __init__(self, message, code=EXIT_EXECUTOR):
        super().__init__(message)
        self.code = code


class StepNotImplemented(Exception):
    """Raised by registered default steps when no executor is configured."""


class StepExecutionError(Exception):
    """Raised when the delegated step executor fails or misbehaves."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def canonical_digest(value):
    return sha256_hex(canonical(value).encode("utf-8"))


def now_utc():
    return datetime.now(timezone.utc).strftime(TIMESTAMP_FORMAT)


def valid_timestamp(value):
    if not isinstance(value, str) or len(value) != 20 or not value.endswith("Z"):
        return False
    try:
        datetime.strptime(value, TIMESTAMP_FORMAT)
    except ValueError:
        return False
    return True


def exact_keys(value, keys, label):
    if not isinstance(value, dict) or set(value.keys()) != set(keys):
        raise TransactionError(f"{label} is not one exact closed object.", EXIT_JOURNAL_CORRUPT)
    return value


def journal_path_from_env():
    configured = os.environ.get(ENV_JOURNAL)
    if configured:
        return os.path.abspath(configured)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, "reports", "greenfield", "transaction", "journal.jsonl")

# Registered step functions.  Each state plus the ROLLBACK pseudo state maps to
# one uniform step(context) -> receipt-dict callable delegating to the external
# executor executable; without one they fail closed.


def make_delegated_step(state):
    def step(context):
        executor = resolve_step_executor(required=False)
        if executor is None:
            raise StepNotImplemented(state)
        return call_step_executor(executor, state, context)

    step.__name__ = f"step_{state.lower()}"
    return step


STEPS = {state: make_delegated_step(state) for state in STATES}
STEPS[ROLLBACK_STATE] = make_delegated_step(ROLLBACK_STATE)


def resolve_step_executor(required=True):
    configured = os.environ.get(ENV_STEP_EXECUTOR)
    if not configured:
        if required:
            raise TransactionError(
                f"{ENV_STEP_EXECUTOR} is not configured; refusing to execute greenfield "
                "transaction steps fail-closed.",
                EXIT_EXECUTOR,
            )
        return None
    if not os.path.isabs(configured):
        raise TransactionError(
            f"{ENV_STEP_EXECUTOR} must be one absolute executable path.", EXIT_EXECUTOR)
    if os.path.islink(configured) or not os.path.isfile(configured):
        raise TransactionError(
            f"{ENV_STEP_EXECUTOR} does not name one regular executable file: {configured}.",
            EXIT_EXECUTOR,
        )
    if not os.access(configured, os.X_OK):
        raise TransactionError(f"{ENV_STEP_EXECUTOR} is not executable: {configured}.", EXIT_EXECUTOR)
    return configured


def call_step_executor(executor, state, context):
    payload = (canonical({"state": state, "context": context}) + "\n").encode("utf-8")
    try:
        completed = subprocess.run(
            [executor],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=STEP_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise StepExecutionError(f"step executor timed out for state {state}.")
    except OSError as error:
        raise StepExecutionError(f"step executor could not be launched for {state}: {error}.")
    if completed.returncode != 0:
        detail = _leak_guard(
            completed.stderr.decode("utf-8", errors="replace").strip()[-512:])
        raise StepExecutionError(
            f"step executor failed for state {state} (exit {completed.returncode}): {detail}.")
    if len(completed.stdout) > MAX_REPLY_BYTES:
        raise StepExecutionError(f"step executor reply for {state} exceeds its byte boundary.")
    try:
        text = completed.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise StepExecutionError(f"step executor reply for {state} is not strict UTF-8.")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if len(lines) != 1 or not lines[0].strip():
        raise StepExecutionError(f"step executor for {state} must reply exactly one JSON line.")
    try:
        reply = json.loads(lines[0])
    except ValueError as error:
        raise StepExecutionError(f"step executor reply for {state} is not JSON: {error}.")
    exact_keys(reply, REPLY_KEYS, f"step executor reply for {state}")
    outputs = reply["outputs"]
    if not isinstance(outputs, dict) or len(outputs) > MAX_OUTPUT_ENTRIES:
        raise TransactionError(
            f"step executor outputs for {state} is not one bounded object.", EXIT_EXECUTOR)
    normalized = {}
    for key, value in outputs.items():
        valid = (
            isinstance(key, str)
            and OUTPUT_KEY_RE.fullmatch(key) is not None
            and isinstance(value, str)
            and len(value) <= MAX_OUTPUT_VALUE_CHARS
        )
        if not valid:
            raise TransactionError(
                f"step executor output {key!r} for {state} is not one small string pair.",
                EXIT_EXECUTOR,
            )
        normalized[key] = _leak_guard(value)
    return normalized


# Mirrors assertNoSecretMaterialization from the sibling Node modules: receipts
# and error surfaces must never carry credential-shaped material.
_LEAK_PATTERNS = (
    re.compile(r"-----BEGIN", re.IGNORECASE),
    re.compile(r"(?:password|passwd|pwd)\s*=", re.IGNORECASE),
    re.compile(r"token\s*=", re.IGNORECASE),
    re.compile(r"[A-Za-z0-9+/]{65,}={0,2}"),
)


def _leak_guard(text):
    if any(pattern.search(text) for pattern in _LEAK_PATTERNS):
        raise StepExecutionError(
            "step executor surface refused: potential secret materialization.")
    return text

# Journal storage: append-only JSONL with one fsync per durable record.


def fsync_directory(pathname):
    descriptor = os.open(pathname, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class JournalStore:
    def __init__(self, pathname):
        self.path = os.path.abspath(pathname)
        self.directory = os.path.dirname(self.path)

    def exists(self):
        return os.path.isfile(self.path) and not os.path.islink(self.path)

    def read_bytes(self):
        with open(self.path, "rb") as handle:
            return handle.read(MAX_JOURNAL_BYTES + 1)

    def ensure_directory(self):
        if os.path.isdir(self.directory) and not os.path.islink(self.directory):
            return
        if os.path.exists(self.directory):
            raise TransactionError(
                f"journal directory parent exists with an unsafe type: {self.directory}.",
                EXIT_JOURNAL_CORRUPT,
            )
        os.makedirs(self.directory, mode=0o700)
        fsync_directory(os.path.dirname(self.directory))

    def append_canonical(self, value):
        line = (canonical(value) + "\n").encode("utf-8")
        self.ensure_directory()
        first_append = not self.exists()
        descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(descriptor, line)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if first_append:
            fsync_directory(self.directory)
        return sha256_hex(line[:-1])

    def write_aux_file(self, filename, value):
        """Atomically write one bounded auxiliary document in the journal dir."""
        self.ensure_directory()
        target = os.path.join(self.directory, filename)
        temporary = os.path.join(self.directory, f".tmp-{filename}-{os.getpid()}")
        data = (canonical(value) + "\n").encode("utf-8")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, target)
        fsync_directory(self.directory)
        return sha256_hex(data[:-1])

    def read_aux_document(self, filename, keys, label):
        pathname = os.path.join(self.directory, filename)
        if not os.path.isfile(pathname) or os.path.islink(pathname):
            return None
        with open(pathname, "rb") as handle:
            data = handle.read(MAX_REPLY_BYTES + 1)
        if len(data) > MAX_REPLY_BYTES:
            raise TransactionError(f"{label} exceeds its byte boundary.", EXIT_JOURNAL_CORRUPT)
        try:
            value = json.loads(data.decode("utf-8"))
        except ValueError as error:
            raise TransactionError(f"{label} is not valid JSON: {error}.", EXIT_JOURNAL_CORRUPT)
        return exact_keys(value, keys, label)

# Journal loading and structural verification.  Every command loads through
# this single path so any tampering fails closed everywhere.


class TransactionView:
    def __init__(self):
        self.journal_exists = False
        self.records = []
        self.chain_head = GENESIS_PREV
        self.terminal_status = None
        self.ponr_crossed = False
        self.go_receipted = False
        self.received = []
        self.received_set = frozenset()
        self.prefix_len = 0
        self.dangling = None
        self.attempt_kinds = {}
        self.attempt_entries = {}

    def attempts_for(self, state):
        return self.attempt_entries.get(state, 0)

    def last_attempt_kind(self, state):
        kinds = self.attempt_kinds.get(state)
        return kinds[-1] if kinds else None

    def cutover_receipt_sha256(self):
        for record in self.records:
            if record["state"] == PONR_STATE and record["status"] == STATUS_RECEIPTED:
                return record["receiptSha256"]
        return None


def _checked_receipt_bytes(store, filename, receipt_sha, expected_seq):
    receipt_path = os.path.join(store.directory, filename)
    if os.path.islink(receipt_path) or not os.path.isfile(receipt_path):
        raise TransactionError(
            f"receipt file for journal record {expected_seq} is missing: {filename}.",
            EXIT_JOURNAL_CORRUPT,
        )
    with open(receipt_path, "rb") as handle:
        receipt_bytes = handle.read(MAX_REPLY_BYTES + 1)
    intact = (
        len(receipt_bytes) <= MAX_REPLY_BYTES
        and receipt_bytes.endswith(b"\n")
        and sha256_hex(receipt_bytes[:-1]) == receipt_sha
    )
    if not intact:
        raise TransactionError(
            f"receipt file does not match the committed digest at record {expected_seq}.",
            EXIT_JOURNAL_CORRUPT,
        )


def _validate_record(record, expected_seq, previous_digest, store):
    def bad(message):
        raise TransactionError(
            f"transaction journal record {expected_seq} {message}", EXIT_JOURNAL_CORRUPT)

    exact_keys(record, RECORD_KEYS, f"transaction journal record {expected_seq}")
    if isinstance(record["seq"], bool) or record["seq"] != expected_seq:
        bad("has a broken sequence number.")
    if not valid_timestamp(record["tsUtc"]):
        bad("has an invalid timestamp.")
    status, state = record["status"], record["state"]
    if status not in RECORD_STATUSES:
        bad("has an unknown status.")
    digest = canonical_digest(record)
    if record["prevRecordSha256"] != previous_digest:
        bad("breaks the hash chain (prev mismatch).")
    if status in DIGEST_RECORD_STATUSES:
        receipt_sha = record["receiptSha256"]
        if not isinstance(receipt_sha, str) or SHA256_RE.fullmatch(receipt_sha) is None:
            bad("lacks one receipt digest.")
        filename = (
            f"{ROLLBACK_STATE}-receipt.json"
            if status == STATUS_ROLLED_BACK
            else f"{state}-receipt.json"
        )
        _checked_receipt_bytes(store, filename, receipt_sha, expected_seq)
    elif record["receiptSha256"] is not None:
        bad("carries an unexpected receipt digest.")
    return status, state, digest


def load_transaction(store):
    view = TransactionView()
    if not store.exists():
        return view
    view.journal_exists = True
    raw = store.read_bytes()
    if not raw or len(raw) > MAX_JOURNAL_BYTES or not raw.endswith(b"\n"):
        raise TransactionError(
            "transaction journal is empty, oversized, or truncated.", EXIT_JOURNAL_CORRUPT)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise TransactionError("transaction journal is not strict UTF-8.", EXIT_JOURNAL_CORRUPT)
    lines = text.split("\n")
    lines.pop()
    if any(line.strip() == "" for line in lines):
        raise TransactionError(
            "transaction journal contains one blank record.", EXIT_JOURNAL_CORRUPT)

    previous_digest = GENESIS_PREV
    frontier = 0
    seen_rolled_back = False
    seen_sealed = False
    for expected_seq, line in enumerate(lines, start=1):
        def bad(message, seq=expected_seq):
            raise TransactionError(
                f"transaction journal record {seq} {message}", EXIT_JOURNAL_CORRUPT)

        try:
            record = json.loads(line)
        except ValueError as error:
            bad(f"is not JSON: {error}.")
        status, state, digest = _validate_record(record, expected_seq, previous_digest, store)
        previous_digest = digest

        if seen_rolled_back or seen_sealed:
            bad("follows one terminal marker.")
        if status == STATUS_ROLLED_BACK:
            if state != ROLLBACK_STATE:
                bad("misnames the rollback marker.")
            seen_rolled_back, view.terminal_status = True, STATUS_ROLLED_BACK
            view.records.append(record)
            continue
        if status == STATUS_SEALED:
            if state != SEALED_MARKER_STATE:
                bad("misnames the seal marker.")
            if not view.go_receipted:
                bad("seals before GO.")
            seen_sealed, view.terminal_status = True, STATUS_SEALED
            view.records.append(record)
            continue

        if state not in STATE_INDEX:
            bad("names an unknown state.")
        if STATE_INDEX[state] != frontier:
            bad(f"touches out-of-order state {state}.")
        last_kind = view.last_attempt_kind(state)
        if status == STATUS_ENTERED:
            if last_kind == STATUS_RECEIPTED:
                bad(f"re-enters {state} illegally.")
            view.attempt_entries[state] = view.attempt_entries.get(state, 0) + 1
        elif status == STATUS_FAILED:
            if last_kind != STATUS_ENTERED:
                bad(f"fails {state} without one open attempt.")
        else:  # RECEIPTED
            if last_kind not in (STATUS_ENTERED, STATUS_FAILED):
                bad(f"receipts {state} without one open attempt.")
            view.received.append(state)
            view.prefix_len += 1
            frontier += 1
            if state == PONR_STATE:
                view.ponr_crossed = True
            if state == TERMINAL_STATE:
                view.go_receipted = True
        view.attempt_kinds.setdefault(state, []).append(status)
        view.records.append(record)

    if frontier < len(STATES):
        pending_state = STATES[frontier]
        kinds = view.attempt_kinds.get(pending_state)
        if kinds and kinds[-1] in (STATUS_ENTERED, STATUS_FAILED):
            view.dangling = {"state": pending_state, "kind": kinds[-1]}
    view.chain_head = previous_digest
    if lines:
        anchor = store.read_aux_document(
            ANCHOR_FILENAME,
            frozenset({"recordCount", "chainHeadSha256"}),
            "journal chain anchor",
        )
        if anchor is None:
            raise TransactionError(
                "journal chain anchor is missing; out-of-band tail binding required.",
                EXIT_JOURNAL_CORRUPT,
            )
        if anchor["recordCount"] != len(view.records) or anchor["chainHeadSha256"] != previous_digest:
            raise TransactionError(
                "journal tail diverges from its chain anchor (truncation, reordering, "
                "or unanchored append detected).",
                EXIT_JOURNAL_CORRUPT,
            )
    view.received_set = frozenset(view.received)
    return view

# Authority binding: candidate commit/tree are required for every mutating
# command, bound once in authority.json plus inside every receipt; drift on
# resume refuses with exit 88.


def requested_authority():
    commit = os.environ.get(ENV_CANDIDATE_COMMIT)
    tree = os.environ.get(ENV_CANDIDATE_TREE)
    topology = os.environ.get(ENV_TOPOLOGY, "PARALLEL")
    for name, value in ((ENV_CANDIDATE_COMMIT, commit), (ENV_CANDIDATE_TREE, tree)):
        if value is None or GIT_OBJECT_RE.fullmatch(value) is None:
            raise TransactionError(
                f"{name} must be set to one lowercase 40-hex git object id.", EXIT_USAGE)
    if topology not in TOPOLOGIES:
        raise TransactionError(
            f"{ENV_TOPOLOGY} must be one of {'/'.join(TOPOLOGIES)}.", EXIT_USAGE)
    return {
        "schema": AUTHORITY_SCHEMA,
        "project": PROJECT_NAME,
        "topology": topology,
        "candidateCommit": commit,
        "candidateTree": tree,
    }


def bind_authority(store, view):
    requested = requested_authority()
    stored = store.read_aux_document(
        AUTHORITY_FILENAME, AUTHORITY_KEYS, "transaction authority document"
    )
    if stored is None:
        if view.journal_exists:
            raise TransactionError(
                "transaction journal exists without its authority document.",
                EXIT_JOURNAL_CORRUPT,
            )
        store.write_aux_file(AUTHORITY_FILENAME, requested)
        return requested
    for field in ("candidateCommit", "candidateTree"):
        value = stored[field]
        if not isinstance(value, str) or GIT_OBJECT_RE.fullmatch(value) is None:
            raise TransactionError(
                f"transaction authority {field} is not one lowercase git object id.",
                EXIT_JOURNAL_CORRUPT,
            )
    if stored["project"] != PROJECT_NAME:
        raise TransactionError("transaction authority project identity drifted.", EXIT_AUTHORITY_DRIFT)
    if stored["topology"] not in TOPOLOGIES:
        raise TransactionError("transaction authority topology is invalid.", EXIT_JOURNAL_CORRUPT)
    if stored != requested:
        differing = ",".join(sorted(f for f in sorted(AUTHORITY_KEYS) if stored[f] != requested[f]))
        raise TransactionError(
            f"authority drift refused: bound {canonical(stored)} but environment requests "
            f"{canonical(requested)} (differing: {differing}).",
            EXIT_AUTHORITY_DRIFT,
        )
    return stored

# Record appends, durable receipt writing, and shared builders.


def append_record(store, view, state, status, receipt_sha=None):
    record = {
        "seq": len(view.records) + 1,
        "tsUtc": now_utc(),
        "state": state,
        "status": status,
        "receiptSha256": receipt_sha,
        "prevRecordSha256": view.chain_head,
    }
    digest = store.append_canonical(record)
    view.records.append(record)
    view.chain_head = digest
    store.write_aux_file(
        ANCHOR_FILENAME,
        {"recordCount": len(view.records), "chainHeadSha256": digest},
    )
    return record


def authority_pair(authority):
    return {
        "candidateCommit": authority["candidateCommit"],
        "candidateTree": authority["candidateTree"],
    }


def prior_receipts(view):
    return {
        r["state"]: r["receiptSha256"]
        for r in view.records
        if r["status"] == STATUS_RECEIPTED
    }


def build_context(authority, store, command, stop_after, attempt, previous, view):
    return {
        "schema": CONTEXT_SCHEMA,
        "project": PROJECT_NAME,
        "topology": authority["topology"],
        "journalDir": store.directory,
        "authority": authority_pair(authority),
        "priorReceipts": prior_receipts(view),
        "attempt": attempt,
        "previousAttempt": previous,
        "command": command,
        "stopAfter": stop_after,
    }


def build_receipt(state, run_id, authority, started, finished, outputs):
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "state": state,
        "runId": run_id,
        "authority": authority_pair(authority),
        "startedUtc": started,
        "finishedUtc": finished,
        "executor": "delegated",
        "outputs": outputs,
    }
    exact_keys(receipt, RECEIPT_KEYS, f"constructed {state} receipt")
    return receipt


def emit(document):
    sys.stdout.write(canonical(document) + "\n")


def build_run_summary(command, executed, view, stop_after, store):
    return {
        "schema": RUN_SUMMARY_SCHEMA,
        "command": command,
        "executed": list(executed),
        "stopAfter": stop_after,
        "receivedCount": len(view.received),
        "pointOfNoReturnCrossed": view.ponr_crossed,
        "sealed": view.terminal_status == STATUS_SEALED,
        "journalPath": store.path,
    }

# Forward execution engine shared by `run` and `reconcile`.


def execute_forward(command, store, from_state, stop_after):
    allow_full_run = os.environ.get(ENV_ALLOW_FULL_RUN)
    if allow_full_run is not None and allow_full_run != "1":
        raise TransactionError(f'{ENV_ALLOW_FULL_RUN} must be exactly "1" when set.', EXIT_USAGE)
    view = load_transaction(store)
    if view.go_receipted and view.terminal_status != STATUS_SEALED:
        # Crash between the GO receipt and the seal marker: complete the seal.
        append_record(store, view, SEALED_MARKER_STATE, STATUS_SEALED)
        view.terminal_status = STATUS_SEALED
    if view.terminal_status == STATUS_SEALED:
        raise TransactionError(
            "transaction journal is sealed; no further mutation is permitted.", EXIT_SEALED)
    if view.terminal_status == STATUS_ROLLED_BACK:
        raise TransactionError(
            "transaction journal is terminally ROLLED_BACK; forward mutation refused.",
            EXIT_ROLLBACK_INCAPABLE,
        )
    authority = bind_authority(store, view)

    horizon = STATE_INDEX[stop_after]
    floor = STATE_INDEX[from_state]
    dangling = view.dangling
    if dangling is not None and command == "run":
        if dangling["kind"] == STATUS_ENTERED:
            raise TransactionError(
                f"ambiguous crash retry refused: state {dangling['state']} left dangling "
                f"{dangling['kind']} with no receipt; run 'reconcile' to recover "
                "deterministically with an incremented attempt.",
                EXIT_AMBIGUOUS_CRASH,
            )
        if dangling["state"] in NON_IDEMPOTENT_STATES:
            raise TransactionError(
                f"{dangling['state']} is non-idempotent; its failed attempt requires "
                "'reconcile' to re-run deterministically.",
                EXIT_AMBIGUOUS_CRASH,
            )
        # Idempotent clean failure: `run` may transparently retry below.
    if view.journal_exists:
        if floor > view.prefix_len:
            raise TransactionError(
                f"--from {from_state} would skip states still pending at "
                f"{STATES[view.prefix_len]}.",
                EXIT_USAGE,
            )
        start = view.prefix_len
    else:
        start = floor
        if horizon >= STATE_INDEX[PONR_STATE] and floor > STATE_INDEX[STATES[0]]:
            raise TransactionError(
                f"a virgin journal cannot start a cutover-capable run at {from_state}; "
                f"begin at {STATES[0]} so PREPARE/BACKUP_PRE evidence precedes every later state.",
                EXIT_USAGE,
            )
    if dangling is not None and horizon < view.prefix_len:
        raise TransactionError(
            f"--stop-after {stop_after} precedes pending state {dangling['state']}; "
            "recovery must reach it.",
            EXIT_USAGE,
        )
    if horizon >= STATE_INDEX[PONR_STATE] and not view.ponr_crossed \
            and os.environ.get(ENV_ALLOW_FULL_RUN) != "1":
        raise TransactionError(
            f"this plan would cross the point of no return (the {PONR_STATE} receipt); "
            f"set {ENV_ALLOW_FULL_RUN}=1 to authorize deliberate cutover.",
            EXIT_USAGE,
        )
    plan = list(STATES[start : horizon + 1])
    if not plan:
        emit(build_run_summary(command, [], view, stop_after, store))
        return 0

    resolve_step_executor(required=True)  # fail closed before any journal mutation
    run_id = uuid.uuid4().hex
    executed = []
    for state in plan:
        attempt = view.attempts_for(state) + 1
        previous_kind = view.last_attempt_kind(state)
        previous = None if previous_kind is None else {
            "status": previous_kind, "crashed": previous_kind == STATUS_ENTERED}
        append_record(store, view, state, STATUS_ENTERED)
        started = now_utc()
        context = build_context(authority, store, command, stop_after, attempt, previous, view)
        try:
            outputs = STEPS[state](context)
        except StepNotImplemented:
            append_record(store, view, state, STATUS_FAILED)
            raise TransactionError(
                f"no step implementation for {state}; failing closed.", EXIT_EXECUTOR)
        except StepExecutionError as error:
            append_record(store, view, state, STATUS_FAILED)
            raise TransactionError(str(error), EXIT_EXECUTOR)
        receipt = build_receipt(
            state, run_id, authority, started, now_utc(), dict(outputs, attempt=str(attempt)))
        digest = store.write_aux_file(f"{state}-receipt.json", receipt)
        append_record(store, view, state, STATUS_RECEIPTED, digest)
        view.received.append(state)
        view.prefix_len += 1
        if state == PONR_STATE:
            view.ponr_crossed = True
        executed.append(state)
        if state == TERMINAL_STATE:
            append_record(store, view, SEALED_MARKER_STATE, STATUS_SEALED)
            view.terminal_status = STATUS_SEALED
    emit(build_run_summary(command, executed, view, stop_after, store))
    return 0

# Rollback: legal only before the point of no return.  It delegates the real
# greenfield-stop/routing-restore through the same step executor (state
# ROLLBACK) and never performs destructive repair itself.


def execute_rollback(store):
    view = load_transaction(store)
    if not view.records:
        raise TransactionError(
            "rollback incapable: transaction has no journal records.", EXIT_ROLLBACK_INCAPABLE)
    if view.terminal_status == STATUS_ROLLED_BACK:
        raise TransactionError(
            "rollback incapable: transaction journal already carries terminal ROLLED_BACK.",
            EXIT_ROLLBACK_INCAPABLE,
        )
    if view.ponr_crossed:
        raise TransactionError(
            "point of no return crossed: the CUTOVER receipt is durably committed "
            f"(cutoverReceiptSha256={view.cutover_receipt_sha256()}); rollback is "
            "refused, recover forward deterministically via 'reconcile'.",
            EXIT_PONR_REFUSAL,
        )
    authority = bind_authority(store, view)
    completed = list(view.received)
    if not completed:
        raise TransactionError(
            "rollback incapable: no state carries a committed receipt.",
            EXIT_ROLLBACK_INCAPABLE,
        )
    resolve_step_executor(required=True)  # fail closed before any journal mutation
    context = build_context(authority, store, "rollback", None, 1, None, view)
    try:
        outputs = STEPS[ROLLBACK_STATE](context)
    except StepNotImplemented:
        raise TransactionError("no step implementation for ROLLBACK; failing closed.", EXIT_EXECUTOR)
    except StepExecutionError as error:
        raise TransactionError(str(error), EXIT_EXECUTOR)
    merged_outputs = dict(outputs)
    merged_outputs["attempt"] = "1"
    merged_outputs["completedStates"] = ",".join(completed)
    receipt = build_receipt(
        ROLLBACK_STATE, uuid.uuid4().hex, authority, now_utc(), now_utc(), merged_outputs)
    digest = store.write_aux_file(f"{ROLLBACK_STATE}-receipt.json", receipt)
    append_record(store, view, ROLLBACK_STATE, STATUS_ROLLED_BACK, digest)
    emit({
        "schema": RUN_SUMMARY_SCHEMA,
        "command": "rollback",
        "executed": [ROLLBACK_STATE],
        "stopAfter": None,
        "rolledBack": True,
        "completedStates": completed,
        "pointOfNoReturnCrossed": False,
        "sealed": False,
        "journalPath": store.path,
    })
    return 0

# Read-only commands.


def command_status(store):
    view = load_transaction(store)
    stored_authority = store.read_aux_document(
        AUTHORITY_FILENAME, AUTHORITY_KEYS, "transaction authority document"
    )
    received_set = frozenset(view.received)
    emit({
        "schema": STATUS_SCHEMA,
        "journalPath": store.path,
        "exists": view.journal_exists,
        "project": PROJECT_NAME,
        "authority": stored_authority,
        "terminalStatus": view.terminal_status,
        "sealed": view.terminal_status == STATUS_SEALED,
        "rolledBack": view.terminal_status == STATUS_ROLLED_BACK,
        "pointOfNoReturnCrossed": view.ponr_crossed,
        "receivedCount": len(view.received),
        "receivedStates": list(view.received),
        "pendingStates": [s for s in STATES if s not in received_set],
        "dangling": view.dangling,
        "chainHead": view.chain_head,
    })
    return 0


def command_verify_journal(store):
    view = load_transaction(store)
    if not view.journal_exists:
        raise TransactionError(
            f"transaction journal does not exist: {store.path}", EXIT_JOURNAL_CORRUPT)
    emit({
        "schema": VERIFY_SCHEMA,
        "ok": True,
        "records": len(view.records),
        "chainHead": view.chain_head,
        "terminalStatus": view.terminal_status,
        "pointOfNoReturnCrossed": view.ponr_crossed,
        "journalPath": store.path,
    })
    return 0


# CLI.


USAGE = """usage:
  v1-greenfield-transaction.py run|reconcile [--from STATE] [--stop-after STATE]
  v1-greenfield-transaction.py status | rollback | verify-journal
states (exact order): PREPARE BACKUP_PRE BUILD CREATE_GREENFIELD_RESOURCES
  RESTORE VERIFY START_ISOLATED FUNCTIONAL_VERIFY READY_FOR_FINAL_SYNC
  QUIESCE_WRITERS FINAL_CAPTURE FINAL_RESTORE VERIFY_DELTA POST CUTOVER
  OBSERVE SEAL GO"""


def usage_error(message):
    raise TransactionError(f"{message}\n{USAGE}", EXIT_USAGE)


def parse_forward_arguments(arguments, command, default_stop_after):
    values = {"--from": DEFAULT_FROM_STATE, "--stop-after": default_stop_after}
    seen = set()
    index = 0
    while index < len(arguments):
        flag = arguments[index]
        if flag not in values:
            usage_error(f"unknown argument for {command}: {flag}")
        if flag in seen:
            usage_error(f"duplicate argument {flag} for {command}")
        if index + 1 >= len(arguments):
            usage_error(f"{flag} requires one state value")
        seen.add(flag)
        values[flag] = arguments[index + 1]
        index += 2
    for name, value in values.items():
        if value not in STATE_INDEX:
            usage_error(f"{name} must name one transaction state, got {value!r}")
    if STATE_INDEX[values["--from"]] > STATE_INDEX[values["--stop-after"]]:
        usage_error("--from must not follow --stop-after")
    return values["--from"], values["--stop-after"]


def main(argv):
    try:
        if not argv:
            usage_error("missing command")
        command, rest = argv[0], argv[1:]
        store = JournalStore(journal_path_from_env())
        if command in ("run", "reconcile"):
            default_stop = DEFAULT_STOP_AFTER if command == "run" else TERMINAL_STATE
            from_state, stop_after = parse_forward_arguments(rest, command, default_stop)
            return execute_forward(command, store, from_state, stop_after)
        if command in ("status", "rollback", "verify-journal"):
            if rest:
                usage_error(f"{command} takes no arguments")
            dispatch = {
                "status": command_status,
                "rollback": execute_rollback,
                "verify-journal": command_verify_journal,
            }
            return dispatch[command](store)
        usage_error(f"unknown command: {command}")
    except TransactionError as error:
        sys.stderr.write(f"v1-greenfield-transaction: error: {error}\n")
        return error.code
    except StepExecutionError as error:
        sys.stderr.write(f"v1-greenfield-transaction: error: {error}\n")
        return EXIT_EXECUTOR
    except OSError as error:
        sys.stderr.write(f"v1-greenfield-transaction: error: {error}\n")
        return 74
    except Exception as error:  # pragma: no cover - unexpected internal fault
        sys.stderr.write(f"v1-greenfield-transaction: internal error: {error!r}\n")
        return 70


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
