# Governance Ownership And Runbook Catalogs

Status: `LOCAL-SUPPORT-READY-EXTERNAL-PENDING`.

The repository now contains closed, machine-readable support for accountable
asset ownership and the required operational runbooks. This is local control
support for `DOC-EVD-001` and `DOC-EVD-002`; it is not proof that a person
accepted a role or that a real drill succeeded. Both conditions remain
GO-blocking until their external evidence is independently authenticated.

## Authoritative local artifacts

| Artifact | Purpose |
| --- | --- |
| `governance/service-asset-ownership.json` | Closed coverage of hardware, network, applications, data, backups, secrets, observability, CI, providers, and 20 required capabilities. |
| `governance/runbook-catalog.json` | Closed catalog for operations, incident, provider, rollout, rollback, backup, restore, and access recovery. |
| `governance/catalog-artifacts/asset-ownership-scope.md` | Hash-bound scope and evidence boundary for each catalog asset. |
| `governance/catalog-artifacts/governance-runbooks.md` | Hash-bound versioned procedures, preservation rules, rollback rules, and drill boundary. |
| `governance/schemas/*.schema.json` | JSON Schema 2020-12 contracts with closed object fields for both catalogs and both receipt types. |
| `scripts/governance-documentation-closure.mjs` | Offline fail-closed catalog and receipt structure validator. |
| `scripts/governance-documentation-closure.test.mjs` | Positive, negative, hostile, path, binding, identity, and false-GO regression coverage. |

The catalogs bind tracked regular files by repository-relative path, SHA-256,
and an exact unique anchor. Missing files, untracked artifacts, symlinks, stale
hashes, unknown fields, duplicate coverage, undeclared roles, collapsed role
separation, placeholders, and runtime identities fail validation.

## Accountability boundary

The identifiers under `roles` are human-accountability slots, not people:

- primary;
- substitute;
- release approval;
- incident escalation.

Every asset uses four distinct slots. `root`, containers, daemons, services,
database users, and other runtime principals are invalid owners. The repository
does not infer a person from an account name and contains no acknowledgement
receipt. Identity binding remains `GOVERNANCE-EXTERNAL`.

To close `COND-DOC-EVD-001`, an external process must authenticate exactly one
current acceptance set that:

1. binds the exact ownership catalog bytes;
2. covers the primary and substitute role for every catalog asset;
3. binds each role consistently to a distinct authenticated subject;
4. acknowledges closure, preservation, rollback, and review;
5. carries a separate authenticated approval after the acknowledgements;
6. remains within the catalog review cadence; and
7. is verified under independent trust, not by fields asserted in a local JSON
   document.

## Runbook and drill boundary

The runbook catalog contains the complete required type set. Preservation,
bounded rollback, review before rollout, review after material change, exact
artifact binding, and independent execution are mandatory.

To close `COND-DOC-EVD-002`, external independent operators must successfully
exercise rollout, rollback, backup, restore, and access recovery against the
exact approved artifact bytes. Every receipt must bind the catalog and
procedure hashes, authenticated operator identity, execution time, preservation
result, rollback result, and independently held evidence. The operator must not
match an accepted accountability subject.

No real drill is stored or claimed in this repository. A configuration check,
dry run, local restore, provider-free simulation, or test of the original state
does not become production drill evidence.

## Local validation

Validate the committed catalogs:

```sh
node scripts/governance-documentation-closure.mjs catalogs \
  --root "$PWD" \
  --ownership governance/service-asset-ownership.json \
  --runbooks governance/runbook-catalog.json

node --test scripts/governance-documentation-closure.test.mjs
```

The catalog command must return:

```text
status=LOCAL-SUPPORT-READY-EXTERNAL-PENDING
gateAdmissible=false
```

Receipt fixtures in the test suite use `evidenceClass=SYNTHETIC-TEST`,
`synthetic=true`, and `gateAdmissible=false`. They test parsing and rejection
only. They never satisfy an external condition.

The validator may also check the structure and exact catalog binding of an
untracked external receipt. That result remains
`GOVERNANCE-EXTERNAL-VERIFICATION-PENDING`, is non-gate-admissible, and does not
authorize deployment. Strings such as `provider-signed`, subject digests, and
evidence hashes are not cryptographic verification by themselves. An
independent trusted verifier outside this local boundary must authenticate
them.

The local `gate` command deliberately exits nonzero even when a structurally
complete external set is supplied:

```sh
node scripts/governance-documentation-closure.mjs gate \
  --root "$PWD" \
  --ownership governance/service-asset-ownership.json \
  --runbooks governance/runbook-catalog.json \
  --acceptance-dir reports/governance/acceptance \
  --drill-dir reports/governance/drills
```

Receipt directories must remain untracked, contain only regular JSON files,
and contain no symlinks or ambiguous entries. Never commit personal identity,
authentication material, secret values, or live provider responses merely to
make a local test pass.

## Closure and rollback

| Condition | Local support | External closure |
| --- | --- | --- |
| `COND-DOC-EVD-001` | Catalog, schema, artifact binding, role separation, and receipt structure validation are ready. | Authenticated primary/substitute acknowledgements for every asset plus distinct authenticated approval. |
| `COND-DOC-EVD-002` | Complete runbook type catalog, versioned procedures, schema, exact artifact binding, and receipt structure validation are ready. | Fresh independent successful rollout, rollback, backup, restore, and access-recovery drills. |

Reverting these files removes local support only; it does not undo or invalidate
external evidence. Before reverting a catalog version, preserve its exact bytes
and receipts as historical evidence, mark it superseded, and keep deployment
blocked until a replacement catalog and matching external evidence exist.
