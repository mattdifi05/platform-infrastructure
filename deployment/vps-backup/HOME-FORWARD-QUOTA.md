# Home quota-only forward admission (review procedure, not executed)

Root readback confirmed the installed public helper SHA256 is
`f59cb77d990de2ce8e709e5fa47a9fce9508e7aac6ee217ef64ff34584068586`, exactly the patch
base. Active native admission schema is v2, generation 18, and
`payload.resources.operator.helperSha256` matches that value. No exact hardcoded
current-digest pins were found. Operator/helper wrappers consume the admission pin
dynamically. This evidence was supplied by the coordinating root agent after its
privileged read-only execution of `home-pin-inventory.py`.

The next admission must be **forward generation 19**, with predecessor the canonical
hash of the actual signed generation-18 document. Never edit the active document's
hash field, never reset broker replay/operation state, never import a VPS authority
into home, and never synthesize a new restore/activation receipt.

Minimal native transaction for root review:

1. Keep VPS capture/upload gates false. Keep home backup payloads and retention
   untouched. Stage the patch and shared-quota module in a root-protected separate
   directory. `git apply --check` against the verified base and compile the candidate.
   Compute only public code digests, including the module digest pinned in candidate.
2. With both writer schedules temporarily held and no active backup/restore operation,
   preserve the exact current helper, public admission, active generation document,
   permissions and service/timer enabled states in a root-protected rollback directory.
   Do not copy authority private keys. Do not delete or reset journal/replay files.
3. Create the empty dedicated VPS sibling folder only after root authorizes that
   provider mutation. Run `qualify-ftps-lock.py --root-authorized-mkd-test` against
   both existing server folders with two independent TLS sessions. It must reject
   the second MKD and remove only the lock directory it created. Existing locks are
   never removed by this test. Missing namespaces or uncertain outcomes block.
4. Build native CLI resource input by copying the **public current** `offsite`,
   `objectStore` and `operator` declarations, replacing only operator.helperSha256
   with the candidate public helper digest. All original activationEvidence,
   object-store/peer/image identities and other helper hashes remain genuine and
   unchanged. No new global home recovery/capture is required by this code-only patch.
5. Use the existing `scripts/local-private-backup-admission.mjs create` CLI with
   `--nativeResources <protected-public-resource-json>`, generation 19, predecessor
   hash of the real generation-18 document and the existing native file references
   for render/capability/signing inputs. Existing authority private material may only
   be consumed by that established native signer; do not open, print, hash, copy or
   export it. Preserve all unrelated release/tree/render/source/resource bindings
   from verified current facts. Require a field-by-field public payload review before
   installation; changes beyond generation/predecessor/timestamps/new helper pin and
   necessary native identifiers are a stop condition.
6. Verify the candidate admission through the existing native `verify` command with
   existing public authority and real current render/capability/signing file refs.
   Do not activate a generic v1 document or reinitialize the broker. The broker's
   existing `admitGeneration()` is the monotonic activation path and must preserve
   every replay/request/operation record.
7. Under the existing host operation exclusion, install the candidate module/helper
   and the signed candidate admission as one controlled paused-writer transition.
   Until complete, keep both schedules held. Root must use the established broker
   admission consumption path; this preparation deliberately provides no raw state
   editor and no new authority implementation.
8. Before generation advancement, rollback can restore the preserved helper and
   admission byte-for-byte. **After native generation 19 is admitted, do not roll back
   the generation document to 18**: keep the active state/replay ledger and use a
   forward generation 20 signed admission restoring the previous helper pin if needed.
9. Enable `bothWritersQualified=true` only after both actual writers carry the shared
   module and their code identities verify. Perform native read-only selection and
   quota inventory, then resume the original home timer states. VPS activation still
   requires independent root GO after human passkey setup.

No signing, home installation, namespace creation, MKD test or schedule mutation
has been performed by this preparation. The active protected signer invocation
parameters must come from the existing home operator procedure, not guessed paths.
