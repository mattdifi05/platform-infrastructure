# Home quota-only forward admission — completed 2026-10-06

The home server accepted native v2 backup admission **generation 19** for the
shared FTPS writer quota. This was a helper-only forward transition; home backup
payloads, retention, object-store identity, activation evidence, render, release,
capabilities, replay records and operation state were preserved. The actual signed
generation-18 document and broker state agreed on canonical predecessor SHA256
`4315367bad4be2ca11c4d98a10eff48ad5f1654ff3b335668dd61d888561ddee`.
The signed generation-19 document's canonical SHA256 is
`5d76cff3ddd11e4078a1b0065a0872098fd59f5dd26918ba9e399569ecd68c42`.
The broker's native `loadLocalPrivateTrust()` verified the real render,
capability and signing bindings, then native `admitGeneration()` advanced the
active state to generation 19. No active broker operation existed before or after.

The reviewed public payload diff from generation 18 contained exactly four
fields: `generation` (18 to 19), `previousAdmissionSha256` (the real predecessor
above), `issuedAt`, and `resources.operator.helperSha256`. The installed home
helper moved from SHA256
`f59cb77d990de2ce8e709e5fa47a9fce9508e7aac6ee217ef64ff34584068586`
to `fc565c7f11e5ffcb8349f1d24538e5ab5a29dd43eb300d13a3fc1e1dc18938aa`.
The installed shared-quota module SHA256 is
`bbfb7263e0f3fb8bd329bb1d33fc01a3e28e2bcb5952715bfeeba3d1f9b5e493`.
The VPS writer's installed module has the same digest. Both root-owned policies
now set `bothWritersQualified=true`. The existing authority private key was
consumed only by the established Ed25519 signer; it was not copied to either
server or included in the review artifacts.

During a bounded home operation lock, the schedule, manual queue and FTPS expiry
timers were held with no active backup/restore operation. The dedicated
`/platform-server-public-backups` FTPS folder was created alongside the existing
`/server-platform-backups` folder, outside `public_html`. The existing
`qualify-ftps-lock.py --root-authorized-mkd-test` verified TLS and both folders
with two independent sessions: the second `MKD` was rejected, and the test
removed only its own temporary lock. No backup object was uploaded or deleted.
Read-only scoped inventory after qualification was 26,209,164,424 bytes home,
0 bytes VPS, and 43,790,835,576 bytes free under the combined 70,000,000,000-byte
limit. The home timers were restored to their original active states, preserving
the home M/W/F schedule. VPS capture/upload gates and both VPS backup timers
remain disabled; this admission is not a successful VPS backup or restore proof.

`home-shared-quota.patch` remains the historical review/forward artifact against
the **f59cb77d** canonical base. The canonical repository helper is deliberately
unchanged so its default home bootstrap contract stays intact. **Do not reapply
the patch to the already-installed fc565c7f helper or overwrite the admitted
home helper with the canonical base.** A later helper change requires a newly
reviewed, signed **forward generation 20** admission. After generation 19 was
admitted, restoring generation 18's document or broker state is invalid; preserve
the active replay and operation ledgers. The root-protected copy of the former
public helper/admission/state is evidence for a possible forward repair, not an
instruction to roll the active generation back.
