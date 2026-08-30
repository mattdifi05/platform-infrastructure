# Rollback Plan

## Baseline restore point

Private server directory: `/home/platform_infrastructure/remediation-work/20260710T034801Z-t00-baseline`.

It contains the dirty file archive, deleted-file copy, binary patch, ignored runtime overlays, hashes, Compose fingerprint and redacted runtime inventory. Manifest and extraction verification passed before remediation started.

## Code/config rollback

The live checkout is not the development worktree. Revert an affected service to the recorded commit/config/image digest, restore only the touched tracked files from the verified bundle when required, render Compose, and recreate only the affected service.

## Data rollback

No database or volume rollback is permitted from an unverified artifact. Select the exact resource by immutable ID, validate checksum/signature, ownership, engine/version and restore manifest, restore into staging or a replacement resource, verify invariants, then cut over. A live delete always requires separate explicit confirmation.

## Credential rollback

Use dual credentials. Keep the old principal active through functional smoke, retain encrypted historical Vault keys by key ID and revoke only after the new credential and rollback path are verified.

Control Center auth rollback must never republish a fail-open portal. If a
passkey rollout fails, first remove the portal route or restrict it to the
management LAN, then restore the recorded image and control-plane database.
Do not delete the enrolled passkey as part of rollback.

## Network rollback

Keep the previous network attachment until positive and negative connectivity checks pass. Firewall changes require console/out-of-band access and a timed rollback path before apply.
