# Host deployment code

`host/libexec/` and `host/systemd/` contain the current host-side Python, MJS, and shell programs and systemd units exported from the home server. These are the deployed host code paths represented in this repository.

Operator-generated JSON catalogs and configuration pairs are intentionally kept out of this source tree. Runtime secrets, admissions, keys, proofs, and data are also excluded. Reconstruct those values through the operator's reviewed generation and authorization workflow; this repository is not a source for copying credentials or live state.

The systemd units preserve absolute paths and service assumptions from the current home-server installation. Treat them as installation snapshots: configure paths, identities, dependencies, and credentials for a new VPS before installing or enabling units. A future VPS with no applications, a new VPN, and a new Cloudflare domain has not been deployed or validated by these files.

The current backup policy has generation-18 readers, a four-hour cadence, a Monday/Wednesday/Friday 70 GB schedule, and 14-day native retention. These are concise policy parameters for operator review, not proof that a new full backup has completed or can be restored. Verify the generated catalogs, schedule state, and restore evidence independently on the target host.

## Pinned historical configuration assets

The G17/G18 namespace catalogs, source maps, mount plans and pins are included as historical infrastructure contracts. They preserve the validated canonical Scripta Redis startup binding and the generation-18 source count; they are not a default workload configuration for a new VPS. Their digests must remain consistent with the matching readers. Install operational catalogs with the root-private permissions required by those readers.

The signed `g16-historical-parent-manifest.json`, the application-derived `stream-expired-cache-descriptor-actual.json`, live admissions, replay ledgers and host `paths.json` remain private runtime inputs. Existing native readers refer to them; provision them from the operator-controlled backup configuration rather than inventing replacements or downloading user data from GitHub.
