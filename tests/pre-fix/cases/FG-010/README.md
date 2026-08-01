# Release admission provenance and SBOM binding PoC

This probe runs the affected release-artifact gate with three synthetic release
evidence sets. It demonstrates separately that the default gate accepts no
cryptographic provenance and that changing a plausible SBOM to unrelated or
wrong-subject JSON does not change the admission result.

The wrapper imports source only from a clean `git archive` of the requested
revision. All generated reports stay inside that disposable archive, which is
deleted on exit. The probe does not invoke Docker, contact GitHub or another
provider, pull an image, deploy software, or make network requests.

Requirements: Git, tar, Make, and Node.js 20 or newer.

Run from this directory:

```sh
make run REPOSITORY=/path/to/platform-infrastructure
```

The default revision is the affected commit
`68cd05895b8d479ffb8167344282e7d922958bfc`, with `EXPECT=vulnerable`.
The harness checks source-file SHA-256 digests before executing the gate.

For a coarse post-fix regression check:

```sh
make run \
  REPOSITORY=/path/to/platform-infrastructure \
  REVISION=<fixed-revision> \
  EXPECT=fixed
```

The fixed expectation requires every unproven evidence set to be rejected. A
project test should additionally supply a valid cryptographic attestation and
then vary only the SBOM schema, release commit, and image subjects, because a
safe standalone PoC cannot manufacture trusted provider provenance.
