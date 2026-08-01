# Hosted workload physical-volume alias probe

This probe exercises `validateRenderedWorkloads` with eight synthetic foreign
physical-volume aliases. It does not invoke Docker or Compose, create or mount a
volume, access a network, or read data.

Requirements:

- Node.js 20 or newer;
- a source checkout containing `scripts/hosted-workload-contract.mjs`.

Run against a vulnerable checkout:

```sh
make run CONTRACT=../../repository/scripts/hosted-workload-contract.mjs
```

Run the same corpus as a post-fix negative test:

```sh
make fixed CONTRACT=../../fixed-repository/scripts/hosted-workload-contract.mjs
```

The probe first confirms that a direct bind mount is rejected. In vulnerable
mode it then requires all eight external physical aliases to be accepted. In
fixed mode it requires all eight to be rejected. Any mixed result exits
non-zero. The probe creates no files, so no cleanup is required.
