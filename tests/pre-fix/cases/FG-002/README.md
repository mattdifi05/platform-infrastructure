# Synthetic `volumes_from` admission probe

This probe exercises the two vulnerable validation layers with in-memory
configuration objects. It does not invoke Docker, start containers, connect to
a socket, or read a real volume. The only required input is a source checkout
containing the two validator modules.

From this `poc` directory, run it against the adjacent frozen checkout:

```sh
make check
node admission-probe.mjs --source-root ../../repository --expect vulnerable
```

To test another checkout, provide its relative path:

```sh
node admission-probe.mjs --source-root ../../path/to/platform-infrastructure --expect vulnerable
```

After applying the remediation to both validation layers, use:

```sh
node admission-probe.mjs --source-root ../../path/to/platform-infrastructure --expect fixed
```

The vulnerable expectation succeeds only when all 12 exact inherited-mount
instances pass both admission and the runtime countercheck. The fixed
expectation succeeds only when both layers reject all 12. A `PARTIAL` result
means only one layer rejected the primitive and the defense-in-depth fix is
incomplete.

No cleanup is required; the probe creates no files or runtime resources.
