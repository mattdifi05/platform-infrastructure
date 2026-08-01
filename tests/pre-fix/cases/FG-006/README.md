# OIDC internal-TLS offline source-model probe

This migrated FG-006 seed verifies the exact vulnerable OIDC source blob and
evaluates its pinned `requiredUrl` and `requiredHttpsUrl` functions in an
isolated VM. It proves that the token endpoint and JWKS URI use the generic
HTTP-or-HTTPS control while issuer and redirect URI use the HTTPS-only control.

The probe does not install packages, open a listener, perform a fetch, use a
network, read a secret, start a service, or inspect live state. Its evidence is
explicitly `offline-source-model`; it is not a deployed-runtime reproduction.

Run it through the exact detached baseline:

```sh
make run REPO=/path/to/local/repository-containing-the-baseline
```

The wrapper verifies commit `68cd05895b8d479ffb8167344282e7d922958bfc`
and tree `70031b30316fbaecbb23249491d6ff4e364d65d5`, exports only
`control-center/auth/oidc.mjs` into wrapper-owned temporary storage, and removes
that storage on exit.
