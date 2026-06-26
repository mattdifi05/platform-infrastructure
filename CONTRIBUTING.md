# Contributing

Thank you for improving Platform Infrastructure.

## Before opening a PR

- Keep the repository infrastructure-only and white-label.
- Do not add application project source code.
- Do not commit `.env`, secrets, reports, backups, dumps, generated SBOMs or evidence bundles.
- Do not run live provider apply actions unless the change explicitly requires it and the maintainer has approved it.
- Update documentation when behavior, scripts or configuration changes.

## License of contributions

By contributing to this repository, you agree that your contribution is licensed under the Apache License, Version 2.0.

## Minimum safe checks

Run the checks that match your change:

```sh
node --check scripts/infra-ops.mjs
node --check control-center/server.mjs
node --check project-router/server.mjs
node --test control-center/tests/control-center.test.mjs
node --test project-router/tests/project-router.test.mjs
sh ./scripts/static-security-check.sh --infraOnly
sh ./scripts/linux-portability-check.sh
git diff --check
```

Do not run destructive Docker commands or provider mutations as part of a normal documentation/code PR.

## Security review

Call out any change that affects:

- secrets
- authentication
- WAF or rate limits
- admin surfaces
- backup/restore
- release evidence
- provider apply behavior

## White-label check

Use neutral examples such as `example.com`, `localhost.com`, `client-portal`, `node-demo`, `php-demo` and `worker-demo`.

## Commit and push

Maintainers may choose their own commit workflow. Automated agents should not commit or push unless explicitly asked.
