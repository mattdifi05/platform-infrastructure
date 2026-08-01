SHELL := /bin/sh

.PHONY: run check

SOURCE_REPO ?=

run:
	@test -n "$(SOURCE_REPO)" || { \
		echo "usage: make run SOURCE_REPO=/path/to/platform-infrastructure" >&2; \
		exit 2; \
	}
	@sh ./run-from-git-archive.sh "$(SOURCE_REPO)"

check:
	@sh -n run-from-git-archive.sh
	@node --check cloudflare-access-policy-exactness-probe.mjs
	@node -e 'JSON.parse(require("fs").readFileSync("fixtures/synthetic-provider-cases.json", "utf8"))'
