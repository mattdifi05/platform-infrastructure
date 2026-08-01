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
	@node --check project-route-owner-binding-probe.mjs
	@node -e 'const fs=require("fs"); for (const name of fs.readdirSync("fixtures")) JSON.parse(fs.readFileSync(`fixtures/$${name}`, "utf8"))'
