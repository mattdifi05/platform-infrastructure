SHELL := /bin/sh

.PHONY: check run

SOURCE_REPO ?=

check:
	@sh -n run-from-git-archive.sh
	@node --check redis-workload-authorization-probe.mjs

run:
	@test -n "$(SOURCE_REPO)" || { \
		echo "usage: make run SOURCE_REPO=/path/to/platform-infrastructure" >&2; \
		exit 2; \
	}
	@sh ./run-from-git-archive.sh "$(SOURCE_REPO)"
