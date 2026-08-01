SHELL := /bin/sh

SOURCE_REPO ?=

.PHONY: run check

run: check
	@test -n "$(SOURCE_REPO)" || { \
		echo "usage: make run SOURCE_REPO=/path/to/platform-infrastructure" >&2; \
		exit 2; \
	}
	@sh ./run-from-git-archive.sh "$(SOURCE_REPO)"

check:
	@sh -n run-from-git-archive.sh
	@node --check privileged-job-queue-backpressure-probe.mjs
	@if env -i PATH="$$PATH" HOME=/nonexistent LANG=C LC_ALL=C NODE_OPTIONS= \
		node privileged-job-queue-backpressure-probe.mjs . . >/dev/null 2>&1; then \
		echo "unwrapped direct invocation unexpectedly succeeded" >&2; \
		exit 1; \
	else \
		echo "[+] unwrapped direct invocation rejected"; \
	fi
