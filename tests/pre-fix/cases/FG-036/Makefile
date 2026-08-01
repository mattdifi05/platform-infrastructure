SHELL := /bin/sh

.PHONY: run check

SOURCE_REPO ?=

run: check
	@test -n "$(SOURCE_REPO)" || { \
		echo "usage: make run SOURCE_REPO=../../repository" >&2; \
		exit 2; \
	}
	@sh ./run-from-git-archive.sh "$(SOURCE_REPO)"

check:
	@sh -n run-from-git-archive.sh
	@node --check backup-signing-tofu-probe.mjs
	@if node backup-signing-tofu-probe.mjs . >/dev/null 2>&1; then \
		echo "unwrapped direct invocation unexpectedly succeeded" >&2; \
		exit 1; \
	else \
		echo "[+] unwrapped direct invocation rejected"; \
	fi
