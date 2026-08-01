SHELL := /bin/sh

.PHONY: check run

SOURCE_REPO ?=

check:
	@sh -n run-from-git-archive.sh
	@node --check oci-runtime-admission-probe.mjs
	@if node ./oci-runtime-admission-probe.mjs . . . >/dev/null 2>&1; then \
		echo "unwrapped direct invocation unexpectedly succeeded" >&2; \
		exit 1; \
	else \
		echo "[+] unwrapped direct invocation rejected"; \
	fi

run: check
	@test -n "$(SOURCE_REPO)" || { \
		echo "usage: make run SOURCE_REPO=/path/to/platform-infrastructure" >&2; \
		exit 2; \
	}
	@sh ./run-from-git-archive.sh "$(SOURCE_REPO)"
