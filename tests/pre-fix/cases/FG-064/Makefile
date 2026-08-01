SHELL := /bin/sh

.PHONY: run check

SOURCE_REPO ?=

run: check
	@test -n "$(SOURCE_REPO)" || { \
		echo "usage: make run SOURCE_REPO=../../repository" >&2; \
		exit 2; \
	}
	@sh ./run-from-git-blobs.sh "$(SOURCE_REPO)"

check:
	@sh -n run-from-git-blobs.sh
	@node --check backup-tar-option-probe.mjs
	@if grep -Eq 'node:child_process|spawnSync|execSync|execFileSync' backup-tar-option-probe.mjs; then \
		echo "probe contains a child-process primitive" >&2; \
		exit 1; \
	fi
	@if grep -Eq '(^|[;&|[:space:]])tar[[:space:]]' run-from-git-blobs.sh; then \
		echo "wrapper unexpectedly invokes an archive utility" >&2; \
		exit 1; \
	fi
	@if node backup-tar-option-probe.mjs . >/dev/null 2>&1; then \
		echo "unwrapped direct invocation unexpectedly succeeded" >&2; \
		exit 1; \
	else \
		echo "[+] unwrapped direct invocation rejected"; \
	fi
