SHELL := /bin/sh

.PHONY: run check

SOURCE_REPO ?=

run:
	@test -n "$(SOURCE_REPO)" || { echo "SOURCE_REPO must point to the repository containing the pinned revision" >&2; exit 2; }
	@sh ./run-from-git-archive.sh "$(SOURCE_REPO)"

check:
	@sh -n run-from-git-archive.sh
	@node --check hosted-secret-ownership-probe.mjs
