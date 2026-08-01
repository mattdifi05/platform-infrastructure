REPOSITORY ?=
REVISION ?= 68cd05895b8d479ffb8167344282e7d922958bfc

.PHONY: run
run:
	@test -n "$(REPOSITORY)" || { \
		echo "usage: make REPOSITORY=/path/to/platform-infrastructure [REVISION=$(REVISION)]" >&2; \
		exit 2; \
	}
	./run-from-git-archive.sh "$(REPOSITORY)" "$(REVISION)"

