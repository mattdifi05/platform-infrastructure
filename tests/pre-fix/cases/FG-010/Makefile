REPOSITORY ?=
REVISION ?= 68cd05895b8d479ffb8167344282e7d922958bfc
EXPECT ?= vulnerable

.PHONY: run
run:
	@test -n "$(REPOSITORY)" || { printf '%s\n' 'REPOSITORY=/path/to/platform-infrastructure is required' >&2; exit 2; }
	./run-from-git-archive.sh "$(REPOSITORY)" "$(REVISION)" "$(EXPECT)"
