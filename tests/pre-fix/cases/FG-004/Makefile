SOURCE_ROOT ?=
REVISION ?= 68cd05895b8d479ffb8167344282e7d922958bfc
EXPECT ?= vulnerable

.PHONY: run
run:
	@test -n "$(SOURCE_ROOT)" || { echo "SOURCE_ROOT is required" >&2; exit 64; }
	node authorization-route-probe.mjs --source-root "$(SOURCE_ROOT)" --revision "$(REVISION)" --expect "$(EXPECT)"
