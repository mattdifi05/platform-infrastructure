CANDIDATE_ROOT ?=

.PHONY: all vulnerable fixed syntax

all: vulnerable

vulnerable:
	@test -n "$(CANDIDATE_ROOT)" || { echo "CANDIDATE_ROOT is required" >&2; exit 64; }
	node probe.mjs --candidate-root "$(CANDIDATE_ROOT)" --expect vulnerable

fixed:
	@test -n "$(CANDIDATE_ROOT)" || { echo "CANDIDATE_ROOT is required" >&2; exit 64; }
	node probe.mjs --candidate-root "$(CANDIDATE_ROOT)" --expect fixed

syntax:
	node --check probe.mjs
