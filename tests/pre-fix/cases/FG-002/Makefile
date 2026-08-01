SOURCE_ROOT ?=

.PHONY: probe fixed check

probe: check
	@test -n "$(SOURCE_ROOT)" || { echo "SOURCE_ROOT is required" >&2; exit 64; }
	@node admission-probe.mjs --source-root "$(SOURCE_ROOT)" --expect vulnerable

fixed: check
	@test -n "$(SOURCE_ROOT)" || { echo "SOURCE_ROOT is required" >&2; exit 64; }
	@node admission-probe.mjs --source-root "$(SOURCE_ROOT)" --expect fixed

check:
	@node --check admission-probe.mjs
