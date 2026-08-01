.PHONY: check guard run fixed

check:
	node --check volume-alias-probe.mjs

guard:
	@test -n "$(CONTRACT)" || { \
		echo "Set CONTRACT to a relative path to scripts/hosted-workload-contract.mjs" >&2; \
		exit 2; \
	}

run: check guard
	node volume-alias-probe.mjs --contract "$(CONTRACT)" --expect vulnerable

fixed: check guard
	node volume-alias-probe.mjs --contract "$(CONTRACT)" --expect fixed
