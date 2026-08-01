.PHONY: check guard run

check:
	node --check oidc-internal-tls-probe.mjs
	sh -n run-archive.sh

guard:
	@test -n "$(REPO)" || { \
		echo "Set REPO to a relative path to the Git repository" >&2; \
		exit 2; \
	}

run: check guard
	sh ./run-archive.sh "$(REPO)"
