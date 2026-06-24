#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$SCRIPT_DIR/stexor-ops.sh" enterprise-requirements-check --manifest governance/production-readiness.json --requireLiveProofs "$@"
