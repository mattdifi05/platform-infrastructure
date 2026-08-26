#!/usr/bin/env bash
# Greenfield workload image builder.
#
# Builds greenfield application images from EXACT-MAIN bytes (git archive of
# HEAD) so no secrets, no mutable state, and no local edits can enter image
# layers.
#
# Subcommands:
#   build-context <commit> <destDir>   Extract exact-main build context.
#   audit-context <destDir>            Fail-closed scan for forbidden material.
#   build-image <contextDir> <df> <tag>  Docker build (runner only).
#   plan                               Print planned builds as JSON (no builds).
#
# Exit codes:
#   0  success
#   2  usage / missing input
#   3  refused: worktree dirty, commit is not HEAD, or destination not empty
#   4  audit-context found forbidden material
#   5  refused: ROOT_DIR repository is dirty (audit/build-image guard)
#  78  docker unavailable: image build must run on the CI runner
set -euo pipefail

ROOT_DIR="${GREENFIELD_WORKLOAD_BUILDER_ROOT:-}"
if [ -z "$ROOT_DIR" ]; then
  ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fi

err() {
  printf 'greenfield-workload-builder: %s\n' "$*" >&2
}

usage() {
  cat >&2 <<'EOF'
usage:
  greenfield-workload-builder.sh build-context <commit> <destDir>
  greenfield-workload-builder.sh audit-context <destDir>
  greenfield-workload-builder.sh build-image <contextDir> <dockerfile> <tag>
  greenfield-workload-builder.sh plan
EOF
}

# True when the ROOT_DIR worktree has any modification, staging entry, or
# untracked file.
repo_is_dirty() {
  [ -n "$(git -C "$ROOT_DIR" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)" ]
}

# Guard for subcommands that consume or produce artifacts beyond the archive:
# they may only run against a clean checkout so evidence stays attributable.
require_clean_repo() {
  if repo_is_dirty; then
    err "ROOT_DIR worktree is dirty; refusing to run '$1' (exit 5)"
    exit 5
  fi
}

# Resolve the requested commit and require it to be the current HEAD so the
# archived bytes are always exact-main bytes.
resolve_head_commit() {
  commit=$1
  resolved=$(git -C "$ROOT_DIR" rev-parse --verify --quiet "${commit}^{commit}" 2>/dev/null || true)
  if [ -z "$resolved" ]; then
    err "unknown commit: $commit"
    exit 3
  fi
  head_sha=$(git -C "$ROOT_DIR" rev-parse HEAD)
  if [ "$resolved" != "$head_sha" ]; then
    err "commit $resolved ($commit) is not current HEAD $head_sha; refusing non-exact-main archive"
    exit 3
  fi
  printf '%s\n' "$resolved"
}

add_finding() {
  findings="${findings}${1}: ${2}"$'\n'
}

scan_findings() {
  ctx=$1
  findings=""

  # secrets/: only secrets/README.md is allowed.
  if [ -d "$ctx/secrets" ]; then
    while IFS= read -r path; do
      [ -z "$path" ] && continue
      add_finding "${path#$ctx/}" "forbidden secrets/ entry (only secrets/README.md allowed)"
    done <<EOF
$(find "$ctx/secrets" -mindepth 1 ! -path "$ctx/secrets/README.md" -print)
EOF
  fi

  # .env* files except example templates (.env.example, .env.*.example).
  while IFS= read -r path; do
      [ -z "$path" ] && continue
    add_finding "${path#$ctx/}" "forbidden environment file (.env*)"
  done <<EOF
$(find "$ctx" -type f -name '.env*' ! -name '.env.example' ! -name '.env.*.example' -print)
EOF

  # Secret-manager master keys.
  while IFS= read -r path; do
      [ -z "$path" ] && continue
    add_finding "${path#$ctx/}" "forbidden infra-secret-manager-master.key* entry"
  done <<EOF
$(find "$ctx" -name 'infra-secret-manager-master.key*' -print)
EOF

  # Any pem under traefik/certs/.
  if [ -d "$ctx/traefik/certs" ]; then
    while IFS= read -r path; do
      [ -z "$path" ] && continue
      add_finding "${path#$ctx/}" "forbidden certificate material (.pem)"
    done <<EOF
$(find "$ctx/traefik/certs" -name '*.pem' -print)
EOF
  fi

  # projects-portal/state/: mutable state, only .gitkeep allowed.
  if [ -d "$ctx/projects-portal/state" ]; then
    while IFS= read -r path; do
      [ -z "$path" ] && continue
      add_finding "${path#$ctx/}" "forbidden mutable state entry (projects-portal/state/)"
    done <<EOF
$(find "$ctx/projects-portal/state" -mindepth 1 ! -name '.gitkeep' -print)
EOF
  fi

  # backups/ directory presence.
  if [ -d "$ctx/backups" ]; then
    add_finding "backups/" "forbidden backups/ directory present"
  fi

  # Symlinks, FIFOs, and device nodes must never enter image layers.
  while IFS= read -r path; do
      [ -z "$path" ] && continue
    add_finding "${path#$ctx/}" "forbidden symlink entry"
  done <<EOF
$(find "$ctx" -type l -print)
EOF
  while IFS= read -r path; do
      [ -z "$path" ] && continue
    add_finding "${path#$ctx/}" "forbidden fifo entry"
  done <<EOF
$(find "$ctx" -type p -print)
EOF
  while IFS= read -r path; do
      [ -z "$path" ] && continue
    add_finding "${path#$ctx/}" "forbidden device entry"
  done <<EOF
$(find "$ctx" \( -type b -o -type c \) -print)
EOF
}

cmd_build_context() {
  if [ "$#" -ne 2 ]; then
    usage
    exit 2
  fi
  commit=$1
  dest_dir=$2

  if repo_is_dirty; then
    err "worktree is not clean (git status --porcelain=v1 --untracked-files=all); refusing to archive (exit 3)"
    exit 3
  fi

  resolved=$(resolve_head_commit "$commit")

  if [ -e "$dest_dir" ] && [ -n "$(ls -A "$dest_dir" 2>/dev/null || true)" ]; then
    err "destination exists and is not empty: $dest_dir"
    exit 3
  fi
  mkdir -p "$dest_dir"

  git -C "$ROOT_DIR" archive --format=tar "$resolved" | tar -x -C "$dest_dir"
}

cmd_audit_context() {
  if [ "$#" -ne 1 ]; then
    usage
    exit 2
  fi
  ctx=$1
  require_clean_repo "audit-context"

  if [ ! -d "$ctx" ]; then
    err "context directory does not exist: $ctx"
    exit 2
  fi

  scan_findings "$ctx"

  if [ -n "$findings" ]; then
    printf '%s' "$findings"
    err "$(printf '%s' "$findings" | grep -c ':') finding(s); failing closed (exit 4)"
    exit 4
  fi
}

cmd_build_image() {
  if [ "$#" -ne 3 ]; then
    usage
    exit 2
  fi
  ctx=$1
  dockerfile=$2
  tag=$3
  require_clean_repo "build-image"

  if [ ! -d "$ctx" ]; then
    err "context directory does not exist: $ctx"
    exit 2
  fi
  if [ ! -f "$dockerfile" ]; then
    err "dockerfile does not exist: $dockerfile"
    exit 2
  fi

  if ! command -v docker >/dev/null 2>&1; then
    err "docker unavailable: image build must run on the CI runner"
    exit 78
  fi

  # Local tags are exempt from the supply-chain digest lock; never forward
  # --build-arg (and therefore never secrets) into the build.
  iid_base=$(printf '%s' "$tag" | tr '/:' '__')
  iid_file="$(CDPATH= cd -- "$(dirname -- "$ctx")" && pwd)/${iid_base}.iid"

  docker build --iidfile "$iid_file" -f "$dockerfile" "$ctx" >/dev/null
  image_id=$(cat "$iid_file")
  printf '%s\n' "$image_id"
}

cmd_plan() {
  if [ "$#" -ne 0 ]; then
    usage
    exit 2
  fi
  printf '[\n'
  first=1
  for name in alert-dispatcher backup-scheduler control-center docker-action-broker ops php-apache project-router restic-rclone; do
    if [ "$first" -eq 0 ]; then
      printf ',\n'
    fi
    first=0
    printf '  {"name": "%s", "dockerfile": "docker/%s.Dockerfile", "image": "platform/greenfield-%s:local"}' \
      "$name" "$name" "$name"
  done
  printf '\n]\n'
}

main() {
  if [ "$#" -lt 1 ]; then
    usage
    exit 2
  fi
  subcommand=$1
  shift
  case "$subcommand" in
    build-context) cmd_build_context "$@" ;;
    audit-context) cmd_audit_context "$@" ;;
    build-image)   cmd_build_image "$@" ;;
    plan)          cmd_plan "$@" ;;
    *)
      err "unknown subcommand: $subcommand"
      usage
      exit 2
      ;;
  esac
}

main "$@"
