#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ENV_FILE="$ROOT_DIR/.env"
PROJECT_NAME="${COMPOSE_PROJECT_NAME:-stexor_platform_vps}"
DEPLOY_REPO_VALUE="${DEPLOY_REPO:-}"
DEPLOY_USER="${DEPLOY_USER:-}"
SSH_PORT="${SSH_PORT:-65002}"

PLAN_ONLY=1
RUN_BOOTSTRAP=0
APPLY_HARDENING=0
START_STACK=0
RUN_PRODUCTION_PREFLIGHT=1
RUN_PRE_GO_LIVE=0
RUN_GO_NO_GO=0
RUN_BUNDLE=1
INCLUDE_RESTORE_DRILL=0
INCLUDE_OFFSITE_RESTORE_DRY_RUN=0
VERIFY_GITHUB_REMOTE=0
REPLACE_DOCKER_DAEMON_CONFIG=0
RELOAD_SSHD=0

usage() {
  cat <<'EOF'
Usage: hostinger-go-live.sh [options]

Safe-by-default Hostinger VPS go-live orchestrator. Without --confirmLive it
only writes a plan report. With --confirmLive it runs the selected live steps in
order and writes JSON/Markdown reports under reports/hostinger-go-live/.

Options:
  --confirmLive                         Execute live checks/actions.
  --planOnly                            Write the plan only. This is default.
  --env-file PATH                       Production env file. Default: .env.
  --project-name NAME                   Compose project name.
  --repo OWNER/REPO                     GitHub repository for governance checks.
  --ssh-port PORT                       SSH port for optional host hardening.
  --bootstrap                           Install Git, Docker Engine, Buildx and
                                        Docker Compose plugin before hardening.
  --deploy-user USER                    Optional deploy user for Docker group.
  --apply-hardening                     Run vps-hardening-ubuntu.sh before checks.
  --reload-sshd                         Validate sshd config and reload SSH during
                                        hardening. Use only after key access and
                                        the target SSH port are verified.
  --replace-docker-daemon-config        When applying hardening, back up and
                                        replace an existing Docker daemon config
                                        that is missing Stexor hardening keys.
  --start-stack                         Run docker compose up for Hostinger stack.
  --pre-go-live                         Run pre-go-live evidence during postdeploy.
  --include-restore-drill               Include full restore drill in pre-go-live.
  --include-offsite-restore-dry-run     Include Restic dry-run in pre-go-live.
  --verify-github-remote                Verify live GitHub branch/env/runtime config.
  --go-no-go                            Enforce production go/no-go and live readiness after postdeploy.
  --no-bundle                           Skip evidence bundle creation.
  --full-evidence                       Enable pre-go-live, restore, off-site dry-run,
                                        GitHub remote verification and go/no-go.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --confirmLive)
      PLAN_ONLY=0
      ;;
    --planOnly)
      PLAN_ONLY=1
      ;;
    --env-file)
      ENV_FILE="$2"
      shift
      ;;
    --project-name)
      PROJECT_NAME="$2"
      shift
      ;;
    --repo)
      DEPLOY_REPO_VALUE="$2"
      shift
      ;;
    --ssh-port)
      SSH_PORT="$2"
      shift
      ;;
    --bootstrap)
      RUN_BOOTSTRAP=1
      ;;
    --deploy-user)
      DEPLOY_USER="$2"
      shift
      ;;
    --apply-hardening)
      APPLY_HARDENING=1
      ;;
    --reload-sshd)
      RELOAD_SSHD=1
      ;;
    --replace-docker-daemon-config)
      REPLACE_DOCKER_DAEMON_CONFIG=1
      ;;
    --start-stack)
      START_STACK=1
      ;;
    --pre-go-live)
      RUN_PRE_GO_LIVE=1
      ;;
    --include-restore-drill)
      INCLUDE_RESTORE_DRILL=1
      ;;
    --include-offsite-restore-dry-run)
      INCLUDE_OFFSITE_RESTORE_DRY_RUN=1
      ;;
    --verify-github-remote)
      VERIFY_GITHUB_REMOTE=1
      ;;
    --go-no-go)
      RUN_GO_NO_GO=1
      ;;
    --no-bundle)
      RUN_BUNDLE=0
      ;;
    --full-evidence)
      RUN_PRE_GO_LIVE=1
      RUN_GO_NO_GO=1
      INCLUDE_RESTORE_DRILL=1
      INCLUDE_OFFSITE_RESTORE_DRY_RUN=1
      VERIFY_GITHUB_REMOTE=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

case "$ENV_FILE" in
  /*) ;;
  *) ENV_FILE="$ROOT_DIR/$ENV_FILE" ;;
esac

cd "$ROOT_DIR"

REPORT_DIR="$ROOT_DIR/reports/hostinger-go-live"
mkdir -p "$REPORT_DIR"
STAMP=$(date -u +%Y%m%d%H%M%S)
ROWS_FILE=$(mktemp)
REPORT_PREFIX="hostinger-go-live"
if [ "$PLAN_ONLY" -eq 1 ]; then
  REPORT_PREFIX="hostinger-go-live-plan"
fi
JSON_REPORT="$REPORT_DIR/$REPORT_PREFIX-$STAMP.json"
MD_REPORT="$REPORT_DIR/$REPORT_PREFIX-$STAMP.md"

cleanup() {
  rm -f "$ROWS_FILE"
}
trap cleanup EXIT

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g'
}

add_step() {
  name="$1"
  status="$2"
  command_line="$3"
  detail="$4"
  printf '%s\t%s\t%s\t%s\n' "$name" "$status" "$command_line" "$detail" >> "$ROWS_FILE"
  printf '%s [%s]: %s\n' "$name" "$status" "$detail"
}

write_reports() {
  generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  failed_count=$(awk -F '\t' '$2 == "failed" { count++ } END { print count + 0 }' "$ROWS_FILE")
  passed_count=$(awk -F '\t' '$2 == "passed" { count++ } END { print count + 0 }' "$ROWS_FILE")
  planned_count=$(awk -F '\t' '$2 == "planned" { count++ } END { print count + 0 }' "$ROWS_FILE")
  skipped_count=$(awk -F '\t' '$2 == "skipped" { count++ } END { print count + 0 }' "$ROWS_FILE")
  if [ "$failed_count" -gt 0 ]; then
    status="failed"
  elif [ "$PLAN_ONLY" -eq 1 ]; then
    status="planned"
  else
    status="passed"
  fi

  {
    printf '{\n'
    printf '  "generatedAt": "%s",\n' "$(json_escape "$generated_at")"
    printf '  "status": "%s",\n' "$status"
    printf '  "mode": "%s",\n' "$([ "$PLAN_ONLY" -eq 1 ] && printf plan || printf live)"
    printf '  "envFile": "%s",\n' "$(json_escape "$ENV_FILE")"
    printf '  "projectName": "%s",\n' "$(json_escape "$PROJECT_NAME")"
    printf '  "repo": "%s",\n' "$(json_escape "$DEPLOY_REPO_VALUE")"
    printf '  "options": {\n'
    printf '    "runBootstrap": %s,\n' "$([ "$RUN_BOOTSTRAP" -eq 1 ] && printf true || printf false)"
    printf '    "applyHardening": %s,\n' "$([ "$APPLY_HARDENING" -eq 1 ] && printf true || printf false)"
    printf '    "reloadSshd": %s,\n' "$([ "$RELOAD_SSHD" -eq 1 ] && printf true || printf false)"
    printf '    "replaceDockerDaemonConfig": %s,\n' "$([ "$REPLACE_DOCKER_DAEMON_CONFIG" -eq 1 ] && printf true || printf false)"
    printf '    "startStack": %s,\n' "$([ "$START_STACK" -eq 1 ] && printf true || printf false)"
    printf '    "runProductionPreflight": %s,\n' "$([ "$RUN_PRODUCTION_PREFLIGHT" -eq 1 ] && printf true || printf false)"
    printf '    "runPreGoLive": %s,\n' "$([ "$RUN_PRE_GO_LIVE" -eq 1 ] && printf true || printf false)"
    printf '    "includeRestoreDrill": %s,\n' "$([ "$INCLUDE_RESTORE_DRILL" -eq 1 ] && printf true || printf false)"
    printf '    "includeOffsiteRestoreDryRun": %s,\n' "$([ "$INCLUDE_OFFSITE_RESTORE_DRY_RUN" -eq 1 ] && printf true || printf false)"
    printf '    "verifyGithubRemote": %s,\n' "$([ "$VERIFY_GITHUB_REMOTE" -eq 1 ] && printf true || printf false)"
    printf '    "runGoNoGo": %s,\n' "$([ "$RUN_GO_NO_GO" -eq 1 ] && printf true || printf false)"
    printf '    "runBundle": %s\n' "$([ "$RUN_BUNDLE" -eq 1 ] && printf true || printf false)"
    printf '  },\n'
    printf '  "summary": {\n'
    printf '    "passed": %s,\n' "$passed_count"
    printf '    "planned": %s,\n' "$planned_count"
    printf '    "skipped": %s,\n' "$skipped_count"
    printf '    "failed": %s\n' "$failed_count"
    printf '  },\n'
    printf '  "steps": [\n'
    first=1
    while IFS='	' read -r name step_status command_line detail; do
      [ -n "$name" ] || continue
      if [ "$first" -eq 0 ]; then
        printf ',\n'
      fi
      first=0
      printf '    { "name": "%s", "status": "%s", "command": "%s", "detail": "%s" }' \
        "$(json_escape "$name")" \
        "$(json_escape "$step_status")" \
        "$(json_escape "$command_line")" \
        "$(json_escape "$detail")"
    done < "$ROWS_FILE"
    printf '\n  ]\n'
    printf '}\n'
  } > "$JSON_REPORT"

  {
    printf '# Stexor Hostinger Go-Live\n\n'
    printf 'Generated at: %s\n\n' "$generated_at"
    printf 'Status: %s\n\n' "$status"
    printf 'Mode: %s\n\n' "$([ "$PLAN_ONLY" -eq 1 ] && printf plan || printf live)"
    printf 'Env file: %s\n\n' "$ENV_FILE"
    printf '| Step | Status | Command | Detail |\n'
    printf '| --- | --- | --- | --- |\n'
    while IFS='	' read -r name step_status command_line detail; do
      [ -n "$name" ] || continue
      printf '| %s | %s | `%s` | %s |\n' "$name" "$step_status" "$command_line" "$detail"
    done < "$ROWS_FILE"
  } > "$MD_REPORT"

  echo "Hostinger go-live reports written to $JSON_REPORT and $MD_REPORT"
}

run_step() {
  name="$1"
  command_line="$2"
  function_name="$3"
  if [ "$PLAN_ONLY" -eq 1 ]; then
    add_step "$name" "planned" "$command_line" "not executed; pass --confirmLive on the VPS"
    return
  fi
  if "$function_name"; then
    add_step "$name" "passed" "$command_line" "completed"
  else
    code="$?"
    add_step "$name" "failed" "$command_line" "exit code $code"
    write_reports
    exit "$code"
  fi
}

step_bootstrap() {
  if [ -n "${DEPLOY_USER:-}" ]; then
    sudo sh ./scripts/vps-bootstrap-ubuntu.sh --apply --deploy-user "$DEPLOY_USER"
  else
    sudo sh ./scripts/vps-bootstrap-ubuntu.sh --apply
  fi
}

step_apply_hardening() {
  reload_flag=""
  if [ "$RELOAD_SSHD" -eq 1 ]; then
    reload_flag="--reload-sshd"
  fi
  if [ "$REPLACE_DOCKER_DAEMON_CONFIG" -eq 1 ]; then
    sudo sh ./scripts/vps-hardening-ubuntu.sh --apply --ssh-port "$SSH_PORT" $reload_flag --replace-docker-daemon-config
  else
    sudo sh ./scripts/vps-hardening-ubuntu.sh --apply --ssh-port "$SSH_PORT" $reload_flag
  fi
}

step_vps_readiness() {
  sudo sh ./scripts/vps-host-readiness.sh --ssh-port "$SSH_PORT" --enforce
}

step_hostinger_preflight() {
  sh ./scripts/hostinger-preflight.sh "$ENV_FILE"
}

step_start_stack() {
  docker compose --env-file "$ENV_FILE" -p "$PROJECT_NAME" \
    -f compose.yaml \
    -f compose.build.yaml \
    -f compose.secrets.yaml \
    -f compose.hostinger.yaml \
    -f compose.waf.yaml \
    -f compose.hostinger-waf.yaml \
    up -d --build --remove-orphans
}

step_hostinger_postdeploy() {
  DEPLOY_RUN_WAF_SMOKE=1 \
  DEPLOY_RUN_INFRA_HEALTH=1 \
  DEPLOY_RUN_PRODUCTION_PREFLIGHT="$RUN_PRODUCTION_PREFLIGHT" \
  DEPLOY_RUN_PRE_GO_LIVE="$RUN_PRE_GO_LIVE" \
  DEPLOY_RUN_GO_NO_GO=0 \
  DEPLOY_REPO="$DEPLOY_REPO_VALUE" \
  DEPLOY_PRE_GO_LIVE_PRODUCTION_PREFLIGHT=1 \
  DEPLOY_PRE_GO_LIVE_RESTORE_DRILL="$INCLUDE_RESTORE_DRILL" \
  DEPLOY_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN="$INCLUDE_OFFSITE_RESTORE_DRY_RUN" \
  DEPLOY_PRE_GO_LIVE_GITHUB_REMOTE="$VERIFY_GITHUB_REMOTE" \
    sh ./scripts/hostinger-postdeploy.sh "$ENV_FILE"
}

step_go_no_go() {
  sh ./scripts/production-go-no-go.sh --enforce
}

step_production_readiness_live() {
  sh ./scripts/production-readiness-live.sh
}

step_evidence_bundle() {
  sh ./scripts/evidence-bundle.sh
}

step_evidence_bundle_verify() {
  if [ "$RUN_GO_NO_GO" -eq 1 ]; then
    sh ./scripts/evidence-bundle-verify.sh --requireComplete
  else
    sh ./scripts/evidence-bundle-verify.sh
  fi
}

if [ "$RUN_PRE_GO_LIVE" -eq 1 ] && [ -z "$DEPLOY_REPO_VALUE" ]; then
  echo "Set --repo OWNER/REPO before enabling --pre-go-live or --full-evidence." >&2
  exit 1
fi

if [ "$REPLACE_DOCKER_DAEMON_CONFIG" -eq 1 ] && [ "$APPLY_HARDENING" -ne 1 ]; then
  echo "--replace-docker-daemon-config requires --apply-hardening so the reviewed Docker daemon replacement is actually executed." >&2
  exit 1
fi

if [ "$RELOAD_SSHD" -eq 1 ] && [ "$APPLY_HARDENING" -ne 1 ]; then
  echo "--reload-sshd requires --apply-hardening so the reviewed SSH reload is actually executed." >&2
  exit 1
fi

if [ "$PLAN_ONLY" -eq 0 ] && [ ! -f "$ENV_FILE" ]; then
  echo "Env file not found: $ENV_FILE" >&2
  exit 1
fi

if [ "$RUN_BOOTSTRAP" -eq 1 ]; then
  if [ -n "${DEPLOY_USER:-}" ]; then
    run_step "vps-bootstrap" "sudo sh ./scripts/vps-bootstrap-ubuntu.sh --apply --deploy-user $DEPLOY_USER" step_bootstrap
  else
    run_step "vps-bootstrap" "sudo sh ./scripts/vps-bootstrap-ubuntu.sh --apply" step_bootstrap
  fi
else
  add_step "vps-bootstrap" "skipped" "sudo sh ./scripts/vps-bootstrap-ubuntu.sh --apply" "enable with --bootstrap on a fresh Ubuntu LTS VPS"
fi

if [ "$APPLY_HARDENING" -eq 1 ]; then
  hardening_command="sudo sh ./scripts/vps-hardening-ubuntu.sh --apply --ssh-port $SSH_PORT"
  if [ "$RELOAD_SSHD" -eq 1 ]; then
    hardening_command="$hardening_command --reload-sshd"
  fi
  if [ "$REPLACE_DOCKER_DAEMON_CONFIG" -eq 1 ]; then
    hardening_command="$hardening_command --replace-docker-daemon-config"
  fi
  run_step "vps-hardening" "$hardening_command" step_apply_hardening
else
  add_step "vps-hardening" "skipped" "sudo sh ./scripts/vps-hardening-ubuntu.sh --apply --ssh-port $SSH_PORT" "enable with --apply-hardening after SSH key access is verified"
fi

run_step "vps-host-readiness" "sudo sh ./scripts/vps-host-readiness.sh --ssh-port $SSH_PORT --enforce" step_vps_readiness
run_step "hostinger-preflight" "sh ./scripts/hostinger-preflight.sh $ENV_FILE" step_hostinger_preflight

if [ "$START_STACK" -eq 1 ]; then
  run_step "compose-up" "docker compose --env-file $ENV_FILE -p $PROJECT_NAME -f compose.yaml -f compose.build.yaml -f compose.secrets.yaml -f compose.hostinger.yaml -f compose.waf.yaml -f compose.hostinger-waf.yaml up -d --build --remove-orphans" step_start_stack
else
  add_step "compose-up" "skipped" "docker compose --env-file $ENV_FILE -p $PROJECT_NAME ... up -d --build --remove-orphans" "enable with --start-stack"
fi

run_step "hostinger-postdeploy" "sh ./scripts/hostinger-postdeploy.sh $ENV_FILE" step_hostinger_postdeploy

if [ "$RUN_GO_NO_GO" -eq 1 ]; then
  run_step "production-go-no-go" "sh ./scripts/production-go-no-go.sh --enforce" step_go_no_go
  run_step "production-readiness-live" "sh ./scripts/production-readiness-live.sh" step_production_readiness_live
else
  add_step "production-go-no-go" "skipped" "sh ./scripts/production-go-no-go.sh --enforce" "enable with --go-no-go or --full-evidence"
  add_step "production-readiness-live" "skipped" "sh ./scripts/production-readiness-live.sh" "enable with --go-no-go or --full-evidence"
fi

if [ "$RUN_BUNDLE" -eq 1 ]; then
  run_step "evidence-bundle" "sh ./scripts/evidence-bundle.sh" step_evidence_bundle
  if [ "$RUN_GO_NO_GO" -eq 1 ]; then
    run_step "evidence-bundle-verify" "sh ./scripts/evidence-bundle-verify.sh --requireComplete" step_evidence_bundle_verify
  else
    run_step "evidence-bundle-verify" "sh ./scripts/evidence-bundle-verify.sh" step_evidence_bundle_verify
  fi
else
  add_step "evidence-bundle" "skipped" "sh ./scripts/evidence-bundle.sh" "disabled with --no-bundle"
  add_step "evidence-bundle-verify" "skipped" "sh ./scripts/evidence-bundle-verify.sh" "disabled with --no-bundle"
fi

write_reports

if [ "$PLAN_ONLY" -eq 1 ]; then
  echo "Plan only. Re-run with --confirmLive on the Hostinger VPS when ready."
fi
