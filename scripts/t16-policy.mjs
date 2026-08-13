#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const checks = [];

function read(relative) {
  return fs.readFileSync(path.join(root, relative), "utf8");
}

function record(name, passed, detail) {
  checks.push({ name, passed: Boolean(passed), detail });
}

function includes(text, value) {
  return text.includes(value);
}

const trustPolicy = JSON.parse(read("governance/release-trust.json"));
const branchPolicy = JSON.parse(read("governance/github-branch-protection.json"));
const environments = JSON.parse(read("governance/github-environments.json"));
const trustModule = read("scripts/release-trust.mjs");
const governanceModule = read("scripts/github-governance-policy.mjs");
const ops = read("scripts/infra-ops.mjs");
const opsWrapper = read("scripts/infra-ops.sh");
const opsDockerfile = read("docker/ops.Dockerfile");
const releaseWorkflow = read(".github/workflows/release-attestation.yml");
const vpsWorkflow = read(".github/workflows/enterprise-vps-evidence.yml");
const vpsRemote = read("scripts/vps-evidence-remote.sh");
const deployVps = read("scripts/deploy-vps.sh");
const deployVpsRemote = read("scripts/deploy-vps-remote.sh");
const v1InstallWorkflow = read(".github/workflows/v1-install-only.yml");
const readme = read("README.md");
const runbook = read("RUNBOOK.md");
const releaseTrustDoc = read("RELEASE-TRUST-AND-WORKFLOW-SECURITY.md");

record("trust-provider", trustPolicy.provider === "github-artifact-attestations", "GitHub Artifact Attestations is the configured provider");
record("trust-predicate", trustPolicy.predicate_type === "https://slsa.dev/provenance/v1", "SLSA provenance v1 is exact");
record("trust-issuer", trustPolicy.cert_oidc_issuer === "https://token.actions.githubusercontent.com", "GitHub Actions OIDC issuer is exact");
record("trust-no-self-hosted", trustPolicy.deny_self_hosted_runners === true, "self-hosted signing runners are denied");
record("trust-timestamp", trustPolicy.require_verified_timestamp === true, "verified timestamp is required");
record("trust-no-unsigned", trustPolicy.accept_unsigned_local_provenance === false, "unsigned local provenance is rejected");
record("trust-no-normalized-report", trustPolicy.accept_normalized_verification_reports === false, "normalized JSON is not a trust input");

for (const flag of [
  "--repo",
  "--signer-workflow",
  "--source-digest",
  "--signer-digest",
  "--source-ref",
  "--cert-oidc-issuer",
  "--predicate-type",
  "--deny-self-hosted-runners",
  "--format",
]) {
  record(`verifier-flag-${flag.slice(2)}`, includes(trustModule, `"${flag}"`), `cryptographic verifier enforces ${flag}`);
}
record(
  "verifier-fixed-binary",
  /export function verifyGithubAttestation\(options,\s*\{\s*verifierBinary = "\/usr\/local\/bin\/gh"\s*\} = \{\}\)/.test(trustModule)
    && /spawnSync\(verifierBinary,\s*args,/.test(trustModule)
    && !/GITHUB_CLI_BIN|PLATFORM_RELEASE_TRUST_TEST_MODE/.test(trustModule),
  "production verification defaults to the image-owned binary and exposes no environment-controlled override",
);
record("verifier-certificate", includes(trustModule, "verification.signature?.certificate"), "verified certificate is required");
record("verifier-transparency", includes(trustModule, "verification.verifiedTimestamps"), "transparency/timestamp witness is required");
record("verifier-no-self-assertion", includes(trustModule, "self-asserted reports are not accepted"), "legacy verified booleans are rejected");
record("verifier-subject-digest", includes(trustModule, "does not cover expected subject"), "subject digest must match");
const exactOfflineTrustMode = includes(trustModule, "(!bundle && (trustedRoot || useGithubPublicGoodRoot))")
  && includes(trustModule, "(bundle && !trustedRoot && !useGithubPublicGoodRoot)")
  && includes(trustModule, "(trustedRoot && useGithubPublicGoodRoot)")
  && includes(trustModule, "bundle plus exactly one explicit trust mode: custom trusted root or GitHub public-good roots")
  && includes(trustModule, 'args.push("--bundle", existingFile(bundle, "attestation bundle"))')
  && includes(trustModule, 'args.push("--custom-trusted-root", existingFile(trustedRoot, "trusted root"))');
record("verifier-offline-pair", exactOfflineTrustMode, "offline bundle requires exactly one fail-closed trust mode: custom root or GitHub public-good roots");

record("ops-rejects-local-json", includes(ops, "Unsigned local SLSA JSON is not admissible"), "release gate rejects loose SLSA JSON");
record("ops-rejects-normalized-json", includes(ops, "Normalized GitHub attestation reports are not trust inputs"), "release gate rejects normalized reports");
record("ops-direct-verifier", includes(ops, "verifyGithubReleaseImages"), "release gate invokes cryptographic verification");
record("ops-no-legacy-validator", !includes(ops, "function validateSlsaProvenance") && !includes(ops, "function validateGithubSigstoreAttestation"), "self-asserted validators are removed");
const envForwardingLoop = opsWrapper.match(
  /for name in \\\n[\s\S]*?\n\s*do\n\s+set -- -e "\$name" "\$@"\n\s*done/,
)?.[0] ?? "";
record(
  "ops-forwards-source-ref",
  /\bGITHUB_REF\b/.test(envForwardingLoop)
    && /set -- -e "\$name" "\$@"/.test(envForwardingLoop)
    && /set -- "\$OPS_IMAGE_ID" "\$@"/.test(opsWrapper)
    && /docker run[\s\S]*?"\$@"/.test(opsWrapper),
  "ops container forwards the exact source ref through the bounded environment allowlist",
);

record("gh-version-pinned", /ARG GH_VERSION=2\.93\.0/.test(opsDockerfile), "GitHub CLI version is fixed");
record("gh-checksum-pinned", /ARG GH_SHA256=[a-f0-9]{64}/.test(opsDockerfile), "GitHub CLI archive checksum is fixed");
record("gh-download-verified", includes(opsDockerfile, "sha256sum -c -"), "GitHub CLI bytes are verified before install");

record("release-default-deny-permissions", /^permissions: \{\}$/m.test(releaseWorkflow), "release workflow defaults permissions to none");
for (const permission of ["contents: read", "id-token: write", "attestations: write", "packages: write"]) {
  record(`release-permission-${permission.replace(/[: ]/g, "-")}`, includes(releaseWorkflow, permission), `${permission} is explicit on the signing job`);
}
record("release-direct-evidence", includes(releaseWorkflow, "Cryptographically verify and record attestations"), "workflow invokes the verifier-backed evidence command");
record("release-exact-signer", includes(releaseWorkflow, '--signerWorkflow "${GITHUB_REPOSITORY}/.github/workflows/release-attestation.yml"'), "signer workflow path is exact");
record("release-source-digest", includes(releaseWorkflow, '--sourceDigest "${GITHUB_SHA}"'), "release commit is bound");
record("release-source-ref", includes(releaseWorkflow, '--sourceRef "${GITHUB_REF}"'), "release ref is bound");
record("release-no-fake-verified", !includes(releaseWorkflow, "verified: true") && !includes(releaseWorkflow, "--verification"), "workflow cannot mint a normalized verified report");

record("vps-request-generator", includes(vpsWorkflow, "vps-evidence-request.mjs render"), "VPS request is validated and encoded");
record("vps-fixed-remote-command", includes(vpsWorkflow, "'$DEPLOY_REMOTE' 'bash -s'") || includes(vpsWorkflow, '"$DEPLOY_REMOTE" \'bash -s\''), "remote shell command is fixed");
record("vps-no-remote-argv", !includes(vpsWorkflow, "bash -s --"), "workflow inputs are absent from SSH remote argv");
record("vps-array-arguments", includes(vpsRemote, 'bootstrap_args+=(--deploy-user "$deploy_user")') && includes(vpsRemote, '"${hardening_args[@]}"'), "remote mutating scripts use arrays");
const vpsWorkflowStop = vpsWorkflow.indexOf("      - name: V1 brownfield existing-host admission stop");
const vpsWorkflowNextStep = vpsWorkflow.indexOf("      - name: Install SSH key");
const vpsWorkflowSsh = vpsWorkflow.indexOf('ssh -F /dev/null -i "$ssh_key_snapshot"');
const vpsWorkflowStopStep = vpsWorkflow.slice(vpsWorkflowStop, vpsWorkflowNextStep);
record(
  "vps-v1-stop-before-ssh",
  vpsWorkflowStop >= 0
    && vpsWorkflowNextStep > vpsWorkflowStop
    && /run: \|\n\s+echo .*V1 brownfield existing-host path is STOP.*\n\s+exit 78\s*$/.test(vpsWorkflowStopStep)
    && !/\bif:|continue-on-error|\$\{\{/.test(vpsWorkflowStopStep)
    && vpsWorkflowSsh > vpsWorkflowStop,
  "V1 brownfield workflow stops unconditionally with exit 78 before SSH",
);
const vpsRemoteStop = vpsRemote.indexOf("V1 brownfield existing-host path is STOP");
const vpsRemoteExit = vpsRemote.indexOf("exit 78", vpsRemoteStop);
const vpsRemotePrelude = vpsRemote.slice(0, vpsRemote.indexOf("decode_field()"));
const vpsRemoteFirstMutation = Math.min(
  vpsRemote.indexOf('git -C "$remote_dir" fetch'),
  vpsRemote.indexOf("sudo sh ./scripts/vps-bootstrap-ubuntu.sh"),
  vpsRemote.indexOf("sudo sh ./scripts/vps-hardening-ubuntu.sh"),
);
record(
  "vps-v1-remote-stop-before-mutation",
  vpsRemoteStop >= 0
    && vpsRemoteExit > vpsRemoteStop
    && vpsRemoteExit < vpsRemoteFirstMutation
    && /^#!\/usr\/bin\/env bash\nset -euo pipefail\n\necho "V1 brownfield existing-host path is STOP:[^\n]+" >&2\nexit 78\n\n$/.test(vpsRemotePrelude),
  "V1 remote collector stops with exit 78 before git, bootstrap, hardening or evidence output",
);
record("deploy-vps-fixed-command", includes(deployVps, 'ssh "$@" -- "$REMOTE" \'/usr/bin/sudo -n -- /usr/local/libexec/platform-activation-broker activate\''), "production deploy uses the absolute root-owned activation broker command");
record(
  "deploy-vps-canonical-request",
  includes(deployVps, 'node "$SCRIPT_ROOT/activation-request.mjs"')
    && includes(deployVps, '< "$request" > "$receipt"')
    && !includes(deployVps, "base64"),
  "production deploy sends only the bounded canonical activation request on stdin",
);
record("deploy-vps-no-remote-argv", !includes(deployVps, "sh -s --") && !includes(deployVps, "REMOTE_SCRIPT"), "production deploy has no dynamic SSH argv or heredoc interpolation");
const boundedInstallOnlyShim = [
  "CONSUMER=/usr/local/libexec/platform-v1-brownfield-install-consumer",
  "SUDO=/usr/bin/sudo",
  'SYSTEM_NAME=$(/usr/bin/uname -s)',
  "/bin/dd if=/dev/stdin bs=1 count=1",
  '[ "$stdin_bytes" = 0 ]',
  'exec "$SUDO" -n -- "$CONSUMER" install < /dev/null',
].every((needle) => includes(deployVpsRemote, needle))
  && /if \[ "\$SYSTEM_NAME" != Linux \]; then[\s\S]*SUDO=\$\{PLATFORM_V1_INSTALL_TEST_SUDO:-\$SUDO\}[\s\S]*fi/.test(deployVpsRemote);
record(
  "deploy-vps-remote-revalidation",
  boundedInstallOnlyShim
    && includes(deployVps, 'node "$SCRIPT_ROOT/activation-receipt-policy.mjs"')
    && !/platform-activation-broker|decode_field|candidate_release_root|--extractedRoot|--archive|git checkout|PLATFORM_BRANCH_B64/.test(deployVpsRemote),
  "remote compatibility sink accepts only empty stdin and invokes the fixed root install-only consumer",
);
const v1InstallSinks = v1InstallWorkflow.match(/^\s+sh \.\/scripts\/deploy-v1-install-only\.sh > "\$receipt"\s*$/gm) ?? [];
record(
  "v1-install-only-workflow-boundary",
  v1InstallSinks.length === 1
    && includes(v1InstallWorkflow, "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.ref_protected == true")
    && includes(v1InstallWorkflow, "group: infra-production-deploy")
    && includes(v1InstallWorkflow, "name: production")
    && includes(v1InstallWorkflow, 'test "$APPROVED_CANDIDATE_SHA" = 832bf2baec47055342af7e7f73425444381b91e0')
    && includes(v1InstallWorkflow, 'test "$APPROVED_CONTROLLER_SHA" = "$GITHUB_SHA"')
    && includes(v1InstallWorkflow, "node ./scripts/v1-brownfield-install-receipt.mjs verify")
    && !/\bdocker\b|platform-activation-broker|release-admission|dast-zap|sigstore|promoter|activation-request/i.test(v1InstallWorkflow),
  "manual protected-main install-only uses one fixed client, shared production serialization and no activation or Docker path",
);

record("branch-strict", branchPolicy.required_status_checks?.strict === true, "status checks require the latest branch state");
record("branch-admins", branchPolicy.enforce_admins === true, "admins cannot bypass protection");
record("branch-last-push", branchPolicy.required_pull_request_reviews?.require_last_push_approval === true, "last pusher cannot satisfy approval alone");
record("branch-no-bypass", ["users", "teams", "apps"].every((key) => branchPolicy.required_pull_request_reviews?.bypass_pull_request_allowances?.[key]?.length === 0), "review bypass allowlists are empty");
record(
  "branch-exact-verifier",
  includes(governanceModule, "required status check producer bindings differ")
    && includes(governanceModule, "exact empty contexts array")
    && includes(governanceModule, "applyAndVerifyBranchProtection"),
  "branch verifier compares exact producer-bound state and requires fresh post-apply readback",
);
record("github-repository-normalized", includes(ops, "return normalizeRepository(repo)") && includes(ops, "githubRepoApiPath(repo)"), "GitHub API repository path uses strict owner/name normalization");

const production = environments.environments?.find((environment) => environment.name === "production");
record("environment-exact-reviewer", production?.reviewers?.length > 0 && production.reviewers.every((reviewer) => Number.isInteger(reviewer.id)), "production reviewer IDs are explicit");
record("environment-self-review", production?.prevent_self_review === true, "production self-review is denied");
record("environment-exact-verifier", includes(governanceModule, "reviewer identities differ"), "environment verifier rejects wrong or additional reviewers");
record("environment-no-dynamic-reviewer", !includes(JSON.stringify(environments), "required_reviewers_env"), "reviewer identity is not supplied by mutable process env");
const obsoleteReleaseCommands = `${readme}\n${runbook}`.split(/\r?\n/).filter((line) => line.includes("release-evidence") && (line.includes("--githubAttestation") || line.includes("--provenance ")));
record("docs-no-obsolete-release-command", obsoleteReleaseCommands.length === 0, obsoleteReleaseCommands.length ? obsoleteReleaseCommands.join(" | ") : "runbooks invoke direct cryptographic verification");
record("docs-trust-boundary", includes(releaseTrustDoc, "audit receipt, not a trust input") && includes(releaseTrustDoc, "exact signer workflow path"), "release trust boundary is explicit");

const workflowFiles = fs.readdirSync(path.join(root, ".github", "workflows")).filter((file) => file.endsWith(".yml"));
for (const file of workflowFiles) {
  const source = read(path.join(".github", "workflows", file));
  const mutableUses = [...source.matchAll(/uses:\s*[^\s@]+@([^\s#]+)/g)].map((match) => match[1]).filter((ref) => !/^[a-f0-9]{40}$/.test(ref));
  record(`action-sha-${file}`, mutableUses.length === 0, mutableUses.length ? `mutable refs: ${mutableUses.join(",")}` : "all actions are commit-SHA pinned");
}

const failed = checks.filter((check) => !check.passed);
for (const check of checks) {
  process.stdout.write(`${check.passed ? "PASS" : "FAIL"}\t${check.name}\t${check.detail}\n`);
}
process.stdout.write(`T16 policy ${checks.length - failed.length}/${checks.length} passed\n`);
if (failed.length) {
  process.exitCode = 1;
}
