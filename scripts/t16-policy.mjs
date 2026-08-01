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
record("verifier-offline-pair", includes(trustModule, "both an attestation bundle and a custom trusted root"), "offline bundle and root are paired");

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
record("deploy-vps-fixed-command", includes(deployVps, 'ssh "$@" -- "$REMOTE" \'/usr/bin/sudo -n -- /usr/local/libexec/platform-activation-broker activate\''), "production deploy uses the absolute root-owned activation broker command");
record(
  "deploy-vps-canonical-request",
  includes(deployVps, 'node "$SCRIPT_ROOT/activation-request.mjs"')
    && includes(deployVps, '< "$request" > "$receipt"')
    && !includes(deployVps, "base64"),
  "production deploy sends only the bounded canonical activation request on stdin",
);
record("deploy-vps-no-remote-argv", !includes(deployVps, "sh -s --") && !includes(deployVps, "REMOTE_SCRIPT"), "production deploy has no dynamic SSH argv or heredoc interpolation");
record(
  "deploy-vps-remote-revalidation",
  includes(deployVpsRemote, "exec /usr/bin/sudo -n -- /usr/local/libexec/platform-activation-broker activate")
    && includes(deployVps, 'node "$SCRIPT_ROOT/activation-receipt-policy.mjs"')
    && !/decode_field|candidate_release_root|--extractedRoot|--archive|git checkout|PLATFORM_BRANCH_B64/.test(deployVpsRemote),
  "remote sink delegates only to the root-owned broker and the client validates its exact receipt",
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
