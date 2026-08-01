import fs from "node:fs";

const TRUSTED_REF_GUARD = "github.ref == 'refs/heads/main' && github.ref_protected == true";

function jobBlock(text, jobName) {
  const jobStart = text.search(new RegExp(`^  ${jobName}:`, "m"));
  if (jobStart < 0) return null;
  const followingJob = text.slice(jobStart + 1).search(/^  [A-Za-z0-9_-]+:/m);
  return followingJob < 0 ? text.slice(jobStart) : text.slice(jobStart, jobStart + 1 + followingJob);
}

function exactNeeds(jobText) {
  const match = jobText.match(/^    needs:[ \t]*\r?\n((?:^      - [A-Za-z0-9_-]+[ \t]*\r?\n)+)/m);
  return match ? [...match[1].matchAll(/^      - ([A-Za-z0-9_-]+)[ \t]*$/gm)].map((item) => item[1]) : [];
}

export function privilegedWorkflowMismatches(workflowText, { jobName, forbidTagTrigger = false } = {}) {
  const text = String(workflowText);
  const issues = [];
  const jobText = jobBlock(text, jobName);
  if (!jobText) return [`missing privileged job ${jobName}`];
  if (!jobText.includes(TRUSTED_REF_GUARD)) {
    issues.push(`${jobName} lacks the exact protected-main admission guard`);
  }
  if (!/environment:\s*\n\s+name:\s+production/.test(jobText)) {
    issues.push(`${jobName} lacks the production environment gate`);
  }
  if (!/uses:\s*actions\/checkout@[a-f0-9]{40}[\s\S]*?with:\s*\n\s+ref:\s*\$\{\{ github\.sha \}\}\s*\n\s+persist-credentials:\s*false/.test(jobText)) {
    issues.push(`${jobName} must checkout github.sha without persisted credentials`);
  }
  if (forbidTagTrigger && /^\s{2}push:/m.test(text)) {
    issues.push("privileged release workflow must not admit unverified tag triggers");
  }
  return issues;
}

export function deploymentPrerequisiteMismatches(workflowText) {
  const text = String(workflowText);
  const issues = [];
  const deploy = jobBlock(text, "deploy-vps");
  const dast = jobBlock(text, "dast-zap");
  const admission = jobBlock(text, "release-admission");
  if (!deploy || !dast || !admission) return ["deployment DAG is missing deploy-vps, dast-zap, or release-admission"];

  const needs = exactNeeds(deploy);
  const expectedNeeds = ["enterprise-readiness", "release-admission", "dast-zap"];
  if (JSON.stringify(needs) !== JSON.stringify(expectedNeeds)) {
    issues.push("deploy-vps must depend on the exact enterprise-readiness, release-admission, and dast-zap prerequisite set");
  }
  if (/if:\s*.*(?:always\(\)|!\s*cancelled\(\))/.test(deploy)) {
    issues.push("deploy-vps must preserve default fail/skip propagation from every prerequisite");
  }
  if (!/^    if: github\.event_name == 'workflow_dispatch'\s*$/m.test(dast)) {
    issues.push("dast-zap must run unconditionally for every manual production deployment request");
  }
  if (JSON.stringify(exactNeeds(dast)) !== JSON.stringify(["enterprise-readiness", "release-admission"])
    || !/environment:\s*\n\s+name:\s+staging/.test(dast)
    || !/dast-zap-baseline\.sh/.test(dast)
    || !/dast-admission-policy\.mjs/.test(dast)) {
    issues.push("dast-zap must consume the exact readiness and release-admission prerequisites and mint the run-bound DAST receipt");
  }
  if (!/^    needs: enterprise-readiness\s*$/m.test(admission)
    || !admission.includes(TRUSTED_REF_GUARD)
    || !/(?:release-artifact-gate\.sh|node \.\/scripts\/infra-ops\.mjs release-artifact-gate)/.test(admission)) {
    issues.push("release-admission must consume readiness and enforce protected-main artifact admission");
  }
  if (/continue-on-error:\s*true/.test(`${dast}\n${admission}`)) {
    issues.push("DAST and release admission may not continue on error");
  }
  const legacyDeployCalls = text.match(/run:\s*sh \.\/scripts\/deploy-vps\.sh/g) ?? [];
  if (legacyDeployCalls.length !== 0) {
    issues.push("production mutation must not invoke the candidate checkout deploy-vps.sh directly");
  }
  const trustedOpsSinks = text.match(/^\s+"\$OPS_IMAGE_ID" deploy-vps > "\$ACTIVATION_RECEIPT"\s*$/gm) ?? [];
  if (trustedOpsSinks.length !== 1 || !/^\s+"\$OPS_IMAGE_ID" deploy-vps > "\$ACTIVATION_RECEIPT"\s*$/m.test(deploy)) {
    issues.push("production mutation must have exactly one trusted ops image deploy-vps entrypoint sink inside the gated deploy-vps job");
  }
  const productionEnvironments = text.match(/environment:\s*\n\s+name:\s+production/g) ?? [];
  if (productionEnvironments.length !== 1) {
    issues.push("enterprise-infra must expose exactly one production environment job");
  }
  return issues;
}

export function assertPrivilegedWorkflow(pathname, options) {
  const issues = privilegedWorkflowMismatches(fs.readFileSync(pathname, "utf8"), options);
  if (issues.length) throw new Error(issues.join("; "));
}
