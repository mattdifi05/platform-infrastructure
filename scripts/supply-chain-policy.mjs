import fs from "node:fs";
import path from "node:path";

const IMAGE_DIGEST = /@sha256:[a-f0-9]{64}$/;
const ACTION_COMMIT = /^[a-f0-9]{40}$/;
const ZERO_DIGEST = /@sha256:0{64}$/;

export function evaluateSupplyChain(rootDirectory) {
  const checks = [];
  const failures = [];
  const discoveredImages = new Map();
  const usedActions = new Set();
  const record = (id, passed, detail) => {
    checks.push({ id, status: passed ? "passed" : "failed", detail });
    if (!passed) failures.push(`${id}: ${detail}`);
  };
  const read = (relativePath) => {
    const target = path.join(rootDirectory, relativePath);
    if (!fs.existsSync(target)) {
      record(`required-file-${relativePath}`, false, `${relativePath} is missing`);
      return "";
    }
    return fs.readFileSync(target, "utf8");
  };
  const addImage = (reference, origin) => {
    const value = String(reference || "").trim();
    if (!value || isLocalImage(value) || ZERO_DIGEST.test(value)) return;
    if (!discoveredImages.has(value)) discoveredImages.set(value, new Set());
    discoveredImages.get(value).add(origin);
  };

  let lock = { actions: {}, images: {}, downloads: {} };
  try {
    lock = JSON.parse(read("governance/supply-chain-lock.json"));
  } catch (error) {
    record("lock-json", false, `supply-chain lock is invalid JSON: ${error.message}`);
  }
  record("lock-schema", lock.schemaVersion === 1, `schemaVersion=${lock.schemaVersion ?? "missing"}`);
  const lockedImages = new Set(Object.values(lock.images || {}).map(String));

  const workflowsDirectory = path.join(rootDirectory, ".github", "workflows");
  const workflowFiles = fs.existsSync(workflowsDirectory)
    ? fs.readdirSync(workflowsDirectory).filter((name) => /\.ya?ml$/.test(name)).sort()
    : [];
  record("workflow-files", workflowFiles.length > 0, `workflowFiles=${workflowFiles.length}`);
  for (const file of workflowFiles) {
    const text = read(path.join(".github", "workflows", file));
    for (const [index, line] of text.split(/\r?\n/).entries()) {
      const match = line.match(/^\s*(?:-\s*)?uses:\s*([^\s#]+)/);
      if (!match) continue;
      const usage = match[1];
      if (usage.startsWith("./")) continue;
      if (usage.startsWith("docker://")) {
        const image = usage.slice("docker://".length);
        addImage(image, `${file}:${index + 1}`);
        record(`workflow-container-${file}-${index + 1}`, IMAGE_DIGEST.test(image), `${usage} must use sha256`);
        continue;
      }
      const action = usage.match(/^([^/]+\/[^/@]+)@(.+)$/);
      const actionName = action?.[1] || usage;
      const commit = action?.[2] || "";
      const locked = lock.actions?.[actionName];
      usedActions.add(actionName);
      record(`action-immutable-${file}-${index + 1}`, ACTION_COMMIT.test(commit), `${usage} must use a 40-character commit`);
      record(`action-lock-${file}-${index + 1}`, Boolean(locked) && locked.commit === commit, `${actionName} commit must match the lock manifest`);
    }
  }
  for (const [actionName, entry] of Object.entries(lock.actions || {})) {
    record(`action-lock-format-${actionName}`, ACTION_COMMIT.test(String(entry.commit || "")) && /^v\d+(?:\.\d+)*$/.test(String(entry.version || "")), `${actionName} requires version metadata and a commit SHA`);
    record(`action-lock-used-${actionName}`, usedActions.has(actionName), `${actionName} must be referenced by a workflow`);
  }

  const dockerDirectory = path.join(rootDirectory, "docker");
  const dockerfiles = fs.existsSync(dockerDirectory)
    ? fs.readdirSync(dockerDirectory).filter((name) => name.endsWith(".Dockerfile")).sort()
    : [];
  record("dockerfiles", dockerfiles.length > 0, `dockerfiles=${dockerfiles.length}`);
  for (const file of dockerfiles) {
    const relativePath = path.join("docker", file);
    const text = read(relativePath);
    const syntax = text.match(/^#\s*syntax=([^\s]+)$/m)?.[1] || "";
    addImage(syntax, `${relativePath}:syntax`);
    record(`dockerfile-syntax-${file}`, IMAGE_DIGEST.test(syntax), `${relativePath} frontend must be digest-pinned`);
    const args = new Map();
    for (const line of text.split(/\r?\n/)) {
      const arg = line.match(/^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)/);
      if (arg) args.set(arg[1], arg[2]);
    }
    for (const [index, line] of text.split(/\r?\n/).entries()) {
      const from = line.match(/^\s*FROM\s+(\S+)/i);
      if (!from) continue;
      const variable = from[1].match(/^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$/);
      const image = variable ? args.get(variable[1]) : from[1];
      addImage(image, `${relativePath}:${index + 1}`);
      record(`dockerfile-image-${file}-${index + 1}`, IMAGE_DIGEST.test(String(image || "")), `${relativePath} FROM must resolve to a digest-pinned image`);
    }
  }

  for (const file of fs.readdirSync(rootDirectory).filter((name) => /^compose(?:\..+)?\.ya?ml$/.test(name)).sort()) {
    for (const [index, line] of read(file).split(/\r?\n/).entries()) {
      const match = line.match(/^\s*image:\s+(.+?)\s*(?:#.*)?$/);
      if (!match) continue;
      const image = imageReferenceFromTemplate(match[1]);
      if (!image) continue;
      addImage(image, `${file}:${index + 1}`);
      if (!isLocalImage(image)) record(`compose-image-${file}-${index + 1}`, IMAGE_DIGEST.test(image), `${image} must be digest-pinned`);
    }
  }
  for (const [index, line] of read(".env.example").split(/\r?\n/).entries()) {
    const match = line.match(/^[A-Z0-9_]+_IMAGE=(\S+)$/);
    if (!match) continue;
    if (!/[:/@]/.test(match[1])) continue;
    addImage(match[1], `.env.example:${index + 1}`);
  }

  const opsScript = read("scripts/infra-ops.mjs");
  for (const [id, pattern] of [
    ["playwright", /defaultPlaywrightImage\s*=\s*"([^"]+)"/],
    ["restic", /defaultResticImage\s*=\s*"([^"]+)"/],
  ]) {
    const image = opsScript.match(pattern)?.[1] || "";
    addImage(image, `scripts/infra-ops.mjs:${id}`);
    record(`script-image-${id}`, IMAGE_DIGEST.test(image), `${id} helper must be digest-pinned`);
  }
  const zapScript = read("scripts/dast-zap-baseline.sh");
  const zapImage = zapScript.match(/ZAP_IMAGE:-([^}"]+)/)?.[1] || "";
  addImage(zapImage, "scripts/dast-zap-baseline.sh");
  record("script-image-zap", IMAGE_DIGEST.test(zapImage), "ZAP helper must be digest-pinned");

  for (const [reference, origins] of discoveredImages) {
    record(`image-immutable-${stableId(reference)}`, IMAGE_DIGEST.test(reference), `${reference} from ${[...origins].join(",")}`);
    record(`image-locked-${stableId(reference)}`, lockedImages.has(reference), `${reference} must exist in governance/supply-chain-lock.json`);
  }
  for (const reference of lockedImages) {
    record(`image-lock-used-${stableId(reference)}`, discoveredImages.has(reference), `${reference} must be referenced by tracked configuration`);
  }

  const phpDockerfile = read("docker/php-apache.Dockerfile");
  const imagick = lock.downloads?.imagick || {};
  record("imagick-version", new RegExp(`ARG IMAGICK_VERSION=${escapeRegExp(imagick.version || "missing")}`).test(phpDockerfile), "Imagick version must match the lock manifest");
  record("imagick-checksum", new RegExp(`ARG IMAGICK_SHA256=${escapeRegExp(imagick.sha256 || "missing")}`).test(phpDockerfile), "Imagick checksum must match the lock manifest");
  record("imagick-verified-before-extract", /curl[^\n]*-o \/tmp\/imagick\.tgz[\s\S]*sha256sum -c -[\s\S]*tar -xzf \/tmp\/imagick\.tgz/.test(phpDockerfile), "Imagick archive must be saved, verified and only then extracted");
  record("imagick-no-pipe-extract", !/curl[^\n]*imagick[^\n]*\|\s*tar/.test(phpDockerfile), "Imagick download must not be piped directly to tar");

  const phpIni = read("php-apache/php/conf.d/zz-production.ini");
  record("php-display-errors", /^display_errors=Off$/m.test(phpIni) && /^display_startup_errors=Off$/m.test(phpIni), "production PHP must hide runtime and startup errors");
  record("php-error-log", /^log_errors=On$/m.test(phpIni), "production PHP must log errors");
  record("php-config-installed", /COPY php-apache\/php\/conf\.d\/zz-production\.ini \/usr\/local\/etc\/php\/conf\.d\/zz-production\.ini/.test(phpDockerfile), "production PHP config must be copied into the image");

  const dockerignore = read(".dockerignore");
  for (const required of [".git", ".env", "secrets", "backups", "reports", ".tmp", "node_modules", "traefik/certs", "projects-portal/state"]) {
    const present = dockerignore.split(/\r?\n/).some((line) => line.trim().replace(/\/$/, "") === required);
    record(`dockerignore-${stableId(required)}`, present, `.dockerignore must exclude ${required}`);
  }

  const browserRunner = section(opsScript, "async function browserE2eTests", "async function platformBrowserE2e");
  record("browser-runner-no-socket", !/docker\.sock/.test(browserRunner), "browser runner must not mount the Docker socket");
  record("browser-runner-no-docker-install", !/install -y docker|docker\.io/.test(browserRunner), "browser runner must not install a Docker client");
  record("browser-runner-platform-only", /platformBrowserE2e\(\)/.test(browserRunner), "browser runner must execute only the platform-owned browser suite");

  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    status: failures.length ? "failed" : "passed",
    summary: {
      checks: checks.length,
      passed: checks.filter((item) => item.status === "passed").length,
      failed: failures.length,
      workflows: workflowFiles.length,
      actions: usedActions.size,
      images: discoveredImages.size,
      dockerfiles: dockerfiles.length,
    },
    checks,
    failures,
    inventory: {
      actions: [...usedActions].sort(),
      images: [...discoveredImages.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([reference, origins]) => ({ reference, origins: [...origins].sort() })),
      downloads: lock.downloads || {},
    },
  };
}

function imageReferenceFromTemplate(value) {
  const clean = String(value || "").trim().replace(/^["']|["']$/g, "");
  const defaultMatch = clean.match(/^\$\{[A-Za-z_][A-Za-z0-9_]*:-([^}]+)\}$/);
  if (defaultMatch) return defaultMatch[1];
  if (clean.startsWith("${")) return null;
  return clean || null;
}

function isLocalImage(value) {
  return /^platform\/[a-z0-9._/-]+:local$/.test(String(value || ""));
}

function section(text, start, end) {
  const startIndex = text.indexOf(start);
  const endIndex = text.indexOf(end, startIndex + start.length);
  if (startIndex < 0 || endIndex < 0) return "";
  return text.slice(startIndex, endIndex);
}

function stableId(value) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 100);
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
