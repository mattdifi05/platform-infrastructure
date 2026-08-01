#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const documents = Object.freeze([
  {
    file: "README.md",
    marker: "Schedulazione consigliata, container-first:",
  },
  {
    file: "RUNBOOK.md",
    marker: "Preferred VPS scheduler:",
  },
]);

function usage() {
  process.stderr.write(
    "Usage: node probe.mjs --candidate-root <path> [--expect vulnerable|fixed]\n",
  );
}

function parseArgs(argv) {
  const parsed = { expect: "vulnerable" };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === "--candidate-root") parsed.candidateRoot = argv[++index];
    else if (value === "--expect") parsed.expect = argv[++index];
    else {
      usage();
      throw new Error(`unsupported argument: ${value}`);
    }
  }
  if (!parsed.candidateRoot) throw new Error("--candidate-root is required");
  if (!new Set(["vulnerable", "fixed"]).has(parsed.expect)) {
    throw new Error("--expect must be vulnerable or fixed");
  }
  return parsed;
}

function read(root, relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

function fencedBlockAfter(text, marker, file) {
  const markerOffset = text.indexOf(marker);
  if (markerOffset < 0) throw new Error(`${file} is missing scheduler marker`);
  const tail = text.slice(markerOffset + marker.length);
  const match = tail.match(/```(?:sh|bash)\s*\n([\s\S]*?)```/);
  if (!match) throw new Error(`${file} scheduler section has no shell block`);
  return match[1].trim();
}

function composeFiles(command) {
  return [...command.matchAll(/(?:^|\s)-f\s+([^\s\\]+)/gm)].map(
    (match) => match[1],
  );
}

function serviceBlock(document, name, file) {
  const startPattern = new RegExp(`^  ${name}:\\s*$`, "m");
  const start = startPattern.exec(document);
  if (!start) throw new Error(`${file} has no ${name} service block`);
  const tail = document.slice(start.index);
  const nextTopLevel = tail.slice(start[0].length).search(/^\S/m);
  return nextTopLevel < 0
    ? tail
    : tail.slice(0, start[0].length + nextTopLevel);
}

function lineMatches(block, pattern) {
  return block.split(/\r?\n/).some((line) => pattern.test(line));
}

function verifySourceControls(root) {
  const base = serviceBlock(
    read(root, "compose.backup-scheduler.yaml"),
    "backup-scheduler",
    "compose.backup-scheduler.yaml",
  );
  const isolation = serviceBlock(
    read(root, "compose.runtime-isolation.yaml"),
    "backup-scheduler",
    "compose.runtime-isolation.yaml",
  );
  const wrapper = read(root, "scripts/compose-vps.sh");

  const baseRawSocket = lineMatches(
    base,
    /^\s*-\s*\/var\/run\/docker\.sock:\/var\/run\/docker\.sock\s*$/,
  );
  const baseWritableInfra = lineMatches(base, /^\s*-\s*\.:\/infra\s*$/);
  const executesInfra = lineMatches(
    base,
    /^\s*-\s*\/infra\/scripts\/backup-scheduler\.sh\s*$/,
  );
  if (!baseRawSocket) throw new Error("base scheduler raw-socket sink not found");
  if (!baseWritableInfra) throw new Error("base scheduler writable /infra sink not found");
  if (!executesInfra) throw new Error("scheduler /infra entrypoint not found");

  const isolationHasOverride = /volumes:\s*!override/.test(isolation);
  const isolationReadOnlyInfra = lineMatches(
    isolation,
    /^\s*-\s*\.:\/infra:ro\s*$/,
  );
  const isolationUsesProxy = /DOCKER_HOST:\s*tcp:\/\/docker-socket-proxy:2375/.test(
    isolation,
  );
  const isolationStillHasRawSocket = /\/var\/run\/docker\.sock/.test(isolation);
  if (
    !isolationHasOverride ||
    !isolationReadOnlyInfra ||
    !isolationUsesProxy ||
    isolationStillHasRawSocket
  ) {
    throw new Error("runtime-isolation scheduler override is not the expected safe control");
  }

  const wrapperFiles = composeFiles(wrapper);
  const schedulerIndex = wrapperFiles.indexOf("compose.backup-scheduler.yaml");
  const isolationIndex = wrapperFiles.indexOf("compose.runtime-isolation.yaml");
  if (schedulerIndex < 0 || isolationIndex <= schedulerIndex) {
    throw new Error("compose-vps wrapper does not load runtime isolation after scheduler");
  }

  process.stdout.write(
    "[+] CAN-045 sink confirmed: base scheduler mounts the raw Docker socket\n",
  );
  process.stdout.write(
    "[+] CAN-046 sink confirmed: base scheduler executes from writable /infra\n",
  );
  process.stdout.write(
    "[+] negative control confirmed: compose-vps loads the read-only proxy override after scheduler\n",
  );
}

function classifyCommand(command) {
  if (/scripts\/compose-vps\.sh/.test(command)) return "wrapper";
  if (!/(?:^|\s)docker\s+compose(?:\s|$)/m.test(command)) return "unknown";
  const files = composeFiles(command);
  const schedulerIndex = files.indexOf("compose.backup-scheduler.yaml");
  const isolationIndex = files.indexOf("compose.runtime-isolation.yaml");
  if (schedulerIndex >= 0 && isolationIndex < 0) return "unsafe-direct";
  if (schedulerIndex >= 0 && isolationIndex > schedulerIndex) return "complete-direct";
  return "unknown";
}

function inspectDocument(root, document) {
  const text = read(root, document.file);
  const command = fencedBlockAfter(text, document.marker, document.file);
  const classification = classifyCommand(command);
  if (classification === "unsafe-direct") {
    process.stdout.write(
      `[VULNERABLE] CAN-045 ${document.file}: direct command omits runtime isolation; raw socket remains\n`,
    );
    process.stdout.write(
      `[VULNERABLE] CAN-046 ${document.file}: direct command omits runtime isolation; /infra remains writable\n`,
    );
  } else if (classification === "wrapper") {
    process.stdout.write(
      `[FIXED] CAN-045/CAN-046 ${document.file}: scheduler command delegates to compose-vps\n`,
    );
  } else if (classification === "complete-direct") {
    process.stdout.write(
      `[PARTIAL] CAN-045/CAN-046 ${document.file}: complete direct list found, but wrapper is not the sole entrypoint\n`,
    );
  } else {
    process.stdout.write(
      `[UNKNOWN] CAN-045/CAN-046 ${document.file}: scheduler command cannot be classified\n`,
    );
  }
  return classification;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const root = path.resolve(args.candidateRoot);
  verifySourceControls(root);
  const classifications = documents.map((document) => inspectDocument(root, document));
  const expected = args.expect === "vulnerable" ? "unsafe-direct" : "wrapper";
  const matching = classifications.filter((value) => value === expected).length;
  if (matching !== documents.length) {
    throw new Error(
      `expected ${documents.length} scheduler entrypoints to classify as ${expected}, observed ${matching}`,
    );
  }
  const result = args.expect === "vulnerable" ? "bypass isolation" : "use safe wrapper";
  process.stdout.write(
    `[+] result: ${matching}/${documents.length} documented scheduler entrypoints ${result} as expected\n`,
  );
}

try {
  main();
} catch (error) {
  process.stderr.write(`[-] ${error.message}\n`);
  process.exitCode = 1;
}
