import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const adminServices = ["phpmyadmin", "phppgadmin"];

test("every Compose declaration preserves the database-admin profile gate", () => {
  const composeFiles = fs.readdirSync(root)
    .filter((name) => /^compose(?:\..+)?\.ya?ml$/.test(name))
    .sort();

  for (const service of adminServices) {
    assert.deepEqual(
      profileDirective(serviceBlock(read("compose.yaml"), service)),
      { operation: "merge", profiles: ["admin"] },
      `${service} must be gated by the admin profile in compose.yaml`,
    );

    for (const file of composeFiles) {
      const block = serviceBlock(read(file), service);
      if (block === null) continue;
      const directive = profileDirective(block);
      assert.notEqual(directive.operation, "reset", `${file} must not reset ${service} profiles`);
      assert.notEqual(directive.operation, "override", `${file} must not override ${service} profiles`);
      if (directive.operation === "merge") {
        assert.deepEqual(directive.profiles, ["admin"], `${file} may only preserve ${service}'s admin profile`);
      }
    }
  }
});

test("the runtime overlay does not own database-admin profile or restart policy", () => {
  const runtime = read("compose.runtime.yaml");
  for (const service of adminServices) {
    assert.equal(
      serviceBlock(runtime, service),
      null,
      `compose.runtime.yaml must not redeclare ${service}`,
    );
  }
});

test("every tracked canonical overlay order keeps database-admin services opt-in", () => {
  const orders = canonicalOverlayOrders();
  assert.ok(orders.some(({ files }) => files.includes("compose.runtime.yaml")), "expected a runtime overlay order");
  assert.ok(orders.some(({ files }) => files.includes("compose.staging.yaml")), "expected a staging overlay order");
  assert.ok(orders.some(({ files }) => files.includes("compose.backup-scheduler.yaml")), "expected a backup overlay order");

  for (const { source, files } of orders) {
    for (const service of adminServices) {
      const profiles = mergedProfiles(files, service);
      assert.deepEqual(profiles, ["admin"], `${source}: ${service} profiles after ${files.join(" -> ")}`);
      assert.equal(isActive(profiles, []), false, `${source}: default must not activate ${service}`);
      assert.equal(isActive(profiles, ["backup"]), false, `${source}: backup must not activate ${service}`);
      assert.equal(isActive(profiles, ["admin"]), true, `${source}: admin must activate ${service}`);
      assert.equal(isActive(profiles, ["backup", "admin"]), true, `${source}: admin plus backup must activate ${service}`);
    }
  }
});

test("the regression harness rejects the former runtime reset", () => {
  const vulnerableRuntime = [
    "services:",
    "  phpmyadmin:",
    "    profiles: !reset []",
    "    restart: unless-stopped",
    "  phppgadmin:",
    "    profiles: !reset []",
    "    restart: unless-stopped",
    "",
  ].join("\n");
  const files = ["compose.yaml", "compose.runtime.yaml", "compose.networks.yaml", "compose.runtime-isolation.yaml"];

  for (const service of adminServices) {
    const profiles = mergedProfiles(files, service, new Map([["compose.runtime.yaml", vulnerableRuntime]]));
    assert.deepEqual(profiles, []);
    assert.equal(isActive(profiles, []), true, `former reset must reproduce default activation for ${service}`);
    assert.equal(isActive(profiles, ["backup"]), true, `former reset must reproduce backup activation for ${service}`);
  }
});

function canonicalOverlayOrders() {
  const sources = [
    ".github/workflows/enterprise-infra.yml",
    "CURRENT-OPERATING-MODEL.md",
    "INFRASTRUCTURE-DEEP-DIVE.md",
    "README.md",
    "RUNBOOK.md",
  ];
  const trackedComposeFiles = new Set(
    fs.readdirSync(root).filter((name) => /^compose(?:\..+)?\.ya?ml$/.test(name)),
  );
  const orders = [];

  for (const source of sources) {
    const logicalLines = read(source).replace(/\\\r?\n[ \t]*/g, " ").split(/\r?\n/);
    let occurrence = 0;
    for (const line of logicalLines) {
      if (!/\bdocker\s+compose\b/.test(line)) continue;
      const files = [...line.matchAll(/(?:^|\s)-f\s+([^\s]+)/g)].map((match) => match[1]);
      if (!files.includes("compose.yaml") || files.some((file) => !trackedComposeFiles.has(file))) continue;
      occurrence += 1;
      orders.push({ source: `${source}#${occurrence}`, files });
    }
  }

  const wrapper = read("scripts/compose-vps.sh");
  const wrapperArray = wrapper.match(/compose\+=\(\s*([\s\S]*?)\n\)/);
  assert.ok(wrapperArray, "scripts/compose-vps.sh must declare its canonical Compose array");
  const wrapperFiles = [...wrapperArray[1].matchAll(/(?:^|\s)-f\s+([^\s]+)/g)].map((match) => match[1]);
  assert.ok(wrapperFiles.includes("compose.yaml"), "VPS wrapper must include compose.yaml");
  assert.ok(wrapperFiles.every((file) => trackedComposeFiles.has(file)), "VPS wrapper must reference tracked Compose overlays");
  orders.push({ source: "scripts/compose-vps.sh", files: wrapperFiles });

  const unique = new Map();
  for (const order of orders) {
    const key = order.files.join("\0");
    if (!unique.has(key)) unique.set(key, order);
  }
  return [...unique.values()];
}

function mergedProfiles(files, service, replacements = new Map()) {
  let profiles;
  for (const file of files) {
    const text = replacements.has(file) ? replacements.get(file) : read(file);
    const directive = profileDirective(serviceBlock(text, service));
    if (directive.operation === "inherit") continue;
    if (directive.operation === "reset") {
      profiles = [];
      continue;
    }
    if (directive.operation === "override") {
      profiles = [...directive.profiles];
      continue;
    }
    profiles = [...new Set([...(profiles ?? []), ...directive.profiles])];
  }
  return profiles;
}

function isActive(profiles, selectedProfiles) {
  if (profiles === undefined || profiles.length === 0) return true;
  return profiles.some((profile) => selectedProfiles.includes(profile));
}

function profileDirective(block) {
  if (block === null) return { operation: "inherit", profiles: [] };
  const lines = block.split(/\r?\n/);
  const index = lines.findIndex((line) => /^    profiles:/.test(line));
  if (index === -1) return { operation: "inherit", profiles: [] };

  const header = lines[index].replace(/^    profiles:\s*/, "");
  const operation = /!reset\b/.test(header) ? "reset" : /!override\b/.test(header) ? "override" : "merge";
  const profiles = [];
  const inline = header.replace(/!(?:reset|override)\b/g, "").trim();
  if (/^\[.*\]$/.test(inline)) {
    profiles.push(...inline.slice(1, -1).split(",").map(cleanScalar).filter(Boolean));
  } else if (inline && !/^null$|^~$/.test(inline)) {
    profiles.push(cleanScalar(inline));
  }
  for (const line of lines.slice(index + 1)) {
    if (/^    \S/.test(line)) break;
    const match = line.match(/^\s{6,}-\s+(.+?)\s*$/);
    if (match) profiles.push(cleanScalar(match[1]));
  }
  return { operation, profiles };
}

function serviceBlock(text, service) {
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex((line) => line === `  ${service}:`);
  if (start === -1) return null;
  let end = start + 1;
  while (end < lines.length && !/^  \S[^:]*:\s*(?:#.*)?$/.test(lines[end]) && !/^\S/.test(lines[end])) end += 1;
  return lines.slice(start, end).join("\n");
}

function cleanScalar(value) {
  return value.trim().replace(/^(["'])(.*)\1$/, "$2");
}

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}
