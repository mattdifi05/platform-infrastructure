import { randomBytes } from "node:crypto";
import { chmodSync, closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createControlStateStore } from "./catalog.mjs";

export function exportStateSnapshot(store, outputPath) {
  const snapshot = store.exportSnapshot();
  writePrivateJson(outputPath, snapshot);
  return snapshotSummary(snapshot, { status: "exported", outputPath });
}

export function planStateImport(store, snapshotPath) {
  const snapshot = readSnapshot(snapshotPath);
  const plan = store.planImport(snapshot);
  return { ...plan, snapshotPath };
}

export function applyStateImport(store, snapshotPath, { confirm = "", rollbackPath = "" } = {}) {
  if (confirm !== "IMPORT-CONTROL-CENTER-STATE") throw new Error("State import requires explicit confirmation.");
  if (!rollbackPath) throw new Error("State import requires a rollback output path.");
  const snapshot = readSnapshot(snapshotPath);
  const rollback = store.exportSnapshot(Object.keys(snapshot.datasets || {}));
  writePrivateJson(rollbackPath, rollback);
  const result = store.importSnapshot(snapshot, { apply: true, confirm });
  return {
    status: result.status,
    apply: result.apply,
    datasetCount: result.datasetCount,
    changedCount: result.changedCount,
    snapshotPath,
    rollbackPath,
  };
}

export function readSnapshot(snapshotPath) {
  return JSON.parse(readFileSync(snapshotPath, "utf8"));
}

function snapshotSummary(snapshot, details = {}) {
  return {
    schemaVersion: snapshot.schemaVersion,
    datasetCount: Object.keys(snapshot.datasets || {}).length,
    generatedAt: snapshot.generatedAt,
    ...details,
  };
}

function writePrivateJson(filePath, value) {
  const resolved = path.resolve(filePath);
  mkdirSync(path.dirname(resolved), { recursive: true, mode: 0o700 });
  const temporary = `${resolved}.tmp-${process.pid}-${randomBytes(6).toString("hex")}`;
  let fd;
  try {
    fd = openSync(temporary, "wx", 0o600);
    writeFileSync(fd, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(temporary, resolved);
    chmodSync(resolved, 0o600);
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    rmSync(temporary, { force: true });
    throw error;
  }
}

async function main(argv) {
  const [command, snapshotPath, ...rest] = argv;
  if (!command || !snapshotPath) throw new Error("Usage: migration.mjs <export|plan-import|apply-import> <snapshot> [--rollback <path>] [--confirm <value>]");
  const store = createControlStateStore(process.env);
  if (command === "export") return exportStateSnapshot(store, snapshotPath);
  if (command === "plan-import") return planStateImport(store, snapshotPath);
  if (command === "apply-import") {
    return applyStateImport(store, snapshotPath, {
      rollbackPath: option(rest, "--rollback"),
      confirm: option(rest, "--confirm"),
    });
  }
  throw new Error(`Unknown state migration command: ${command}.`);
}

function option(args, name) {
  const index = args.indexOf(name);
  return index >= 0 ? String(args[index + 1] || "") : "";
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2))
    .then((result) => process.stdout.write(`${JSON.stringify(result)}\n`))
    .catch((error) => {
      process.stderr.write(`${error.message}\n`);
      process.exitCode = 1;
    });
}
