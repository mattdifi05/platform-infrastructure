#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const distRoot = path.join(packageRoot, "dist");
const manifest = JSON.parse(readFileSync(path.join(packageRoot, "package.json"), "utf8"));

const coverageResult = spawnSync(process.execPath, [path.join(packageRoot, "scripts", "check-catalog-coverage.mjs")], {
  cwd: packageRoot,
  stdio: "inherit",
});
if (coverageResult.status !== 0) process.exit(coverageResult.status ?? 1);

rmSync(distRoot, { force: true, recursive: true });
mkdirSync(distRoot, { recursive: true });

const tscBin = path.resolve(packageRoot, "..", "..", "node_modules", "typescript", "bin", "tsc");
const result = spawnSync(process.execPath, [tscBin, "-p", "tsconfig.build.json"], {
  cwd: packageRoot,
  stdio: "inherit",
});
if (result.status !== 0) process.exit(result.status ?? 1);

copyCss(path.join(packageRoot, "src"), distRoot);
cpSync(path.join(packageRoot, "README.md"), path.join(distRoot, "README.md"));
writeFileSync(path.join(distRoot, "package.json"), `${JSON.stringify(createDistManifest(), null, 2)}\n`);

function copyCss(sourceDir, targetDir) {
  for (const entry of readdirSync(sourceDir, { withFileTypes: true })) {
    const sourcePath = path.join(sourceDir, entry.name);
    const targetPath = path.join(targetDir, entry.name);
    if (entry.isDirectory()) {
      copyCss(sourcePath, targetPath);
      continue;
    }
    if (!entry.name.endsWith(".css")) continue;
    mkdirSync(path.dirname(targetPath), { recursive: true });
    cpSync(sourcePath, targetPath);
  }
}

function createDistManifest() {
  const exports = Object.fromEntries(
    Object.entries(manifest.exports).map(([key, target]) => [key, distExportForTarget(target)]),
  );

  return {
    name: manifest.name,
    version: manifest.version,
    license: manifest.license,
    type: manifest.type,
    sideEffects: manifest.sideEffects,
    main: "./index.js",
    types: "./index.d.ts",
    exports,
    dependencies: manifest.dependencies,
    peerDependencies: manifest.peerDependencies,
  };
}

function distExportForTarget(target) {
  if (target.endsWith(".css")) return target.replace("./src/", "./");
  const runtimeTarget = target
    .replace("./src/", "./")
    .replace(/\.tsx?$/, ".js");
  const typeTarget = runtimeTarget.replace(/\.js$/, ".d.ts");

  return {
    types: existsSync(path.join(distRoot, typeTarget)) ? typeTarget : undefined,
    import: runtimeTarget,
    default: runtimeTarget,
  };
}
