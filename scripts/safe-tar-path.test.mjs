import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { safeTarCreateArgs, validateTarEntryName } from "./safe-tar-path.mjs";

for (const hostile of ["-T", "--checkpoint-action=exec=sh", "--", "@response", "-C", "bad\nname", "../escape", "nested/path"]) {
  test(`rejects option-like tar source ${JSON.stringify(hostile)}`, () => {
    assert.throws(() => validateTarEntryName(hostile), /Invalid archive source name/);
  });
}

test("legitimate names use an option terminator before the operand", () => {
  const args = safeTarCreateArgs({
    archivePath: "/backup/my-app.tar.gz",
    excludeArgs: ["--exclude", "node_modules"],
    sourceRoot: "/source",
    entryName: "My app-v2",
  });
  assert.deepEqual(args, ["-czf", "/backup/my-app.tar.gz", "--exclude", "node_modules", "-C", "/source", "--", "My app-v2"]);
});

test("application backup integrates the validated tar argument builder", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const source = fs.readFileSync(path.join(here, "infra-ops.mjs"), "utf8");
  assert.match(source, /validateTarEntryName\(entry\.name/);
  assert.match(source, /safeTarCreateArgs\(\{/);
  assert.doesNotMatch(source, /"-C", sourceRoot, application\.name/);
});

