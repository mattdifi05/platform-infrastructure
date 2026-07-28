#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const hardening = fs.readFileSync(path.join(import.meta.dirname, "vps-hardening-ubuntu.sh"), "utf8");
const readiness = fs.readFileSync(path.join(import.meta.dirname, "vps-host-readiness.sh"), "utf8");

test("hardening and readiness enforce the same live-restore=false contract", () => {
  assert.match(hardening, /"live-restore"\[\[:space:\]\]\*:\[\[:space:\]\]\*false/);
  assert.match(hardening, /\\"live-restore\\": false/);
  assert.match(readiness, /"live-restore"\[\[:space:\]\]\*:\[\[:space:\]\]\*false/);
  assert.doesNotMatch(readiness, /"live-restore"\[\[:space:\]\]\*:\[\[:space:\]\]\*true/);
  assert.match(readiness, /daemon restart cannot bypass the firewall-gated restart=no workload policy/);
  assert.equal(fs.existsSync(path.join(root, "compose.runtime-isolation.yaml")), true);
});
