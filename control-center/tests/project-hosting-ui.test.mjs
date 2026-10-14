import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
const sourceRoot = new URL("../styles/", import.meta.url);
const script = readFileSync(new URL("control-center.js", sourceRoot), "utf8");
const css = readFileSync(new URL("control-center.css", sourceRoot), "utf8");

test("visibility writes require a loaded review plan and its current confirmation", () => {
  assert.match(script, /\.ops-project-detail-screen\[id\^='project-'\]/);
  assert.match(script, /\/control\/projects\/" \+ encodeURIComponent\(projectId\) \+ "\/hosting-status/);
  assert.match(script, /\/hosting-plan\?mode=/);
  assert.match(script, /visibility\.verified === true/);
  assert.match(script, /authenticateWithSystemPasskey\(\)/);
  assert.match(script, /expectedRevision: reviewedPlan\.revision/);
  assert.match(script, /confirm: reviewedPlan\.confirmationRequired/);
  assert.match(script, /plan\.revision/);
  assert.match(script, /plan\.actions/);
  assert.match(script, /plan\.hostnames/);
  assert.match(script, /plan\.hostPlans/);
  assert.match(script, /data-hosting-plan-hosts/);
  assert.match(script, /Host verificati:/);
  assert.doesNotMatch(script, /SET-VISIBILITY:/);
  assert.match(script, /CLONE-PRIVATE:/);
  assert.match(script, /CANCEL-CLONE:/);
});

test("private copy review exposes isolation and restricted access without app-specific hostnames", () => {
  assert.match(script, /Cloudflare Access · solo account owner/);
  assert.match(script, /Archivio e credenziali isolati dalla produzione/);
  assert.match(script, /Invio email/);
  assert.match(script, /Pianificazioni/);
  assert.match(script, /clone\.eligible === true/);
  assert.match(script, /privateCopyUnavailableReason\(clone\.reason\)/);
  assert.match(script, /source not admitted by native application operator/);
  assert.match(script, /non è ancora stata verificata per la copia privata/);
  assert.doesNotMatch(script, /return reason\.trim\(\)/);
  assert.match(script, /status === "absent"/);
  assert.match(script, /"staged", "publishing", "activating"/);
  assert.doesNotMatch(script, /scriptastudents\.com|stexor\.com/i);
});

test("hosting controls keep the detail panel usable at narrow widths", () => {
  assert.match(css, /\.cc-hosting-copy \{[^}]*flex-direction: column/s);
  assert.match(css, /\.cc-hosting-review \{[^}]*grid-template-columns: 1fr/s);
  assert.match(css, /\.cc-hosting-plan \{/);
  assert.match(css, /\.cc-hosting-plan-hosts \{/);
  assert.match(css, /\.cc-hosting-dialog-actions \.ops-button \{ width: 100%; \}/);
});
