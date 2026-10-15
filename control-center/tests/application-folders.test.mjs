import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { createControlStateStore } from "../state/catalog.mjs";
import { ApplicationFolderError, applicationFolderCatalog, updateApplicationFolders } from "../state/application-folders.mjs";
import { resolveAuthorizationCapability } from "../auth/route-capabilities.mjs";

const apps = [{ key: "project:alpha" }, { key: "project:beta" }, { key: "observed:alpha" }];

test("folders persist in project state, isolate memberships, and preserve app and unrelated metadata", t => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "application-folders-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const env = { PROJECT_STATE_FILE: path.join(dir, "projects.json") };
  const store = createControlStateStore(env);
  const initial = { projects: { alpha: { declaredProject: true, host: "alpha.example.test", runtime: "node" }, beta: { enabled: true } }, subdomains: { preserved: true }, otherMetadata: { keep: "yes" } };
  store.write("projects", initial);
  const a = updateApplicationFolders(store, "create", { name: "Personali" }, apps).folderId;
  const b = updateApplicationFolders(store, "create", { name: "Clienti" }, apps).folderId;
  updateApplicationFolders(store, "membership", { applicationKey: apps[0].key, folderId: a }, apps);
  updateApplicationFolders(store, "membership", { applicationKey: apps[1].key, folderId: b }, apps);
  const reloaded = createControlStateStore(env).read("projects").value;
  assert.deepEqual(reloaded.projects, initial.projects);
  assert.deepEqual(reloaded.subdomains, initial.subdomains);
  assert.deepEqual(reloaded.otherMetadata, initial.otherMetadata);
  let catalog = applicationFolderCatalog(reloaded, apps);
  assert.equal(catalog.memberships["project:alpha"], a);
  assert.equal(catalog.memberships["project:beta"], b);
  assert.equal(catalog.memberships["observed:alpha"], "", "source-qualified app IDs must not mix");
  updateApplicationFolders(store, "rename", { folderId: a, name: "Lavoro" }, apps);
  const renamed = store.read("projects").value;
  assert.equal(renamed.applicationFolders.folders[a].name, "Lavoro");
  assert.equal(renamed.applicationFolders.memberships["project:alpha"], a);
  updateApplicationFolders(store, "membership", { applicationKey: "project:alpha", folderId: b }, apps);
  for (const applicationKey of ["project:alpha", "project:beta"]) updateApplicationFolders(store, "membership", { applicationKey, folderId: "" }, apps);
  updateApplicationFolders(store, "delete", { folderId: b }, apps);
  catalog = applicationFolderCatalog(store.read("projects").value, apps);
  assert.deepEqual(catalog.folders, [{ id: a, name: "Lavoro", canDelete: true }]);
  assert.deepEqual(catalog.memberships, Object.fromEntries(apps.map(app => [app.key, ""])));
  assert.deepEqual(store.read("projects").value.projects, initial.projects);
});

test("stale apps and removed folders never leak into visible groups, and invalid mutations preserve state", t => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "application-folders-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const store = createControlStateStore({ PROJECT_STATE_FILE: path.join(dir, "projects.json") });
  const id = updateApplicationFolders(store, "create", { name: "Gruppo" }, apps).folderId;
  updateApplicationFolders(store, "membership", { applicationKey: "project:alpha", folderId: id }, apps);
  assert.deepEqual(applicationFolderCatalog(store.read("projects").value, []).memberships, {});
  const before = store.read("projects").token;
  for (const [action, payload] of [["create", { name: "gruppo" }], ["create", { name: "\u200b" }], ["rename", { folderId: "__proto__", name: "x" }], ["membership", { applicationKey: "project:deleted", folderId: id }], ["membership", { applicationKey: "project:alpha", folderId: "removed" }]]) {
    assert.throws(() => updateApplicationFolders(store, action, payload, apps));
    assert.equal(store.read("projects").token, before);
  }
  updateApplicationFolders(store, "membership", { applicationKey: "project:alpha", folderId: "" }, apps);
  assert.equal(applicationFolderCatalog(store.read("projects").value, apps).memberships["project:alpha"], "");
});

test("nonempty folders cannot be deleted even when assigned apps are absent, and rejected writes preserve exact metadata", t => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "application-folders-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, "projects.json");
  const store = createControlStateStore({ PROJECT_STATE_FILE: file });
  const folderId = updateApplicationFolders(store, "create", { name: "In uso" }, apps).folderId;
  const emptyId = updateApplicationFolders(store, "create", { name: "Vuota" }, apps).folderId;
  updateApplicationFolders(store, "membership", { applicationKey: "project:alpha", folderId }, apps);
  for (const catalogApps of [apps, []]) {
    const before = readFileSync(file, "utf8");
    const token = store.read("projects").token;
    const catalog = applicationFolderCatalog(store.read("projects").value, catalogApps);
    assert.equal(catalog.folders.find(folder => folder.id === folderId).canDelete, false);
    assert.equal(catalog.folders.find(folder => folder.id === emptyId).canDelete, true);
    assert.throws(() => updateApplicationFolders(store, "delete", { folderId }, catalogApps), error => error instanceof ApplicationFolderError && /contiene applicazioni/.test(error.message));
    assert.equal(readFileSync(file, "utf8"), before);
    assert.equal(store.read("projects").token, token);
  }
  updateApplicationFolders(store, "rename", { folderId, name: "  Nuovo nome  " }, []);
  assert.deepEqual(applicationFolderCatalog(store.read("projects").value, []).folders.find(folder => folder.id === folderId), { id: folderId, name: "Nuovo nome", canDelete: false });
  assert.equal(store.read("projects").value.applicationFolders.memberships["project:alpha"], folderId);
  updateApplicationFolders(store, "membership", { applicationKey: "project:alpha", folderId: "" }, apps);
  assert.equal(applicationFolderCatalog(store.read("projects").value, []).folders.find(folder => folder.id === folderId).canDelete, true);
  assert.deepEqual(updateApplicationFolders(store, "delete", { folderId }, []), { folderId: "unfiled" });
  updateApplicationFolders(store, "delete", { folderId: emptyId }, []);
  assert.deepEqual(store.read("projects").value.applicationFolders, { folders: {}, memberships: {} });
});

test("folder API uses the explicit viewer/admin route catalog for canonical and v1 routes", () => {
  for (const prefix of ["/control", "/control/v1"]) {
    assert.equal(resolveAuthorizationCapability("GET", `${prefix}/project-folders`).capability, "viewer");
    for (const suffix of ["", "/membership", "/folder-fixture/rename", "/folder-fixture/delete"]) {
      assert.equal(resolveAuthorizationCapability("POST", `${prefix}/project-folders${suffix}`).capability, "admin");
    }
  }
});
