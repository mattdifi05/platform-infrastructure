import { randomUUID } from "node:crypto";

export class ApplicationFolderError extends Error {}
const own = (object, key) => Object.hasOwn(object, key);
const object = (value) => value && typeof value === "object" && !Array.isArray(value) ? value : {};

// Catalog metadata only. Memberships use source-qualified IDs so an observed
// app cannot silently inherit a managed app's placement with the same name.
export function applicationFolderCatalog(state, applications = []) {
  const metadata = object(state.applicationFolders);
  const folders = Object.entries(object(metadata.folders))
    .filter(([id, folder]) => /^folder-[a-f0-9-]{36}$/.test(id) && typeof folder?.name === "string")
    .map(([id, folder]) => ({ id, name: folder.name }))
    .sort((a, b) => a.name.localeCompare(b.name, "it"));
  const ids = new Set(folders.map(folder => folder.id));
  const memberships = Object.fromEntries(applications.map(app => [app.key,
    ids.has(object(metadata.memberships)[app.key]) ? metadata.memberships[app.key] : "",
  ]));
  return { folders, memberships };
}

export function updateApplicationFolders(store, action, payload, applications = []) {
  let result;
  store.update("projects", state => {
    const metadata = object(state.applicationFolders);
    const folders = { ...object(metadata.folders) };
    const memberships = { ...object(metadata.memberships) };
    const folderId = String(payload.folderId || "");
    if (["rename", "delete"].includes(action) && !own(folders, folderId)) throw new ApplicationFolderError("Cartella non trovata. Aggiorna la pagina.");
    if (action === "create" || action === "rename") {
      const name = typeof payload.name === "string" ? payload.name.trim().replace(/\s+/gu, " ") : "";
      if (!name || name.length > 80 || /[\p{Cc}\p{Cf}]/u.test(name)) throw new ApplicationFolderError("Inserisci un nome cartella da 1 a 80 caratteri.");
      if (Object.entries(folders).some(([id, folder]) => id !== folderId && folder.name?.toLocaleLowerCase("it") === name.toLocaleLowerCase("it"))) throw new ApplicationFolderError("Esiste già una cartella con questo nome.");
      if (action === "create" && Object.keys(folders).length >= 100) throw new ApplicationFolderError("Puoi creare fino a 100 cartelle.");
      const id = action === "create" ? `folder-${randomUUID()}` : folderId;
      folders[id] = { ...object(folders[id]), name };
      result = { folderId: id };
    } else if (action === "delete") {
      delete folders[folderId];
      for (const [key, id] of Object.entries(memberships)) if (id === folderId) delete memberships[key];
      result = { folderId: "unfiled" };
    } else if (action === "membership") {
      const key = String(payload.applicationKey || "");
      if (!applications.some(app => app.key === key)) throw new ApplicationFolderError("Applicazione non presente nel catalogo corrente.");
      if (folderId && !own(folders, folderId)) throw new ApplicationFolderError("Cartella non trovata. Aggiorna la pagina.");
      if (folderId) memberships[key] = folderId;
      else delete memberships[key];
      result = { applicationKey: key, folderId };
    } else throw new ApplicationFolderError("Operazione cartella non valida.");
    return { ...state, applicationFolders: { ...metadata, folders, memberships } };
  });
  return result;
}
