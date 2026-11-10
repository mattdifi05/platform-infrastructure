import SwiftUI

@MainActor
struct ApplicationsView: View {
    @Environment(AppModel.self) private var model
    @State private var store = ApplicationsStore()
    @State private var search = ""
    @State private var selectedFolder = "all"
    @State private var operation: ApplicationOperation?

    var body: some View {
        List {
                if let error = store.error { ErrorNotice(message: error, retry: { Task { await store.load(model) } }) }
                if store.isLoading && !store.hasLoaded { LoadingState(title: "Caricamento applicazioni…") }
                Section {
                    Picker("Cartella", selection: $selectedFolder) {
                        Text("Tutte").tag("all")
                        Text("Senza cartella").tag("")
                        ForEach(store.folders, id: \.id) { folder in Text(folder["name"].text).tag(folder.id) }
                    }
                }
                ForEach(visibleGroups, id: \.id) { folder in
                    let entries = entries(in: folder.id)
                    if !entries.isEmpty || selectedFolder != "all" {
                        Section {
                            ForEach(entries) { entry in
                                if entry.observed {
                                    NavigationLink {
                                        ObservedApplicationView(application: entry.value, store: store)
                                    } label: { ApplicationCatalogRow(value: entry.value, observed: true) }
                                    .contextMenu { moveMenu(entry) }
                                } else {
                                    NavigationLink {
                                        ApplicationDetailView(projectID: entry.slug, store: store)
                                    } label: { ApplicationCatalogRow(value: entry.value) }
                                    .contextMenu { moveMenu(entry) }
                                }
                            }
                            if entries.isEmpty { Text("Cartella vuota").foregroundStyle(.secondary) }
                        } header: {
                            HStack {
                                Label(folder.name, systemImage: "folder")
                                Spacer()
                                Text("\(entries.count)")
                                if !folder.id.isEmpty {
                                    Menu {
                                        Button("Rinomina", systemImage: "pencil") { renameFolder(folder) }
                                        Button("Elimina cartella", systemImage: "trash", role: .destructive) { deleteFolder(folder) }
                                            .disabled(!folder.canDelete)
                                    } label: { Image(systemName: "ellipsis.circle") }
                                    .accessibilityLabel("Gestisci \(folder.name)")
                                }
                            }
                        }
                    }
                }
                if store.hasLoaded && filteredEntries.isEmpty {
                    EmptyState(title: "Nessuna applicazione", systemImage: "app.dashed", description: search.isEmpty ? "Crea un'applicazione o scegli un'altra cartella." : "Nessun risultato per questa ricerca.")
                }
                Section("Servizi") {
                    NavigationLink { ApplicationRedisView(store: store) } label: { Label("Redis", systemImage: "memorychip") }
                }
            }
            .navigationTitle("Applicazioni")
            .searchable(text: $search, prompt: "Nome, host o runtime")
            .refreshable { await store.load(model) }
            .task { if !store.hasLoaded { await store.load(model) } }
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Menu {
                        Button("Nuova applicazione", systemImage: "plus.app") { createProject() }
                        Button("Nuova cartella", systemImage: "folder.badge.plus") { createFolder() }
                    } label: { Label("Aggiungi", systemImage: "plus") }
                }
            }
            .sheet(item: $operation) { ApplicationOperationSheet(operation: $0, store: store) }
    }

    private struct Folder: Identifiable {
        var id: String
        var name: String
        var canDelete: Bool
    }
    private struct Entry: Identifiable {
        let value: JSONValue
        let observed: Bool
        var slug: String { value["slug"].stringValue ?? value.id }
        var id: String { "\(observed ? "observed" : "project"):\(slug)" }
    }
    private var allEntries: [Entry] {
        let managed = store.projects.map { Entry(value: $0, observed: false) }
        let observed = store.observed.filter { app in
            !store.projects.contains { project in
                project["slug"].text == app.id || project["aliases"].arrayValue.contains { $0.text == app.id }
            }
        }.map { Entry(value: $0, observed: true) }
        return (managed + observed).sorted { $0.value["name"].text.localizedStandardCompare($1.value["name"].text) == .orderedAscending }
    }
    private var filteredEntries: [Entry] {
        allEntries.filter { entry in
            let folder = store.memberships[entry.id].text
            let matchesFolder = selectedFolder == "all" || folder == selectedFolder
            let searchable = [entry.value["name"].text, entry.slug, entry.value["host"].text, entry.value["runtime"].text].joined(separator: " ")
            return matchesFolder && (search.isEmpty || searchable.localizedStandardContains(search))
        }
    }
    private var visibleGroups: [Folder] {
        let groups = store.folders.map { Folder(id: $0.id, name: $0["name"].text, canDelete: $0["canDelete"].boolValue == true) }
            + [Folder(id: "", name: "Senza cartella", canDelete: false)]
        return groups.filter { selectedFolder == "all" || $0.id == selectedFolder }
    }
    private func entries(in folderID: String) -> [Entry] { filteredEntries.filter { store.memberships[$0.id].text == folderID } }

    @ViewBuilder private func moveMenu(_ entry: Entry) -> some View {
        Menu("Sposta in cartella", systemImage: "folder") {
            Button("Senza cartella") { move(entry, to: "", name: "Senza cartella") }
            ForEach(store.folders, id: \.id) { folder in
                Button(folder["name"].text) { move(entry, to: folder.id, name: folder["name"].text) }
            }
        }
    }
    private func move(_ entry: Entry, to folderID: String, name: String) {
        operation = ApplicationOperation(title: "Sposta applicazione", explanation: "Sposta \(entry.value["name"].text) nella cartella \(name).", path: "/control/project-folders/membership", body: ["applicationKey": .string(entry.id), "folderId": .string(folderID)])
    }
    private func createFolder() {
        operation = ApplicationOperation(title: "Nuova cartella", explanation: "Organizza le applicazioni in una cartella.", path: "/control/project-folders", fields: [.init(key: "name", title: "Nome cartella")])
    }
    private func renameFolder(_ folder: Folder) {
        operation = ApplicationOperation(title: "Rinomina cartella", explanation: "Modifica il nome di \(folder.name).", path: "/control/project-folders/\(applicationPathComponent(folder.id))/rename", fields: [.init(key: "name", title: "Nome cartella", value: folder.name)])
    }
    private func deleteFolder(_ folder: Folder) {
        operation = ApplicationOperation(title: "Elimina cartella", explanation: "Elimina la cartella vuota \(folder.name). Il server verifica nuovamente che non contenga applicazioni.", path: "/control/project-folders/\(applicationPathComponent(folder.id))/delete", destructive: true)
    }
    private func createProject() {
        operation = ApplicationOperation(title: "Nuova applicazione", explanation: "Dichiara l'applicazione nel catalogo. La creazione configura i metadati; il server non avvia container o deploy.", path: "/control/projects", fields: [
            .init(key: "displayName", title: "Nome"), .init(key: "slug", title: "Identificativo"),
            .init(key: "runtime", title: "Runtime", value: "node", kind: .choices(["node", "php", "static"])),
            .init(key: "host", title: "Host", required: false), .init(key: "description", title: "Descrizione", kind: .multiline, required: false)
        ], confirmation: "CREATE-PROJECT", planPath: "/control/projects")
    }
}

@MainActor
struct ApplicationCatalogRow: View {
    let value: JSONValue
    var observed = false
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "app.fill").font(.title2).foregroundStyle(.tint).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(value["name"].stringValue ?? value.id).font(.headline)
                if !value["host"].text.isEmpty { Text(value["host"].text).font(.subheadline).foregroundStyle(.secondary) }
                Text([applicationLabel(value["runtime"].text), observed ? "Rilevata sul VPS" : applicationLabel(value["status"].text)].filter { !$0.isEmpty }.joined(separator: " · "))
                    .font(.caption).foregroundStyle(.secondary)
            }
        }.padding(.vertical, 3)
    }
}

@MainActor
struct ObservedApplicationView: View {
    let application: JSONValue
    let store: ApplicationsStore
    @State private var operation: ApplicationOperation?
    var body: some View {
        List {
            Section("Applicazione rilevata") {
                LabeledContent("Nome", value: application["name"].stringValue ?? application.id)
                LabeledContent("Host", value: application["host"].text)
                LabeledContent("Runtime", value: applicationLabel(application["runtime"].text))
                if !application["status"].text.isEmpty { LabeledContent("Stato", value: applicationLabel(application["status"].text)) }
            }
            Section("Cartella") {
                Menu("Sposta in cartella", systemImage: "folder") {
                    Button("Senza cartella") { move(to: "", name: "Senza cartella") }
                    ForEach(store.folders, id: \.id) { folder in Button(folder["name"].text) { move(to: folder.id, name: folder["name"].text) } }
                }
            }
            Section {
                Text("Questa applicazione è stata rilevata nel catalogo VPS. I controlli di gestione sono disponibili solo per le applicazioni ammesse dal server.").foregroundStyle(.secondary)
                NavigationLink("Dettagli rilevati") { JSONDetailView(title: "Applicazione", value: application) }
            }
        }
        .navigationTitle(application["name"].stringValue ?? application.id)
        .sheet(item: $operation) { ApplicationOperationSheet(operation: $0, store: store) }
    }
    private func move(to folderID: String, name: String) {
        operation = ApplicationOperation(title: "Sposta applicazione", explanation: "Sposta l'applicazione in \(name).", path: "/control/project-folders/membership", body: ["applicationKey": .string("observed:\(application.id)"), "folderId": .string(folderID)])
    }
}
