import SwiftUI

@MainActor
struct ApplicationsView: View {
    @Environment(AppModel.self) private var model
    @State private var store = ApplicationsStore()
    @State private var search = ""
    @State private var selectedFolder = "all"
    @State private var operation: ApplicationOperation?

    var body: some View {
        let filtered = filteredEntries
        let entriesByFolder = Dictionary(grouping: filtered) { store.memberships[$0.id].text }
        List {
            if let error = store.error {
                Section { ErrorNotice(message: error) { Task { await store.load(model) } } }
            }
            if !store.hasLoaded {
                if store.error == nil { LoadingState(title: "Caricamento applicazioni…") }
            } else {
                folderFilter
                ForEach(visibleGroups) { folder in
                    let entries = entriesByFolder[folder.id, default: []]
                    if !entries.isEmpty || (search.isEmpty && (!folder.id.isEmpty || selectedFolder.isEmpty)) {
                        Section {
                            ForEach(entries) { entry in applicationRow(entry) }
                            if entries.isEmpty { Text("Cartella vuota").foregroundStyle(.secondary) }
                        } header: {
                            folderHeader(folder)
                        }
                    }
                }
                if !search.isEmpty && filtered.isEmpty {
                    EmptyState(title: "Nessun risultato", systemImage: "magnifyingglass", description: "Prova un altro nome o indirizzo.")
                } else if allEntries.isEmpty && store.folders.isEmpty && selectedFolder == "all" {
                    EmptyState(title: "Nessuna applicazione", systemImage: "app.dashed", description: "Le applicazioni del server appariranno qui.")
                }
            }
        }
        .navigationTitle("Applicazioni")
        .searchable(text: $search, prompt: "Nome o indirizzo")
        .skeletonRefreshable { await store.load(model) }
        .task { if !store.hasLoaded { await store.load(model) } }
        .onChange(of: store.folders.map(\.id)) { _, folderIDs in
            if selectedFolder != "all" && !selectedFolder.isEmpty && !folderIDs.contains(selectedFolder) {
                selectedFolder = "all"
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("Nuova cartella", systemImage: "folder.badge.plus", action: createFolder)
                    .labelStyle(.iconOnly)
                    .disabled(!store.hasLoaded)
            }
        }
        .sheet(item: $operation) { ApplicationOperationSheet(operation: $0, store: store) }
    }

    private struct Folder: Identifiable {
        let id: String
        let name: String
        let canDelete: Bool
    }

    private struct Entry: Identifiable {
        let value: JSONValue
        let observed: Bool
        var slug: String { observed ? value.id : value["slug"].stringValue ?? value.id }
        var id: String { "\(observed ? "observed" : "project"):\(slug)" }
        var name: String { value["name"].stringValue ?? slug }
        var host: String {
            if let host = value["host"].stringValue, !host.isEmpty { return host }
            return URL(string: value["siteOrigin"].text)?.host ?? ""
        }
    }

    private var allEntries: [Entry] {
        let projects = store.projects
        let managed = projects.map { Entry(value: $0, observed: false) }
        let observed = store.observed.filter { app in
            !projects.contains { project in
                project["slug"].text == app.id || project["aliases"].arrayValue.contains { $0.text == app.id }
            }
        }.map { Entry(value: $0, observed: true) }
        return (managed + observed).sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    private var filteredEntries: [Entry] {
        allEntries.filter { entry in
            let folder = store.memberships[entry.id].text
            let matchesFolder = selectedFolder == "all" || folder == selectedFolder
            let matchesSearch = search.isEmpty || [entry.name, entry.host].contains { $0.localizedStandardContains(search) }
            return matchesFolder && matchesSearch
        }
    }

    private var folders: [Folder] {
        store.folders.map { Folder(id: $0.id, name: $0["name"].text, canDelete: $0["canDelete"].boolValue == true) }
    }

    private var unfiled: Folder { Folder(id: "", name: "Senza cartella", canDelete: false) }

    private var visibleGroups: [Folder] {
        (folders + [unfiled]).filter { selectedFolder == "all" || $0.id == selectedFolder }
    }

    private var folderFilter: some View {
        Section {
            Picker("Cartella", selection: $selectedFolder) {
                Text("Tutte").tag("all")
                Text(unfiled.name).tag(unfiled.id)
                ForEach(folders) { folder in Text(folder.name).tag(folder.id) }
            }
        }
    }

    private func folderHeader(_ folder: Folder) -> some View {
        HStack {
            Label(folder.name, systemImage: "folder")
            Spacer()
            if !folder.id.isEmpty {
                Menu {
                    Button("Rinomina", systemImage: "pencil") { renameFolder(folder) }
                    Button("Elimina cartella", systemImage: "trash", role: .destructive) { deleteFolder(folder) }
                        .disabled(!folder.canDelete)
                } label: {
                    Image(systemName: "ellipsis.circle").font(.body)
                }
                .accessibilityLabel("Gestisci \(folder.name)")
            }
        }
    }

    private func applicationRow(_ entry: Entry) -> some View {
        NavigationLink {
            ApplicationDetailView(projectID: entry.slug, observed: entry.observed, store: store)
        } label: {
            ApplicationCatalogRow(value: entry.value)
        }
        .accessibilityIdentifier("application.row.\(entry.id)")
        .contextMenu {
            if !folders.isEmpty {
                Menu("Sposta in cartella", systemImage: "folder") {
                    let current = store.memberships[entry.id].text
                    ForEach([unfiled] + folders) { folder in
                        Button {
                            move(entry, to: folder)
                        } label: {
                            Label(folder.name, systemImage: folder.id == current ? "checkmark" : "folder")
                        }
                        .disabled(folder.id == current)
                    }
                }
            }
        }
    }

    private func move(_ entry: Entry, to folder: Folder) {
        operation = ApplicationOperation(title: "Sposta applicazione", explanation: "Sposta \(entry.name) in \(folder.name).", path: "/control/project-folders/membership", body: ["applicationKey": .string(entry.id), "folderId": .string(folder.id)])
    }

    private func createFolder() {
        operation = ApplicationOperation(title: "Nuova cartella", explanation: "Organizza le applicazioni in una cartella.", path: "/control/project-folders", fields: [.init(key: "name", title: "Nome cartella")])
    }

    private func renameFolder(_ folder: Folder) {
        operation = ApplicationOperation(title: "Rinomina cartella", explanation: "Modifica il nome di \(folder.name).", path: "/control/project-folders/\(applicationPathComponent(folder.id))/rename", fields: [.init(key: "name", title: "Nome cartella", value: folder.name)])
    }

    private func deleteFolder(_ folder: Folder) {
        operation = ApplicationOperation(title: "Elimina cartella", explanation: "Elimina la cartella vuota \(folder.name).", path: "/control/project-folders/\(applicationPathComponent(folder.id))/delete", destructive: true)
    }
}

@MainActor
struct ApplicationCatalogRow: View {
    let value: JSONValue

    var body: some View {
        HStack(spacing: 12) {
            ApplicationIcon(entry: value)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(value["name"].stringValue ?? value.id)
                    .font(.headline)
                    .foregroundStyle(.primary)
                let host = value["host"].stringValue ?? applicationSiteURL(value)?.host ?? ""
                if !host.isEmpty { Text(host).font(.subheadline).foregroundStyle(.secondary) }
            }
        }
        .padding(.vertical, 4)
    }
}
