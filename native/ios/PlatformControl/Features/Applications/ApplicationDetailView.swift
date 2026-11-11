import SwiftUI

@MainActor
struct ApplicationDetailView: View {
    @Environment(AppModel.self) private var model
    let projectID: String
    let observed: Bool
    let store: ApplicationsStore
    @State private var hosting: JSONValue?
    @State private var hostingError: String?
    @State private var isLoadingHosting = false
    @State private var scopedDatabases: [JSONValue]?
    @State private var isLoadingDatabases = false
    @State private var databaseLookupFailed = false
    @State private var operation: ApplicationOperation?

    private var entry: JSONValue? {
        observed ? store.observed.first { $0.id == projectID } : store.project(projectID)
    }
    private var route: String { "/control/projects/\(applicationPathComponent(projectID))" }
    private var membershipKey: String { "\(observed ? "observed" : "project"):\(projectID)" }

    var body: some View {
        List {
            if let entry {
                identitySection(entry)
                hostingSection
                resourcesSection
                databaseSection(entry)
                if !store.folders.isEmpty { organizationSection }
            } else {
                EmptyState(title: "Applicazione rimossa", systemImage: "app.dashed", description: "L’applicazione non è più presente nel catalogo.")
            }
            if let error = store.detailError {
                Section { ErrorNotice(message: error) { Task { await store.loadDetails(model, force: true) } } }
            }
            if let error = store.error {
                Section { ErrorNotice(message: error) { Task { await refresh() } } }
            }
        }
        .navigationTitle(entry?["name"].stringValue ?? projectID)
        .navigationBarTitleDisplayMode(.inline)
        .skeletonRefreshable { await refresh() }
        .task(id: store.detailsRevision) { await store.loadDetails(model) }
        .task { await loadHosting() }
        .task { await loadDatabases() }
        .task(id: copyInProgress) {
            guard copyInProgress else { return }
            while !Task.isCancelled {
                do { try await Task.sleep(for: .seconds(8)) } catch { return }
                await loadHosting()
            }
        }
        .sheet(item: $operation, onDismiss: { Task { await loadHosting() } }) {
            ApplicationOperationSheet(operation: $0, store: store)
        }
    }

    private func identitySection(_ entry: JSONValue) -> some View {
        let runtimes = store.applications.filter { $0["projectId"].text == projectID || $0.id == projectID }
        let runtimeNames = Set(([entry["runtime"].text] + runtimes.map { $0["runtime"].text }).filter { !$0.isEmpty })
            .map(applicationLabel).sorted()
        return Section {
            ApplicationCatalogRow(value: entry)
            if let url = applicationSiteURL(entry) {
                Link(destination: url) { Label("Apri applicazione", systemImage: "arrow.up.right.square") }
                    .accessibilityIdentifier("application.site")
            }
            LabeledContent("Runtime", value: runtimeNames.isEmpty ? "Non disponibile" : runtimeNames.joined(separator: ", "))
            if !entry["description"].text.isEmpty {
                Text(entry["description"].text).foregroundStyle(.secondary)
            }
        }
    }

    private var copyInProgress: Bool {
        guard let copy = hosting?["privateCopy"] else { return false }
        return ["authorized", "queued", "running", "staged", "activating", "copying"].contains(copy["status"].text)
    }

    private var hostingSection: some View {
        Section("Visibilità") {
            if let hosting, hostingError == nil {
                let visibility = hosting["project"]["visibility"]
                let mode = visibility["effective"].text
                let verified = visibility["verified"].boolValue == true
                let desired = visibility["desired"].text
                let managedHosting = !hosting["project"]["productionHostname"].text.isEmpty
                LabeledContent("Stato attuale") {
                    StatusPill(
                        text: verified ? applicationLabel(mode) : "Non verificata",
                        tone: verified ? (mode == "offline" ? .gray : .green) : .orange
                    )
                }
                if ["public", "private", "offline"].contains(desired), desired != mode || !verified {
                    LabeledContent("Visibilità richiesta", value: applicationLabel(desired))
                }
                if managedHosting {
                    Menu("Cambia visibilità", systemImage: "eye") {
                        ForEach(["public", "private", "offline"], id: \.self) { option in
                            Button {
                                changeVisibility(option)
                            } label: {
                                Label(applicationLabel(option), systemImage: option == mode && verified ? "checkmark" : visibilityIcon(option))
                            }
                            .disabled(option == mode && verified && desired == mode)
                        }
                    }
                }
                let copy = hosting["privateCopy"]
                if (verified && mode == "public") || (copy["status"] != .null && copy["status"].text != "absent") {
                    privateCopyRows(copy, sourceIsPublic: verified && mode == "public")
                }
            } else if isLoadingHosting || hostingError == nil {
                LabeledContent("Stato attuale") {
                    StatusPill(text: "Visibilità", tone: .secondary)
                }
                .contentSkeleton("Verifica hosting…")
            }
            if let hostingError {
                ErrorNotice(message: hostingError) { Task { await loadHosting() } }
            }
        }
    }

    @ViewBuilder private func privateCopyRows(_ copy: JSONValue, sourceIsPublic: Bool) -> some View {
        let status = copy["status"].text
        let host = copy["hostname"].text
        if !status.isEmpty, status != "absent" {
            LabeledContent("Copia privata", value: applicationLabel(status))
        }
        if status == "available", !host.isEmpty, let url = applicationSiteURL(.object(["host": .string(host)])) {
            Link(destination: url) { Label("Apri copia privata", systemImage: "arrow.up.right.square") }
        } else if status != "absent", !host.isEmpty {
            LabeledContent("Indirizzo copia", value: host)
        }
        if sourceIsPublic, status == "absent" {
            if copy["eligible"].boolValue == true {
                Button("Crea copia privata", systemImage: "document.on.document") { clone() }
            } else {
                LabeledContent("Copia privata", value: "Non disponibile")
            }
        }
        if copy["cancellable"].boolValue == true, !copy["jobId"].text.isEmpty {
            Button("Annulla copia privata", systemImage: "xmark.circle", role: .destructive) { cancelClone(copy["jobId"].text) }
        }
    }

    private var resourcesSection: some View {
        let resources = store.catalog["resources"]
        let usage = resources["projectUsage"].arrayValue.first { $0["projectId"].text == projectID } ?? .null
        let attributed = resources["containersByProject"].arrayValue.filter {
            ($0["projectId"].text == projectID || $0["applicationId"].text == projectID)
                && ["container-dedicato", "docker-stats"].contains($0["attribution"].text)
        }
        let containers = Dictionary(grouping: attributed) { $0["container"].text }
            .values.compactMap { matches in matches.first { $0["attribution"].text == "container-dedicato" } ?? matches.first }
        let memory = measuredTotal("memoryBytes", in: containers)
        let cpu = measuredTotal("cpuCores", in: containers)
        let disk = usage["diskAvailable"].boolValue == true ? usage["diskBytes"].doubleValue : nil
        let diskIsPartial = usage["diskComplete"].boolValue == false || usage["diskTruncated"].boolValue == true
        let diskIsStale = usage["diskStale"].boolValue == true
        return Section {
            Group {
                LabeledContent("CPU", value: cpu.map { $0.formatted(.number.precision(.fractionLength(0...3))) + " core" } ?? "Non disponibile")
                LabeledContent("RAM", value: memory.map { NativeFormatting.bytes($0) } ?? "Non disponibile")
                LabeledContent("Spazio dei file", value: disk.map { NativeFormatting.bytes($0) } ?? "Non disponibile")
                if let files = usage["files"].intValue, disk != nil {
                    LabeledContent("File rilevati", value: files.formatted())
                }
                if disk != nil, diskIsPartial || diskIsStale {
                    Text(diskIsPartial ? "Scansione dei file parziale" : "Scansione dei file da aggiornare")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                if !containers.isEmpty {
                    LabeledContent("Container", value: "\(containers.filter { $0["runtimeStatus"].text == "running" }.count) di \(containers.count) in esecuzione")
                }
            }
            .contentSkeleton(!store.hasLoadedDetails && store.detailError == nil, title: "Caricamento risorse…")
        } header: {
            Text("Risorse applicazione")
        } footer: {
            if let capturedAt = resources["capturedAt"].stringValue, cpu != nil || memory != nil {
                Text("Metriche container rilevate il \(NativeFormatting.date(capturedAt))")
            }
        }
    }

    private func measuredTotal(_ key: String, in containers: [JSONValue]) -> Double? {
        let samples = containers.compactMap { $0[key].doubleValue }.filter { $0.isFinite && $0 >= 0 }
        guard !samples.isEmpty, samples.count == containers.count else { return nil }
        return samples.reduce(0, +)
    }

    private func databaseSection(_ entry: JSONValue) -> some View {
        let identities = Set([projectID, entry.id] + entry["aliases"].arrayValue.map(\.text)).subtracting([""])
        let databases = scopedDatabases ?? store.databases.filter { database in
            identities.contains(database["projectId"].text)
                || database["linkedApps"].arrayValue.contains { identities.contains($0.text) }
        }
        return Section("Database") {
            if databaseLookupFailed {
                Text("Verifica dei database non disponibile").font(.footnote).foregroundStyle(.secondary)
            }
            if databases.isEmpty {
                if scopedDatabases == nil, !databaseLookupFailed {
                    NavigationLink(destination: EmptyView()) {
                        databaseRow(.object([
                            "name": .string("Database applicazione"),
                            "engine": .string("postgresql")
                        ]))
                    }
                    .contentSkeleton("Verifica database…")
                } else {
                    Text("Nessun database collegato nel catalogo").foregroundStyle(.secondary)
                }
            }
            ForEach(databases, id: \.id) { database in
                NavigationLink {
                    ApplicationDatabaseView(databaseID: database.id, store: store, scopedDatabase: database)
                } label: {
                    databaseRow(database)
                }
                .accessibilityIdentifier("application.database.\(database.id)")
            }
        }
    }

    private func databaseRow(_ database: JSONValue) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(applicationDatabaseName(database)).font(.headline)
            Text([applicationLabel(database["engine"].text), database["adminTool"]["label"].text, applicationDatabaseSize(database)]
                .filter { !$0.isEmpty }.joined(separator: " · "))
                .font(.subheadline).foregroundStyle(.secondary)
        }
    }

    private var organizationSection: some View {
        Section("Organizzazione") {
            Menu("Sposta in cartella", systemImage: "folder") {
                let current = store.memberships[membershipKey].text
                Button("Senza cartella") { move(to: "", name: "Senza cartella") }.disabled(current.isEmpty)
                ForEach(store.folders, id: \.id) { folder in
                    Button(folder["name"].text) { move(to: folder.id, name: folder["name"].text) }.disabled(folder.id == current)
                }
            }
        }
    }

    private func refresh() async {
        await store.load(model)
        async let details: Void = store.loadDetails(model, force: true)
        async let visibility: Void = loadHosting()
        async let databases: Void = loadDatabases()
        _ = await (details, visibility, databases)
    }

    private func loadDatabases() async {
        guard entry != nil, !isLoadingDatabases else { return }
        isLoadingDatabases = true
        defer { isLoadingDatabases = false }
        do {
            let response = try await model.get("/api/native/v1/applications/\(applicationPathComponent(projectID))/databases")
            guard !Task.isCancelled else { return }
            guard case .array(let databases) = response["databases"] else {
                throw APIError(status: 0, message: "Elenco database non disponibile.")
            }
            scopedDatabases = databases
            databaseLookupFailed = false
        } catch is CancellationError { }
        catch { if !Task.isCancelled { databaseLookupFailed = true } }
    }

    private func loadHosting() async {
        guard entry != nil, !isLoadingHosting else { return }
        isLoadingHosting = true
        defer { isLoadingHosting = false }
        do {
            let response = try await model.get("\(route)/hosting-status")
            guard !Task.isCancelled else { return }
            guard case .object = response["project"]["visibility"] else {
                throw APIError(status: 0, message: "Stato hosting non disponibile.")
            }
            hosting = response
            hostingError = nil
        } catch is CancellationError { }
        catch { if !Task.isCancelled { hostingError = error.localizedDescription } }
    }

    private func visibilityIcon(_ mode: String) -> String {
        switch mode {
        case "public": "globe"
        case "private": "lock"
        default: "power"
        }
    }

    private func changeVisibility(_ mode: String) {
        let host = hosting?["project"]["productionHostname"].text ?? projectID
        operation = ApplicationOperation(title: "Visibilità \(applicationLabel(mode).lowercased())", explanation: "Rivedi il piano per \(host) prima di confermare.", path: "\(route)/visibility", body: ["mode": .string(mode)], fresh: true, destructive: mode == "offline", planPath: "\(route)/hosting-plan?mode=\(mode)", planGET: true, visibilityPlan: true)
    }

    private func clone() {
        operation = ApplicationOperation(title: "Copia privata", explanation: "Crea una copia indipendente di \(entry?["name"].text ?? projectID), protetta prima della pubblicazione.", path: "\(route)/clone", confirmation: "CLONE-PRIVATE:\(projectID)", fresh: true)
    }

    private func cancelClone(_ jobID: String) {
        operation = ApplicationOperation(title: "Annulla copia privata", explanation: "Richiedi l’annullamento della copia privata.", path: "\(route)/clone/\(applicationPathComponent(jobID))/cancel", confirmation: "CANCEL-CLONE:\(jobID)", fresh: true, destructive: true)
    }

    private func move(to folderID: String, name: String) {
        operation = ApplicationOperation(title: "Sposta applicazione", explanation: "Sposta l’applicazione in \(name).", path: "/control/project-folders/membership", body: ["applicationKey": .string(membershipKey), "folderId": .string(folderID)])
    }
}
