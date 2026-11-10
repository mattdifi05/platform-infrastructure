import SwiftUI

@MainActor
struct ApplicationDetailView: View {
    @Environment(AppModel.self) private var model
    let projectID: String
    let store: ApplicationsStore
    @State private var hosting: JSONValue?
    @State private var hostingError: String?
    @State private var operation: ApplicationOperation?

    private var project: JSONValue { store.project(projectID) ?? .object([:]) }
    private var route: String { "/control/projects/\(applicationPathComponent(projectID))" }
    private var databases: [JSONValue] {
        store.databases.filter { $0["projectId"].text == projectID || $0["linkedApps"].arrayValue.contains { $0.text == projectID } }
    }
    private var applications: [JSONValue] { store.applications.filter { $0["projectId"].text == projectID } }

    var body: some View {
        List {
            if store.project(projectID) == nil {
                EmptyState(title: "Applicazione rimossa", systemImage: "app.dashed", description: "L'applicazione non è più presente nel catalogo corrente.")
            } else {
                identitySection
                hostingSection
                databaseSection
                resourcesSection
                runtimeSection
                Section("Organizzazione") {
                    Menu("Sposta in cartella", systemImage: "folder") {
                        Button("Senza cartella") { move(to: "", name: "Senza cartella") }
                        ForEach(store.folders, id: \.id) { folder in Button(folder["name"].text) { move(to: folder.id, name: folder["name"].text) } }
                    }
                }
            }
            if let error = store.error { Section { ErrorNotice(message: error) } }
        }
        .navigationTitle(project["name"].stringValue ?? projectID)
        .navigationBarTitleDisplayMode(.inline)
        .refreshable { await refresh() }
        .task {
            await loadHosting()
            while !Task.isCancelled {
                do { try await Task.sleep(for: .seconds(8)) } catch { return }
                guard let hosting, hosting["privateCopy"]["cancellable"].boolValue == true else { continue }
                await loadHosting()
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    Button("Rinomina", systemImage: "pencil") { rename() }
                    Button("Archivia", systemImage: "archivebox") { archive() }
                    Button("Rimuovi dalla lista", systemImage: "rectangle.badge.minus", role: .destructive) { removeFromList() }
                    Button("Elimina dal catalogo", systemImage: "trash", role: .destructive) { deleteMetadata() }
                } label: { Label("Gestisci applicazione", systemImage: "ellipsis.circle") }
                .disabled(store.project(projectID) == nil)
            }
        }
        .sheet(item: $operation, onDismiss: { Task { await loadHosting() } }) { ApplicationOperationSheet(operation: $0, store: store) }
    }

    private var identitySection: some View {
        Section {
            ApplicationCatalogRow(value: project)
            if let url = URL(string: project["href"].stringValue ?? "https://\(project["host"].text)"), url.scheme == "https" {
                Link(destination: url) { Label("Apri applicazione", systemImage: "arrow.up.right.square") }
            }
            if !project["description"].text.isEmpty { Text(project["description"].text).foregroundStyle(.secondary) }
        }
    }

    @ViewBuilder private var hostingSection: some View {
        Section("Visibilità e copia privata") {
            if let hosting {
                let visibility = hosting["project"]["visibility"]
                LabeledContent("Visibilità effettiva") {
                    StatusPill(text: applicationLabel(visibility["effective"].text), tone: visibility["verified"].boolValue == true ? .green : .orange)
                }
                if visibility["desired"].text != visibility["effective"].text {
                    LabeledContent("Visibilità richiesta", value: applicationLabel(visibility["desired"].text))
                }
                if !visibility["updatedAt"].text.isEmpty { LabeledContent("Aggiornata", value: NativeFormatting.date(visibility["updatedAt"].text)) }
                Menu("Cambia visibilità", systemImage: "eye") {
                    Button("Pubblica") { changeVisibility("public") }
                    Button("Privata") { changeVisibility("private") }
                    Button("Offline") { changeVisibility("offline") }
                }
                let copy = hosting["privateCopy"]
                LabeledContent("Copia privata", value: applicationLabel(copy["status"].text))
                if !copy["hostname"].text.isEmpty { LabeledContent("Host copia", value: copy["hostname"].text) }
                if !copy["reason"].text.isEmpty { Text(copy["reason"].text).font(.footnote).foregroundStyle(.secondary) }
                Button("Crea copia privata", systemImage: "document.on.document") { clone() }
                    .disabled(copy["eligible"].boolValue != true)
                if copy["cancellable"].boolValue == true {
                    Button("Annulla copia privata", systemImage: "xmark.circle", role: .destructive) { cancelClone(copy["jobId"].text) }
                }
                Button("Ricontrolla hosting", systemImage: "arrow.clockwise") { Task { await loadHosting() } }
            } else if hostingError == nil {
                ProgressView("Verifica hosting…")
            }
            if let hostingError { ErrorNotice(message: hostingError, retry: { Task { await loadHosting() } }) }
        }
    }

    private var databaseSection: some View {
        Section("Database") {
            ForEach(databases, id: \.id) { database in
                NavigationLink { ApplicationDatabaseView(databaseID: database.id, store: store) } label: {
                    VStack(alignment: .leading, spacing: 5) {
                        Label(database["displayName"].text.isEmpty ? database["name"].text : database["displayName"].text, systemImage: "externaldrive")
                        Text("\(applicationLabel(database["engine"].text)) · \(database["name"].text)").font(.caption).foregroundStyle(.secondary)
                        Text("Utente: \(database["ownerRole"].text)").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            if databases.isEmpty { Text("Nessun database collegato").foregroundStyle(.secondary) }
            Button("Crea database", systemImage: "plus") { operation = ApplicationDatabaseView.createOperation(projectID: projectID) }
        }
    }

    private var resourcesSection: some View {
        let resources = store.catalog["resources"]
        let usage = resources["projectUsage"].arrayValue.first { $0["projectId"].text == projectID } ?? .null
        let containers = resources["containersByProject"].arrayValue.filter { $0["projectId"].text == projectID || $0["applicationId"].text == projectID }
        let measured = containers.filter { ["container-dedicato", "docker-stats"].contains($0["attribution"].text) }
        let memory = measured.isEmpty ? nil : measured.reduce(0) { $0 + ($1["memoryBytes"].doubleValue ?? 0) }
        let cpu = measured.isEmpty ? nil : measured.reduce(0) { $0 + ($1["cpuCores"].doubleValue ?? 0) }
        return Section("Risorse applicazione") {
            LabeledContent("CPU", value: cpu.map { $0.formatted(.number.precision(.fractionLength(2))) + " core" } ?? usage["cpuMessage"].stringValue ?? "Non disponibile")
            LabeledContent("RAM", value: memory.map { NativeFormatting.bytes($0) } ?? usage["memoryMessage"].stringValue ?? "Non disponibile")
            LabeledContent("Disco", value: usage["diskAvailable"].boolValue == true ? NativeFormatting.bytes(usage["diskBytes"].doubleValue) : "Non disponibile")
            LabeledContent("Container", value: "\(containers.filter { $0["runtimeStatus"].text == "running" }.count)/\(containers.count) in esecuzione")
            ForEach(Array(containers.enumerated()), id: \.offset) { _, container in
                NavigationLink(container["container"].stringValue ?? "Container") { JSONDetailView(title: "Container", value: container) }
            }
            if !usage.objectValue.isEmpty { NavigationLink("Dettagli risorse") { JSONDetailView(title: "Risorse", value: usage) } }
        }
    }

    private var runtimeSection: some View {
        Section("Runtime e deploy") {
            ForEach(applications, id: \.id) { app in
                NavigationLink { ApplicationRuntimeView(applicationID: app.id, store: store) } label: {
                    VStack(alignment: .leading) {
                        Text(app["name"].text)
                        Text("\(applicationLabel(app["runtime"].text)) · \(applicationLabel(app["status"].text))").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            Button("Aggiungi runtime", systemImage: "plus") { createRuntime() }
        }
    }

    private func refresh() async { await store.load(model); await loadHosting() }
    private func loadHosting() async {
        do { hosting = try await model.get("\(route)/hosting-status"); hostingError = nil }
        catch is CancellationError { }
        catch { hostingError = error.localizedDescription }
    }
    private func changeVisibility(_ mode: String) {
        operation = ApplicationOperation(title: "Visibilità \(applicationLabel(mode).lowercased())", explanation: "Modifica la visibilità di \(project["host"].text). Rivedi il piano corrente prima di confermare.", path: "\(route)/visibility", body: ["mode": .string(mode)], fresh: true, destructive: mode == "offline", planPath: "\(route)/hosting-plan?mode=\(mode)", planGET: true, visibilityPlan: true)
    }
    private func clone() {
        operation = ApplicationOperation(title: "Copia privata", explanation: "Crea una copia privata indipendente di \(project["name"].text), protetta prima della pubblicazione. Segui lo stato in questa schermata.", path: "\(route)/clone", confirmation: "CLONE-PRIVATE:\(projectID)", fresh: true)
    }
    private func cancelClone(_ jobID: String) {
        operation = ApplicationOperation(title: "Annulla copia", explanation: "Richiede l'annullamento della copia privata. Il completamento viene verificato dal server.", path: "\(route)/clone/\(applicationPathComponent(jobID))/cancel", confirmation: "CANCEL-CLONE:\(jobID)", fresh: true, destructive: true)
    }
    private func rename() {
        operation = ApplicationOperation(title: "Rinomina applicazione", explanation: "Modifica il nome visualizzato nel catalogo.", path: "\(route)/update", fields: [.init(key: "displayName", title: "Nome", value: project["name"].text)], confirmation: "UPDATE-PROJECT", planPath: "\(route)/update")
    }
    private func archive() {
        operation = ApplicationOperation(title: "Archivia applicazione", explanation: "Archivia la voce e disabilita il routing locale nei metadati. I file vengono conservati.", path: "\(route)/archive/apply", confirmation: "ARCHIVE-PROJECT", destructive: true, planPath: "\(route)/archive/plan")
    }
    private func removeFromList() {
        operation = ApplicationOperation(title: "Rimuovi dalla lista", explanation: "Rimuove \(project["name"].text) dalla lista Applicazioni. Hosting, dati e container restano attivi.", path: "\(route)/list/remove", confirmation: "REMOVE-FROM-LIST:\(projectID)", fresh: true, destructive: true)
    }
    private func deleteMetadata() {
        operation = ApplicationOperation(title: "Elimina dal catalogo", explanation: "Rimuove la voce dal catalogo e disabilita il routing locale nei metadati. File e database vengono conservati.", path: "\(route)/delete/apply", confirmation: "DELETE-PROJECT:\(projectID)", destructive: true, planPath: "\(route)/delete/plan", requiresTypedName: projectID)
    }
    private func move(to folderID: String, name: String) {
        operation = ApplicationOperation(title: "Sposta applicazione", explanation: "Sposta l'applicazione in \(name).", path: "/control/project-folders/membership", body: ["applicationKey": .string("project:\(projectID)"), "folderId": .string(folderID)])
    }
    private func createRuntime() {
        operation = ApplicationOperation(title: "Nuovo runtime", explanation: "Dichiara un runtime applicativo nel catalogo. Il server configura solo i metadati.", path: "/control/applications", body: ["projectId": .string(projectID)], fields: [
            .init(key: "name", title: "Identificativo"), .init(key: "displayName", title: "Nome visualizzato"),
            .init(key: "runtime", title: "Runtime", value: "node", kind: .choices(["node", "php", "static", "api", "worker"])),
            .init(key: "host", title: "Host", required: false), .init(key: "repositoryUrl", title: "Repository", required: false),
            .init(key: "webspaceId", title: "Webspace", required: false)
        ], confirmation: "CREATE-APPLICATION", planPath: "/control/applications")
    }
}

@MainActor
struct ApplicationRuntimeView: View {
    let applicationID: String
    let store: ApplicationsStore
    @State private var operation: ApplicationOperation?
    private var app: JSONValue { store.applications.first { $0.id == applicationID } ?? .null }
    var body: some View {
        List {
            Section("Runtime") {
                LabeledContent("Nome", value: app["name"].text)
                LabeledContent("Runtime", value: applicationLabel(app["runtime"].text))
                LabeledContent("Stato", value: applicationLabel(app["status"].text))
                LabeledContent("Healthcheck", value: app["healthStatus"].text.isEmpty ? "Non verificato" : app["healthStatus"].text)
                if !app["lastLifecycleAt"].text.isEmpty { LabeledContent("Ultima operazione", value: NativeFormatting.date(app["lastLifecycleAt"].text)) }
            }
            Section {
                Button("Avvia", systemImage: "play") { lifecycle("start", title: "Avvia") }
                Button("Arresta", systemImage: "stop", role: .destructive) { lifecycle("stop", title: "Arresta") }
                Button("Riavvia", systemImage: "arrow.clockwise") { lifecycle("restart", title: "Riavvia") }
                Button("Healthcheck", systemImage: "heart.text.clipboard") { lifecycle("healthcheck", title: "Healthcheck") }
            } header: { Text("Ciclo di vita") } footer: { Text("Queste azioni aggiornano i metadati del catalogo. L'esito del server indica separatamente se sono stati eseguiti comandi reali.") }
            Section("Deploy") {
                Button("Prepara deploy", systemImage: "shippingbox") { deployment("deploy") }
                Button("Prepara rollback", systemImage: "arrow.uturn.backward") { deployment("rollback") }
                Text("Il server genera un piano e registra la richiesta; non esegue il deploy in produzione.").font(.footnote).foregroundStyle(.secondary)
            }
            Section { NavigationLink("Dettagli runtime") { JSONDetailView(title: "Runtime", value: app) } }
        }
        .navigationTitle(app["name"].stringValue ?? applicationID)
        .sheet(item: $operation) { ApplicationOperationSheet(operation: $0, store: store) }
    }
    private func lifecycle(_ action: String, title: String) {
        let path = "/control/applications/\(applicationPathComponent(applicationID))/\(action)"
        operation = ApplicationOperation(title: title, explanation: "Rivedi l'aggiornamento di \(app["name"].text). Questa funzione gestisce i metadati del ciclo di vita.", path: path, confirmation: "\(action.uppercased())-APPLICATION:\(applicationID)", destructive: action == "stop", planPath: path)
    }
    private func deployment(_ action: String) {
        let path = "/control/applications/\(applicationPathComponent(applicationID))/\(action)"
        let fields: [ApplicationField] = action == "deploy" ? [.init(key: "branch", title: "Branch", value: "local"), .init(key: "commit", title: "Commit", value: "unresolved-local")] : [.init(key: "rollbackTarget", title: "Release di destinazione", value: "previous-approved-release")]
        operation = ApplicationOperation(title: action == "deploy" ? "Piano deploy" : "Piano rollback", explanation: "Genera il piano del server per \(app["name"].text).", path: path, fields: fields, planPath: path, planOnly: true)
    }
}
