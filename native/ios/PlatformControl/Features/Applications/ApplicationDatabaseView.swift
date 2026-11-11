import SwiftUI

@MainActor
struct ApplicationDatabaseView: View {
    @Environment(AppModel.self) private var model
    let databaseID: String
    let store: ApplicationsStore
    var scopedDatabase: JSONValue? = nil
    @State private var operation: ApplicationOperation?
    private var database: JSONValue { scopedDatabase ?? store.databases.first { $0.id == databaseID } ?? .null }
    private var deleteOperations: [JSONValue] {
        let value = store.catalog["destructiveOperations"]
        let items = value.arrayValue.isEmpty ? Array(value.objectValue.values) : value.arrayValue
        return items.filter { $0["database"]["id"].text == databaseID }
    }
    private var isExternal: Bool { database["source"].text.contains("external") || database["external"].boolValue == true }

    var body: some View {
        Group {
            if scopedDatabase == nil {
                databaseList.skeletonRefreshable { await store.loadDetails(model, force: true) }
            } else {
                databaseList
            }
        }
        .navigationTitle(database == .null ? "Database" : applicationDatabaseName(database))
        .navigationBarTitleDisplayMode(.inline)
        .task(id: store.detailsRevision) { await store.loadDetails(model) }
        .sheet(item: $operation) { ApplicationOperationSheet(operation: $0, store: store) }
    }

    private var databaseList: some View {
        List {
            if database == .null && !store.hasLoadedDetails && store.detailError == nil {
                Section { LabeledContent("Database", value: "Database applicazione") }
                    .contentSkeleton(true, title: "Caricamento database…")
            } else if database == .null {
                EmptyState(title: "Database non presente", systemImage: "externaldrive.badge.xmark", description: "Il database non compare nel catalogo corrente. Le eventuali operazioni restano consultabili qui sotto.")
            } else {
                identitySection
                adminToolSection
                if scopedDatabase == nil {
                    principalSection
                    managementSection
                    backupSection
                }
            }
            if scopedDatabase == nil {
                ForEach(deleteOperations, id: \.id) { deletion in deletionSection(deletion) }
                if let error = store.detailError ?? store.error { Section { ErrorNotice(message: error) } }
            }
        }
    }

    private var identitySection: some View {
        Section("Database") {
            LabeledContent("Nome", value: database["name"].text)
            LabeledContent("Nome visualizzato", value: database["displayName"].text.isEmpty ? database["name"].text : database["displayName"].text)
            LabeledContent("Motore", value: applicationLabel(database["engine"].text))
            LabeledContent("Stato", value: applicationLabel(database["status"].text))
            LabeledContent("Connessione", value: applicationLabel(database["connectionStatus"].text))
            LabeledContent("Dimensione", value: applicationDatabaseSize(database))
            if let measuredAt = database["sizeMeasuredAt"].stringValue, !measuredAt.isEmpty {
                LabeledContent("Dimensione rilevata", value: NativeFormatting.date(measuredAt))
            }
        }
    }
    private var principalSection: some View {
        Section {
            LabeledContent("Utente dedicato", value: database["ownerRole"].text)
            LabeledContent("Associazione", value: applicationLabel(database["principalBindingStatus"].text))
            LabeledContent("Password", value: applicationLabel(database["credentialStatus"].text))
            if !database["credentialUpdatedAt"].text.isEmpty { LabeledContent("Password aggiornata", value: NativeFormatting.date(database["credentialUpdatedAt"].text)) }
            ForEach(database["users"].arrayValue, id: \.self) { Text($0.text) }
            ForEach(database["permissions"].arrayValue, id: \.self) { Label($0.text, systemImage: "lock.shield") }
        } header: { Text("Principal e credenziali") } footer: {
            Text("Il principal è assegnato dal server e la sua proprietà non può essere modificata da questo modulo. Il valore della password non viene mostrato.")
        }
    }
    private var managementSection: some View {
        Section("Gestione") {
            Button("Modifica database", systemImage: "pencil") { edit() }.disabled(isExternal)
            Button("Imposta nuova password", systemImage: "key") { rotatePassword() }.disabled(isExternal)
            Button("Elimina database", systemImage: "trash", role: .destructive) { delete() }.disabled(isExternal || deletionInProgress)
            if isExternal { Text("Il database utilizza un collegamento dedicato. Le azioni disponibili sono verificate dal server.").font(.footnote).foregroundStyle(.secondary) }
            NavigationLink("Dettagli database") { JSONDetailView(title: "Database", value: database) }
        }
    }
    private var backupSection: some View {
        Section("Backup e ripristino") {
            LabeledContent("Backup", value: database["backupPolicy"].text)
            LabeledContent("Ripristino", value: database["restoreStatus"].text)
            Button("Crea backup", systemImage: "externaldrive.badge.plus") {
                operation = ApplicationOperation(title: "Backup database", explanation: "Accoda un backup del solo database \(database["name"].text). Il completamento va verificato nello stato dei backup.", path: "/api/native/v1/database-command", body: command("backup"), fresh: true)
            }
            Button("Prepara prova di ripristino", systemImage: "arrow.counterclockwise") {
                operation = ApplicationOperation(title: "Prova di ripristino", explanation: "Prepara un piano di ripristino su una destinazione di prova. Questa funzione non sovrascrive il database attivo.", path: "/api/native/v1/database-command", body: command("restore"), fields: [.init(key: "backupRef", title: "Riferimento backup", value: "latest")], fresh: true, planPath: "/api/native/v1/database-command", planOnly: true)
            }
        }
    }
    @ViewBuilder private var adminToolSection: some View {
        if let url = URL(string: database["adminTool"]["url"].text), url.scheme == "https", url.host != nil {
            Section {
                Link(destination: url) { Label("Apri \(database["adminTool"]["label"].text)", systemImage: "arrow.up.right.square") }
                    .accessibilityIdentifier("application.database.admin")
            } header: { Text("Strumento database esterno") } footer: {
                Text("Si apre in Safari. Potrebbe essere richiesta una sessione passkey separata per accedere allo strumento di amministrazione.")
            }
        }
    }
    private var deletionInProgress: Bool {
        deleteOperations.contains { ["approved", "executing", "database-dropped", "rollback-required"].contains($0["status"].text) }
    }
    @ViewBuilder private func deletionSection(_ deletion: JSONValue) -> some View {
        Section("Eliminazione \(deletion.id)") {
            LabeledContent("Stato", value: applicationLabel(deletion["status"].text))
            if deletion["evidence"]["waived"].boolValue == true { Label("Evidence di backup derogata", systemImage: "exclamationmark.triangle").foregroundStyle(.orange) }
            if !deletion["execution"]["failure"].text.isEmpty { ErrorNotice(message: deletion["execution"]["failure"].text) }
            if ["evidence-verified", "failed"].contains(deletion["status"].text) {
                Button("Approva eliminazione", systemImage: "checkmark.shield", role: .destructive) { advanceDeletion(deletion, action: "delete-approve", phase: "APPROVE") }
            }
            if deletion["status"].text == "approved" {
                Button("Esegui eliminazione", systemImage: "trash", role: .destructive) { advanceDeletion(deletion, action: "delete-execute", phase: "EXECUTE") }
            }
            if ["executing", "database-dropped", "rollback-required"].contains(deletion["status"].text) {
                Text("Nessun retry automatico. Il database può essere già stato eliminato: verifica il checkpoint prima di procedere.").foregroundStyle(.orange)
            }
            NavigationLink("Dettagli operazione") { JSONDetailView(title: "Eliminazione", value: deletion) }
        }
    }
    private func command(_ action: String) -> [String: JSONValue] {
        ["action": .string(action), "id": .string(databaseID), "projectId": database["projectId"]]
    }
    private func edit() {
        operation = ApplicationOperation(title: "Modifica database", explanation: "Aggiorna i metadati del database. La proprietà del principal resta associata alla risorsa corrente.", path: "/api/native/v1/database-command", body: command("update"), fields: [
            .init(key: "displayName", title: "Nome visualizzato", value: database["displayName"].text, required: false),
            .init(key: "status", title: "Stato", value: database["status"].stringValue ?? "declared", kind: .choices(["declared", "active", "maintenance", "disabled"])),
            .init(key: "connectionStatus", title: "Connessione", value: database["connectionStatus"].stringValue ?? "metadata-only", kind: .choices(["metadata-only", "configured", "healthy", "needs-check", "disabled"]))
        ], confirmation: "UPDATE-DATABASE:\(databaseID)", fresh: true, planPath: "/api/native/v1/database-command")
    }
    private func rotatePassword() {
        operation = ApplicationOperation(title: "Nuova password database", explanation: "Aggiorna la password del solo principal associato a \(database["name"].text). Le applicazioni collegate potrebbero richiedere una riconfigurazione.", path: "/api/native/v1/database-command", body: command("credential"), fields: [.init(key: "password", title: "Nuova password", kind: .secret)], confirmation: "ROTATE-DATABASE-CREDENTIAL:\(databaseID)", fresh: true, planPath: "/api/native/v1/database-command")
    }
    private func delete() {
        var body = command("delete-now")
        body["idempotencyKey"] = .string(UUID().uuidString)
        operation = ApplicationOperation(title: "Elimina database", explanation: "Elimina definitivamente \(database["name"].text), il principal gestito e la credenziale associata. Il server registra i checkpoint e non richiede un backup: proseguendo accetti la deroga all'evidence di backup.", path: "/api/native/v1/database-delete-command", body: body, confirmation: "DELETE-DATABASE-NOW:\(databaseID)", fresh: true, destructive: true, requiresTypedName: database["name"].text)
    }
    private func advanceDeletion(_ deletion: JSONValue, action: String, phase: String) {
        operation = ApplicationOperation(title: action == "delete-approve" ? "Approva eliminazione" : "Esegui eliminazione", explanation: "\(action == "delete-approve" ? "Approva" : "Esegui") l'operazione \(deletion.id) sul database \(deletion["database"]["name"].text). Il server verifica il checkpoint e l'identità esatta della risorsa.", path: "/api/native/v1/database-command", body: ["action": .string(action), "operationId": .string(deletion.id)], confirmation: "\(phase)-DATABASE-DELETE:\(deletion.id)", fresh: true, destructive: true, requiresTypedName: deletion["database"]["name"].text)
    }

    static func createOperation(projectID: String) -> ApplicationOperation {
        ApplicationOperation(title: "Crea database", explanation: "Crea un database e un principal dedicato generato dal server. La password viene inviata al server e non viene conservata nell'app.", path: "/api/native/v1/database-command", body: ["action": .string("create"), "projectId": .string(projectID)], fields: [
            .init(key: "engine", title: "Motore", value: "mariadb", kind: .choices(["mariadb", "postgres"])),
            .init(key: "name", title: "Nome database", value: projectID.replacingOccurrences(of: "-", with: "_") + "_app"),
            .init(key: "displayName", title: "Nome visualizzato", required: false),
            .init(key: "password", title: "Password", kind: .secret)
        ], confirmation: "CREATE-DATABASE", fresh: true, planPath: "/api/native/v1/database-command")
    }
}

func applicationDatabaseName(_ database: JSONValue) -> String {
    database["displayName"].text.isEmpty ? database["name"].text : database["displayName"].text
}

func applicationDatabaseSize(_ database: JSONValue) -> String {
    guard let size = database["sizeBytes"].doubleValue, size.isFinite, size >= 0,
          database["sizeAvailable"].boolValue ?? (size > 0) else { return "Dimensione non disponibile" }
    return NativeFormatting.bytes(size)
}
