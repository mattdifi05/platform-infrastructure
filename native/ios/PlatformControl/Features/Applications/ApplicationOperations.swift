import SwiftUI
import Observation

@MainActor @Observable
final class ApplicationsStore {
    var catalog: JSONValue = .object([:])
    var isLoading = false
    var error: String?
    var hasLoaded = false

    var projects: [JSONValue] { catalog["projects"].arrayValue }
    var applications: [JSONValue] { catalog["applications"].arrayValue }
    var observed: [JSONValue] { catalog["observed"].arrayValue }
    var folders: [JSONValue] { catalog["folders"]["folders"].arrayValue }
    var memberships: JSONValue { catalog["folders"]["memberships"] }
    var databases: [JSONValue] { catalog["databases"].arrayValue }

    func load(_ model: AppModel) async {
        guard !isLoading else { return }
        isLoading = true
        defer { isLoading = false }
        do {
            let response = try await model.get("/api/native/v1/applications")
            guard !Task.isCancelled else { return }
            guard case .array = response["projects"], case .array = response["observed"],
                  case .array = response["folders"]["folders"], case .object = response["folders"]["memberships"] else {
                throw APIError(status: 0, message: "Il catalogo delle applicazioni non è disponibile.")
            }
            catalog = response
            error = nil
            hasLoaded = true
        } catch is CancellationError { }
        catch { if !Task.isCancelled { self.error = error.localizedDescription } }
    }

    func project(_ id: String) -> JSONValue? {
        projects.first { $0["slug"].text == id || $0.id == id }
    }
}

struct ApplicationField: Identifiable {
    enum Kind { case text, secret, choices([String]), multiline }
    let key: String
    let title: String
    var value = ""
    var kind: Kind = .text
    var required = true
    var id: String { key }
}

/// Every mutation passes a review screen. Server plans bind hosting revisions;
/// secrets live only in the presented form and are cleared when it closes.
struct ApplicationOperation: Identifiable {
    let id = UUID()
    var title: String
    var explanation: String
    var path: String
    var body: [String: JSONValue] = [:]
    var fields: [ApplicationField] = []
    var confirmation: String?
    var fresh = false
    var destructive = false
    var planPath: String?
    var planGET = false
    var planOnly = false
    var visibilityPlan = false
    var requiresTypedName: String?
}

@MainActor
struct ApplicationOperationSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let operation: ApplicationOperation
    let store: ApplicationsStore
    @State private var values: [String: String]
    @State private var plan: JSONValue?
    @State private var result: JSONValue?
    @State private var reviewing = false
    @State private var isWorking = false
    @State private var error: String?
    @State private var typedName = ""
    @State private var verifiedAt: Date?
    @FocusState private var focusedField: String?

    init(operation: ApplicationOperation, store: ApplicationsStore) {
        self.operation = operation
        self.store = store
        _values = State(initialValue: Dictionary(uniqueKeysWithValues: operation.fields.map { ($0.key, $0.value) }))
    }

    var body: some View {
        NavigationStack {
            Form {
                Section { Text(operation.explanation).foregroundStyle(.secondary) }
                if let result {
                    ApplicationOperationResult(value: result)
                } else if reviewing {
                    reviewSection
                } else {
                    ForEach(operation.fields) { field in
                        Section(field.title) { fieldControl(field) }
                    }
                }
                if let error { Section { ErrorNotice(message: error) } }
                if isWorking { Section { LoadingState(title: "Operazione in corso…", style: .row) } }
                if result == nil {
                    Section {
                        if reviewing {
                            Button(operation.planOnly ? "Chiudi" : "Conferma", role: operation.destructive ? .destructive : nil) {
                                if operation.planOnly { dismiss() } else { Task { await apply() } }
                            }
                            .disabled(isWorking || !typedConfirmationMatches)
                            if !operation.planOnly {
                                Button("Modifica") { reviewing = false; plan = nil; error = nil }
                                    .disabled(isWorking)
                            }
                        } else {
                            Button(operation.planOnly ? "Genera piano" : "Rivedi operazione") { Task { await prepare() } }
                                .disabled(isWorking || !validFields)
                        }
                    }
                }
            }
            .navigationTitle(operation.title)
            .scrollDismissesKeyboard(.interactively)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(result == nil ? "Annulla" : "Fine") { clearSecrets(); dismiss() }
                        .disabled(isWorking)
                }
            }
            .interactiveDismissDisabled(isWorking)
            .onDisappear { clearSecrets() }
        }
    }

    @ViewBuilder private func fieldControl(_ field: ApplicationField) -> some View {
        let binding = Binding(get: { values[field.key] ?? "" }, set: { values[field.key] = $0 })
        switch field.kind {
        case .secret:
            SecureField(field.title, text: binding)
                .focused($focusedField, equals: field.key)
                .textContentType(.newPassword)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
        case .choices(let choices):
            Picker(field.title, selection: binding) {
                ForEach(choices, id: \.self) { choice in Text(applicationLabel(choice)).tag(choice) }
            }
        case .multiline:
            TextField(field.title, text: binding, axis: .vertical).lineLimit(3...6)
                .focused($focusedField, equals: field.key)
        case .text:
            TextField(field.title, text: binding)
                .focused($focusedField, equals: field.key)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
        }
    }

    private var reviewSection: some View {
        Group {
            Section("Riepilogo") {
                ForEach(operation.fields) { field in
                    let summary = isSecret(field) ? "Password inserita" : (values[field.key] ?? "")
                    LabeledContent(field.title, value: summary)
                        .accessibilityElement(children: .ignore)
                        .accessibilityLabel(field.title)
                        .accessibilityValue(summary)
                        .accessibilityIdentifier("application.review.\(field.key)")
                }
                if operation.fresh { Label("Verifica con passkey richiesta", systemImage: "person.badge.key") }
                if let name = operation.requiresTypedName {
                    Text("Per confermare, scrivi “\(name)”.")
                    TextField("Nome esatto", text: $typedName)
                        .autocorrectionDisabled().textInputAutocapitalization(.never)
                }
            }
            if let plan {
                Section("Piano del server") {
                    if !plan["resultSummary"].text.isEmpty { Text(plan["resultSummary"].text) }
                    if operation.visibilityPlan {
                        LabeledContent("Host", value: plan["plan"]["hostname"].text)
                        LabeledContent("Visibilità attuale", value: applicationLabel(plan["plan"]["currentMode"].text))
                        LabeledContent("Visibilità richiesta", value: applicationLabel(plan["plan"]["requestedMode"].text))
                        ForEach(Array(plan["plan"]["actions"].arrayValue.enumerated()), id: \.offset) { _, action in
                            Label(action.text, systemImage: "checklist")
                        }
                    }
                    ForEach(Array(plan["steps"].arrayValue.enumerated()), id: \.offset) { _, step in
                        Label(step["name"].text, systemImage: "checklist")
                    }
                    NavigationLink("Dettagli del piano") { JSONDetailView(title: "Piano", value: plan) }
                }
            }
        }
    }

    private func isSecret(_ field: ApplicationField) -> Bool {
        if case .secret = field.kind { return true }; return false
    }
    private var validFields: Bool {
        operation.fields.allSatisfy { !$0.required || !(values[$0.key] ?? "").trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
    }
    private var typedConfirmationMatches: Bool {
        operation.requiresTypedName == nil || typedName == operation.requiresTypedName
    }
    private var payload: [String: JSONValue] {
        var body = operation.body
        for field in operation.fields { body[field.key] = .string(values[field.key] ?? "") }
        return body
    }
    private func clearSecrets() {
        for field in operation.fields where isSecret(field) { values[field.key] = "" }
    }

    private func prepare() async {
        focusedField = nil
        isWorking = true; error = nil
        defer { isWorking = false }
        do {
            if let path = operation.planPath {
                if operation.fresh && !operation.planGET { try await verifyIfNeeded() }
                plan = operation.planGET ? try await model.get(path) : try await model.post(path, body: .object(payload))
                if operation.planOnly { result = plan; clearSecrets() }
            }
            reviewing = true
        } catch { self.error = error.localizedDescription; verifiedAt = nil }
    }

    private func apply() async {
        isWorking = true; error = nil
        defer { isWorking = false }
        do {
            var body = payload
            if operation.visibilityPlan {
                guard let plan, !plan["plan"]["revision"].text.isEmpty,
                      !plan["plan"]["confirmationRequired"].text.isEmpty else {
                    error = "Il piano non contiene una revisione valida. Genera un nuovo piano."; return
                }
                body["expectedRevision"] = plan["plan"]["revision"]
                body["confirm"] = plan["plan"]["confirmationRequired"]
            } else if let confirmation = operation.confirmation {
                body["confirm"] = .string(confirmation)
            } else if let confirmation = plan?["details"]["confirmationRequired"].stringValue, !confirmation.isEmpty {
                body["confirm"] = .string(confirmation)
            }
            if operation.fresh { try await verifyIfNeeded() }
            result = try await model.post(operation.path, body: .object(body))
            clearSecrets()
            await store.load(model)
        } catch { self.error = error.localizedDescription; verifiedAt = nil }
    }

    private func verifyIfNeeded() async throws {
        if let verifiedAt, Date().timeIntervalSince(verifiedAt) < 60 { return }
        try await model.stepUp()
        verifiedAt = Date()
    }
}

@MainActor
struct ApplicationOperationResult: View {
    let value: JSONValue
    var body: some View {
        Section(value["dryRun"].boolValue == true ? "Piano generato" : "Risposta del server") {
            Label(value["dryRun"].boolValue == true ? "Piano pronto" : "Richiesta completata", systemImage: "checkmark.circle")
                .foregroundStyle(.green)
            if !value["resultSummary"].text.isEmpty { Text(value["resultSummary"].text) }
            if !value["job"]["status"].text.isEmpty { LabeledContent("Stato", value: applicationLabel(value["job"]["status"].text)) }
            if !value["result"]["effective"].text.isEmpty { LabeledContent("Visibilità effettiva", value: applicationLabel(value["result"]["effective"].text)) }
            if value["result"]["verified"].boolValue == true { Label("Visibilità verificata dal server", systemImage: "checkmark.shield") }
            if !value["deleteOperation"]["status"].text.isEmpty { LabeledContent("Eliminazione", value: applicationLabel(value["deleteOperation"]["status"].text)) }
            if value["details"]["databaseTouched"].boolValue == false { Text("Il server dichiara che il database non è stato modificato.").foregroundStyle(.secondary) }
            if value["details"]["commandExecuted"].boolValue == false { Text("Aggiornati i metadati: nessun comando sul container è stato eseguito.").foregroundStyle(.secondary) }
            NavigationLink("Dettagli della risposta") { JSONDetailView(title: "Risultato", value: value) }
        }
    }
}

func applicationPathComponent(_ value: String) -> String {
    value.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(CharacterSet(charactersIn: "-_."))) ?? ""
}

func applicationLabel(_ value: String) -> String {
    ["public": "Pubblica", "private": "Privata", "offline": "Offline", "unknown": "Non verificata",
     "online": "Online", "running": "In esecuzione", "stopped": "Arrestata", "absent": "Assente",
     "available": "Disponibile", "authorized": "Autorizzata", "cancelled": "Annullata", "failed": "Fallita",
     "queued": "In coda", "staged": "Preparata", "activating": "In attivazione", "copying": "In copia",
     "interrupted": "Interrotta", "activation_failed": "Attivazione fallita",
     "active": "Attivo", "declared": "Dichiarato", "maintenance": "Manutenzione", "disabled": "Disabilitato",
     "configured": "Configurato", "healthy": "Verificato", "needs-check": "Da verificare", "metadata-only": "Solo metadati",
     "mariadb": "MariaDB", "mysql": "MySQL", "postgres": "PostgreSQL", "postgresql": "PostgreSQL", "static": "Statico", "node": "Node.js", "php": "PHP",
     "reserved": "Riservato", "legacy-unbound": "Principal non associato", "migration-required": "Migrazione richiesta",
     "protected": "Protetta", "secret-file-set": "Password configurata", "completed": "Completata",
     "rollback-required": "Ripristino richiesto", "evidence-verified": "Evidence verificata", "approved": "Approvata"] [value] ?? value
}
