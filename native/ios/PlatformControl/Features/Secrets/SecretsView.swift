import SwiftUI
import UIKit
import UniformTypeIdentifiers

private struct VaultEntry: Identifiable {
    let value: JSONValue
    var id: String { value["id"].text }
    var title: String { value["label"].stringValue ?? value["itemKey"].text }
}

private enum VaultSheet: Identifiable {
    case create, edit(VaultEntry), delete(VaultEntry), importExisting
    var id: String {
        switch self {
        case .create: "create"
        case .edit(let item): "edit-\(item.id)"
        case .delete(let item): "delete-\(item.id)"
        case .importExisting: "import"
        }
    }
}

struct SecretsView: View {
    @Environment(AppModel.self) private var app
    @State private var catalog: JSONValue = .null
    @State private var loading = true
    @State private var error: String?
    @State private var search = ""
    @State private var filter = "all"
    @State private var sheet: VaultSheet?
    @State private var feedback: String?

    private var entries: [VaultEntry] {
        catalog["items"].arrayValue.map { VaultEntry(value: $0) }.filter { entry in
            let matches = search.isEmpty || ["label", "itemKey", "projectId", "environment", "kind", "username", "url"]
                .map { entry.value[$0].text }.joined(separator: " ").localizedCaseInsensitiveContains(search)
            let linked = bindings(for: entry.id).count > 0
            return matches && (filter == "all" || (filter == "linked" ? linked : !linked))
        }
    }

    var body: some View {
        List {
            if let error { ErrorNotice(message: error, retry: { Task { await load() } }) }
            if let feedback { Text(feedback).foregroundStyle(.secondary).accessibilityAddTraits(.updatesFrequently) }
            Section {
                Picker("Mostra", selection: $filter) {
                    Text("Tutti").tag("all")
                    Text("Collegati").tag("linked")
                    Text("Solo Vault").tag("vault")
                }.pickerStyle(.segmented)
            }
            if loading && catalog["items"].arrayValue.isEmpty {
                LoadingState(title: "Caricamento secret…")
            } else if entries.isEmpty {
                EmptyState(title: search.isEmpty ? "Nessun secret" : "Nessun risultato", systemImage: "key", description: search.isEmpty ? "Aggiungi un secret o importa quelli esistenti." : "Modifica la ricerca o il filtro.")
            } else {
                Section("\(entries.count) secret") {
                    ForEach(entries) { entry in
                        NavigationLink {
                            VaultEntryView(entryID: entry.id, catalog: $catalog) { mode in
                                sheet = mode == "edit" ? .edit(entry) : .delete(entry)
                            }
                        } label: {
                            Label {
                                VStack(alignment: .leading, spacing: 5) {
                                    Text(entry.title).font(.headline)
                                    Text([entry.value["projectId"].text, entry.value["environment"].text, entry.value["kind"].text].filter { !$0.isEmpty }.joined(separator: " · "))
                                        .font(.subheadline).foregroundStyle(.secondary)
                                    if !bindings(for: entry.id).isEmpty { Label("Collegamento gestito", systemImage: "link").font(.caption).foregroundStyle(.secondary) }
                                }
                            } icon: { Image(systemName: "key.fill").foregroundStyle(.tint) }
                        }
                    }
                }
            }
            Section {
                Button("Importa secret esistenti", systemImage: "square.and.arrow.down") { sheet = .importExisting }
            } footer: { Text("L’importazione conserva i file di origine. Salvare una nuova versione nel Vault non cambia la credenziale in uso.") }
            Section("Consegna alle applicazioni") {
                if catalog["runtime"]["available"].boolValue == true {
                    ForEach(Array(catalog["runtime"]["bindings"].arrayValue.enumerated()), id: \.offset) { _, binding in
                        NavigationLink {
                            VaultDeliveryView(bindingID: binding["bindingId"].text, catalog: $catalog) { await load() }
                        } label: {
                            Label {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(binding["label"].stringValue ?? binding["bindingId"].text)
                                    Text(binding["deliveryVerified"].boolValue == true ? "Consegna verificata" : "Consegna non verificata").font(.caption).foregroundStyle(.secondary)
                                }
                            } icon: { Image(systemName: "shippingbox") }
                        }
                    }
                } else {
                    Text(catalog["runtime"]["reason"].stringValue ?? "Distribuzione non configurata o non disponibile. I valori restano nel Vault.").foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle("Secrets")
        .searchable(text: $search, prompt: "Nome, applicazione o ambiente")
        .toolbar { ToolbarItem(placement: .primaryAction) { Button("Nuovo secret", systemImage: "plus") { sheet = .create } } }
        .refreshable { await load() }
        .task { await load() }
        .sheet(item: $sheet) { mode in
            VaultEditorSheet(mode: mode, revision: catalog["revision"].text, projects: catalog["projects"].arrayValue) { message in
                feedback = message
                await load()
            }
        }
    }

    private func bindings(for id: String) -> [JSONValue] { catalog["runtime"]["bindings"].arrayValue.filter { $0["itemId"].text == id } }

    @MainActor private func load() async {
        loading = true
        defer { loading = false }
        do { catalog = try await app.get("/control/v1/vault"); error = nil }
        catch { self.error = error.localizedDescription }
    }
}

private struct VaultEntryView: View {
    @Environment(AppModel.self) private var app
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.dismiss) private var dismiss
    let entryID: String
    @Binding var catalog: JSONValue
    private var entry: VaultEntry { VaultEntry(value: catalog["items"].arrayValue.first { $0["id"].text == entryID } ?? .object(["id": .string(entryID)])) }
    private var applications: String {
        let bindings = catalog["runtime"]["bindings"].arrayValue.filter { $0["itemId"].text == entryID }
        let ids = [entry.value["projectId"].text] + entry.value["linkedApps"].arrayValue.map(\.text) + bindings.map { $0["project"].text }
        var seen = Set<String>()
        let names = ids.filter { !$0.isEmpty && seen.insert($0).inserted }.map { id in
            if id == "platform" { return "Platform" }
            return catalog["projects"].arrayValue.first { $0["slug"].text == id || $0["id"].text == id }?["name"].stringValue ?? id
        }
        return names.isEmpty ? "Nessuna" : names.formatted(.list(type: .and))
    }

    private var rotation: String {
        guard let days = entry.value["rotationDays"].intValue else { return "Non impostata" }
        switch days {
        case 0: return "Disattivata"
        case 1: return "Ogni giorno"
        default: return "Ogni \(days) giorni"
        }
    }
    let manage: (String) -> Void
    @State private var revealedValue: String?
    @State private var expiresAt: Date?
    @State private var revealRequest: Task<Void, Never>?
    @State private var revealTask: Task<Void, Never>?
    @State private var pasteboardChange: Int?
    @State private var revealGeneration = UUID()
    @State private var revealing = false
    @State private var error: String?

    var body: some View {
        List {
            Section {
                if let revealedValue, let expiresAt, expiresAt > Date(), scenePhase == .active {
                    Text(revealedValue).font(.body.monospaced()).privacySensitive()
                        .accessibilityLabel("Valore secret").accessibilityValue(revealedValue)
                    Button("Copia valore", systemImage: "doc.on.doc") { copy(revealedValue, until: expiresAt) }
                    Button("Nascondi", systemImage: "eye.slash") { clear() }
                } else if entry.value["valueStored"].boolValue == false {
                    Text("Nessun valore salvato").foregroundStyle(.secondary)
                } else if !app.vaultFaceIDSupported {
                    Text("Face ID non disponibile per questo server").foregroundStyle(.secondary)
                } else {
                    Button(action: beginReveal) {
                        if revealing { ProgressView() }
                        else { Label(app.vaultFaceIDRegistered ? "Mostra con Face ID" : "Abilita Face ID", systemImage: "faceid") }
                    }.disabled(revealing)
                }
                if let error { ErrorNotice(message: error) }
            } header: { Text("Valore") } footer: {
                if app.vaultFaceIDSupported && !app.vaultFaceIDRegistered && entry.value["valueStored"].boolValue != false {
                    Text("Conferma l’accesso una volta per abilitare Face ID in questa sessione.")
                }
            }
            Section {
                LabeledContent("Nome", value: entry.value["itemKey"].stringValue ?? entry.title)
                LabeledContent("Applicazioni", value: applications)
                LabeledContent("Ambiente", value: entry.value["environment"].text.capitalized)
                dateRow("Creato", value: entry.value["createdAt"].text)
                dateRow("Aggiornato", value: entry.value["updatedAt"].text)
                LabeledContent("Rotazione", value: rotation)
            }
            Section {
                Button("Modifica valore", systemImage: "square.and.pencil") { clear(); manage("edit") }
                Button("Rimuovi dal Vault", systemImage: "trash", role: .destructive) { clear(); manage("delete") }
            }.disabled(revealing)
        }
        .navigationTitle(entry.title)
        .onChange(of: scenePhase) { _, phase in if phase == .background { clear() } }
        .onChange(of: catalog["items"].arrayValue.contains { $0["id"].text == entryID }) { _, exists in if !exists { clear(); dismiss() } }
        .onDisappear { clear() }
    }

    private func dateRow(_ title: String, value: String) -> some View {
        LabeledContent(title) {
            if let date = vaultDate(value) { Text(date, format: .dateTime.day().month(.abbreviated).year().hour().minute()) }
            else { Text("Non disponibile") }
        }
    }

    @MainActor private func beginReveal() {
        guard !revealing else { return }
        clear()
        let generation = revealGeneration
        revealing = true
        error = nil
        revealRequest = Task { await showValue(generation: generation) }
    }

    @MainActor private func showValue(generation: UUID) async {
        defer {
            if generation == revealGeneration {
                revealing = false
                revealRequest = nil
            }
        }
        do {
            try Task.checkCancellation()
            if !app.vaultFaceIDRegistered {
                try await app.enableVaultFaceID()
                return
            }
            let proof = try await app.vaultRevealProof(itemID: entryID)
            guard !Task.isCancelled, generation == revealGeneration, scenePhase != .background else { return }
            let result = try await app.post("/api/native/v1/vault/secrets/\(entryID)/reveal", body: proof)
            guard !Task.isCancelled, generation == revealGeneration, scenePhase != .background else { return }
            let value = result["value"].stringValue
            let serverExpiry = vaultDate(result["revealExpiresAt"].text)
            guard let value, let serverExpiry, serverExpiry > Date() else { throw VaultUIError.invalidReveal }
            let ttl = min(30, max(0, (result["ttlMs"].doubleValue ?? 30_000) / 1_000))
            let expiry = min(serverExpiry, Date().addingTimeInterval(ttl))
            guard expiry > Date() else { throw VaultUIError.invalidReveal }
            revealedValue = value
            expiresAt = expiry
            error = nil
            revealTask = Task { @MainActor in
                try? await Task.sleep(for: .seconds(max(0, expiry.timeIntervalSinceNow)))
                guard !Task.isCancelled, generation == revealGeneration else { return }
                clear()
            }
        } catch is CancellationError { }
        catch { if generation == revealGeneration { self.error = error.localizedDescription } }
    }

    @MainActor private func copy(_ value: String, until expiry: Date) {
        guard expiry > Date(), scenePhase == .active else { clear(); return }
        UIPasteboard.general.setItems([[UTType.utf8PlainText.identifier: value]], options: [.localOnly: true, .expirationDate: expiry])
        pasteboardChange = UIPasteboard.general.changeCount
    }

    @MainActor private func clear() {
        revealGeneration = UUID()
        revealRequest?.cancel()
        revealRequest = nil
        revealing = false
        revealTask?.cancel(); revealTask = nil
        revealedValue = nil; expiresAt = nil
        if let pasteboardChange, UIPasteboard.general.changeCount == pasteboardChange { UIPasteboard.general.items = [] }
        pasteboardChange = nil
    }
}

private struct VaultEditorSheet: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    let mode: VaultSheet
    let revision: String
    let projects: [JSONValue]
    let completed: (String) async -> Void
    @State private var key = ""
    @State private var label = ""
    @State private var project = "platform"
    @State private var environment = "local"
    @State private var kind = "application"
    @State private var username = ""
    @State private var host = ""
    @State private var rotationDays = 90
    @State private var value = ""
    @State private var confirmation = ""
    @State private var busy = false
    @State private var error: String?
    @State private var importPlan: JSONValue = .null
    @State private var lifecycle = UUID()

    private var title: String {
        switch mode { case .create: "Nuovo secret"; case .edit: "Modifica valore"; case .delete: "Rimuovi secret"; case .importExisting: "Importa esistenti" }
    }
    private var enabled: Bool {
        guard !busy else { return false }
        switch mode {
        case .create: return !key.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !value.isEmpty && !revision.isEmpty
        case .edit: return !value.isEmpty && !revision.isEmpty
        case .delete: return confirmation == "RIMUOVI" && !revision.isEmpty
        case .importExisting: return importPlan["details"]["importableCount"].intValue != nil || importPlan["dryRun"].boolValue == true
        }
    }

    var body: some View {
        NavigationStack {
            Form {
                if let error { ErrorNotice(message: error) }
                switch mode {
                case .create: createFields
                case .edit(let item):
                    Section(item.title) { secretEditor }
                    Section { Text("Salva una nuova versione cifrata. Il valore attuale non viene letto e la credenziale in uso non cambia.") }
                case .delete(let item):
                    Section(item.title) {
                        Text("Rimuovi il record cifrato dal Vault e gli eventuali collegamenti gestiti. Le credenziali dei servizi e del provider restano in uso.")
                        TextField("Scrivi RIMUOVI", text: $confirmation).textInputAutocapitalization(.characters).autocorrectionDisabled()
                    }
                case .importExisting:
                    Section {
                        Text("Importa i valori dalle sole posizioni già approvate sul server. I file originali vengono conservati; i record presenti vengono saltati.")
                        if busy { ProgressView("Preparazione…") }
                        if importPlan["dryRun"].boolValue == true {
                            let details = importPlan["details"]
                            LabeledContent("Importabili", value: "\(details["importableCount"].intValue ?? 0)")
                            LabeledContent("Trovati", value: "\(details["itemCount"].intValue ?? 0)")
                        }
                    }
                }
                if revision.isEmpty, case .importExisting = mode {} else if revision.isEmpty {
                    Text("Revisione Vault non disponibile. Chiudi e aggiorna l’elenco prima di salvare.").foregroundStyle(.orange)
                }
                Section {
                    Button { Task { await save() } } label: {
                        if busy { ProgressView("Operazione in corso…") } else { Text(title) }
                    }.disabled(!enabled).foregroundStyle(isDelete ? .red : .accentColor)
                }
            }
            .navigationTitle(title).navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Annulla") { clear(); dismiss() }.disabled(busy) } }
            .interactiveDismissDisabled(busy)
            .task { if case .importExisting = mode { await prepareImport() } }
            .onChange(of: scenePhase) { _, phase in
                if phase == .background { clear(); dismiss() }
            }
            .onDisappear { clear() }
        }
    }

    private var isDelete: Bool { if case .delete = mode { true } else { false } }

    private var createFields: some View {
        Group {
            Section("Identità") {
                TextField("Nome secret", text: $key).textInputAutocapitalization(.never).autocorrectionDisabled()
                TextField("Etichetta", text: $label)
                Picker("Applicazione", selection: $project) {
                    Text("Platform").tag("platform")
                    ForEach(Array(projects.enumerated()), id: \.offset) { _, entry in
                        if entry["slug"].text != "platform" { Text(entry["name"].stringValue ?? entry["slug"].text).tag(entry["slug"].text) }
                    }
                }
                Picker("Ambiente", selection: $environment) {
                    Text("Local").tag("local"); Text("Staging").tag("staging"); Text("Production").tag("production")
                }
                Picker("Tipo", selection: $kind) {
                    ForEach(["application", "database", "provider", "storage", "docker", "kms", "runtime"], id: \.self) { Text($0).tag($0) }
                }
            }
            Section("Metadati") {
                TextField("Utente / account", text: $username).textInputAutocapitalization(.never).autocorrectionDisabled()
                TextField("URL / host", text: $host).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                Stepper("Rotazione: \(rotationDays) giorni", value: $rotationDays, in: 0...3650)
            }
            Section { secretEditor } header: { Text("Valore") } footer: { Text("Il valore viene cifrato al salvataggio. I ritorni a capo vengono conservati.") }
        }
    }

    private var secretEditor: some View {
        Group {
            if scenePhase == .active {
                TextEditor(text: $value).frame(minHeight: 120).font(.body.monospaced())
                    .textInputAutocapitalization(.never).autocorrectionDisabled().privacySensitive().accessibilityLabel("Nuovo valore secret")
            } else {
                Label("Valore nascosto", systemImage: "lock.fill").frame(minHeight: 120).foregroundStyle(.secondary)
            }
        }
    }

    @MainActor private func prepareImport() async {
        busy = true
        defer { busy = false }
        do { importPlan = try await app.post("/control/v1/vault/import-existing"); error = nil }
        catch { self.error = error.localizedDescription }
    }

    @MainActor private func save() async {
        guard enabled else { return }
        let generation = lifecycle
        busy = true
        defer { busy = false }
        do {
            try await app.confirmVaultAction("Conferma l’operazione nel Vault.")
            guard generation == lifecycle, scenePhase != .background else { return }
            let path: String
            let body: JSONValue
            let message: String
            switch mode {
            case .create:
                path = "/control/v1/vault/secrets"
                body = .object(["itemKey": .string(key), "label": .string(label), "projectId": .string(project), "targetEnv": .string(environment), "kind": .string(kind), "username": .string(username), "url": .string(host), "rotationDays": .number(Double(rotationDays)), "value": .string(value), "expectedVaultRevision": .string(revision), "confirm": .string("STORE-VAULT-SECRET")])
                message = "Secret salvato nel Vault."
            case .edit(let item):
                path = "/control/v1/vault/secrets/\(item.id)/versions"
                body = .object(["itemId": .string(item.id), "newValue": .string(value), "expectedVaultRevision": .string(revision)])
                message = "Nuova versione cifrata salvata. La credenziale in uso non cambia."
            case .delete(let item):
                path = "/control/v1/vault/secrets/\(item.id)/delete"
                body = .object(["confirm": .string("DELETE-VAULT-SECRET:\(item.id)"), "typedConfirmation": .string(confirmation), "expectedVaultRevision": .string(revision)])
                message = "Record rimosso dal Vault. Le credenziali dei servizi restano in uso."
            case .importExisting:
                path = "/control/v1/vault/import-existing"
                body = .object(["confirm": .string("IMPORT-EXISTING-SECRETS")])
                message = "Importazione completata. I file di origine sono stati conservati."
            }
            let result = try await app.post(path, body: body)
            guard generation == lifecycle else { await completed("Operazione inviata. Verifica lo stato aggiornato del Vault."); return }
            guard result["dryRun"].boolValue != true else { throw VaultUIError.planOnly }
            value = ""
            await completed(message)
            dismiss()
        } catch is CancellationError { }
        catch { if generation == lifecycle { self.error = error.localizedDescription } }
    }

    @MainActor private func clear() { lifecycle = UUID(); value = ""; confirmation = "" }
}

private enum VaultUIError: LocalizedError {
    case invalidReveal, planOnly
    var errorDescription: String? {
        switch self {
        case .invalidReveal: "Il server non ha restituito un valore con una scadenza valida."
        case .planOnly: "Il server ha restituito un piano: la modifica non è stata applicata. Aggiorna il Vault e riprova."
        }
    }
}

private func vaultDate(_ raw: String) -> Date? {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.date(from: raw) ?? ISO8601DateFormatter().date(from: raw)
}
