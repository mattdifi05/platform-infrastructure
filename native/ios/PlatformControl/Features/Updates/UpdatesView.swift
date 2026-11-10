import SwiftUI

private struct UpdateReview: Identifiable {
    let target: String
    let title: String
    let revision: String
    var id: String { target }
    var basePath: String { "/control/v1/runtime-updates/\(target)" }
    var reboot: Bool { target == "system/reboot" }
    var host: Bool { target == "system" || reboot }
    var confirmation: String { reboot ? "REBOOT" : "UPDATE" }
}

struct UpdatesView: View {
    @Environment(AppModel.self) private var app
    @Environment(\.scenePhase) private var scenePhase
    @State private var runtime: JSONValue = .null
    @State private var system: JSONValue = .null
    @State private var operations: [String: JSONValue] = [:]
    @State private var review: UpdateReview?
    @State private var loading = true
    @State private var sending = false
    @State private var error: String?
    @State private var notice: String?
    @State private var search = ""

    private var working: Bool { sending || operations.values.contains { updatePending($0) } }
    private var components: [JSONValue] {
        runtime["components"].arrayValue.filter { search.isEmpty || [$0["label"].text, $0["category"].text, $0["services"].arrayValue.map(\.text).joined(separator: " ")].joined(separator: " ").localizedCaseInsensitiveContains(search) }
    }
    private var orderedOperations: [JSONValue] {
        operations.values.sorted { left, right in
            if updatePending(left) != updatePending(right) { return updatePending(left) }
            return (left["createdAt"].stringValue ?? left["id"].text) > (right["createdAt"].stringValue ?? right["id"].text)
        }
    }

    var body: some View {
        List {
            if let error { ErrorNotice(message: error, retry: { Task { await refresh() } }) }
            if let notice { Text(notice).foregroundStyle(.secondary).accessibilityAddTraits(.updatesFrequently) }
            if loading && runtime == .null && system == .null { LoadingState(title: "Verifica aggiornamenti…") }
            systemSection
            if !orderedOperations.isEmpty {
                Section("Operazioni") {
                    ForEach(orderedOperations, id: \.id) { operation in
                        NavigationLink { UpdateOperationDetail(operationID: operation["id"].text, operations: $operations) } label: { UpdateOperationSummary(operation: operation) }
                    }
                }
            }
            Section {
                HStack {
                    Text("Componenti runtime").font(.headline)
                    Spacer()
                    StatusPill(text: runtime["available"].boolValue == true ? "Disponibile" : "Non disponibile", tone: runtime["available"].boolValue == true ? .green : .orange)
                }
                if !runtime["checkedAt"].text.isEmpty { LabeledContent("Ultima verifica", value: runtime["checkedAt"].text) }
                Button("Verifica versioni stabili", systemImage: "arrow.clockwise") { Task { await check(host: false) } }
                    .disabled(working || runtime["canCheck"].boolValue != true)
                Button("Rivedi aggiornamento di tutti", systemImage: "arrow.up.circle") {
                    review = UpdateReview(target: "all", title: "Aggiorna tutti i componenti", revision: runtime["revision"].text)
                }.disabled(working || runtime["canApply"].boolValue != true || !runtime["components"].arrayValue.contains { $0["canUpdate"].boolValue == true } || runtime["revision"].text.isEmpty)
            } footer: { Text("La verifica legge le versioni stabili. Ogni aggiornamento richiede un piano valido, la conferma UPDATE e una nuova verifica passkey.") }
            if components.isEmpty && !loading {
                EmptyState(title: "Nessun componente", systemImage: "shippingbox", description: search.isEmpty ? "Il catalogo runtime non contiene componenti disponibili." : "Nessun componente corrisponde alla ricerca.")
            }
            ForEach(components, id: \.id) { component in componentSection(component) }
        }
        .navigationTitle("Aggiornamenti")
        .searchable(text: $search, prompt: "Componente o servizio")
        .refreshable { await refresh() }
        .task(id: scenePhase) {
            guard scenePhase == .active else { return }
            await refresh()
            while !Task.isCancelled {
                do { try await Task.sleep(for: .seconds(working ? 2 : 30)) }
                catch { return }
                guard !Task.isCancelled, scenePhase == .active else { return }
                await refresh()
            }
        }
        .sheet(item: $review) { request in
            UpdatePlanSheet(review: request) { accepted in
                accept(accepted)
                await refresh()
            }
        }
    }

    private var systemSection: some View {
        Section {
            HStack {
                Label("Sistema operativo", systemImage: "server.rack").font(.headline)
                Spacer()
                StatusPill(text: system["available"].boolValue == true ? "Disponibile" : "Non disponibile", tone: system["available"].boolValue == true ? .green : .orange)
            }
            if !system["os"]["name"].text.isEmpty { LabeledContent("Sistema", value: [system["os"]["name"].text, system["os"]["version"].text].joined(separator: " ")) }
            if !system["os"]["kernel"].text.isEmpty { LabeledContent("Kernel", value: system["os"]["kernel"].text) }
            if system["available"].boolValue == true {
                LabeledContent("Pacchetti aggiornabili", value: "\(system["updateCount"].intValue ?? 0)")
                LabeledContent("Dipendenze da rimuovere", value: "\(system["autoremoveCount"].intValue ?? 0)")
                LabeledContent("Mantenuti alla versione attuale", value: "\(system["keptBackCount"].intValue ?? 0)")
                if !system["checkedAt"].text.isEmpty { LabeledContent("Ultima verifica", value: system["checkedAt"].text) }
                if system["rebootRequired"].boolValue == true { Label("Riavvio richiesto", systemImage: "restart.circle").foregroundStyle(.orange) }
            }
            Button("Verifica pacchetti APT", systemImage: "arrow.clockwise") { Task { await check(host: true) } }
                .disabled(working || system["canCheck"].boolValue != true)
            Button("Rivedi aggiornamento e pulizia", systemImage: "arrow.up.circle") {
                review = UpdateReview(target: "system", title: "Aggiorna sistema", revision: system["revision"].text)
            }.disabled(working || system["canApply"].boolValue != true || system["revision"].text.isEmpty || ((system["updateCount"].intValue ?? 0) + (system["autoremoveCount"].intValue ?? 0) == 0))
            if system["rebootRequired"].boolValue == true {
                Button("Rivedi riavvio server", systemImage: "restart", role: .destructive) {
                    review = UpdateReview(target: "system/reboot", title: "Riavvia server", revision: system["revision"].text)
                }.disabled(working || system["canReboot"].boolValue != true || system["revision"].text.isEmpty)
            }
        } footer: { Text("Il piano APT include autoremove verificato, anche quando non ci sono aggiornamenti. Il riavvio richiede REBOOT e rende il server temporaneamente non raggiungibile.") }
    }

    private func componentSection(_ component: JSONValue) -> some View {
        Section {
            VStack(alignment: .leading, spacing: 8) {
                HStack(alignment: .top) {
                    Text(component["label"].stringValue ?? component["id"].text).font(.headline)
                    Spacer()
                    StatusPill(text: updateLabel(component["status"].text), tone: updateTone(component["status"].text))
                }
                Text(component["category"].text).font(.caption).foregroundStyle(.secondary)
            }
            LabeledContent("Installata", value: component["current"]["versions"].arrayValue.isEmpty ? (component["current"]["version"].stringValue ?? "Non verificata") : component["current"]["versions"].arrayValue.map(\.text).joined(separator: ", "))
            LabeledContent("Ultima stabile", value: component["latestStable"]["version"].stringValue ?? "Non verificata")
            if let candidate = component["candidateRelease"]["version"].stringValue, candidate != component["latestStable"]["version"].text {
                LabeledContent("Versione compatibile", value: candidate)
            }
            if component["needsAlignment"].boolValue == true { Label("I servizi richiedono allineamento", systemImage: "arrow.triangle.merge").foregroundStyle(.orange) }
            if !component["blockedReason"].text.isEmpty { Text(component["blockedReason"].text).font(.subheadline).foregroundStyle(.secondary) }
            if !component["services"].arrayValue.isEmpty {
                DisclosureGroup("\(component["services"].arrayValue.count) servizi") {
                    ForEach(component["services"].arrayValue.map(\.text), id: \.self) { Text($0).font(.subheadline) }
                }
            }
            if let source = component["latestStable"]["sourceUrl"].stringValue, let url = URL(string: source), url.scheme == "https" {
                Link("Fonte della versione stabile", destination: url)
            }
            Button("Rivedi aggiornamento", systemImage: "arrow.up.circle") {
                review = UpdateReview(target: component["id"].text, title: component["label"].stringValue ?? component["id"].text, revision: runtime["revision"].text)
            }.disabled(working || component["canUpdate"].boolValue != true || runtime["revision"].text.isEmpty)
        }
    }

    @MainActor private func refresh() async {
        guard !Task.isCancelled else { return }
        loading = true
        defer { loading = false }
        var failures: [String] = []
        // Catalogs are independent: retain the available side if one bridge is offline.
        do {
            runtime = try await app.get("/control/v1/runtime-updates")
            merge(runtime["operations"].arrayValue)
        } catch { failures.append("Runtime: \(error.localizedDescription)") }
        guard !Task.isCancelled else { return }
        do {
            system = try await app.get("/control/v1/runtime-updates/system")
            merge(system["operations"].arrayValue)
        } catch { failures.append("Sistema: \(error.localizedDescription)") }
        for operation in operations.values.filter({ updatePending($0) }) {
            guard !Task.isCancelled else { return }
            do {
                let value = try await app.get("/control/v1/runtime-updates/operations/\(operation["id"].text)")
                let result = value["operation"] == .null ? value : value["operation"]
                guard result["id"].text == operation["id"].text else { throw UpdateUIError.invalidOperation }
                operations[result["id"].text] = result
            } catch { failures.append("Operazione \(operation["id"].text): connessione interrotta; esito ancora da verificare. \(error.localizedDescription)") }
        }
        error = failures.isEmpty ? nil : failures.joined(separator: "\n")
    }

    @MainActor private func merge(_ values: [JSONValue]) {
        for value in values where !value["id"].text.isEmpty { operations[value["id"].text] = value }
    }

    @MainActor private func accept(_ value: JSONValue) {
        let id = value["operationId"].text
        guard !id.isEmpty else { error = UpdateUIError.invalidOperation.localizedDescription; return }
        operations[id] = .object(["id": .string(id), "status": .string(value["status"].stringValue ?? "queued"), "stage": .string("Richiesta accettata; attesa della verifica server")])
        notice = "Richiesta accettata. Il risultato sarà confermato dallo stato dell’operazione."
    }

    @MainActor private func check(host: Bool) async {
        guard !working else { return }
        sending = true
        defer { sending = false }
        do {
            let result = try await app.post("/control/v1/runtime-updates/\(host ? "system/" : "")check")
            guard !result["operationId"].text.isEmpty else { throw UpdateUIError.invalidOperation }
            accept(result)
            await refresh()
        } catch {
            self.notice = "Richiesta non confermata. Lo stato deve essere verificato prima di riprovare. \(error.localizedDescription)"
            await refresh()
        }
    }
}

private struct UpdatePlanSheet: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    let review: UpdateReview
    let accepted: (JSONValue) async -> Void
    @State private var plan: JSONValue = .null
    @State private var confirmation = ""
    @State private var busy = true
    @State private var error: String?
    @State private var generation = UUID()
    @State private var idempotencyKey = UUID().uuidString

    var body: some View {
        NavigationStack {
            Form {
                if busy { LoadingState(title: plan == .null ? "Conferma passkey e verifica piano…" : "Invio richiesta…") }
                if let error { ErrorNotice(message: error) }
                if plan != .null {
                    Section("Piano verificato") {
                        if let expiry = updateDate(plan["expiresAt"].text) { LabeledContent("Scadenza") { Text(expiry, style: .time) } }
                        if review.host && !review.reboot {
                            LabeledContent("Pacchetti", value: "\(plan["packageCount"].intValue ?? 0)")
                            LabeledContent("Dipendenze da rimuovere", value: "\(plan["autoremoveCount"].intValue ?? 0)")
                        } else if !review.host {
                            if review.target != "all" { LabeledContent("Versione destinazione", value: plan["targetVersion"].text) }
                            ForEach(plan["components"].arrayValue, id: \.id) { component in
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(component["label"].text).font(.headline)
                                    Text(component["targetVersion"].text)
                                    Text(component["affectedServices"].arrayValue.map(\.text).joined(separator: ", ")).font(.caption).foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                    if !plan["affectedServices"].arrayValue.isEmpty {
                        Section("Servizi interessati") { ForEach(plan["affectedServices"].arrayValue.map(\.text), id: \.self) { Text($0) } }
                    }
                    planList("Passaggi", key: "steps")
                    planList("Impatto e rischi", key: "risks")
                    Section {
                        if review.reboot { Text("Durante il riavvio il server sarà temporaneamente non raggiungibile. La disconnessione non conferma il completamento.") }
                        TextField("Scrivi \(review.confirmation)", text: $confirmation).textInputAutocapitalization(.characters).autocorrectionDisabled()
                        TimelineView(.periodic(from: .now, by: 1)) { context in
                            let valid = updateDate(plan["expiresAt"].text).map { $0 > context.date } ?? false
                            if !valid { Text("Piano scaduto. Chiudi e prepara un nuovo piano.").foregroundStyle(.orange) }
                            Button(review.reboot ? "Conferma riavvio con passkey" : "Conferma aggiornamento con passkey", role: review.reboot ? .destructive : nil) { Task { await apply() } }
                                .disabled(busy || confirmation != review.confirmation || !valid)
                        }
                    } header: { Text("Conferma") } footer: { Text("Verrà richiesta una nuova verifica passkey prima di inviare questo piano.") }
                }
            }
            .navigationTitle(review.title).navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Chiudi") { invalidate(); dismiss() }.disabled(busy && plan != .null) } }
            .interactiveDismissDisabled(busy && plan != .null)
            .task { await prepare() }
            .onChange(of: scenePhase) { _, phase in
                if phase == .background { invalidate(); dismiss() }
            }
            .onDisappear { invalidate() }
        }
    }

    private func planList(_ title: String, key: String) -> some View {
        Section(title) {
            if plan[key].arrayValue.isEmpty { Text("Nessuna indicazione restituita dal server.").foregroundStyle(.secondary) }
            ForEach(Array(plan[key].arrayValue.enumerated()), id: \.offset) { _, entry in Text(entry.text) }
        }
    }

    @MainActor private func prepare() async {
        let current = generation
        busy = true
        defer { busy = false }
        do {
            try await app.stepUp()
            guard current == generation, !Task.isCancelled, scenePhase == .active else { return }
            let result = try await app.post(review.basePath + "/plan", body: .object(["revision": .string(review.revision)]))
            guard current == generation, !Task.isCancelled, scenePhase == .active else { return }
            let candidate = result["plan"] == .null ? result : result["plan"]
            try validate(candidate)
            plan = candidate; error = nil
        } catch { if current == generation { self.error = error.localizedDescription } }
    }

    @MainActor private func apply() async {
        guard !busy, confirmation == review.confirmation else { return }
        let current = generation
        busy = true
        defer { busy = false }
        do {
            try validate(plan)
            try await app.stepUp()
            guard current == generation, scenePhase == .active else { return }
            try validate(plan)
            let result = try await app.post(review.basePath + "/apply", body: .object(["revision": plan["revision"], "planId": plan["planId"], "confirmation": .string(review.confirmation), "idempotencyKey": .string(idempotencyKey)]))
            guard !result["operationId"].text.isEmpty else { throw UpdateUIError.invalidOperation }
            await accepted(result)
            dismiss()
        } catch { if current == generation { self.error = "Esito da verificare prima di ripetere la richiesta. \(error.localizedDescription)" } }
    }

    private func validate(_ value: JSONValue) throws {
        guard !value["planId"].text.isEmpty, value["revision"].text == review.revision,
              value["confirmationRequired"].text == review.confirmation,
              let expiry = updateDate(value["expiresAt"].text), expiry > Date() else { throw UpdateUIError.invalidPlan }
        if review.host {
            guard value["kind"].text == (review.reboot ? "host-reboot" : "host-upgrade") else { throw UpdateUIError.invalidPlan }
        } else {
            guard value["componentId"].text == review.target, !value["targetVersion"].text.isEmpty, !value["targetDigest"].text.isEmpty else { throw UpdateUIError.invalidPlan }
            if review.target == "all" { guard value["kind"].text == "batch", !value["components"].arrayValue.isEmpty else { throw UpdateUIError.invalidPlan } }
        }
    }

    @MainActor private func invalidate() { generation = UUID(); plan = .null; confirmation = "" }
}

private struct UpdateOperationSummary: View {
    let operation: JSONValue
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(operation["componentId"].stringValue ?? "Manutenzione server").font(.headline)
                Spacer()
                StatusPill(text: updateLabel(operation["status"].text), tone: updateTone(operation["status"].text))
            }
            Text(operation["stage"].text).font(.subheadline)
            if !operation["currentService"].text.isEmpty { Text(operation["currentService"].text).font(.caption).foregroundStyle(.secondary) }
            else if !operation["currentComponent"].text.isEmpty { Text(operation["currentComponent"].text).font(.caption).foregroundStyle(.secondary) }
            if let completed = operation["completedServices"].intValue, let total = operation["totalServices"].intValue, total > 0 {
                ProgressView(value: Double(completed), total: Double(total)) { Text("\(completed) di \(total) servizi") }
            } else if let completed = operation["completedSteps"].intValue, let total = operation["totalSteps"].intValue, total > 0 {
                ProgressView(value: Double(completed), total: Double(total)) { Text("\(completed) di \(total) passaggi") }
            } else if updatePending(operation) { ProgressView("In attesa dello stato server") }
            if operation["recoveryRequired"].boolValue == true { Label("Verifica amministrativa richiesta", systemImage: "exclamationmark.triangle").foregroundStyle(.orange) }
            if !operation["error"].text.isEmpty { Text(operation["error"].text).foregroundStyle(.red) }
        }.accessibilityElement(children: .combine)
    }
}

private struct UpdateOperationDetail: View {
    let operationID: String
    @Binding var operations: [String: JSONValue]
    private var operation: JSONValue { operations[operationID] ?? .null }
    var body: some View {
        List {
            Section { UpdateOperationSummary(operation: operation) }
            Section("Dettagli") {
                LabeledContent("Operazione", value: operation["id"].text)
                if !operation["targetVersion"].text.isEmpty { LabeledContent("Versione destinazione", value: operation["targetVersion"].text) }
                ForEach([("Creata", "createdAt"), ("Avviata", "startedAt"), ("Terminata", "finishedAt")], id: \.1) { field in
                    if !operation[field.1].text.isEmpty { LabeledContent(field.0, value: operation[field.1].text) }
                }
            }
            if !operation["serviceResults"].arrayValue.isEmpty {
                Section("Stato di ogni servizio") {
                    ForEach(Array(operation["serviceResults"].arrayValue.enumerated()), id: \.offset) { _, service in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(service["service"].text).font(.headline)
                            Text(service["componentId"].text).font(.caption).foregroundStyle(.secondary)
                            StatusPill(text: updateLabel(service["status"].text), tone: updateTone(service["status"].text))
                            Text(service["stage"].text).font(.subheadline)
                            if !service["error"].text.isEmpty { Text(service["error"].text).foregroundStyle(.red) }
                        }
                    }
                }
            }
            if !operation["componentResults"].arrayValue.isEmpty {
                Section("Componenti") {
                    ForEach(Array(operation["componentResults"].arrayValue.enumerated()), id: \.offset) { _, component in
                        LabeledContent(component["componentId"].text, value: updateLabel(component["status"].text))
                    }
                }
            }
        }.navigationTitle("Operazione").navigationBarTitleDisplayMode(.inline)
    }
}

private func updatePending(_ operation: JSONValue) -> Bool {
    !["succeeded", "completed", "failed", "rolled_back", "rolled-back", "rollback_failed", "interrupted"].contains(operation["status"].text)
}

private func updateLabel(_ status: String) -> String {
    ["current": "Aggiornato", "update-available": "Aggiornamento disponibile", "unsupported": "Non supportato", "unavailable": "Versione non verificabile", "not-installed": "Non installato", "queued": "In coda", "running": "In corso", "preparing": "Preparazione", "checking": "Verifica", "updating": "Aggiornamento", "verifying": "Verifica servizio", "verified": "Verificato", "succeeded": "Completato", "completed": "Completato", "failed": "Non riuscito", "rolled-back": "Ripristinato", "rolled_back": "Ripristinato", "rollback_failed": "Ripristino non riuscito", "interrupted": "Interrotto", "skipped": "Non eseguito"][status] ?? (status.isEmpty ? "Stato non disponibile" : status)
}

private func updateTone(_ status: String) -> Color {
    if ["current", "succeeded", "completed", "verified"].contains(status) { return .green }
    if ["failed", "rollback_failed"].contains(status) { return .red }
    if ["unsupported", "unavailable", "interrupted", "rolled-back", "rolled_back", "update-available"].contains(status) { return .orange }
    return .secondary
}

private func updateDate(_ raw: String) -> Date? {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.date(from: raw) ?? ISO8601DateFormatter().date(from: raw)
}

private enum UpdateUIError: LocalizedError {
    case invalidPlan, invalidOperation
    var errorDescription: String? {
        switch self {
        case .invalidPlan: "Piano non valido, cambiato o scaduto. Prepara un nuovo piano."
        case .invalidOperation: "Il server non ha restituito un identificativo operazione verificabile."
        }
    }
}
