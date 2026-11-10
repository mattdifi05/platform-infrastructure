import SwiftUI

private enum UpdateScope: String, CaseIterable {
    case system, services

    var title: String { self == .system ? "Sistema" : "Servizi" }
    var path: String { "/control/v1/runtime-updates" + (self == .system ? "/system" : "") }
}

private struct UpdateReview: Identifiable {
    enum Action { case update, updateAndRestart, restart }

    let scope: UpdateScope
    let target: String
    let title: String
    let revision: String
    var action: Action = .update

    var id: String { target }
    var path: String {
        if scope == .services { return scope.path + "/" + target }
        return scope.path + (action == .restart ? "/reboot" : "")
    }
    var confirmation: String {
        switch action {
        case .update: "UPDATE"
        case .updateAndRestart: "UPDATE_AND_REBOOT"
        case .restart: "REBOOT"
        }
    }
    var buttonTitle: String {
        switch action {
        case .update: target == "all" ? "Aggiorna tutti" : "Aggiorna"
        case .updateAndRestart: "Aggiorna e riavvia"
        case .restart: "Riavvia"
        }
    }
    var planRequest: JSONValue {
        var fields: [String: JSONValue] = ["revision": .string(revision)]
        if action == .updateAndRestart { fields["rebootAfter"] = .bool(true) }
        return .object(fields)
    }
}

struct UpdatesView: View {
    @Environment(AppModel.self) private var app
    @Environment(\.scenePhase) private var scenePhase
    @State private var catalogs: [UpdateScope: JSONValue] = [:]
    @State private var catalogRequests: [UpdateScope: UUID] = [:]
    @State private var failures: [UpdateScope: String] = [:]
    @State private var operations: [String: JSONValue] = [:]
    @State private var operationScopes: [String: UpdateScope] = [:]
    @State private var trackedOperations: Set<String> = []
    @State private var review: UpdateReview?
    @State private var checking: Set<UpdateScope> = []
    @State private var loading = true
    @State private var pollingError = false

    private var system: JSONValue { catalogs[.system] ?? .null }
    private var services: JSONValue { catalogs[.services] ?? .null }
    private var components: [JSONValue] { services["components"].arrayValue.filter { $0["installed"].boolValue != false } }
    private var availableComponents: [JSONValue] { components.filter { $0["canUpdate"].boolValue == true } }
    private var pending: Bool { operations.values.contains(where: updatePending) }
    private var maintenanceInProgress: Bool { pending || !checking.isEmpty }
    private var packages: [JSONValue] { system["packages"].arrayValue }
    var body: some View {
        List {
            if loading && catalogs.isEmpty && failures.isEmpty { LoadingState(title: "Caricamento aggiornamenti…") }
            systemSection
            servicesSection
            if !availableComponents.isEmpty {
                Section("Da aggiornare") {
                    ForEach(availableComponents, id: \.id) { component in
                        VStack(alignment: .leading, spacing: 8) {
                            componentRow(component)
                            Button("Aggiorna", systemImage: "arrow.up.circle") {
                                review = UpdateReview(scope: .services, target: component.id, title: component["label"].text, revision: services["revision"].text)
                            }
                            .disabled(!canUpdateServices)
                            .accessibilityIdentifier("updates.service.\(component.id)")
                        }
                    }
                }
            }
            let remaining = components.filter { $0["canUpdate"].boolValue != true }
            if !remaining.isEmpty {
                Section("Altri servizi") {
                    ForEach(remaining, id: \.id) { componentRow($0) }
                }
            }
        }
        .navigationTitle("Aggiornamenti")
        .refreshable { await refreshCatalogs() }
        .task(id: scenePhase) {
            guard scenePhase == .active else { return }
            await refreshCatalogs()
        }
        .task(id: scenePhase == .active && pending) {
            guard scenePhase == .active, pending else { return }
            await monitorOperations()
        }
        .sheet(item: $review) { request in
            UpdatePlanSheet(review: request) { accepted in
                accept(accepted, scope: request.scope, title: request.title)
            }
        }
    }

    @ViewBuilder
    private func operationStatus(for scope: UpdateScope) -> some View {
        let scoped = operations.values.filter { operationScopes[$0.id] == scope }
        let active = scoped.filter(updatePending).sorted(by: mostRecentFirst)
        if pollingError && !active.isEmpty {
            Label("Connessione interrotta. Verifica in corso.", systemImage: "arrow.trianglehead.clockwise")
                .font(.subheadline).foregroundStyle(.secondary)
        }
        ForEach(active, id: \.id) { operation in
            operationRow(operation)
        }
        let recovery = scoped.filter { $0["recoveryRequired"].boolValue == true }.sorted(by: mostRecentFirst).first
        if let recovery, !updatePending(recovery) {
            operationRow(recovery)
        } else if active.isEmpty,
                  let latest = scoped.filter({ trackedOperations.contains($0.id) }).sorted(by: mostRecentFirst).first,
                  updateFailed(latest) {
            operationRow(latest)
        }
    }

    private func mostRecentFirst(_ left: JSONValue, _ right: JSONValue) -> Bool {
        (left["createdAt"].stringValue ?? left.id) > (right["createdAt"].stringValue ?? right.id)
    }

    private func operationRow(_ operation: JSONValue) -> some View {
        NavigationLink {
            UpdateOperationDetail(operationID: operation.id, operations: $operations)
        } label: {
            UpdateOperationSummary(operation: operation)
        }
    }

    private var systemSection: some View {
        Section(UpdateScope.system.title) {
            if let error = failures[.system] { ErrorNotice(message: error) { Task { await refreshCatalog(.system) } } }
            operationStatus(for: .system)
            Button(checking.contains(.system) ? "Verifica in corso…" : "Verifica aggiornamenti", systemImage: "arrow.clockwise") {
                Task { await check(.system) }
            }
            .disabled(maintenanceInProgress || system["canCheck"].boolValue != true)
            .accessibilityIdentifier("updates.system.check")
            if system["available"].boolValue == false {
                Text("Verifica del sistema momentaneamente indisponibile.").foregroundStyle(.secondary)
            } else if !system["checkedAt"].text.isEmpty && packages.isEmpty && system["updateCount"].intValue == 0 {
                Text("Nessun pacchetto da aggiornare.").foregroundStyle(.secondary)
            }
            if system["rebootRequired"].boolValue == true {
                Label("Riavvio richiesto", systemImage: "restart.circle").foregroundStyle(.orange)
            }
            ForEach(packages, id: \.self) { package in
                VersionChangeRow(
                    name: package["name"].text,
                    installed: package["currentVersion"].stringValue ?? "Non installata",
                    target: package["targetVersion"].stringValue
                )
            }
            if (system["updateCount"].intValue ?? 0) + (system["autoremoveCount"].intValue ?? 0) > 0 {
                Button("Aggiorna", systemImage: "arrow.up.circle") { reviewSystem(.update) }
                    .disabled(!canUpdateSystem)
                Button("Aggiorna e riavvia", systemImage: "restart") { reviewSystem(.updateAndRestart) }
                    .disabled(!canUpdateSystem)
                if !canUpdateSystem, !pending, failures[.system] == nil, system["busy"].boolValue != true {
                    Text(operations.values.contains { $0["recoveryRequired"].boolValue == true }
                         ? "Controlla l’operazione precedente prima di aggiornare."
                         : "Verifica gli aggiornamenti per avere un elenco attuale.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
            if system["rebootRequired"].boolValue == true {
                Button("Riavvia", systemImage: "restart", role: .destructive) { reviewSystem(.restart) }
                    .disabled(maintenanceInProgress || system["canReboot"].boolValue != true || system["revision"].text.isEmpty)
            }
        }
    }

    private var canUpdateSystem: Bool {
        !maintenanceInProgress && failures[.system] == nil && system["canApply"].boolValue == true && !system["revision"].text.isEmpty
    }

    private var canUpdateServices: Bool {
        !maintenanceInProgress && failures[.services] == nil && services["canApply"].boolValue == true && !services["revision"].text.isEmpty
    }

    private func reviewSystem(_ action: UpdateReview.Action) {
        review = UpdateReview(scope: .system, target: "system", title: "Sistema", revision: system["revision"].text, action: action)
    }

    private var servicesSection: some View {
        Section {
            if let error = failures[.services] { ErrorNotice(message: error) { Task { await refreshCatalog(.services) } } }
            operationStatus(for: .services)
            Button(checking.contains(.services) ? "Verifica in corso…" : "Verifica aggiornamenti", systemImage: "arrow.clockwise") {
                Task { await check(.services) }
            }
            .disabled(maintenanceInProgress || services["canCheck"].boolValue != true)
            .accessibilityIdentifier("updates.services.check")
            if !availableComponents.isEmpty {
                Button("Aggiorna tutti", systemImage: "arrow.up.circle") {
                    review = UpdateReview(scope: .services, target: "all", title: "Aggiorna tutti i servizi", revision: services["revision"].text)
                }
                .disabled(!canUpdateServices)
            } else if services["available"].boolValue == true && !services["checkedAt"].text.isEmpty {
                Text("Nessun aggiornamento pronto per l’installazione.").foregroundStyle(.secondary)
            } else if services["available"].boolValue == false {
                Text("Verifica dei servizi momentaneamente indisponibile.").foregroundStyle(.secondary)
            }
        } header: {
            Text(UpdateScope.services.title)
        } footer: {
            Text("I servizi aggiornati si riavviano automaticamente.")
        }
    }

    private func componentRow(_ component: JSONValue) -> some View {
        let installed = component["current"]["versions"].arrayValue.map(\.text).joined(separator: ", ")
        let candidate = component["candidateRelease"]["version"].stringValue ?? component["latestStable"]["version"].stringValue
        return VStack(alignment: .leading, spacing: 6) {
            VersionChangeRow(
                name: component["label"].stringValue ?? component.id,
                installed: installed.isEmpty ? (component["current"]["version"].stringValue ?? "Non disponibile") : installed,
                target: component["status"].text == "current" ? nil : candidate
            )
            if let reason = component["blockedReason"].stringValue {
                Text(reason).font(.footnote).foregroundStyle(.secondary)
            }
        }
    }

    private func refreshCatalogs() async {
        guard !Task.isCancelled else { return }
        async let host: Void = refreshCatalog(.system)
        async let services: Void = refreshCatalog(.services)
        _ = await (host, services)
        if !Task.isCancelled { loading = false }
    }

    private func refreshCatalog(_ scope: UpdateScope) async {
        let request = UUID()
        catalogRequests[scope] = request
        do {
            let catalog = try await app.get(scope.path)
            guard !Task.isCancelled, catalogRequests[scope] == request else { return }
            catalogs[scope] = catalog
            failures[scope] = nil
            for value in catalog["operations"].arrayValue where !value.id.isEmpty {
                if let known = operations[value.id], !updatePending(known) && updatePending(value) { continue }
                operationScopes[value.id] = scope
                storeOperation(value)
            }
        } catch {
            guard !Task.isCancelled, catalogRequests[scope] == request else { return }
            failures[scope] = error.localizedDescription
        }
    }

    private func monitorOperations() async {
        while !Task.isCancelled && scenePhase == .active {
            let ids = operations.values.filter(updatePending).map(\.id)
            guard !ids.isEmpty else { return }
            var interrupted = false
            var finished = false
            for id in ids {
                do {
                    let value = try await app.get("/control/v1/runtime-updates/operations/\(id)")
                    let operation = value["operation"] == .null ? value : value["operation"]
                    guard operation.id == id else { throw UpdateUIError.invalidOperation }
                    guard !Task.isCancelled else { return }
                    storeOperation(operation)
                    finished = finished || !updatePending(operation)
                } catch {
                    guard !Task.isCancelled else { return }
                    interrupted = true
                }
            }
            pollingError = interrupted
            if finished { Task { await refreshCatalogs() } }
            do { try await Task.sleep(for: .seconds(2)) }
            catch { return }
        }
    }

    private func storeOperation(_ operation: JSONValue) {
        var fields = operation.objectValue
        if let title = operations[operation.id]?["displayTitle"].stringValue { fields["displayTitle"] = .string(title) }
        operations[operation.id] = .object(fields)
        if updatePending(operation) { trackedOperations.insert(operation.id) }
    }

    private func accept(_ response: JSONValue, scope: UpdateScope, title: String) {
        let id = response["operationId"].text
        guard !id.isEmpty else { return }
        operationScopes[id] = scope
        trackedOperations.insert(id)
        operations[id] = .object([
            "id": .string(id),
            "createdAt": .string(Date.now.ISO8601Format()),
            "status": .string(response["status"].stringValue ?? "queued"),
            "displayTitle": .string(title)
        ])
    }

    private func check(_ scope: UpdateScope) async {
        guard !maintenanceInProgress else { return }
        checking.insert(scope)
        defer { checking.remove(scope) }
        do {
            let result = try await app.post(scope.path + "/check")
            guard !result["operationId"].text.isEmpty else { throw UpdateUIError.invalidOperation }
            failures[scope] = nil
            accept(result, scope: scope, title: "Verifica \(scope.title.lowercased())")
        } catch {
            failures[scope] = error.localizedDescription
        }
    }
}

private struct VersionChangeRow: View {
    let name: String
    let installed: String
    let target: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(name).font(.subheadline.weight(.semibold))
            if let target, target != installed {
                Text("\(installed) → \(target)")
                    .accessibilityLabel("Attuale \(installed), disponibile \(target)")
            } else {
                Text(installed).accessibilityLabel("Versione attuale \(installed)")
            }
        }
        .font(.footnote)
        .foregroundStyle(.primary)
        .accessibilityElement(children: .combine)
    }
}

private struct UpdatePlanSheet: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    let review: UpdateReview
    let accepted: (JSONValue) -> Void
    @State private var plan: JSONValue = .null
    @State private var preparing = true
    @State private var applying = false
    @State private var error: String?
    @State private var idempotencyKey = UUID().uuidString

    var body: some View {
        NavigationStack {
            Form {
                if preparing { LoadingState(title: "Preparazione aggiornamento…") }
                if let error { ErrorNotice(message: error, retry: plan == .null ? { Task { await prepare() } } : nil) }
                if plan != .null {
                    reviewedChanges
                    Section {
                        TimelineView(.periodic(from: .now, by: 1)) { context in
                            let valid = updateDate(plan["expiresAt"].text).map { $0 > context.date } ?? false
                            if !valid {
                                Button("Prepara di nuovo") { Task { await prepare() } }
                            } else {
                                Button(review.buttonTitle, role: review.action == .restart ? .destructive : nil) {
                                    Task { await apply() }
                                }
                                .disabled(applying)
                                .accessibilityIdentifier("updates.confirm")
                            }
                        }
                        if applying { ProgressView("Invio richiesta…") }
                    } footer: {
                        if review.action != .update {
                            Text("Il server sarà temporaneamente irraggiungibile durante il riavvio.")
                        } else if review.scope == .services {
                            Text("I servizi aggiornati si riavvieranno automaticamente.")
                        }
                    }
                }
            }
            .navigationTitle(review.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Annulla") { dismiss() }.disabled(applying) } }
            .interactiveDismissDisabled(applying)
            .task { await prepare() }
            .onChange(of: scenePhase) { _, phase in
                if phase == .background && !applying { dismiss() }
            }
        }
    }

    private var reviewedChanges: some View {
        Section("Riepilogo") {
            if review.scope == .system {
                if review.action == .restart {
                    Label("Riavvio del server", systemImage: "restart")
                } else {
                    ForEach(plan["packages"].arrayValue, id: \.self) { package in
                        VersionChangeRow(name: package["name"].text, installed: package["currentVersion"].stringValue ?? "Non installata", target: package["targetVersion"].stringValue)
                    }
                    if let cleanup = plan["autoremoveCount"].intValue, cleanup > 0 {
                        LabeledContent("Dipendenze inutilizzate da rimuovere", value: "\(cleanup)")
                    }
                }
            } else if review.target == "all" {
                ForEach(plan["components"].arrayValue, id: \.self) { component in
                    LabeledContent(component["label"].text, value: component["targetVersion"].text)
                }
            } else {
                LabeledContent("Nuova versione", value: plan["targetVersion"].text)
            }
        }
    }

    private func postAuthorized(_ path: String, body: JSONValue) async throws -> JSONValue {
        do { return try await app.post(path, body: body) }
        catch let error as APIError where error.status == 428 {
            try await app.stepUp()
            try Task.checkCancellation()
            guard scenePhase != .background else { throw CancellationError() }
            return try await app.post(path, body: body)
        }
    }

    private func prepare() async {
        preparing = true
        plan = .null
        error = nil
        defer { preparing = false }
        do {
            let result = try await postAuthorized(review.path + "/plan", body: review.planRequest)
            let candidate = result["plan"] == .null ? result : result["plan"]
            try validate(candidate)
            guard !Task.isCancelled, scenePhase != .background else { return }
            idempotencyKey = UUID().uuidString
            plan = candidate
        } catch is CancellationError {
        } catch { self.error = error.localizedDescription }
    }

    private func apply() async {
        guard !applying else { return }
        applying = true
        error = nil
        defer { applying = false }
        do {
            try validate(plan)
            let body = JSONValue.object([
                "revision": plan["revision"], "planId": plan["planId"],
                "confirmation": .string(review.confirmation), "idempotencyKey": .string(idempotencyKey)
            ])
            let result = try await postAuthorized(review.path + "/apply", body: body)
            guard !result["operationId"].text.isEmpty else { throw UpdateUIError.invalidOperation }
            accepted(result)
            dismiss()
        } catch is CancellationError {
        } catch let failure as APIError {
            error = failure.localizedDescription
        } catch {
            self.error = "Esito da verificare. Puoi riprovare senza inviare due aggiornamenti. \(error.localizedDescription)"
        }
    }

    private func validate(_ value: JSONValue) throws {
        guard !value["planId"].text.isEmpty, value["revision"].text == review.revision,
              value["confirmationRequired"].text == review.confirmation,
              let expiry = updateDate(value["expiresAt"].text), expiry > Date() else { throw UpdateUIError.invalidPlan }
        if review.scope == .system {
            guard value["kind"].text == (review.action == .restart ? "host-reboot" : "host-upgrade"),
                  (value["rebootAfter"].boolValue == true) == (review.action == .updateAndRestart) else { throw UpdateUIError.invalidPlan }
        } else {
            guard value["componentId"].text == review.target, !value["targetVersion"].text.isEmpty,
                  !value["targetDigest"].text.isEmpty else { throw UpdateUIError.invalidPlan }
            if review.target == "all" {
                guard value["kind"].text == "batch", !value["components"].arrayValue.isEmpty else { throw UpdateUIError.invalidPlan }
            }
        }
    }
}

private struct UpdateOperationSummary: View {
    let operation: JSONValue
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(title).font(.headline)
                Spacer()
                StatusPill(text: updateLabel(operation["status"].text), tone: updateTone(operation["status"].text))
            }
            if let stage = operation["stage"].stringValue { Text(stage).font(.subheadline) }
            if !operation["currentService"].text.isEmpty { Text(operation["currentService"].text).font(.caption).foregroundStyle(.secondary) }
            else if !operation["currentComponent"].text.isEmpty { Text(operation["currentComponent"].text).font(.caption).foregroundStyle(.secondary) }
            if let completed = operation["completedServices"].intValue, let total = operation["totalServices"].intValue, total > 0 {
                ProgressView(value: Double(completed), total: Double(total)) { Text("\(completed) di \(total) servizi") }
            } else if let completed = operation["completedSteps"].intValue, let total = operation["totalSteps"].intValue, total > 0 {
                ProgressView(value: Double(completed), total: Double(total)) { Text("\(completed) di \(total) passaggi") }
            } else if updatePending(operation) { ProgressView("In attesa") }
            if operation["recoveryRequired"].boolValue == true { Label("Verifica amministrativa richiesta", systemImage: "exclamationmark.triangle").foregroundStyle(.orange) }
            if !operation["error"].text.isEmpty {
                Text(operation["error"].text).foregroundStyle(.red)
            } else if updateFailed(operation), operation["recoveryRequired"].boolValue != true {
                Text("Verifica nuovamente gli aggiornamenti prima di riprovare.").font(.footnote).foregroundStyle(.secondary)
            }
        }.accessibilityElement(children: .combine)
    }

    private var title: String {
        if let title = operation["displayTitle"].stringValue { return title }
        switch operation["kind"].text {
        case "host-check": return "Verifica sistema"
        case "host-upgrade": return "Aggiornamento sistema"
        case "host-reboot": return "Riavvio"
        case "check": return "Verifica servizi"
        case "batch": return "Aggiornamento servizi"
        default: return operation["componentId"].stringValue ?? "Aggiornamento"
        }
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
                if !operation["targetVersion"].text.isEmpty { LabeledContent("Nuova versione", value: operation["targetVersion"].text) }
                ForEach([("Creata", "createdAt"), ("Avviata", "startedAt"), ("Terminata", "finishedAt")], id: \.1) { field in
                    if let date = updateDate(operation[field.1].text) { LabeledContent(field.0, value: date.formatted(date: .abbreviated, time: .shortened)) }
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
    !["succeeded", "completed"].contains(operation["status"].text) && !updateFailed(operation)
}

private func updateFailed(_ operation: JSONValue) -> Bool {
    ["failed", "rolled_back", "rolled-back", "rollback_failed", "interrupted"].contains(operation["status"].text)
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
