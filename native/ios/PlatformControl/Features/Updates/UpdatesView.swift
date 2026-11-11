import SwiftUI

private enum UpdateScope: String, CaseIterable, Sendable {
    case system, services

    var title: String { self == .system ? "Sistema" : "Servizi" }
    var path: String { "/control/v1/runtime-updates" + (self == .system ? "/system" : "") }
}

private struct UpdateReview: Identifiable, Sendable {
    enum Action: Sendable { case update, updateAndRestart, restart }

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

private struct CombinedUpdateReview: Identifiable {
    let id = UUID()
    let requests: [UpdateReview]
    var aggregate = false
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
    @State private var review: CombinedUpdateReview?
    @State private var checking: Set<UpdateScope> = []
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
            Section {
                Button {
                    Task { await checkAll() }
                } label: {
                    Label("Verifica aggiornamenti", systemImage: "arrow.clockwise")
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .contentShape(.rect)
                }
                .disabled(maintenanceInProgress || system["canCheck"].boolValue != true || services["canCheck"].boolValue != true)
                .accessibilityIdentifier("updates.check")
                .contentSkeleton(!checking.isEmpty, title: "Verifica aggiornamenti in corso…")
                if hasUpdates {
                    Button {
                        review = CombinedUpdateReview(requests: combinedRequests, aggregate: true)
                    } label: {
                        Label("Aggiorna tutto", systemImage: "arrow.up.circle")
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .contentShape(.rect)
                    }
                    .disabled(!canUpdateAll)
                    .accessibilityIdentifier("updates.all")
                }
            }
            .contentSkeleton(catalogs.count < UpdateScope.allCases.count && failures.isEmpty, title: "Caricamento aggiornamenti…")
            systemSection
            servicesSection
            if !availableComponents.isEmpty {
                Section("Da aggiornare") {
                    ForEach(availableComponents, id: \.id) { component in
                        VStack(alignment: .leading, spacing: 8) {
                            componentRow(component)
                            Button("Aggiorna", systemImage: "arrow.up.circle") {
                                review = CombinedUpdateReview(requests: [UpdateReview(scope: .services, target: component.id, title: component["label"].text, revision: services["revision"].text)])
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
        .skeletonRefreshable { await refreshCatalogs() }
        .task(id: scenePhase) {
            guard scenePhase == .active else { return }
            for scope in UpdateScope.allCases where catalogs[scope] == nil {
                if let cached = app.cachedPage(scope.path) { catalogs[scope] = cached }
            }
            await refreshCatalogs()
        }
        .task(id: scenePhase == .active && pending) {
            guard scenePhase == .active, pending else { return }
            await monitorOperations()
        }
        .sheet(item: $review) { batch in
            UpdatePlanSheet(reviews: batch.requests, aggregate: batch.aggregate) { accepted, item in
                accept(accepted, scope: item.scope, title: item.title)
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

    private var systemNeedsUpdate: Bool {
        (system["updateCount"].intValue ?? 0) + (system["autoremoveCount"].intValue ?? 0) > 0
    }

    private var hasUpdates: Bool { systemNeedsUpdate || !availableComponents.isEmpty }

    private var canUpdateAll: Bool {
        hasUpdates && !maintenanceInProgress && catalogs.count == UpdateScope.allCases.count && failures.isEmpty
            && (!systemNeedsUpdate || canUpdateSystem) && (availableComponents.isEmpty || canUpdateServices)
    }

    private var combinedRequests: [UpdateReview] {
        var requests: [UpdateReview] = []
        if systemNeedsUpdate {
            requests.append(UpdateReview(scope: .system, target: "system", title: "Sistema", revision: system["revision"].text))
        }
        if !availableComponents.isEmpty {
            requests.append(UpdateReview(scope: .services, target: "all", title: "Servizi", revision: services["revision"].text))
        }
        return requests
    }

    private var canUpdateSystem: Bool {
        !maintenanceInProgress && failures[.system] == nil && system["canApply"].boolValue == true && !system["revision"].text.isEmpty
    }

    private var canUpdateServices: Bool {
        !maintenanceInProgress && failures[.services] == nil && services["canApply"].boolValue == true && !services["revision"].text.isEmpty
    }

    private func reviewSystem(_ action: UpdateReview.Action) {
        review = CombinedUpdateReview(requests: [UpdateReview(scope: .system, target: "system", title: "Sistema", revision: system["revision"].text, action: action)])
    }

    private var servicesSection: some View {
        Section {
            if let error = failures[.services] { ErrorNotice(message: error) { Task { await refreshCatalog(.services) } } }
            operationStatus(for: .services)
            if availableComponents.isEmpty && services["available"].boolValue == true && !services["checkedAt"].text.isEmpty {
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
    }

    private func refreshCatalog(_ scope: UpdateScope) async {
        let request = UUID()
        catalogRequests[scope] = request
        do {
            let catalog = try await app.readPage(scope.path)
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

    private func checkAll() async {
        guard !maintenanceInProgress else { return }
        checking = Set(UpdateScope.allCases)
        defer { checking.removeAll() }
        async let host: Void = submitCheck(.system)
        async let services: Void = submitCheck(.services)
        _ = await (host, services)
    }

    private func submitCheck(_ scope: UpdateScope) async {
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

private struct UpdatePlanSubmission: Sendable {
    let review: UpdateReview
    let body: JSONValue
    let path: String
}

private struct UpdatePlanResult: Sendable {
    let review: UpdateReview
    var value: JSONValue?
    var error: String?
    var needsAuthentication = false
}

private struct UpdatePlanSheet: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    let reviews: [UpdateReview]
    var aggregate = false
    let accepted: (JSONValue, UpdateReview) -> Void
    @State private var plans: [String: JSONValue] = [:]
    @State private var preparing = true
    @State private var applying = false
    @State private var errors: [String: String] = [:]
    @State private var idempotencyKeys: [String: String] = [:]
    @State private var submitted: Set<String> = []
    @State private var attempted: Set<String> = []

    private var combined: Bool { aggregate }
    private var title: String { combined ? "Aggiorna tutto" : reviews.first?.title ?? "Aggiornamenti" }
    private var buttonTitle: String { combined ? "Aggiorna tutto" : reviews.first?.buttonTitle ?? "Aggiorna" }
    private var ready: Bool { !reviews.isEmpty && reviews.allSatisfy { plans[$0.scope.rawValue] != nil } }

    var body: some View {
        NavigationStack {
            Form {
                ForEach(reviews) { review in
                    Section(combined ? review.scope.title : "Riepilogo") {
                        if let message = errors[review.scope.rawValue] { ErrorNotice(message: message) }
                        if submitted.contains(review.scope.rawValue) {
                            Label("Richiesta accettata", systemImage: "checkmark.circle")
                        }
                        if let plan = plans[review.scope.rawValue] {
                            reviewedChanges(plan, review: review)
                        } else if preparing {
                            VersionChangeRow(name: review.title, installed: "Versione attuale", target: "Versione disponibile")
                                .contentSkeleton("Preparazione aggiornamento…")
                        }
                    }
                }
                Section {
                    if preparing {
                        Button(buttonTitle) {}.contentSkeleton()
                    } else if ready {
                        TimelineView(.periodic(from: .now, by: 1)) { context in
                            let valid = reviews.filter { !submitted.contains($0.scope.rawValue) }.allSatisfy {
                                attempted.contains($0.scope.rawValue)
                                    || (updateDate(plans[$0.scope.rawValue]?["expiresAt"].text ?? "").map { $0 > context.date } ?? false)
                            }
                            if !valid && submitted.isEmpty {
                                Button("Prepara di nuovo") { Task { await prepare() } }
                            } else {
                                Button(attempted.isEmpty ? buttonTitle : "Riprova richieste rimanenti", role: reviews.first?.action == .restart ? .destructive : nil) {
                                    Task { await apply() }
                                }
                                .disabled(applying || !valid)
                                .accessibilityIdentifier("updates.confirm")
                                .contentSkeleton(applying, title: "Invio richieste…")
                            }
                        }
                    } else {
                        Button("Prepara di nuovo") { Task { await prepare() } }
                    }
                } footer: {
                    if reviews.contains(where: { $0.action != .update }) {
                        Text("Il server sarà temporaneamente irraggiungibile durante il riavvio.")
                    } else if reviews.contains(where: { $0.scope == .services }) {
                        Text("I servizi aggiornati si riavvieranno automaticamente.")
                    }
                    if !submitted.isEmpty {
                        Text("Le richieste accettate sono visibili negli aggiornamenti. Chiudi per seguirne l’esito.")
                    }
                }
            }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(submitted.isEmpty ? "Annulla" : "Chiudi") { dismiss() }.disabled(applying)
                }
            }
            .interactiveDismissDisabled(applying)
            .task { await prepare() }
            .onChange(of: scenePhase) { _, phase in
                if phase == .background && !applying { dismiss() }
            }
        }
    }

    @ViewBuilder
    private func reviewedChanges(_ plan: JSONValue, review: UpdateReview) -> some View {
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

    private func send(_ request: UpdatePlanSubmission) async -> UpdatePlanResult {
        do {
            let value = try await app.post(request.path, body: request.body)
            return UpdatePlanResult(review: request.review, value: value)
        } catch {
            return UpdatePlanResult(review: request.review, error: error.localizedDescription,
                                    needsAuthentication: (error as? APIError)?.status == 428)
        }
    }

    private func sendIfPresent(_ request: UpdatePlanSubmission?) async -> UpdatePlanResult? {
        guard let request else { return nil }
        return await send(request)
    }

    private func sendTogether(_ requests: [UpdatePlanSubmission]) async -> [UpdatePlanResult] {
        async let first = sendIfPresent(requests.first)
        async let second = sendIfPresent(requests.dropFirst().first)
        return await [first, second].compactMap { $0 }
    }

    private func postAuthorized(_ requests: [UpdatePlanSubmission]) async -> [UpdatePlanResult] {
        let results = await sendTogether(requests)
        let retryScopes = Set(results.filter(\.needsAuthentication).map { $0.review.scope.rawValue })
        guard !retryScopes.isEmpty else { return results }
        do {
            try await app.stepUp()
            try Task.checkCancellation()
            guard scenePhase != .background else { throw CancellationError() }
            let retried = await sendTogether(requests.filter { retryScopes.contains($0.review.scope.rawValue) })
            return results.filter { !retryScopes.contains($0.review.scope.rawValue) } + retried
        } catch {
            return results.map { result in
                guard result.needsAuthentication else { return result }
                var failure = result
                failure.error = error.localizedDescription
                failure.needsAuthentication = false
                return failure
            }
        }
    }

    private func prepare() async {
        guard submitted.isEmpty, attempted.isEmpty else { return }
        preparing = true
        plans.removeAll()
        errors.removeAll()
        defer { preparing = false }
        let requests = reviews.map { UpdatePlanSubmission(review: $0, body: $0.planRequest, path: $0.path + "/plan") }
        let results = await postAuthorized(requests)
        guard !Task.isCancelled, scenePhase != .background else { return }
        for result in results {
            let key = result.review.scope.rawValue
            do {
                guard let value = result.value else {
                    errors[key] = result.error
                    continue
                }
                let candidate = value["plan"] == .null ? value : value["plan"]
                try validate(candidate, review: result.review)
                idempotencyKeys[key] = UUID().uuidString
                plans[key] = candidate
            } catch { errors[key] = error.localizedDescription }
        }
    }

    private func apply() async {
        guard !applying, ready, scenePhase == .active else { return }
        applying = true
        errors.removeAll()
        defer { applying = false }
        var requests: [UpdatePlanSubmission] = []
        do {
            for review in reviews where !submitted.contains(review.scope.rawValue) {
                let key = review.scope.rawValue
                guard let plan = plans[key], let idempotencyKey = idempotencyKeys[key] else { throw UpdateUIError.invalidPlan }
                if !attempted.contains(key) { try validate(plan, review: review) }
                let body = JSONValue.object([
                    "revision": plan["revision"], "planId": plan["planId"],
                    "confirmation": .string(review.confirmation), "idempotencyKey": .string(idempotencyKey)
                ])
                requests.append(UpdatePlanSubmission(review: review, body: body, path: review.path + "/apply"))
            }
        } catch {
            for review in reviews where !submitted.contains(review.scope.rawValue) {
                errors[review.scope.rawValue] = error.localizedDescription
            }
            return
        }
        attempted.formUnion(requests.map { $0.review.scope.rawValue })
        let results = await postAuthorized(requests)
        for result in results {
            let key = result.review.scope.rawValue
            if let value = result.value, !value["operationId"].text.isEmpty {
                submitted.insert(key)
                accepted(value, result.review)
            } else {
                errors[key] = result.error ?? "Esito da verificare. Riprova con la stessa richiesta per verificarne l’accettazione."
            }
        }
        if submitted.count == reviews.count { dismiss() }
    }

    private func validate(_ value: JSONValue, review: UpdateReview) throws {
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
                Text("\(completed) di \(total) servizi").font(.footnote).foregroundStyle(.secondary)
            } else if let completed = operation["completedSteps"].intValue, let total = operation["totalSteps"].intValue, total > 0 {
                Text("\(completed) di \(total) passaggi").font(.footnote).foregroundStyle(.secondary)
            }
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
