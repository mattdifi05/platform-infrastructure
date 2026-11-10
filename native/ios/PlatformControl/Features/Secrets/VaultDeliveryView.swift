import SwiftUI

private struct VaultDeliveryPlan: Identifiable {
    let value: JSONValue
    var id: String { value["planId"].text }
}

struct VaultDeliveryView: View {
    @Environment(AppModel.self) private var app
    @Environment(\.scenePhase) private var scenePhase
    let bindingID: String
    @Binding var catalog: JSONValue
    let refresh: () async -> Void
    @State private var selectedVersion = ""
    @State private var plan: VaultDeliveryPlan?
    @State private var confirmAdoption = false
    @State private var busy = false
    @State private var error: String?
    @State private var notice: String?
    @State private var operation: JSONValue = .null
    @State private var operationID = ""
    @State private var generation = UUID()

    private var binding: JSONValue { catalog["runtime"]["bindings"].arrayValue.first { $0["bindingId"].text == bindingID } ?? .null }
    private var item: JSONValue { catalog["items"].arrayValue.first { $0["id"].text == binding["itemId"].text } ?? .null }
    private var revision: String { catalog["runtime"]["vaultRevision"].stringValue ?? catalog["revision"].text }
    private var working: Bool { busy || (!operationID.isEmpty && deliveryPending(operation)) }
    private var rotationUnsupported: Bool {
        let raw = binding["rotation"].text.lowercased()
        return binding["rotation"].boolValue == false || binding["rotation"]["supported"].boolValue == false || raw.contains("coupled") || raw.contains("unsupported") || raw.contains("disabled")
    }

    var body: some View {
        List {
            if let error { ErrorNotice(message: error) }
            if let notice { Text(notice).font(.subheadline).foregroundStyle(.secondary) }
            Section("Verifiche indipendenti") {
                deliveryEvidence("Consegna", verified: binding["deliveryVerified"].boolValue == true)
                deliveryEvidence("Salute applicazione", verified: binding["runtimeHealthy"].boolValue == true)
                deliveryEvidence("Provider", verified: binding["providerVerified"].boolValue == true)
                if !binding["verifiedAt"].text.isEmpty { LabeledContent("Ultima verifica", value: binding["verifiedAt"].text) }
                LabeledContent("Applicazione", value: binding["project"].text)
                LabeledContent("Ambiente", value: binding["environment"].text)
            }
            if !binding["consumers"].arrayValue.isEmpty {
                Section("Servizi interessati") {
                    ForEach(Array(binding["consumers"].arrayValue.enumerated()), id: \.offset) { _, consumer in Text(consumer["name"].text) }
                }
            }
            if binding["adopted"].boolValue != true {
                Section {
                    Button("Centralizza credenziale attuale", systemImage: "square.and.arrow.down") { confirmAdoption = true }
                        .disabled(working || revision.isEmpty || binding == .null)
                } footer: { Text("Legge la credenziale già usata dai servizi e la salva cifrata nel Vault. Non viene mostrata né cambiata.") }
            } else {
                Section("Consegna una versione") {
                    if rotationUnsupported {
                        Text("Cambio credenziali non supportato per questo collegamento: occorre una manutenzione coordinata.").foregroundStyle(.secondary)
                    } else {
                        Picker("Versione", selection: $selectedVersion) {
                            ForEach(Array(item["versions"].arrayValue.enumerated()), id: \.offset) { index, version in
                                Text("Versione \(index + 1)\(version["versionId"].text == binding["appliedVersionId"].text ? " · in uso" : "") · \(version["createdAt"].text)").tag(version["versionId"].text)
                            }
                        }
                        Button("Verifica piano di consegna", systemImage: "checklist") { Task { await prepare(rollback: false) } }
                            .disabled(working || selectedVersion.isEmpty || revision.isEmpty)
                    }
                    if !binding["previousVersionId"].text.isEmpty {
                        Button("Verifica ripristino precedente", systemImage: "arrow.uturn.backward") { Task { await prepare(rollback: true) } }
                            .disabled(working || revision.isEmpty)
                    }
                }
            }
            if !operationID.isEmpty || operation != .null {
                Section {
                    StatusPill(text: deliveryPhase(operation["phase"].text), tone: deliveryColor(operation["phase"].text))
                    if !operationID.isEmpty { LabeledContent("Identificativo", value: operationID) }
                    if deliveryPending(operation) { ProgressView("In attesa della verifica server") }
                    deliveryEvidence("Consegna operazione", verified: operation["deliveryVerified"].boolValue == true)
                    deliveryEvidence("Salute applicazione", verified: operation["runtimeHealthy"].boolValue == true)
                    deliveryEvidence("Provider", verified: operation["providerVerified"].boolValue == true)
                    Button("Aggiorna risultato", systemImage: "arrow.clockwise") { Task { await poll() } }.disabled(busy)
                } header: { Text("Operazione") } footer: { Text("Una richiesta in coda non conferma la consegna. Consegna, salute dell’applicazione e verifica del provider sono prove distinte.") }
            } else {
                Section { Button("Controlla stato collegamento", systemImage: "arrow.clockwise") { Task { await poll() } }.disabled(busy) }
            }
            Section("Riferimenti") {
                LabeledContent("Collegamento", value: bindingID)
                LabeledContent("Secret", value: binding["itemId"].text)
                LabeledContent("Versione applicata", value: binding["appliedVersionId"].stringValue ?? "Nessuna")
                if !binding["previousVersionId"].text.isEmpty { LabeledContent("Versione precedente", value: binding["previousVersionId"].text) }
            }
        }
        .navigationTitle(binding["label"].stringValue ?? "Consegna")
        .navigationBarTitleDisplayMode(.inline)
        .refreshable { await refresh(); await poll() }
        .task {
            selectedVersion = item["currentVersionId"].stringValue ?? binding["appliedVersionId"].text
            let last = binding["lastOperation"]
            operationID = last.stringValue ?? last["operationId"].text
            if !operationID.isEmpty { await poll() }
        }
        .task(id: "\(operationID)-\(scenePhase)") {
            guard !operationID.isEmpty, scenePhase == .active else { return }
            for _ in 0..<45 {
                guard !Task.isCancelled, deliveryPending(operation) else { return }
                do { try await Task.sleep(for: .seconds(2)) } catch { return }
                guard !Task.isCancelled, scenePhase == .active else { return }
                await poll()
            }
            if deliveryPending(operation) { notice = "Controllo automatico terminato. L’esito resta da verificare: usa Aggiorna risultato." }
        }
        .confirmationDialog("Centralizzare la credenziale attuale?", isPresented: $confirmAdoption, titleVisibility: .visible) {
            Button("Centralizza") { Task { await adopt() } }
        } message: { Text("Salva nel Vault la credenziale già in uso, senza cambiarla o mostrarla.") }
        .sheet(item: $plan) { value in
            VaultDeliveryPlanSheet(plan: value.value) { result in
                operationID = result["operationId"].text
                operation = .object(["operationId": .string(operationID), "phase": .string("queued")])
                notice = "Richiesta in coda. In attesa della verifica di consegna."
                await poll()
            }
        }
        .onChange(of: scenePhase) { _, phase in if phase == .background { generation = UUID(); plan = nil } }
        .onDisappear { generation = UUID() }
    }

    private func deliveryEvidence(_ title: String, verified: Bool) -> some View {
        LabeledContent(title) { Label(verified ? "Verificata" : "Non verificata", systemImage: verified ? "checkmark.circle" : "questionmark.circle").foregroundStyle(verified ? .green : .secondary) }
    }

    @MainActor private func adopt() async {
        guard !working else { return }
        let current = generation
        busy = true
        defer { busy = false }
        do {
            try await app.confirmVaultAction("Centralizza la credenziale nel Vault.")
            guard current == generation, scenePhase != .background else { return }
            let result = try await app.post("/control/v1/vault/runtime/adopt", body: .object(["bindingId": .string(bindingID), "confirmation": .string("ADOPT:\(bindingID)"), "expectedVaultRevision": .string(revision)]))
            guard result["bindingId"].text == bindingID, result["adopted"].boolValue == true else { throw DeliveryUIError.invalidResponse }
            notice = "Credenziale centralizzata. Consulta le verifiche del collegamento aggiornato."
            error = nil
            await refresh()
            selectedVersion = item["currentVersionId"].text
        } catch is CancellationError { }
        catch let error as VaultFaceIDError {
            if current == generation { self.error = error.localizedDescription }
        } catch {
            self.error = "Centralizzazione non confermata. Aggiorna il collegamento prima di riprovare. \(error.localizedDescription)"
            await refresh()
        }
    }

    @MainActor private func prepare(rollback: Bool) async {
        guard !working else { return }
        let current = generation
        let expectedVault = revision
        let expectedBinding = binding["bindingRevision"].text
        let expectedVersion = rollback ? binding["previousVersionId"].text : selectedVersion
        busy = true
        defer { busy = false }
        do {
            guard current == generation, scenePhase == .active else { return }
            var body: [String: JSONValue] = ["bindingId": .string(bindingID), "expectedVaultRevision": .string(expectedVault), "expectedBindingRevision": .string(expectedBinding)]
            if !rollback { body["itemId"] = binding["itemId"]; body["versionId"] = .string(expectedVersion) }
            let result = try await app.post("/control/v1/vault/runtime/\(rollback ? "rollback" : "plan")", body: .object(body))
            guard current == generation, scenePhase == .active else { return }
            guard result["bindingId"].text == bindingID, result["versionId"].text == expectedVersion,
                  result["expectedVaultRevision"].text == expectedVault, result["expectedBindingRevision"].text == expectedBinding,
                  result["itemId"].text == binding["itemId"].text else { throw DeliveryUIError.invalidResponse }
            try validateDeliveryPlan(result)
            plan = VaultDeliveryPlan(value: result); error = nil
        } catch { if current == generation { self.error = error.localizedDescription } }
    }

    @MainActor private func poll() async {
        guard scenePhase == .active else { return }
        do {
            let body: JSONValue = operationID.isEmpty ? .object(["bindingId": .string(bindingID)]) : .object(["operationId": .string(operationID)])
            let result = try await app.post("/control/v1/vault/runtime/status", body: body)
            let next = result["operation"]
            if next != .null {
                guard next["bindingId"].text == bindingID,
                      operationID.isEmpty || next["operationId"].text == operationID else { throw DeliveryUIError.invalidResponse }
                operation = next
                operationID = next["operationId"].text
            }
            error = nil
            await refresh()
            if operationID.isEmpty {
                let last = binding["lastOperation"]
                operationID = last.stringValue ?? last["operationId"].text
            }
        } catch { self.error = "Stato non verificabile. L’operazione può proseguire sul server. \(error.localizedDescription)" }
    }
}

private struct VaultDeliveryPlanSheet: View {
    @Environment(AppModel.self) private var app
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    let plan: JSONValue
    let accepted: (JSONValue) async -> Void
    @State private var confirmation = ""
    @State private var busy = false
    @State private var error: String?
    @State private var generation = UUID()
    @State private var dispatched = false

    var body: some View {
        NavigationStack {
            Form {
                if let error { ErrorNotice(message: error) }
                Section("Piano verificato") {
                    LabeledContent("Tipo", value: plan["kind"].text == "rollback" ? "Ripristino" : "Consegna")
                    LabeledContent("Versione", value: plan["versionId"].text)
                    if let expiry = deliveryDate(plan["expiresAt"].text) { LabeledContent("Scadenza") { Text(expiry, style: .time) } }
                    if plan["requiresRestart"].boolValue == true { Label("Richiede un riavvio controllato dei servizi", systemImage: "restart").foregroundStyle(.orange) }
                    Text(plan["providerVerification"].text == "available" ? "Il provider sarà verificato separatamente." : "La verifica automatica del provider non è disponibile.")
                }
                Section("Servizi interessati") {
                    ForEach(Array(plan["consumers"].arrayValue.enumerated()), id: \.offset) { _, consumer in Text(consumer["name"].text) }
                }
                Section {
                    TextField("Scrivi APPLICA", text: $confirmation).textInputAutocapitalization(.characters).autocorrectionDisabled()
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        let valid = deliveryDate(plan["expiresAt"].text).map { $0 > context.date } ?? false
                        if !valid { Text("Piano scaduto. Chiudi e verifica un nuovo piano.").foregroundStyle(.orange) }
                        Button { Task { await apply() } } label: {
                            if busy { ProgressView("Invio richiesta…") } else { Text("Applica") }
                        }.disabled(busy || dispatched || confirmation != "APPLICA" || !valid)
                    }
                } footer: { Text("Il piano è legato al secret, alla versione e alle revisioni verificate. La richiesta in coda non conferma l’esito.") }
            }
            .navigationTitle("Rivedi consegna").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Chiudi") { generation = UUID(); dismiss() }.disabled(busy) } }
            .interactiveDismissDisabled(busy)
            .onChange(of: scenePhase) { _, phase in if phase == .background { generation = UUID(); confirmation = ""; dismiss() } }
            .onDisappear { generation = UUID(); confirmation = "" }
        }
    }

    @MainActor private func apply() async {
        guard !busy, confirmation == "APPLICA" else { return }
        let current = generation
        busy = true
        defer { busy = false }
        do {
            try await app.confirmVaultAction("Applica la modifica della credenziale.")
            guard current == generation, scenePhase != .background else { return }
            try validateDeliveryPlan(plan)
            dispatched = true
            let result = try await app.post("/control/v1/vault/runtime/apply", body: .object(["bindingId": plan["bindingId"], "planId": plan["planId"], "confirmation": plan["confirmation"], "expectedVaultRevision": plan["expectedVaultRevision"], "expectedBindingRevision": plan["expectedBindingRevision"]]))
            guard !result["operationId"].text.isEmpty, result["phase"].text == "queued", result["bindingId"] == plan["bindingId"] else { throw DeliveryUIError.invalidResponse }
            await accepted(result)
            dismiss()
        } catch is CancellationError { }
        catch {
            if current == generation {
                self.error = dispatched ? "Esito da verificare. Chiudi e controlla lo stato del collegamento prima di preparare un altro piano. \(error.localizedDescription)" : error.localizedDescription
            }
        }
    }
}

private func validateDeliveryPlan(_ plan: JSONValue) throws {
    guard !plan["planId"].text.isEmpty, plan["status"].text == "validated",
          plan["confirmation"].text == "APPLY:\(plan["planId"].text)",
          !plan["bindingId"].text.isEmpty, !plan["itemId"].text.isEmpty, !plan["versionId"].text.isEmpty,
          !plan["expectedVaultRevision"].text.isEmpty, !plan["expectedBindingRevision"].text.isEmpty,
          let expiry = deliveryDate(plan["expiresAt"].text), expiry > Date() else { throw DeliveryUIError.invalidResponse }
}

private func deliveryPending(_ operation: JSONValue) -> Bool {
    !["verified", "rolled-back", "failed", "requires-reconciliation"].contains(operation["phase"].text)
}

private func deliveryPhase(_ phase: String) -> String {
    ["queued": "In coda", "applying": "Consegna in corso", "verifying": "Verifica in corso", "rolling-back": "Ripristino in corso", "verified": "Consegna verificata", "rolled-back": "Ripristino completato", "failed": "Non riuscita", "requires-reconciliation": "Verifica amministrativa richiesta"][phase] ?? (phase.isEmpty ? "Esito da verificare" : phase)
}

private func deliveryColor(_ phase: String) -> Color {
    switch phase { case "verified": .green; case "failed": .red; case "rolled-back", "requires-reconciliation": .orange; default: .secondary }
}

private func deliveryDate(_ raw: String) -> Date? {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.date(from: raw) ?? ISO8601DateFormatter().date(from: raw)
}

private enum DeliveryUIError: LocalizedError {
    case invalidResponse
    var errorDescription: String? { "Risposta o piano di consegna non valido, cambiato o scaduto. Aggiorna il collegamento." }
}
