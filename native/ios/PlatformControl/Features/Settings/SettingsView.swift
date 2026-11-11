import SwiftUI

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var backup: JSONValue = .null
    @State private var error: String?
    @State private var busy = false
    @State private var confirmBackup = false
    @State private var confirmLogout = false
    @State private var feedback: String?
    @AppStorage("appearance") private var appearance = "system"

    var body: some View {
        Form {
            if model.isTestEnvironment { Section { Label("Ambiente di prova · nessuna operazione sulla VPS", systemImage: "testtube.2").foregroundStyle(.orange) } }
            if let error { Section { ErrorNotice(message: error) { Task { await load() } } } }
            if let feedback { Section { Label(feedback, systemImage: "checkmark.circle").foregroundStyle(.green) } }
            Section("Server") {
                LabeledContent("Indirizzo", value: "portal.stexor.com")
                LabeledContent("Connessione", value: "HTTPS")
                LabeledContent("Account", value: model.bootstrap["session"]["displayName"].stringValue ?? model.bootstrap["session"]["email"].stringValue ?? "Proprietario")
            }
            Section {
                Toggle(isOn: Binding(get: { backup["control"]["enabled"].boolValue == true }, set: { _ in confirmBackup = true })) {
                    Label("Backup del server", systemImage: "externaldrive.badge.timemachine")
                }.disabled(busy || backup["control"]["available"].boolValue != true || backup["controlQueueActive"].boolValue != true)
                    .contentSkeleton(busy || (backup == .null && error == nil), title: "Verifica backup…")
                NavigationLink { BackupManagementView() } label: { Label("Copie e ripristino", systemImage: "clock.arrow.circlepath") }
            } header: { Text("Backup") } footer: { Text("Controlla le copie locali e FTP. I backup inclusi nel servizio Hostinger hanno una gestione separata.") }
            Section("Aspetto") {
                Picker("Tema", selection: $appearance) { Text("Automatico").tag("system"); Text("Chiaro").tag("light"); Text("Scuro").tag("dark") }
            }
            Section("Gestione") {
                NavigationLink { RemoteDetailView(title: "Connessioni", path: "/control/provider-connections") } label: { Label("Servizi collegati", systemImage: "point.3.connected.trianglepath.dotted") }
                NavigationLink { RemoteDetailView(title: "Configurazione", path: "/control/settings") } label: { Label("Configurazione del server", systemImage: "server.rack") }
                NavigationLink { RemoteDetailView(title: "Sicurezza", path: "/control/security/summary") } label: { Label("Sicurezza", systemImage: "lock.shield") }
            }
            Section {
                Button(role: .destructive) { confirmLogout = true } label: { Label("Esci", systemImage: "rectangle.portrait.and.arrow.right") }.disabled(busy)
            }
            Section { LabeledContent("Platform", value: appVersion) }.foregroundStyle(.secondary)
        }.navigationTitle("Impostazioni").navigationBarTitleDisplayMode(.inline)
            .task {
                if backup == .null, let cached = model.cachedPage("/control/backups/control") { backup = cached }
                await load()
            }.skeletonRefreshable { await load() }
            .confirmationDialog(backup["control"]["enabled"].boolValue == true ? "Disattivare i backup?" : "Attivare i backup?", isPresented: $confirmBackup, titleVisibility: .visible) {
                Button(backup["control"]["enabled"].boolValue == true ? "Disattiva backup" : "Attiva backup") { Task { await changeBackup() } }
                Button("Annulla", role: .cancel) { }
            } message: { Text("La modifica viene applicata sul server dopo la conferma con passkey.") }
            .confirmationDialog("Uscire da Platform?", isPresented: $confirmLogout, titleVisibility: .visible) {
                Button("Esci", role: .destructive) { Task { do { try await model.logout() } catch { self.error = error.localizedDescription } } }
                Button("Annulla", role: .cancel) { }
            }
    }

    private var appVersion: String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "—"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "—"
        return "\(version) (\(build)) · iOS nativo"
    }

    private func load() async { do { backup = try await model.readPage("/control/backups/control"); error = nil } catch { self.error = error.localizedDescription } }
    private func changeBackup() async {
        busy = true; error = nil; feedback = nil
        defer { busy = false }
        do {
            try await model.stepUp()
            let enabled = backup["control"]["enabled"].boolValue != true
            let value = try await model.post("/control/backups/control", body: .object(["enabled": .bool(enabled), "expectedRevision": backup["control"]["revision"]]))
            let id = value["request"]["id"].text
            guard value["accepted"].boolValue == true, !id.isEmpty else { throw APIError(status: 0, message: "Il server non ha accettato la modifica.") }
            for _ in 0..<60 {
                try await Task.sleep(for: .seconds(2))
                let result = try await model.get("/control/backups/control?requestId=" + id)
                backup = result
                if result["control"]["requestId"].text == id, result["control"]["enabled"].boolValue == enabled {
                    feedback = enabled ? "Backup attivati sul server." : "Backup disattivati sul server."
                    return
                }
                if result["request"]["status"].text == "failed" { throw APIError(status: 0, message: "Il server non ha applicato la modifica ai backup.") }
            }
            throw APIError(status: 0, message: "La richiesta è ancora in corso. Aggiorna per verificarne l’esito.")
        } catch is CancellationError { }
        catch { self.error = error.localizedDescription }
    }
}

private struct BackupManagementView: View {
    @Environment(AppModel.self) private var model
    @State private var catalog: JSONValue?
    @State private var error: String?
    @State private var busy = false
    @State private var feedback: String?
    @State private var confirmCapture = false
    var body: some View {
        List {
            if let error { ErrorNotice(message: error) { Task { await load() } } }
            if let feedback { Section { Label(feedback, systemImage: "checkmark.circle").foregroundStyle(.green) } }
            if let catalog {
                Section {
                    StatusPill(text: catalog["enabled"].boolValue == true ? "Backup attivi" : "Backup disattivati", tone: catalog["enabled"].boolValue == true ? .green : .secondary)
                }
                Section("Copie complete") {
                    let records = catalog["manifests"].arrayValue
                    if records.isEmpty { Text("Nessuna copia disponibile.").foregroundStyle(.secondary) }
                    ForEach(Array(records.enumerated()), id: \.offset) { _, record in
                        NavigationLink { BackupRestoreView(record: record) } label: {
                            backupRow(record)
                        }
                        .disabled(record["restoreCompatible"].boolValue == false)
                    }
                }
                Section {
                    Button { confirmCapture = true } label: { Label("Crea backup completo", systemImage: "plus.circle") }
                        .disabled(busy || catalog["enabled"].boolValue != true || catalog["queueActive"].boolValue != true)
                        .contentSkeleton(busy, title: "Richiesta del backup…")
                }
            } else if busy {
                Section {
                    StatusPill(text: "Backup attivi", tone: .secondary)
                        .contentSkeleton("Caricamento copie…")
                }
                Section("Copie complete") {
                    NavigationLink(destination: EmptyView()) {
                        backupRow(.object([
                            "id": .string("Copia del server"),
                            "createdAt": .string("2026-01-01T12:00:00Z")
                        ]))
                    }
                    .contentSkeleton()
                }
                Section {
                    Label("Crea backup completo", systemImage: "plus.circle")
                        .contentSkeleton()
                }
            }
            else { Button("Carica copie con passkey") { Task { await load() } } }
        }.navigationTitle("Copie e ripristino").navigationBarTitleDisplayMode(.inline)
            .confirmationDialog("Creare un backup completo del server?", isPresented: $confirmCapture, titleVisibility: .visible) {
                Button("Accoda backup completo") { Task { await capture() } }
                Button("Annulla", role: .cancel) { }
            } message: { Text("La richiesta include tutte le risorse ammesse dal catalogo VPS. Il completamento viene verificato separatamente dalla creazione della richiesta.") }
    }
    private func backupRow(_ record: JSONValue) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(record["id"].text).font(.headline)
            Text(NativeFormatting.date(record["createdAt"].text))
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private func load() async {
        busy = true; defer { busy = false }
        do { try await model.stepUp(); catalog = try await model.get("/control/backups/vps")["catalog"]; error = nil } catch is CancellationError { } catch { self.error = error.localizedDescription }
    }
    private func capture() async {
        busy = true; error = nil; feedback = nil
        defer { busy = false }
        do {
            try await model.stepUp()
            let result = try await model.post("/control/backups/run", body: .object(["scope": .string("all")]))
            let jobID = result["job"]["id"].text
            guard !jobID.isEmpty else { throw APIError(status: 0, message: "Identificativo del backup assente. Verifica le operazioni prima di riprovare.") }
            if result["job"]["status"].text == "failed" { throw APIError(status: 0, message: result["job"]["resultSummary"].stringValue ?? "Richiesta di backup fallita.") }
            error = nil
            feedback = result["job"]["status"].text == "done" ? "Backup completato: \(jobID)" : "Backup accodato: \(jobID). Il completamento non è ancora verificato."
        } catch is CancellationError { }
        catch { self.error = error.localizedDescription }
    }
}

private struct BackupRestoreView: View {
    @Environment(AppModel.self) private var model
    let record: JSONValue
    @State private var plan: JSONValue?
    @State private var error: String?
    @State private var confirmation = ""
    @State private var busy = false
    @State private var result: JSONValue?
    var body: some View {
        Form {
            Section("Backup selezionato") { Text(record["id"].text); Text(NativeFormatting.date(record["createdAt"].text)).foregroundStyle(.secondary) }
            if let error { ErrorNotice(message: error) }
            if let result { Section("Esito della richiesta") { NavigationLink("Dettagli") { JSONDetailView(title: "Ripristino", value: result) }; Text("Controlla il completamento nelle operazioni del server.").foregroundStyle(.secondary) } }
            else if let plan {
                Section("Ripristino sul server attivo") {
                    Text("Il ripristino sostituisce i dati attuali con quelli della copia selezionata e può fermare temporaneamente i servizi.").foregroundStyle(.orange)
                    NavigationLink("Piano e verifiche") { JSONDetailView(title: "Piano di ripristino", value: plan) }
                    TextField("Scrivi " + plan["details"]["confirmationRequired"].text, text: $confirmation).textInputAutocapitalization(.never).autocorrectionDisabled()
                    Button("Ripristina questa copia", role: .destructive) { Task { await restore() } }.disabled(busy || plan["details"]["enabled"].boolValue != true || confirmation.isEmpty || confirmation != plan["details"]["confirmationRequired"].text)
                        .contentSkeleton(busy, title: "Verifica del server…")
                }
            } else { Button("Verifica il piano di ripristino") { Task { await review() } }.disabled(busy).contentSkeleton(busy, title: "Verifica del server…") }
        }.navigationTitle("Ripristino").navigationBarTitleDisplayMode(.inline)
    }
    private func review() async { busy = true; defer { busy = false }; do { try await model.stepUp(); plan = try await model.post("/control/backups/production-restore", body: .object(["manifestId": record["id"]])); error = nil } catch is CancellationError { } catch { self.error = error.localizedDescription } }
    private func restore() async {
        busy = true; defer { busy = false }
        do { try await model.stepUp(); result = try await model.post("/control/backups/production-restore", body: .object(["manifestId": record["id"], "reviewedManifestId": record["id"], "confirm": .string(confirmation), "apply": .bool(true)])); error = nil }
        catch is CancellationError { } catch { self.error = error.localizedDescription }
    }
}
