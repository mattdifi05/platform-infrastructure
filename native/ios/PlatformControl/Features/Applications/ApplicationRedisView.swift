import SwiftUI

@MainActor
struct ApplicationRedisView: View {
    @Environment(AppModel.self) private var model
    let store: ApplicationsStore
    @State private var operation: ApplicationOperation?
    private var redis: JSONValue { store.catalog["redis"] }
    private var available: Bool { redis["available"].boolValue == true }

    var body: some View {
        List {
            Section("Istanza Redis") {
                LabeledContent("Stato") { StatusPill(text: available ? applicationLabel(redis["status"].text) : "Non raggiungibile", tone: available ? .green : .orange) }
                if !redis["message"].text.isEmpty { Text(redis["message"].text).foregroundStyle(.secondary) }
                LabeledContent("Versione", value: redis["version"].text)
                LabeledContent("Host", value: redis["host"].text)
                LabeledContent("Porta", value: redis["port"].displayText)
                LabeledContent("Database", value: redis["database"].displayText)
            }
            Section("Metriche") {
                LabeledContent("RAM usata", value: available ? NativeFormatting.bytes(redis["memory"]["usedBytes"].doubleValue) : "Non disponibile")
                LabeledContent("Picco RAM", value: available ? NativeFormatting.bytes(redis["memory"]["peakBytes"].doubleValue) : "Non disponibile")
                LabeledContent("Limite RAM", value: (redis["memory"]["maxBytes"].doubleValue ?? 0) > 0 ? NativeFormatting.bytes(redis["memory"]["maxBytes"].doubleValue) : "Limite container")
                LabeledContent("Chiavi", value: available ? redis["keyCount"].displayText : "Non disponibile")
                LabeledContent("Client", value: available ? redis["clients"].displayText : "Non disponibile")
                LabeledContent("Cache hit", value: available ? NativeFormatting.percent(redis["stats"]["hitRate"].doubleValue) : "Non disponibile")
            }
            Section("Persistenza") {
                LabeledContent("AOF", value: available ? (redis["persistence"]["aofEnabled"].boolValue == true ? "Attivo" : "Disattivo") : "Non disponibile")
                LabeledContent("Ultimo rewrite AOF", value: redis["persistence"]["aofLastStatus"].stringValue ?? "Non disponibile")
                LabeledContent("Ultimo RDB", value: NativeFormatting.date(redis["persistence"]["rdbLastSaveAt"].text))
                LabeledContent("Chiavi rimosse per eviction", value: redis["stats"]["evictedKeys"].displayText)
                LabeledContent("Uptime", value: redis["uptimeSeconds"].doubleValue.map { Duration.seconds($0).formatted(.units(allowed: [.days, .hours, .minutes], width: .abbreviated)) } ?? "Non disponibile")
            }
            Section("ACL e applicazioni") {
                ForEach(redis["aclUsers"].arrayValue, id: \.self) { user in Label(user.text, systemImage: "person.badge.key") }
                ForEach(Array(redis["workloads"].arrayValue.enumerated()), id: \.offset) { _, workload in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(workload.id).font(.headline)
                        Text("ACL \(workload["username"].text) · \(workload["commandCount"].displayText) comandi ammessi").font(.caption).foregroundStyle(.secondary)
                    }
                }
                if redis["aclUsers"].arrayValue.isEmpty && redis["workloads"].arrayValue.isEmpty { Text("Nessuna ACL applicativa rilevata").foregroundStyle(.secondary) }
            }
            Section {
                Button("Crea backup Redis", systemImage: "externaldrive.badge.plus") {
                    operation = ApplicationOperation(title: "Backup Redis", explanation: "Crea e verifica un backup firmato e indipendente dell'istanza Redis. Chiavi e valori restano nell'artefatto privato.", path: "/api/native/v1/redis-backup-command", body: ["action": .string("backup")])
                }.disabled(!available)
                ForEach(redis["backups"].arrayValue, id: \.id) { backup in
                    NavigationLink { RedisBackupDetailView(backup: backup, store: store) } label: {
                        VStack(alignment: .leading, spacing: 5) {
                            Text(NativeFormatting.date(backup["createdAt"].text))
                            Text("\(backup["keyCount"].displayText) chiavi · \(NativeFormatting.bytes(backup["payloadBytes"].doubleValue))").font(.caption).foregroundStyle(.secondary)
                            if backup["verified"].boolValue == true { Label("Firma verificata", systemImage: "checkmark.shield").font(.caption).foregroundStyle(.green) }
                        }
                    }
                }
                if redis["backups"].arrayValue.isEmpty { Text("Nessun backup Redis").foregroundStyle(.secondary) }
            } header: { Text("Backup Redis") } footer: { Text("I contenuti delle chiavi non vengono visualizzati nell'app.") }
            if let error = store.detailError ?? store.error { Section { ErrorNotice(message: error) } }
        }
        .contentSkeleton(!store.hasLoadedDetails && store.detailError == nil, title: "Caricamento Redis…")
        .task(id: store.detailsRevision) { await store.loadDetails(model) }
        .navigationTitle("Redis")
        .navigationBarTitleDisplayMode(.inline)
        .skeletonRefreshable { await store.loadDetails(model, force: true) }
        .sheet(item: $operation) { ApplicationOperationSheet(operation: $0, store: store) }
    }
}

@MainActor
private struct RedisBackupDetailView: View {
    let backup: JSONValue
    let store: ApplicationsStore
    @State private var operation: ApplicationOperation?
    private var stillPresent: Bool { store.catalog["redis"]["backups"].arrayValue.contains { $0.id == backup.id } }
    var body: some View {
        List {
            Section("Backup") {
                LabeledContent("Identificativo", value: backup.id)
                LabeledContent("Creato", value: NativeFormatting.date(backup["createdAt"].text))
                LabeledContent("Chiavi", value: backup["keyCount"].displayText)
                LabeledContent("Dimensione", value: NativeFormatting.bytes(backup["sizeBytes"].doubleValue))
                LabeledContent("Firma", value: backup["verified"].boolValue == true ? "Verificata" : "Non verificata")
            }
            if stillPresent {
                Section("Azioni") {
                    Button("Ripristina Redis", systemImage: "arrow.counterclockwise", role: .destructive) {
                        operation = ApplicationOperation(title: "Ripristina Redis", explanation: "Ripristina il backup \(backup.id) sull'istanza Redis. Sessioni e cache correnti possono essere sovrascritte. Il server verifica nuovamente la firma dell'artefatto.", path: "/api/native/v1/redis-restore-command", body: ["action": .string("restore"), "backupId": .string(backup.id)], fresh: true, destructive: true, requiresTypedName: backup.id)
                    }.disabled(backup["verified"].boolValue != true)
                    Button("Elimina backup", systemImage: "trash", role: .destructive) {
                        operation = ApplicationOperation(title: "Elimina backup Redis", explanation: "Elimina definitivamente l'artefatto \(backup.id).", path: "/api/native/v1/redis-backup-delete-command", body: ["action": .string("delete"), "backupId": .string(backup.id)], fresh: true, destructive: true)
                    }
                }
            } else {
                Section { Text("Questo backup non è più presente nel catalogo.").foregroundStyle(.secondary) }
            }
        }
        .navigationTitle("Backup Redis")
        .navigationBarTitleDisplayMode(.inline)
        .sheet(item: $operation) { ApplicationOperationSheet(operation: $0, store: store) }
    }
}
