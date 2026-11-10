import SwiftUI

struct AlertsView: View {
    @Environment(AppModel.self) private var model
    @State private var events: JSONValue = .null
    @State private var error: String?
    @State private var loading = true
    @State private var selection = 0

    private var partialMessage: String {
        if events["sources"].arrayValue.contains(where: { $0["available"].boolValue == false }) {
            return "Alcune fonti non sono disponibili. Lo stato potrebbe essere incompleto."
        }
        return "Il riepilogo mostra un numero limitato di elementi."
    }

    var body: some View {
        List {
            if let error { Section { ErrorNotice(message: error) { Task { await load() } } } }
            if loading { LoadingState(title: "Lettura degli avvisi…") }
            else {
                Section {
                    Picker("Avvisi", selection: $selection) { Text("Attivi").tag(0); Text("Recenti").tag(1) }.pickerStyle(.segmented).listRowBackground(Color.clear).listRowInsets(EdgeInsets())
                }
                if events["partial"].boolValue == true {
                    Section { Label(partialMessage, systemImage: "info.circle").font(.subheadline).foregroundStyle(.orange) }
                }
                let entries = events[selection == 0 ? "issues" : "events"].arrayValue
                if entries.isEmpty {
                    Section { EmptyState(title: selection == 0 ? "Nessun avviso attivo" : "Nessun evento recente", systemImage: selection == 0 ? "checkmark.shield" : "clock", description: events["partial"].boolValue == true ? "Le fonti disponibili non riportano avvisi." : "Il server non segnala problemi in questa sezione.") }
                } else {
                    Section {
                        ForEach(Array(entries.enumerated()), id: \.offset) { _, item in
                            NavigationLink { EventDetailView(item: item) } label: {
                                HStack(alignment: .top, spacing: 12) {
                                    Image(systemName: item["severity"].text == "error" ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill").foregroundStyle(item["severity"].text == "error" ? .red : .orange).padding(.top, 3)
                                    VStack(alignment: .leading, spacing: 6) {
                                        Text(item["service"].text).font(.headline)
                                        Text(item["message"].text).font(.subheadline).foregroundStyle(.secondary).lineLimit(3)
                                        Text(NativeFormatting.date(item["lastSeen"].text)).font(.caption).foregroundStyle(.tertiary)
                                    }
                                }.padding(.vertical, 5)
                            }
                        }
                    }
                }
                Section("Fonti") {
                    ForEach(Array(events["sources"].arrayValue.enumerated()), id: \.offset) { _, source in
                        LabeledContent(source["id"].text) { Image(systemName: source["available"].boolValue == true ? "checkmark.circle.fill" : "exclamationmark.circle").foregroundStyle(source["available"].boolValue == true ? .green : .orange).accessibilityLabel(source["available"].boolValue == true ? "Disponibile" : "Non disponibile") }
                    }
                }
            }
        }.navigationTitle("Avvisi").navigationBarTitleDisplayMode(.inline).refreshable { await load() }
            .task {
                while !Task.isCancelled { await load(); do { try await Task.sleep(for: .seconds(15)) } catch { break } }
            }
    }
    private func load() async {
        do { events = try await model.get("/control/server-events"); error = nil; model.unreadWarnings = events["issues"].arrayValue.count }
        catch is CancellationError { }
        catch { self.error = error.localizedDescription }
        loading = false
    }
}

private struct EventDetailView: View {
    let item: JSONValue
    var body: some View {
        List {
            Section { Text(item["message"].text).textSelection(.enabled) }
            Section("Dettagli") {
                LabeledContent("Servizio", value: item["service"].text)
                LabeledContent("Livello", value: item["severity"].text == "error" ? "Errore" : "Avviso")
                LabeledContent("Fonte", value: item["source"].text)
                LabeledContent("Codice", value: item["code"].text)
                LabeledContent("Prima rilevazione", value: NativeFormatting.date(item["firstSeen"].text))
                LabeledContent("Ultima rilevazione", value: NativeFormatting.date(item["lastSeen"].text))
                LabeledContent("Occorrenze", value: item["count"].displayText)
            }
        }.navigationTitle("Dettaglio avviso").navigationBarTitleDisplayMode(.inline)
    }
}
