import SwiftUI
import Charts

private struct ResourceSample: Identifiable {
    let id = UUID()
    let date: Date
    let cpu: Double?
    let memory: Double?
    let received: Double?
    let sent: Double?
    let read: Double?
    let written: Double?
}

struct HomeView: View {
    @Environment(AppModel.self) private var model
    let isActive: Bool
    @State private var snapshot: JSONValue = .null
    @State private var samples: [ResourceSample] = []
    @State private var error: String?
    @State private var loading = true

    var body: some View {
        ScrollView {
            VStack(spacing: 18) {
                if let error { ErrorNotice(message: error) { Task { await refresh() } } }
                if loading { LoadingState(title: "Lettura delle risorse…") }
                else {
                    HStack {
                        VStack(alignment: .leading, spacing: 5) { Text("Stexor VPS").font(.title2.bold()); Text("Le risorse del tuo server").font(.subheadline).foregroundStyle(.secondary) }
                        Spacer()
                        let fresh = error == nil && snapshot["freshness"]["available"].boolValue == true
                        StatusPill(text: fresh ? "Operativo" : "Dati non aggiornati", tone: fresh ? .green : .orange)
                    }
                    resourceCard("CPU", value: NativeFormatting.percent(snapshot["cpu"]["usedPercent"].doubleValue), detail: snapshot["cpu"]["cores"].intValue.map { "\($0) core" } ?? "—", symbol: "cpu", color: .indigo, series: [("CPU", \.cpu)])
                    resourceCard("Memoria", value: NativeFormatting.percent(snapshot["memory"]["usedPercent"].doubleValue), detail: capacity(snapshot["memory"]), symbol: "memorychip", color: .teal, series: [("RAM", \.memory)])
                    HStack(spacing: 14) {
                        capacityCard("Disco", value: NativeFormatting.percent(snapshot["disk"]["usedPercent"].doubleValue), detail: capacity(snapshot["disk"]), symbol: "internaldrive", color: .orange)
                        capacityCard("Swap", value: NativeFormatting.bytes(snapshot["swap"]["usedBytes"].doubleValue), detail: "di " + NativeFormatting.bytes(snapshot["swap"]["totalBytes"].doubleValue), symbol: "arrow.left.arrow.right", color: .purple)
                    }
                    resourceCard("Connessione", value: NativeFormatting.bytes(snapshot["network"]["totals"]["rxBytesPerSecond"].doubleValue) + "/s", detail: "↑ " + NativeFormatting.bytes(snapshot["network"]["totals"]["txBytesPerSecond"].doubleValue) + "/s", symbol: "network", color: .blue, series: [("Ricezione", \.received), ("Invio", \.sent)])
                    resourceCard("Attività disco", value: NativeFormatting.bytes(snapshot["diskIo"]["totals"]["readBytesPerSecond"].doubleValue) + "/s", detail: "Scrittura " + NativeFormatting.bytes(snapshot["diskIo"]["totals"]["writeBytesPerSecond"].doubleValue) + "/s", symbol: "externaldrive", color: .pink, series: [("Lettura", \.read), ("Scrittura", \.written)])
                    NavigationLink { ServerInformationView(snapshot: snapshot) } label: { Label("Dettagli del server", systemImage: "server.rack").frame(maxWidth: .infinity) }.buttonStyle(.bordered)
                }
            }.padding(20)
        }.background(Color(.systemGroupedBackground)).navigationTitle("Home")
            .refreshable { await refresh() }
            .task(id: isActive) {
                guard isActive else { return }
                while !Task.isCancelled {
                    await refresh()
                    do { try await Task.sleep(for: .seconds(2)) } catch { break }
                }
            }
    }

    private func capacity(_ item: JSONValue) -> String { NativeFormatting.bytes(item["usedBytes"].doubleValue) + " di " + NativeFormatting.bytes(item["totalBytes"].doubleValue) }

    private func capacityCard(_ title: String, value: String, detail: String, symbol: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(title, systemImage: symbol).font(.subheadline.weight(.semibold)).foregroundStyle(color)
            Text(value).font(.title2.bold()).contentTransition(.numericText())
            Text(detail).font(.caption).foregroundStyle(.secondary)
        }.frame(maxWidth: .infinity, alignment: .leading).padding(18).background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 22))
    }

    private func resourceCard(_ title: String, value: String, detail: String, symbol: String, color: Color, series: [(String, KeyPath<ResourceSample, Double?>)]) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack { Label(title, systemImage: symbol).font(.subheadline.weight(.semibold)).foregroundStyle(color); Spacer(); Text(detail).font(.caption).foregroundStyle(.secondary) }
            Text(value).font(.system(size: 34, weight: .semibold, design: .rounded)).monospacedDigit().contentTransition(.numericText())
            ResourceChart(samples: samples, series: series, color: color, percentage: title == "CPU" || title == "Memoria", active: isActive)
        }.padding(20).background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 24))
    }

    private func refresh() async {
        do {
            let value = try await model.get("/control/resources/host")
            guard !Task.isCancelled else { return }
            // The API identifies stale samples explicitly; preserve gaps rather than invent zeroes.
            snapshot = value
            error = nil
            let available = value["freshness"]["available"].boolValue == true
            samples.append(ResourceSample(date: .now, cpu: available ? value["cpu"]["usedPercent"].doubleValue : nil, memory: available ? value["memory"]["usedPercent"].doubleValue : nil, received: available ? value["network"]["totals"]["rxBytesPerSecond"].doubleValue : nil, sent: available ? value["network"]["totals"]["txBytesPerSecond"].doubleValue : nil, read: available ? value["diskIo"]["totals"]["readBytesPerSecond"].doubleValue : nil, written: available ? value["diskIo"]["totals"]["writeBytesPerSecond"].doubleValue : nil))
            samples.removeAll { $0.date < Date.now.addingTimeInterval(-125) }
        } catch is CancellationError { }
        catch {
            self.error = error.localizedDescription
            samples.append(ResourceSample(date: .now, cpu: nil, memory: nil, received: nil, sent: nil, read: nil, written: nil))
            samples.removeAll { $0.date < Date.now.addingTimeInterval(-125) }
        }
        loading = false
    }
}

private struct ResourceChart: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let samples: [ResourceSample]
    let series: [(String, KeyPath<ResourceSample, Double?>)]
    let color: Color
    let percentage: Bool
    let active: Bool

    private struct Point: Identifiable {
        let id: UUID
        let date: Date
        let value: Double
        let segment: Int
    }

    private func points(for key: KeyPath<ResourceSample, Double?>) -> [Point] {
        var segment = 0
        return samples.compactMap { sample in
            guard let value = sample[keyPath: key] else { segment += 1; return nil }
            return Point(id: sample.id, date: sample.date, value: value, segment: segment)
        }
    }
    var body: some View {
        TimelineView(.animation(minimumInterval: reduceMotion ? 2 : 1.0 / 30.0, paused: !active)) { context in
            let now = context.date
            Chart {
                ForEach(Array(series.enumerated()), id: \.offset) { index, line in
                    let points = points(for: line.1)
                    ForEach(points) { point in
                        LineMark(x: .value("Ora", point.date), y: .value(line.0, point.value), series: .value("Serie", "\(line.0)-\(point.segment)"))
                            .interpolationMethod(.monotone).foregroundStyle(index == 0 ? color : color.opacity(0.4)).lineStyle(StrokeStyle(lineWidth: 2.4))
                    }
                    if let last = points.last, last.id == samples.last?.id, now.timeIntervalSince(last.date) < 6 {
                        // Move the time window continuously and extend only the last measured value.
                        LineMark(x: .value("Ora", now), y: .value(line.0, last.value), series: .value("Serie", "\(line.0)-\(last.segment)")).foregroundStyle(index == 0 ? color : color.opacity(0.4)).lineStyle(StrokeStyle(lineWidth: 2.4))
                    }
                }
            }.chartXScale(domain: now.addingTimeInterval(-120)...now)
                .chartYScale(domain: 0...(percentage ? 100 : max(1, samples.flatMap { sample in series.compactMap { sample[keyPath: $0.1] } }.max() ?? 1) * 1.15))
                .chartXAxis(.hidden).chartYAxis(.hidden).chartLegend(.hidden).frame(height: 100)
                .accessibilityLabel("Grafico degli ultimi due minuti")
        }
    }
}

private struct ServerInformationView: View {
    let snapshot: JSONValue
    var body: some View {
        List {
            Section("Server") {
                LabeledContent("Inode usati", value: NativeFormatting.percent(snapshot["inodes"]["usedPercent"].doubleValue))
                LabeledContent("Tempo di attività", value: snapshot["uptimeSeconds"].doubleValue.map { Duration.seconds($0).formatted(.units(allowed: [.days, .hours, .minutes], width: .abbreviated)) } ?? "—")
                LabeledContent("Carico medio", value: ["one", "five", "fifteen"].map { snapshot["load"][$0].displayText }.joined(separator: " / "))
            }
            Section("Approfondimenti") {
                ForEach([("Monitoraggio", "/control/monitoring", "waveform.path.ecg"), ("Risorse", "/control/resources/summary", "cpu"), ("Sicurezza", "/control/security/summary", "shield.lefthalf.filled"), ("Log", "/control/logs/summary", "text.alignleft"), ("Operazioni", "/control/operations", "clock.arrow.circlepath"), ("Audit", "/control/audit", "checkmark.shield")], id: \.1) { item in
                    NavigationLink { RemoteDetailView(title: item.0, path: item.1) } label: { Label(item.0, systemImage: item.2) }
                }
            }
        }.navigationTitle("Server").navigationBarTitleDisplayMode(.inline)
    }
}

struct RemoteDetailView: View {
    @Environment(AppModel.self) private var model
    let title: String
    let path: String
    @State private var value: JSONValue?
    @State private var error: String?
    var body: some View {
        Group {
            if let value { JSONDetailView(title: title, value: value) }
            else if let error { ErrorNotice(message: error) { Task { await load() } }.padding() }
            else { LoadingState(title: "Caricamento…") }
        }.navigationTitle(title).navigationBarTitleDisplayMode(.inline).task { await load() }.refreshable { await load() }
    }
    private func load() async { do { value = try await model.get(path); error = nil } catch { self.error = error.localizedDescription } }
}
