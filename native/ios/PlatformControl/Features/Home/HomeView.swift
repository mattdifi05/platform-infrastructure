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
    @State private var refreshing = false

    var body: some View {
        ScrollView {
            LazyVStack(spacing: 16) {
                if let error { ErrorNotice(message: error) { Task { await refresh() } } }
                if loading { LoadingState(title: "Lettura delle risorse…") }
                else {
                    if error == nil && snapshot["freshness"]["available"].boolValue != true {
                        ErrorNotice(message: "Le misurazioni non sono disponibili al momento.")
                    }
                    resourceCard("CPU", value: NativeFormatting.percent(snapshot["cpu"]["usedPercent"].doubleValue), detail: snapshot["cpu"]["cores"].intValue.map { "\($0) core" } ?? "—", symbol: "cpu", color: .indigo, series: [("CPU", \.cpu)], percentage: true)
                    resourceCard("Memoria", value: NativeFormatting.percent(snapshot["memory"]["usedPercent"].doubleValue), detail: capacity(snapshot["memory"]), symbol: "memorychip", color: .teal, series: [("RAM", \.memory)], percentage: true)
                    HStack(spacing: 14) {
                        capacityCard("Disco", value: NativeFormatting.percent(snapshot["disk"]["usedPercent"].doubleValue), detail: capacity(snapshot["disk"]), symbol: "internaldrive", color: .orange)
                        capacityCard("Swap", value: NativeFormatting.bytes(snapshot["swap"]["usedBytes"].doubleValue), detail: "di " + NativeFormatting.bytes(snapshot["swap"]["totalBytes"].doubleValue), symbol: "arrow.left.arrow.right", color: .purple)
                    }
                    resourceCard("Connessione", value: rate(snapshot["network"]["totals"]["rxBytesPerSecond"]), detail: "↑ " + rate(snapshot["network"]["totals"]["txBytesPerSecond"]), symbol: "network", color: .blue, series: [("Ricezione", \.received), ("Invio", \.sent)])
                    resourceCard("Attività disco", value: rate(snapshot["diskIo"]["totals"]["readBytesPerSecond"]), detail: "Scrittura " + rate(snapshot["diskIo"]["totals"]["writeBytesPerSecond"]), symbol: "externaldrive", color: .pink, series: [("Lettura", \.read), ("Scrittura", \.written)])
                }
            }
            .padding(20)
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle("Home")
        .navigationSubtitle("Le risorse del tuo server")
        .navigationBarTitleDisplayMode(.inline)
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

    private func rate(_ value: JSONValue) -> String {
        guard let bytes = value.doubleValue else { return "—" }
        return NativeFormatting.bytes(bytes) + "/s"
    }

    private func capacityCard(_ title: String, value: String, detail: String, symbol: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(title, systemImage: symbol).font(.subheadline.weight(.semibold)).foregroundStyle(color)
            Text(value).font(.title2.bold()).contentTransition(.numericText())
            Text(detail).font(.caption).foregroundStyle(.secondary)
        }.frame(maxWidth: .infinity, alignment: .leading).padding(18).background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 22))
    }

    private func resourceCard(_ title: String, value: String, detail: String, symbol: String, color: Color, series: [(String, KeyPath<ResourceSample, Double?>)], percentage: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack { Label(title, systemImage: symbol).font(.subheadline.weight(.semibold)).foregroundStyle(color); Spacer(); Text(detail).font(.caption).foregroundStyle(.secondary) }
            Text(value).font(.system(size: 34, weight: .semibold, design: .rounded)).monospacedDigit().contentTransition(.numericText())
            ResourceChart(samples: samples, series: series, color: color, percentage: percentage, active: isActive)
                .accessibilityLabel("Grafico \(title)")
                .accessibilityIdentifier("home.chart.\(symbol)")
        }.padding(20).background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 24))
    }

    private func refresh() async {
        guard !refreshing else { return }
        refreshing = true
        defer { refreshing = false }
        do {
            let value = try await model.get("/control/resources/host")
            guard !Task.isCancelled else { return }
            // The API identifies stale samples explicitly; preserve gaps rather than invent zeroes.
            snapshot = value
            error = nil
            let available = value["freshness"]["available"].boolValue == true
            samples.append(ResourceSample(
                date: .now,
                cpu: available ? value["cpu"]["usedPercent"].doubleValue : nil,
                memory: available ? value["memory"]["usedPercent"].doubleValue : nil,
                received: available ? value["network"]["totals"]["rxBytesPerSecond"].doubleValue : nil,
                sent: available ? value["network"]["totals"]["txBytesPerSecond"].doubleValue : nil,
                read: available ? value["diskIo"]["totals"]["readBytesPerSecond"].doubleValue : nil,
                written: available ? value["diskIo"]["totals"]["writeBytesPerSecond"].doubleValue : nil
            ))
        } catch is CancellationError {
            return
        } catch {
            guard !Task.isCancelled else { return }
            self.error = "Impossibile aggiornare le risorse del server."
            samples.append(ResourceSample(date: .now, cpu: nil, memory: nil, received: nil, sent: nil, read: nil, written: nil))
        }
        samples.removeAll { $0.date < Date.now.addingTimeInterval(-125) }
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

    private struct Trace: Identifiable {
        let id: Int
        let name: String
        let points: [Point]
    }

    private func points(for key: KeyPath<ResourceSample, Double?>) -> [Point] {
        var segment = 0
        var previous: Date?
        return samples.compactMap { sample in
            guard let value = sample[keyPath: key] else { segment += 1; return nil }
            if let previous, sample.date.timeIntervalSince(previous) > 6 { segment += 1 }
            previous = sample.date
            return Point(id: sample.id, date: sample.date, value: value, segment: segment)
        }
    }

    var body: some View {
        let traces = series.enumerated().map { Trace(id: $0.offset, name: $0.element.0, points: points(for: $0.element.1)) }
        let peak = traces.flatMap(\.points).map(\.value).max() ?? 0
        let upperBound = percentage ? 100 : max(1, peak * 1.15)
        let oldest = traces.compactMap { $0.points.first?.date }.min()

        TimelineView(.animation(minimumInterval: reduceMotion ? 2 : 1.0 / 30.0, paused: !active)) { context in
            let now = context.date
            // Expand continuously as samples arrive, then keep a rolling two-minute window.
            let window = min(120, max(8, now.timeIntervalSince(oldest ?? now) + 2))
            let offsets = [1.0, 0.75, 0.5, 0.25, 0].map { window * $0 }
            let grid = offsets.map { now.addingTimeInterval(-$0) }
            Chart {
                ForEach(traces) { trace in
                    let stroke = trace.id == 0 ? color : color.opacity(0.72)
                    ForEach(trace.points) { point in
                        LineMark(x: .value("Ora", point.date), y: .value(trace.name, point.value), series: .value("Serie", "\(trace.id)-\(point.segment)"))
                            .interpolationMethod(.linear)
                            .foregroundStyle(stroke)
                            .lineStyle(StrokeStyle(lineWidth: 2.5, lineCap: .round, dash: trace.id == 0 ? [] : [4, 3]))
                    }
                    if let last = trace.points.last, last.id == samples.last?.id, now.timeIntervalSince(last.date) < 6 {
                        PointMark(x: .value("Ora", last.date), y: .value(trace.name, last.value))
                            .foregroundStyle(stroke)
                            .symbolSize(38)
                    }
                }
            }
            .chartXScale(domain: grid[0]...now, range: .plotDimension(padding: 4))
            .chartYScale(domain: 0...upperBound, range: .plotDimension(padding: 4))
            .chartXAxis {
                AxisMarks(values: grid) { axis in
                    AxisGridLine().foregroundStyle(.secondary.opacity(0.22))
                    if axis.index.isMultiple(of: 2) {
                        AxisValueLabel {
                            Text(timeLabel(offsets[axis.index]))
                                .font(.caption2).foregroundStyle(.secondary).monospacedDigit()
                        }
                    }
                }
            }
            .chartYAxis {
                AxisMarks(position: .leading, values: percentage ? .stride(by: 25) : .automatic(desiredCount: 4)) { axis in
                    AxisGridLine().foregroundStyle(.secondary.opacity(0.22))
                    if let value = axis.as(Double.self) {
                        AxisValueLabel {
                            Text(percentage ? "\(Int(value))%" : NativeFormatting.bytes(value))
                                .font(.caption2).foregroundStyle(.secondary).monospacedDigit()
                        }
                    }
                }
            }
            .chartLegend(.hidden)
            .frame(height: 135)
        }
    }

    private func timeLabel(_ duration: TimeInterval) -> String {
        let seconds = Int(duration.rounded())
        if seconds == 0 { return "Ora" }
        let minutes = seconds / 60
        let remainder = seconds % 60
        if minutes == 0 { return "−\(remainder) s" }
        if remainder == 0 { return "−\(minutes) min" }
        return "−\(minutes) m \(remainder) s"
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
