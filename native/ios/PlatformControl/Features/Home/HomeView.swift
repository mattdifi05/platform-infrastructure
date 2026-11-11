import SwiftUI
import Charts
import Accessibility

private extension Duration {
    var chartSeconds: TimeInterval {
        let parts = components
        return Double(parts.seconds) + Double(parts.attoseconds) / 1e18
    }
}

private struct ResourcePlotClock {
    private let wallStart = Date.now
    private let monotonicStart = ContinuousClock.now

    func date(at instant: ContinuousClock.Instant) -> Date {
        wallStart.addingTimeInterval(monotonicStart.duration(to: instant).chartSeconds)
    }
}

private struct ResourceSample {
    let date: Date
    let cpu: Double?
    let memory: Double?
    let received: Double?
    let sent: Double?
    let read: Double?
    let written: Double?
}

// Present measured segments behind the collector so each frame advances at wall-clock speed.
// Never extrapolate beyond the latest real sample when the source has a gap.
enum ResourceChartTimeline {
    static let delay: TimeInterval = 3
    static let window: TimeInterval = 40
    static let nowPosition = 0.95

    static func presentationDate(now: Date) -> Date {
        now.addingTimeInterval(-delay)
    }

    static func segmentFraction(from start: Date, to end: Date, through cursor: Date) -> Double {
        guard end > start else { return 0 }
        return max(0, min(1, cursor.timeIntervalSince(start) / end.timeIntervalSince(start)))
    }

    static func startsSegment(previous: Date?, current: Date) -> Bool {
        previous.map { current.timeIntervalSince($0) > 6 } ?? true
    }

    static func horizontalFraction(sample: Date, cursor: Date) -> Double {
        nowPosition * (1 + sample.timeIntervalSince(cursor) / window)
    }
}

struct HomeView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase
    let isActive: Bool
    @State private var snapshot: JSONValue = .null
    @State private var samples: [ResourceSample] = []
    @State private var plotClock = ResourcePlotClock()
    @State private var error: String?
    @State private var loading = true
    @State private var refreshing = false

    private var monitoring: Bool { isActive && scenePhase == .active }

    var body: some View {
        ScrollView {
            LazyVStack(spacing: 16) {
                if let error { ErrorNotice(message: error) { Task { await refresh() } } }
                Group {
                    if !loading && error == nil && snapshot["freshness"]["available"].boolValue != true {
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
                .redacted(reason: loading ? .placeholder : [])
                .accessibilityHidden(loading)
            }
            .overlay {
                if loading {
                    Color.clear.accessibilityLabel("Lettura delle risorse…")
                }
            }
            .padding(20)
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle("Home")
        .navigationSubtitle("Le risorse del tuo server")
        .navigationBarTitleDisplayMode(.inline)
        .skeletonRefreshable { await refresh() }
        .task(id: monitoring) {
            guard monitoring else { return }
            async let history: Void = loadHistory()
            async let current: Void = refresh()
            _ = await (history, current)
            guard !Task.isCancelled else { return }
            loading = false
            var deadline = ContinuousClock.now + .seconds(2)
            do { try await ContinuousClock().sleep(until: deadline) } catch { return }
            while !Task.isCancelled {
                await refresh()
                deadline += .seconds(2)
                // Keep request latency out of the sampling cadence. Skip missed slots.
                while deadline < .now { deadline += .seconds(2) }
                do { try await ContinuousClock().sleep(until: deadline) } catch { break }
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
            Text(loading ? "00,0%" : value).font(.title2.bold()).contentTransition(.numericText())
            Text(loading ? "0 GB di 0 GB" : detail).font(.caption).foregroundStyle(.secondary)
        }.frame(maxWidth: .infinity, alignment: .leading).padding(18).background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 22))
    }

    private func resourceCard(_ title: String, value: String, detail: String, symbol: String, color: Color, series: [(String, KeyPath<ResourceSample, Double?>)], percentage: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack { Label(title, systemImage: symbol).font(.subheadline.weight(.semibold)).foregroundStyle(color); Spacer(); Text(loading ? (percentage ? (title == "CPU" ? "0 core" : "0 GB di 0 GB") : "↑ 000 KB/s") : detail).font(.caption).foregroundStyle(.secondary) }
            Text(loading ? (percentage ? "00,0%" : "000 KB/s") : value).font(.system(size: 34, weight: .semibold, design: .rounded)).monospacedDigit().contentTransition(.numericText())
            ResourceChart(title: title, samples: samples, clock: plotClock, series: series, color: color, percentage: percentage, active: isActive && !loading)
                .accessibilityLabel("Grafico \(title)")
                .accessibilityIdentifier("home.chart.\(symbol)")
        }.padding(20).background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 24))
    }

    private func loadHistory() async {
        guard let value = try? await model.get("/control/v1/resources/host/history"), !Task.isCancelled else { return }
        let now = plotClock.date(at: .now)
        let history: [ResourceSample] = value["samples"].arrayValue.compactMap { row in
            guard let date = Self.sampleDate(row["capturedAt"].stringValue), date <= now.addingTimeInterval(5) else { return nil }
            return ResourceSample(date: date, cpu: row["cpu"].doubleValue, memory: row["memory"].doubleValue,
                                  received: row["receive"].doubleValue, sent: row["send"].doubleValue,
                                  read: row["diskRead"].doubleValue, written: row["diskWrite"].doubleValue)
        }
        mergeSamples(history, keepingExisting: true)
    }

    private static func sampleDate(_ raw: String?) -> Date? {
        guard let raw else { return nil }
        return (try? Date.ISO8601FormatStyle(includingFractionalSeconds: true).parse(raw))
            ?? (try? Date.ISO8601FormatStyle().parse(raw))
    }

    private func mergeSamples(_ incoming: [ResourceSample], keepingExisting: Bool = false) {
        let cutoff = plotClock.date(at: .now).addingTimeInterval(-48)
        // Keep a predecessor outside the visible window so a real segment can cross the left edge.
        let ordered = keepingExisting ? incoming + samples : samples + incoming
        var byDate: [Date: ResourceSample] = [:]
        for sample in ordered where sample.date >= cutoff {
            byDate[sample.date] = sample
        }
        samples = byDate.values.sorted { $0.date < $1.date }
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
            let arrival = ContinuousClock.now
            let receivedAt = plotClock.date(at: arrival)
            let observedAt = Self.sampleDate(value["observedAt"].stringValue) ?? receivedAt
            mergeSamples([ResourceSample(
                date: min(observedAt, receivedAt),
                cpu: available ? value["cpu"]["usedPercent"].doubleValue : nil,
                memory: available ? value["memory"]["usedPercent"].doubleValue : nil,
                received: available ? value["network"]["totals"]["rxBytesPerSecond"].doubleValue : nil,
                sent: available ? value["network"]["totals"]["txBytesPerSecond"].doubleValue : nil,
                read: available ? value["diskIo"]["totals"]["readBytesPerSecond"].doubleValue : nil,
                written: available ? value["diskIo"]["totals"]["writeBytesPerSecond"].doubleValue : nil
            )])
        } catch is CancellationError {
            return
        } catch {
            guard !Task.isCancelled else { return }
            self.error = "Impossibile aggiornare le risorse del server."
            mergeSamples([ResourceSample(date: plotClock.date(at: .now), cpu: nil, memory: nil, received: nil, sent: nil, read: nil, written: nil)])
        }
    }
}

private struct ResourceChart: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.scenePhase) private var scenePhase
    @State private var scale: VerticalScale?
    @ScaledMetric(relativeTo: .caption2) private var axisLabelWidth = 52
    let title: String
    let samples: [ResourceSample]
    let clock: ResourcePlotClock
    let series: [(String, KeyPath<ResourceSample, Double?>)]
    let color: Color
    let percentage: Bool
    let active: Bool

    private struct Point {
        let date: Date
        let value: Double
        let startsSegment: Bool

        func interpolated(to point: Point, by fraction: Double) -> Point {
            Point(date: date.addingTimeInterval(point.date.timeIntervalSince(date) * fraction),
                  value: value + (point.value - value) * fraction, startsSegment: false)
        }
    }

    private struct Trace {
        let points: [Point]

        func presented(through date: Date) -> Trace {
            for (index, point) in points.enumerated() where point.date > date {
                var prefix = Array(points.prefix(index))
                if !point.startsSegment, let previous = prefix.last {
                    let fraction = ResourceChartTimeline.segmentFraction(from: previous.date, to: point.date, through: date)
                    if fraction > 0 { prefix.append(previous.interpolated(to: point, by: fraction)) }
                }
                return Trace(points: prefix)
            }
            return self
        }
    }

    private struct VerticalScale {
        let previous: Double
        let target: Double
        let startedAt: ContinuousClock.Instant
        let labelStart: Date

        var labelUpdates: [Date] {
            guard previous != target else { return [] }
            return (1...5).map { labelStart.addingTimeInterval(Double($0) / 10) }
        }

        func upperBound(at instant: ContinuousClock.Instant, containing peak: Double) -> Double {
            let progress = min(1, max(0, startedAt.duration(to: instant).chartSeconds / ResourceChart.headDuration))
            return max(peak, previous + (target - previous) * progress)
        }
    }

    nonisolated private static let headDuration: TimeInterval = 0.5
    private static let window = ResourceChartTimeline.window
    private static let nowPosition = ResourceChartTimeline.nowPosition

    private var isAnimating: Bool { active && scenePhase == .active && !reduceMotion }

    private func trace(for key: KeyPath<ResourceSample, Double?>) -> Trace {
        var previous: Date?
        let points: [Point] = samples.compactMap { sample in
            guard let value = sample[keyPath: key], value.isFinite, value >= 0, !percentage || value <= 100 else {
                previous = nil
                return nil
            }
            let startsSegment = ResourceChartTimeline.startsSegment(previous: previous, current: sample.date)
            previous = sample.date
            return Point(date: sample.date, value: value, startsSegment: startsSegment)
        }
        return Trace(points: points)
    }

    var body: some View {
        let traces = series.map { trace(for: $0.1) }
        let instant = ContinuousClock.now
        let now = ResourceChartTimeline.presentationDate(now: clock.date(at: instant))
        let staticDate = samples.last?.date ?? now
        let reference = isAnimating ? now : staticDate
        let left = reference.addingTimeInterval(-Self.window)
        let peak = Self.visiblePeak(traces, since: left)
        let target = percentage ? Self.percentUpperBound(for: peak) : Self.rateUpperBound(for: peak)
        let presentedPeak = isAnimating ? Self.visiblePeak(traces.map { $0.presented(through: now) }, since: left) : peak
        let current = scale?.upperBound(at: instant, containing: presentedPeak) ?? target
        let nextScale = VerticalScale(previous: isAnimating ? current : target, target: target, startedAt: instant, labelStart: .now)
        let displayScale = scale?.target == target ? scale ?? nextScale : nextScale

        // Keep the native axes out of the frame-by-frame plot updates.
        Chart {
            PointMark(x: .value("Ora", 0.0), y: .value("Valore", 0.0)).opacity(0)
        }
        .chartXScale(domain: 0.0...1.0, range: .plotDimension(padding: 0))
        .chartYScale(domain: 0.0...1.0, range: .plotDimension(padding: 4))
        .chartXAxis {
            AxisMarks(values: (0...4).map { Double($0) * Self.nowPosition / 4 }) { axis in
                AxisGridLine().foregroundStyle(.secondary.opacity(0.22))
                if axis.index.isMultiple(of: 2) {
                    AxisValueLabel {
                        Text(timeLabel(Self.window * Double(4 - axis.index) / 4))
                            .font(.caption2).foregroundStyle(.secondary).monospacedDigit()
                    }
                }
            }
        }
        .chartYAxis {
            AxisMarks(position: .leading, values: [0.0, 0.25, 0.5, 0.75, 1.0]) { axis in
                AxisGridLine().foregroundStyle(.secondary.opacity(0.22))
                if let fraction = axis.as(Double.self) {
                    AxisValueLabel {
                        TimelineView(.explicit(isAnimating ? displayScale.labelUpdates : [])) { _ in
                            let instant = ContinuousClock.now
                            let date = ResourceChartTimeline.presentationDate(now: clock.date(at: instant))
                            let presented = traces.map { $0.presented(through: date) }
                            let peak = Self.visiblePeak(presented, since: date.addingTimeInterval(-Self.window))
                            let bound = isAnimating ? displayScale.upperBound(at: instant, containing: peak) : target
                            Text(axisLabel(fraction * bound))
                                .font(.caption2).foregroundStyle(.secondary).monospacedDigit()
                                .lineLimit(1).minimumScaleFactor(0.75)
                                .frame(width: axisLabelWidth, alignment: .trailing)
                        }
                    }
                }
            }
        }
        .chartLegend(.hidden)
        .chartOverlay { proxy in
            GeometryReader { geometry in
                if let anchor = proxy.plotFrame,
                   let left = proxy.position(forX: 0.0), let right = proxy.position(forX: 1.0),
                   let top = proxy.position(forY: 1.0), let bottom = proxy.position(forY: 0.0) {
                    let frame = geometry[anchor]
                    let plot = CGRect(x: left, y: top, width: right - left, height: bottom - top)
                    TimelineView(.animation(paused: !isAnimating)) { _ in
                        let instant = ContinuousClock.now
                        let date = isAnimating ? ResourceChartTimeline.presentationDate(now: clock.date(at: instant)) : staticDate
                        let presented = isAnimating ? traces.map { $0.presented(through: date) } : traces
                        let peak = Self.visiblePeak(presented, since: date.addingTimeInterval(-Self.window))
                        let upperBound = isAnimating ? displayScale.upperBound(at: instant, containing: peak) : target
                        Canvas { context, size in
                            var clipped = context
                            clipped.clip(to: Path(CGRect(x: plot.minX, y: 0, width: plot.width, height: size.height)))
                            draw(presented, in: clipped, plot: plot, date: date, upperBound: upperBound)
                        }
                    }
                    .frame(width: frame.width, height: frame.height)
                    .clipped()
                    .position(x: frame.midX, y: frame.midY)
                    .allowsHitTesting(false)
                    .accessibilityHidden(true)
                }
            }
        }
        .frame(height: 135)
        .accessibilityChartDescriptor(ChartAccessibility(title: title, traces: traces, seriesNames: series.map(\.0), date: staticDate, window: Self.window, upperBound: target, percentage: percentage))
        .onChange(of: target, initial: true) { _, _ in
            self.scale = displayScale
        }
    }

    private static func visiblePeak(_ traces: [Trace], since left: Date) -> Double {
        var peak = 0.0
        for trace in traces {
            var predecessor: Point?
            for point in trace.points {
                if point.date < left {
                    predecessor = point
                    continue
                }
                if let predecessor, !point.startsSegment {
                    let fraction = left.timeIntervalSince(predecessor.date) / point.date.timeIntervalSince(predecessor.date)
                    peak = max(peak, predecessor.value + (point.value - predecessor.value) * fraction)
                }
                predecessor = nil
                peak = max(peak, point.value)
            }
        }
        return peak
    }

    private static func percentUpperBound(for peak: Double) -> Double {
        let padded = max(1, peak * 1.15)
        return [1.0, 2, 4, 8, 12, 16, 20, 24, 32, 40, 48, 60, 80, 100].first { $0 >= padded } ?? 100
    }

    private func axisLabel(_ value: Double) -> String {
        if percentage {
            return value.formatted(.number.precision(.fractionLength(0...2))) + "%"
        }
        return NativeFormatting.bytes(value)
    }

    private static func rateUpperBound(for peak: Double) -> Double {
        // Rounded scales prevent minor changes in the peak from moving every point.
        let padded = max(4, peak * 1.15)
        let magnitude = pow(10, floor(log10(padded)))
        return ([1.0, 2, 4, 8, 10].first { $0 * magnitude >= padded } ?? 10) * magnitude
    }

    private func draw(_ traces: [Trace], in context: GraphicsContext, plot: CGRect, date: Date, upperBound: Double) {
        func location(_ point: Point) -> CGPoint {
            CGPoint(
                x: plot.minX + plot.width * ResourceChartTimeline.horizontalFraction(sample: point.date, cursor: date),
                y: plot.maxY - plot.height * point.value / upperBound
            )
        }

        for (index, trace) in traces.enumerated() {
            let stroke = index == 0 ? color : color.opacity(0.72)
            let style = StrokeStyle(lineWidth: 2.5, lineCap: .round, lineJoin: .round, dash: index == 0 ? [] : [4, 3])
            var path = Path()
            for point in trace.points {
                let position = location(point)
                if point.startsSegment { path.move(to: position) }
                else { path.addLine(to: position) }
            }
            context.stroke(path, with: .color(stroke), style: style)

            if let endpoint = trace.points.last {
                let position = location(endpoint)
                let age = date.timeIntervalSince(endpoint.date)
                let opacity = min(1, max(0, (6 - age) / 0.4))
                let dot = Path(ellipseIn: CGRect(x: position.x - 3.5, y: position.y - 3.5, width: 7, height: 7))
                context.fill(dot, with: .color(stroke.opacity(opacity)))
            }
        }
    }

    private struct ChartAccessibility: AXChartDescriptorRepresentable {
        let title: String
        let traces: [Trace]
        let seriesNames: [String]
        let date: Date
        let window: TimeInterval
        let upperBound: Double
        let percentage: Bool

        func makeChartDescriptor() -> AXChartDescriptor {
            let end = date.timeIntervalSinceReferenceDate
            let xAxis = AXNumericDataAxisDescriptor(title: "Ora", range: (end - window)...end, gridlinePositions: []) { value in
                Date(timeIntervalSinceReferenceDate: value).formatted(date: .omitted, time: .standard)
            }
            let yAxis = AXNumericDataAxisDescriptor(title: percentage ? "Percentuale" : "Byte al secondo", range: 0...upperBound, gridlinePositions: []) { value in
                percentage ? NativeFormatting.percent(value) : NativeFormatting.bytes(value) + "/s"
            }
            let series = zip(seriesNames, traces).flatMap { name, trace in
                var segments: [[AXDataPoint]] = []
                for point in trace.points where point.date.timeIntervalSinceReferenceDate >= end - window {
                    if point.startsSegment || segments.isEmpty { segments.append([]) }
                    segments[segments.count - 1].append(AXDataPoint(x: point.date.timeIntervalSinceReferenceDate, y: point.value))
                }
                return segments.map { AXDataSeriesDescriptor(name: name, isContinuous: true, dataPoints: $0) }
            }
            return AXChartDescriptor(title: title, xAxis: xAxis, yAxis: yAxis, series: series)
        }

        func updateChartDescriptor(_ descriptor: AXChartDescriptor) {
            let updated = makeChartDescriptor()
            descriptor.xAxis = updated.xAxis
            descriptor.yAxis = updated.yAxis
            descriptor.series = updated.series
        }
    }

    private func timeLabel(_ duration: TimeInterval) -> String {
        guard duration > 0 else { return "Ora" }
        let seconds = max(1, Int(duration.rounded()))
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
        }.navigationTitle(title).navigationBarTitleDisplayMode(.inline).task { await load() }.skeletonRefreshable { await load() }
    }
    private func load() async { do { value = try await model.get(path); error = nil } catch { self.error = error.localizedDescription } }
}
