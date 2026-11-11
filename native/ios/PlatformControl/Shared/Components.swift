import SwiftUI

struct StatusPill: View {
    let text: String
    var tone: Color = .secondary
    var body: some View {
        HStack(spacing: 5) { Circle().fill(tone).frame(width: 5, height: 5); Text(text).font(.caption.weight(.medium)) }
            .foregroundStyle(tone).padding(.horizontal, 9).padding(.vertical, 5).background(tone.opacity(0.09), in: Capsule())
    }
}

struct ErrorNotice: View {
    let message: String
    var retry: (() -> Void)? = nil
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(message, systemImage: "exclamationmark.triangle").font(.subheadline).foregroundStyle(.orange)
            if let retry { Button("Riprova", action: retry).buttonStyle(.bordered) }
        }.frame(maxWidth: .infinity, alignment: .leading).accessibilityElement(children: .contain)
    }
}

struct LoadingState: View {
    enum Style { case screen, row, inline }

    let title: String
    var style: Style = .screen
    @ScaledMetric(relativeTo: .body) private var lineHeight = 12.0

    var body: some View {
        Group {
            switch style {
            case .screen:
                VStack(alignment: .leading, spacing: 20) {
                    bar(width: 152)
                    ForEach(0..<3) { _ in
                        HStack(spacing: 12) {
                            RoundedRectangle(cornerRadius: 8)
                                .fill(.primary.opacity(0.10))
                                .frame(width: 32, height: 32)
                            lines
                        }
                    }
                }
                .frame(maxWidth: 360, alignment: .leading)
                .padding(.vertical, 20)
                .padding(.horizontal, 4)
                .frame(maxWidth: .infinity)
            case .row:
                lines.padding(.vertical, 4)
            case .inline:
                bar(width: 84)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(title)
    }

    private var lines: some View {
        VStack(alignment: .leading, spacing: 7) {
            bar(width: 168)
            bar(width: 96, height: lineHeight * 0.7)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func bar(width: CGFloat, height: CGFloat? = nil) -> some View {
        RoundedRectangle(cornerRadius: 4)
            .fill(.primary.opacity(0.10))
            .frame(maxWidth: width)
            .frame(height: height ?? lineHeight)
    }
}

extension View {
    func contentSkeleton(_ title: String? = nil) -> some View {
        redacted(reason: .placeholder)
            .disabled(true)
            .allowsHitTesting(false)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(title ?? "")
            .accessibilityHidden(title == nil)
    }

    func contentSkeleton(_ active: Bool, title: String) -> some View {
        redacted(reason: active ? .placeholder : [])
            .disabled(active)
            .allowsHitTesting(!active)
            .accessibilityElement(children: active ? .ignore : .contain)
            .accessibilityLabel(Text(title), isEnabled: active)
    }

    func skeletonRefreshable(_ action: @escaping @MainActor () async -> Void) -> some View {
        modifier(SkeletonRefresh(action: action))
    }
}

private struct SkeletonRefresh: ViewModifier {
    let action: @MainActor () async -> Void
    @State private var refreshing = false

    func body(content: Content) -> some View {
        content
            .contentSkeleton(refreshing, title: "Aggiornamento in corso…")
            .scrollBounceBehavior(.always, axes: .vertical)
            .onScrollPhaseChange { oldPhase, newPhase, context in
                let geometry = context.geometry
                let pullDistance = -(geometry.contentOffset.y + geometry.contentInsets.top)
                if oldPhase == .interacting, !newPhase.isScrolling || newPhase == .decelerating,
                   pullDistance >= 72 {
                    refreshing = true
                }
            }
            .accessibilityAction(named: Text("Aggiorna")) { refreshing = true }
            .task(id: refreshing) {
                guard refreshing else { return }
                await action()
                refreshing = false
            }
    }
}

struct EmptyState: View {
    let title: String
    let systemImage: String
    let description: String
    var body: some View { ContentUnavailableView(title, systemImage: systemImage, description: Text(description)) }
}

struct JSONDetailView: View {
    let title: String
    let value: JSONValue
    var body: some View {
        List {
            if case .object(let object) = value {
                ForEach(object.keys.sorted(), id: \.self) { key in JSONPropertyRow(name: key, value: object[key] ?? .null) }
            } else if case .array(let array) = value {
                ForEach(Array(array.enumerated()), id: \.offset) { index, item in JSONPropertyRow(name: item["name"].stringValue ?? item["label"].stringValue ?? "Elemento \(index + 1)", value: item) }
            } else { Text(value.displayText).textSelection(.enabled) }
        }.navigationTitle(title).navigationBarTitleDisplayMode(.inline)
    }
}

private struct JSONPropertyRow: View {
    let name: String
    let value: JSONValue
    var body: some View {
        if case .object = value {
            NavigationLink { JSONDetailView(title: name, value: value) } label: { LabeledContent(name, value: value.displayText) }
        } else if case .array = value {
            NavigationLink { JSONDetailView(title: name, value: value) } label: { LabeledContent(name, value: value.displayText) }
        } else { LabeledContent(name) { Text(value.displayText).textSelection(.enabled).multilineTextAlignment(.trailing) } }
    }
}

enum NativeFormatting {
    static func bytes(_ value: Double?) -> String {
        guard let value, value.isFinite, value >= 0 else { return "—" }
        return ByteCountFormatter.string(fromByteCount: Int64(min(value, Double(Int64.max - 1024))), countStyle: .binary)
    }
    static func percent(_ value: Double?) -> String { value.map { $0.formatted(.number.precision(.fractionLength(1))) + "%" } ?? "—" }
    static func date(_ value: String) -> String {
        let decoder = ISO8601DateFormatter()
        decoder.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return (decoder.date(from: value) ?? ISO8601DateFormatter().date(from: value)).map { $0.formatted(date: .abbreviated, time: .shortened) } ?? value
    }
}
