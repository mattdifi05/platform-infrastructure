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
    let title: String
    var body: some View { VStack(spacing: 16) { ProgressView(); Text(title).font(.subheadline).foregroundStyle(.secondary) }.frame(maxWidth: .infinity, minHeight: 180) }
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
