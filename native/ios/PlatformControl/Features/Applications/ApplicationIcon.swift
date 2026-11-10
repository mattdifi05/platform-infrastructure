import ImageIO
import SwiftUI

func applicationSiteURL(_ entry: JSONValue) -> URL? {
    for address in [entry["href"].text, entry["siteOrigin"].text, "https://\(entry["host"].text)"] {
        guard let url = URL(string: address), url.scheme?.lowercased() == "https",
              let host = url.host, !host.isEmpty, url.user == nil, url.password == nil else { continue }
        return url
    }
    return nil
}

struct ApplicationIcon: View {
    let entry: JSONValue
    var size: CGFloat = 32
    @Environment(AppModel.self) private var app
    @State private var image: CGImage?
    @State private var imageSite: URL?

    private var fallback: String {
        switch (entry["runtime"].stringValue ?? entry["type"].text).lowercased() {
        case "php", "wordpress", "laravel": "chevron.left.forwardslash.chevron.right"
        case "node", "nodejs", "node.js", "nextjs", "next.js": "hexagon"
        case "static", "html": "globe"
        case "api": "point.3.connected.trianglepath.dotted"
        case "worker": "gearshape"
        default: "app.fill"
        }
    }

    var body: some View {
        let site = applicationSiteURL(entry)
        ZStack {
            RoundedRectangle(cornerRadius: size / 4).fill(.tint.opacity(0.12))
            if let image, imageSite == site {
                Image(decorative: image, scale: 1)
                    .resizable()
                    .scaledToFit()
                    .padding(size * 0.16)
            } else {
                Image(systemName: fallback)
                    .font(.system(size: size * 0.49, weight: .semibold))
                    .foregroundStyle(.tint)
            }
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
        .task(id: site) {
            guard !app.isTestEnvironment, let site else { return }
            let result = await ApplicationFaviconLoader.shared.icon(for: site)
            guard !Task.isCancelled else { return }
            image = result
            imageSite = site
        }
    }
}

private actor ApplicationFaviconLoader {
    static let shared = ApplicationFaviconLoader()
    private var inFlight: [URL: Task<CGImage?, Never>] = [:]
    private let cache = NSCache<NSURL, CacheEntry>()

    init() {
        cache.countLimit = 80
    }

    func icon(for site: URL) async -> CGImage? {
        guard var address = URLComponents(url: site, resolvingAgainstBaseURL: false) else { return nil }
        address.query = nil
        address.fragment = nil
        guard let page = address.url else { return nil }
        if let cached = cache.object(forKey: page as NSURL), cached.expires > Date() { return cached.image }
        if let task = inFlight[page] { return await task.value }

        let task = Task { await FaviconRequest.load(from: page) }
        inFlight[page] = task
        let image = await task.value
        inFlight[page] = nil
        cache.setObject(CacheEntry(image: image, expires: Date().addingTimeInterval(image == nil ? 300 : 21_600)), forKey: page as NSURL)
        return image
    }

    private final class CacheEntry {
        let image: CGImage?
        let expires: Date

        init(image: CGImage?, expires: Date) {
            self.image = image
            self.expires = expires
        }
    }
}

enum FaviconLinks {
    private static let tags = try! NSRegularExpression(pattern: #"<link\b[^>]*>"#, options: .caseInsensitive)
    private static let attributes = try! NSRegularExpression(
        pattern: #"([a-zA-Z][a-zA-Z0-9:_-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#
    )

    static func sameOrigin(_ url: URL, as page: URL) -> Bool {
        url.scheme?.lowercased() == "https" && url.host?.lowercased() == page.host?.lowercased()
            && (url.port ?? 443) == (page.port ?? 443) && url.user == nil && url.password == nil
    }

    static func candidates(in html: String, relativeTo page: URL) -> [URL] {
        var links: [URL] = []
        let range = NSRange(html.startIndex..., in: html)
        for match in tags.matches(in: html, range: range) {
            guard let tagRange = Range(match.range, in: html) else { continue }
            let tag = String(html[tagRange])
            let properties = attributes.matches(in: tag, range: NSRange(tag.startIndex..., in: tag))
            var rel: String?
            var href: String?
            for property in properties {
                guard let name = Range(property.range(at: 1), in: tag),
                      let value = (2...4).compactMap({ Range(property.range(at: $0), in: tag) }).first else { continue }
                switch tag[name].lowercased() {
                case "rel": rel = String(tag[value])
                case "href": href = String(tag[value]).replacingOccurrences(of: "&amp;", with: "&")
                default: break
                }
            }
            let relations = rel?.lowercased().split(whereSeparator: \.isWhitespace) ?? []
            guard relations.contains("icon") || relations.contains("apple-touch-icon"),
                  let href, let url = URL(string: href, relativeTo: page)?.absoluteURL,
                  sameOrigin(url, as: page), url.pathExtension.lowercased() != "svg",
                  !links.contains(url) else { continue }
            links.append(url)
            if links.count == 3 { break }
        }
        return links
    }
}

private enum FaviconRequest {
    private static let session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.timeoutIntervalForRequest = 4
        configuration.timeoutIntervalForResource = 6
        configuration.httpMaximumConnectionsPerHost = 2
        return URLSession(configuration: configuration)
    }()

    static func load(from page: URL) async -> CGImage? {
        let htmlResponse = try? await read(page, origin: page, limit: 96 * 1024, html: true)
        let html = htmlResponse.map { String(decoding: $0.data, as: UTF8.self) } ?? ""
        let finalPage = htmlResponse?.url ?? page
        var candidates = FaviconLinks.candidates(in: html, relativeTo: finalPage)
        if let conventional = URL(string: "/favicon.ico", relativeTo: page)?.absoluteURL,
           !candidates.contains(conventional) {
            candidates.append(conventional)
        }
        for icon in candidates {
            if let response = try? await read(icon, origin: page, limit: 256 * 1024),
               let source = CGImageSourceCreateWithData(response.data as CFData, nil),
               let image = CGImageSourceCreateThumbnailAtIndex(source, 0, [
                   kCGImageSourceCreateThumbnailFromImageAlways: true,
                   kCGImageSourceCreateThumbnailWithTransform: true,
                   kCGImageSourceThumbnailMaxPixelSize: 144
               ] as CFDictionary) {
                return image
            }
        }
        return nil
    }

    private static func read(_ url: URL, origin: URL, limit: Int, html: Bool = false) async throws -> (data: Data, url: URL)? {
        let (stream, response) = try await session.bytes(from: url, delegate: Redirect(origin: origin))
        guard let http = response as? HTTPURLResponse, http.statusCode == 200,
              let resolved = http.url, FaviconLinks.sameOrigin(resolved, as: origin) else { return nil }
        if html {
            guard ["text/html", "application/xhtml+xml"].contains(http.mimeType?.lowercased() ?? "") else { return nil }
        } else {
            guard http.expectedContentLength <= limit, http.mimeType?.lowercased() != "text/html" else { return nil }
        }
        var data = Data()
        for try await byte in stream {
            if data.count == limit {
                return html ? (data, resolved) : nil
            }
            data.append(byte)
        }
        return (data, resolved)
    }

    private final class Redirect: NSObject, URLSessionTaskDelegate {
        let origin: URL
        init(origin: URL) { self.origin = origin }

        func urlSession(
            _ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest
        ) async -> URLRequest? {
            guard let url = request.url, FaviconLinks.sameOrigin(url, as: origin) else { return nil }
            return request
        }
    }
}
