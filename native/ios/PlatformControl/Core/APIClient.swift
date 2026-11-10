import Foundation
import Security

struct APIError: LocalizedError, Sendable {
    let status: Int
    let message: String
    var errorDescription: String? { message }
    var requiresAuthentication: Bool { status == 401 || status == 428 }
}

enum ServiceConfiguration {
    static let baseURL = URL(string: "https://portal.stexor.com")!
    static let relyingParty = "portal.stexor.com"
}

private final class SameOriginDelegate: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest) async -> URLRequest? {
        // JSON API traffic must never follow login redirects or leak cookies to another service.
        nil
    }
}

actor APIClient {
    private let baseURL: URL
    private let session: URLSession
    private let cookies: HTTPCookieStorage
    private var csrfToken: String?
    private let vault = SessionKeychain()
    private let fixture: Bool
    private let persistCredentials: Bool
    #if DEBUG
    private let fixtures = NativeFixtures()
    #endif

    init(baseURL: URL = ServiceConfiguration.baseURL, fixture: Bool = false, configuration: URLSessionConfiguration? = nil, persistCredentials: Bool = true) {
        self.baseURL = baseURL
        self.fixture = fixture
        self.persistCredentials = persistCredentials && !fixture
        let config = configuration ?? URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 35
        config.timeoutIntervalForResource = 60
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.httpCookieAcceptPolicy = .always
        self.cookies = config.httpCookieStorage!
        self.session = URLSession(configuration: config, delegate: SameOriginDelegate(), delegateQueue: nil)
        if persistCredentials && !fixture, let saved = vault.load(), let records = try? JSONDecoder().decode([SavedCookie].self, from: saved) {
            for record in records {
                var properties: [HTTPCookiePropertyKey: Any] = [.name: record.name, .value: record.value, .domain: record.domain, .path: record.path, .secure: "TRUE"]
                if let expiry = record.expires { properties[.expires] = Date(timeIntervalSince1970: expiry) }
                if let cookie = HTTPCookie(properties: properties), cookie.domain == baseURL.host, cookie.isSecure,
                   cookie.expiresDate.map({ $0 > Date() }) ?? true { cookies.setCookie(cookie) }
            }
        }
    }

    func request(_ path: String, method: String = "GET", body: JSONValue? = nil) async throws -> JSONValue {
        guard path.hasPrefix("/"), !path.hasPrefix("//"), let url = URL(string: path, relativeTo: baseURL)?.absoluteURL,
              url.scheme == "https", url.host == baseURL.host, url.port == baseURL.port,
              url.user == nil, url.password == nil, url.fragment == nil else {
            throw APIError(status: 0, message: "Indirizzo del servizio non valido.")
        }
        #if DEBUG
        if fixture { return try await fixtures.response(path: path, method: method, body: body) }
        #endif
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(baseURL.absoluteString, forHTTPHeaderField: "Origin")
        request.setValue("same-origin", forHTTPHeaderField: "Sec-Fetch-Site")
        request.setValue("PlatformControl-iOS/1", forHTTPHeaderField: "X-Platform-Client")
        if let body { request.httpBody = try JSONEncoder().encode(body); request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        let csrf = csrfToken ?? cookies.cookies(for: baseURL)?.first { $0.name == "__Host-platform_cc_csrf" }?.value
        if method != "GET", let csrf { request.setValue(csrf, forHTTPHeaderField: "X-CSRF-Token") }
        let (data, response) = try await session.data(for: request)
        guard let response = response as? HTTPURLResponse else { throw APIError(status: 0, message: "Risposta del server non valida.") }
        guard data.count <= 8 * 1024 * 1024 else { throw APIError(status: response.statusCode, message: "Risposta del server troppo grande.") }
        let decoded = try? JSONDecoder().decode(JSONValue.self, from: data)
        let value = decoded ?? .null
        guard (200..<300).contains(response.statusCode) else {
            let message = value["error"]["message"].stringValue ?? value["message"].stringValue ?? value["error"].stringValue
            throw APIError(status: response.statusCode, message: message ?? (response.statusCode == 401 ? "Accedi con la tua passkey." : "Il server non ha completato l’operazione (\(response.statusCode))."))
        }
        guard data.isEmpty || (decoded != nil && response.value(forHTTPHeaderField: "Content-Type")?.contains("application/json") == true) else {
            throw APIError(status: 0, message: "Il servizio non ha restituito una risposta JSON valida. È richiesta l’API nativa aggiornata.")
        }
        if let token = value["csrfToken"].stringValue { csrfToken = token }
        if path == "/auth/passkey/login/verify" || path == "/api/native/v1/bootstrap" { persistSession() }
        return value
    }

    func clearSession() {
        csrfToken = nil
        for cookie in cookies.cookies ?? [] { cookies.deleteCookie(cookie) }
        if persistCredentials { vault.delete() }
    }

    private func persistSession() {
        guard persistCredentials else { return }
        let records = (cookies.cookies(for: baseURL) ?? []).filter { ["__Host-platform_cc_session", "__Host-platform_cc_csrf"].contains($0.name) }.map { SavedCookie(name: $0.name, value: $0.value, domain: $0.domain, path: $0.path, expires: $0.expiresDate?.timeIntervalSince1970) }
        if let data = try? JSONEncoder().encode(records) { vault.save(data) }
    }
}

private struct SavedCookie: Codable { let name: String; let value: String; let domain: String; let path: String; let expires: Double? }

private struct SessionKeychain: Sendable {
    private let service = "com.stexor.controlcenter.session"
    func load() -> Data? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: "portal", kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var item: CFTypeRef?
        return SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess ? item as? Data : nil
    }
    func save(_ data: Data) {
        delete()
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: "portal", kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        SecItemAdd(query as CFDictionary, nil)
    }
    func delete() {
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: "portal"] as CFDictionary)
    }
}
