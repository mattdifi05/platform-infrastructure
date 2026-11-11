import Foundation
import Observation

@MainActor @Observable
final class AppModel {
    let api: APIClient
    var authenticated = false
    var isConnecting = true
    var isAuthenticating = false
    var connectionError: String?
    var bootstrap: JSONValue = .null
    var enrollmentRequired = false
    var unreadWarnings = 0
    let applicationStore = ApplicationsStore()
    let isTestEnvironment: Bool
    private let passkeys = PasskeyCoordinator()
    private var vaultCredentialNeedsRenewal = false
    @ObservationIgnored private var pageCache: [String: (value: JSONValue, receivedAt: ContinuousClock.Instant)] = [:]
    @ObservationIgnored private var pageRequests: [String: (id: UUID, task: Task<JSONValue, Error>)] = [:]
    @ObservationIgnored private var pageGeneration = UUID()
    @ObservationIgnored private var authenticationGeneration = UUID()

    // Only non-value page metadata may be kept for this authenticated session.
    private static let pagePaths: Set<String> = [
        "/api/native/v1/applications", "/api/native/v1/applications?view=catalog", "/control/v1/vault",
        "/control/v1/runtime-updates", "/control/v1/runtime-updates/system",
        "/control/backups/control", "/control/server-events"
    ]

    var vaultFaceIDSupported: Bool { bootstrap["authentication"]["vaultFaceIDSupported"].boolValue == true }
    var vaultFaceIDRegistered: Bool { bootstrap["session"]["vaultFaceIDRegistered"].boolValue == true && !vaultCredentialNeedsRenewal }

    init(testEnvironment: Bool = false, apiClient: APIClient? = nil) {
        isTestEnvironment = testEnvironment
        api = apiClient ?? APIClient(fixture: testEnvironment)
    }

    func connect() async {
        isConnecting = true
        connectionError = nil
        defer { isConnecting = false }
        do {
            bootstrap = try await readSession()
            authenticated = true
        } catch let error as APIError where error.status == 401 {
            clearPageData()
            authenticated = false
            if let setup = try? await api.request("/auth/native/bootstrap") { enrollmentRequired = setup["firstConfiguration"]["required"].boolValue == true && setup["firstConfiguration"]["complete"].boolValue != true }
        } catch {
            connectionError = error.localizedDescription
        }
    }

    func login() async {
        guard !isAuthenticating else { return }
        isAuthenticating = true
        connectionError = nil
        defer { isAuthenticating = false }
        do { try await authenticate(); await connect() }
        catch is CancellationError { }
        catch { connectionError = error.localizedDescription }
    }

    func stepUp() async throws {
        guard !isAuthenticating else { throw APIError(status: 409, message: "Completa la richiesta passkey già aperta.") }
        isAuthenticating = true
        defer { isAuthenticating = false }
        if isTestEnvironment { return }
        try await authenticate()
        bootstrap = try await readSession()
    }

    func enableVaultFaceID() async throws {
        guard vaultFaceIDSupported else { throw VaultFaceIDError.unsupported }
        _ = try VaultFaceID.preparePublicKey()
        try await stepUp()
        guard bootstrap["session"]["vaultFaceIDRegistered"].boolValue == true else { throw VaultFaceIDError.credentialUnavailable }
        vaultCredentialNeedsRenewal = false
    }

    func requestVaultRevealChallenge(itemID: String) async throws -> String {
        let interval = VaultFaceID.timing.beginInterval("Vault challenge request")
        defer { VaultFaceID.timing.endInterval("Vault challenge request", interval) }
        return try await post("/api/native/v1/vault/secrets/\(itemID)/challenge")["challenge"].text
    }

    func vaultRevealProof(requestingChallenge: @MainActor @Sendable () async throws -> String) async throws -> JSONValue {
        do {
            let proof = try await VaultFaceID.sign(requestingChallenge: requestingChallenge)
            return .object(["challenge": .string(proof.challenge), "signature": .string(proof.signature)])
        }
        catch VaultFaceIDError.credentialUnavailable {
            vaultCredentialNeedsRenewal = true
            throw VaultFaceIDError.credentialUnavailable
        }
    }

    func confirmVaultAction(_ reason: String) async throws {
        if isTestEnvironment { return }
        try await VaultFaceID.confirm(reason: reason)
    }

    private func readSession() async throws -> JSONValue {
        let session = try await api.request("/api/native/v1/bootstrap")
        guard session["schemaVersion"].intValue == 1, !session["session"]["subject"].text.isEmpty else {
            throw APIError(status: 0, message: "La sessione restituita dal server non è valida.")
        }
        return session
    }

    private func authenticate() async throws {
        let vaultIdentity = nativeVaultIdentity()
        let value = try await api.request("/auth/passkey/login/options", method: "POST", body: .object(vaultIdentity))
        let options = value["options"]
        let credential = try await passkeys.assertion(options: options)
        let proof = vaultIdentity.merging(["challenge": options["challenge"], "credential": credential]) { _, value in value }
        _ = try await api.request("/auth/passkey/login/verify", method: "POST", body: .object(proof))
        authenticationGeneration = UUID()
        invalidatePages()
        if !vaultIdentity.isEmpty { vaultCredentialNeedsRenewal = false }
    }

    private func nativeVaultIdentity() -> [String: JSONValue] {
        guard let publicKey = try? VaultFaceID.preparePublicKey() else { return [:] }
        return ["nativeVaultPublicKey": .string(publicKey)]
    }

    func enroll(bootstrapToken: String) async {
        guard !isAuthenticating else { return }
        isAuthenticating = true; connectionError = nil
        defer { isAuthenticating = false }
        do {
            let token = JSONValue.string(bootstrapToken)
            let vaultIdentity = nativeVaultIdentity().merging(["bootstrapToken": token]) { _, value in value }
            let value = try await api.request("/auth/passkey/register/options", method: "POST", body: .object(vaultIdentity))
            let credential = try await passkeys.registration(options: value["options"])
            let proof = vaultIdentity.merging(["challenge": value["options"]["challenge"], "credential": credential]) { _, value in value }
            _ = try await api.request("/auth/passkey/register/verify", method: "POST", body: .object(proof))
            await connect()
        } catch is CancellationError { }
        catch { connectionError = error.localizedDescription }
    }

    func get(_ path: String) async throws -> JSONValue { try await request(path, method: "GET") }
    func post(_ path: String, body: JSONValue = .object([:])) async throws -> JSONValue { try await request(path, method: "POST", body: body) }

    func cachedPage(_ path: String) -> JSONValue? {
        guard authenticated, Self.pagePaths.contains(path) else { return nil }
        return pageCache[path]?.value
    }

    func readPage(_ path: String, maxAge: Duration = .zero) async throws -> JSONValue {
        guard authenticated, Self.pagePaths.contains(path) else { return try await get(path) }
        if maxAge > .zero, let cached = pageCache[path], cached.receivedAt.duration(to: .now) < maxAge {
            return cached.value
        }
        let generation = pageGeneration
        let request: (id: UUID, task: Task<JSONValue, Error>)
        if let existing = pageRequests[path] {
            request = existing
        } else {
            request = (UUID(), Task { try await self.get(path) })
            pageRequests[path] = request
        }
        defer {
            if pageRequests[path]?.id == request.id { pageRequests[path] = nil }
        }
        let value = try await request.task.value
        try Task.checkCancellation()
        guard authenticated else { throw CancellationError() }
        if pageGeneration != generation {
            if let refreshed = pageCache[path] { return refreshed.value }
            return try await readPage(path)
        }
        pageCache[path] = (value, .now)
        if path == "/control/server-events" { unreadWarnings = value["issues"].arrayValue.count }
        return value
    }

    func preparePages() async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await self.applicationStore.load(self, maxAge: .seconds(8)) }
            for path in Self.pagePaths where !path.hasPrefix("/api/native/v1/applications") {
                group.addTask { _ = try? await self.readPage(path, maxAge: .seconds(8)) }
            }
        }
    }

    func request(_ path: String, method: String, body: JSONValue? = nil) async throws -> JSONValue {
        let authentication = authenticationGeneration
        do {
            let value = try await api.request(path, method: method, body: body)
            guard authentication == authenticationGeneration else { throw CancellationError() }
            if method != "GET", !path.hasPrefix("/api/native/v1/vault/secrets/") {
                invalidatePages()
            }
            return value
        }
        catch let error as APIError where error.status == 401 {
            guard authentication == authenticationGeneration else { throw CancellationError() }
            clearPageData()
            authenticated = false
            throw error
        }
    }

    func logout() async throws {
        _ = try await post("/logout")
        await api.clearSession()
        clearPageData()
        bootstrap = .null
        authenticated = false
    }

    private func invalidatePages() {
        applicationStore.invalidateDetails()
        pageGeneration = UUID()
        pageCache.removeAll()
        pageRequests.removeAll()
    }

    private func clearPageData() {
        authenticationGeneration = UUID()
        for request in pageRequests.values { request.task.cancel() }
        invalidatePages()
        applicationStore.reset()
        unreadWarnings = 0
    }
}
