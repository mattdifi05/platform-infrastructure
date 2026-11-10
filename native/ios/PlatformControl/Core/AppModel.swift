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
    let isTestEnvironment: Bool
    private let passkeys = PasskeyCoordinator()

    init(testEnvironment: Bool = false) {
        isTestEnvironment = testEnvironment
        api = APIClient(fixture: testEnvironment)
    }

    func connect() async {
        isConnecting = true
        connectionError = nil
        defer { isConnecting = false }
        do {
            bootstrap = try await readSession()
            authenticated = true
        } catch let error as APIError where error.status == 401 {
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

    private func readSession() async throws -> JSONValue {
        let session = try await api.request("/api/native/v1/bootstrap")
        guard session["schemaVersion"].intValue == 1, !session["session"]["subject"].text.isEmpty else {
            throw APIError(status: 0, message: "La sessione restituita dal server non è valida.")
        }
        return session
    }

    private func authenticate() async throws {
        let value = try await api.request("/auth/passkey/login/options", method: "POST", body: .object([:]))
        let options = value["options"]
        let credential = try await passkeys.assertion(options: options)
        _ = try await api.request("/auth/passkey/login/verify", method: "POST", body: .object(["challenge": options["challenge"], "credential": credential]))
    }

    func enroll(bootstrapToken: String) async {
        guard !isAuthenticating else { return }
        isAuthenticating = true; connectionError = nil
        defer { isAuthenticating = false }
        do {
            let token = JSONValue.string(bootstrapToken)
            let value = try await api.request("/auth/passkey/register/options", method: "POST", body: .object(["bootstrapToken": token]))
            let credential = try await passkeys.registration(options: value["options"])
            _ = try await api.request("/auth/passkey/register/verify", method: "POST", body: .object(["challenge": value["options"]["challenge"], "bootstrapToken": token, "credential": credential]))
            await connect()
        } catch is CancellationError { }
        catch { connectionError = error.localizedDescription }
    }

    func get(_ path: String) async throws -> JSONValue { try await request(path, method: "GET") }
    func post(_ path: String, body: JSONValue = .object([:])) async throws -> JSONValue { try await request(path, method: "POST", body: body) }
    func request(_ path: String, method: String, body: JSONValue? = nil) async throws -> JSONValue {
        do { return try await api.request(path, method: method, body: body) }
        catch let error as APIError where error.status == 401 {
            authenticated = false
            throw error
        }
    }

    func logout() async throws {
        _ = try await post("/logout")
        await api.clearSession()
        bootstrap = .null
        authenticated = false
    }
}
