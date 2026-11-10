import CryptoKit
import Foundation
import LocalAuthentication
import Security

@MainActor
enum VaultFaceID {
    private static let keyQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.stexor.controlcenter.vault-face-id",
        kSecAttrAccount as String: ServiceConfiguration.relyingParty
    ]

    static func preparePublicKey() throws -> String {
        let context = try faceIDContext()
        defer { context.invalidate() }
        guard SecureEnclave.isAvailable else { throw VaultFaceIDError.unavailable }
        if let data = try loadKeyData() {
            if let key = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data, authenticationContext: context) {
                return key.publicKey.x963Representation.base64URL
            }
            discardCredential()
        }
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], nil) else {
            throw VaultFaceIDError.credentialUnavailable
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access, authenticationContext: context)
        var item = keyQuery
        item[kSecValueData as String] = key.dataRepresentation
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else { throw VaultFaceIDError.credentialUnavailable }
        return key.publicKey.x963Representation.base64URL
    }

    static func confirm(reason: String) async throws {
        let context = try faceIDContext()
        defer { context.invalidate() }
        try await authenticate(context, reason: reason)
    }

    static func sign(
        requestingChallenge: @MainActor @Sendable () async throws -> String
    ) async throws -> (challenge: String, signature: String) {
        let context = try faceIDContext()
        defer { context.invalidate() }
        guard let data = try loadKeyData() else { throw VaultFaceIDError.credentialUnavailable }

        // The server issues a nonce while Face ID runs. The signature still
        // requires this attempt's successful Face ID and the server's nonce.
        async let pendingChallenge = requestingChallenge()
        try await authenticate(context, reason: "Mostra il valore del secret.")
        let challenge = try await pendingChallenge
        try Task.checkCancellation()
        guard let bytes = Data(base64URL: challenge), bytes.count == 32, bytes.base64URL == challenge else {
            throw VaultFaceIDError.invalidChallenge
        }
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data, authenticationContext: context)
            let signature = try key.signature(for: Data("platform-vault-reveal-v1\n\(challenge)".utf8))
            return (challenge, signature.derRepresentation.base64URL)
        } catch {
            discardCredential()
            throw VaultFaceIDError.credentialUnavailable
        }
    }

    private static func faceIDContext() throws -> LAContext {
        let context = LAContext()
        context.localizedFallbackTitle = ""
        var error: NSError?
        let available = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        guard context.biometryType == .faceID else { throw VaultFaceIDError.unavailable }
        guard available else {
            if error?.code == LAError.biometryLockout.rawValue { throw VaultFaceIDError.locked }
            throw VaultFaceIDError.unavailable
        }
        return context
    }

    private static func authenticate(_ context: LAContext, reason: String) async throws {
        context.localizedReason = reason
        do {
            guard try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) else {
                throw VaultFaceIDError.failed
            }
            try Task.checkCancellation()
        } catch let error as LAError {
            switch error.code {
            case .userCancel, .appCancel, .systemCancel: throw CancellationError()
            case .biometryLockout: throw VaultFaceIDError.locked
            case .biometryNotAvailable, .biometryNotEnrolled: throw VaultFaceIDError.unavailable
            default: throw VaultFaceIDError.failed
            }
        }
    }

    private static func loadKeyData() throws -> Data? {
        var query = keyQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw VaultFaceIDError.credentialUnavailable }
        return data
    }

    private static func discardCredential() { SecItemDelete(keyQuery as CFDictionary) }
}

enum VaultFaceIDError: LocalizedError {
    case unavailable, locked, failed, credentialUnavailable, invalidChallenge, unsupported

    var errorDescription: String? {
        switch self {
        case .unavailable: "Attiva Face ID nelle impostazioni del dispositivo per usare questa funzione."
        case .locked: "Face ID è bloccato. Sblocca il dispositivo con il codice e riprova."
        case .failed: "Verifica Face ID non riuscita. Riprova."
        case .credentialUnavailable: "Abilita di nuovo Face ID per i secret su questo dispositivo."
        case .invalidChallenge: "Il server ha restituito una richiesta Face ID non valida."
        case .unsupported: "L’API del server non supporta ancora la verifica Face ID per i secret."
        }
    }
}
