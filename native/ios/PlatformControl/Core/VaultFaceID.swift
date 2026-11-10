import CryptoKit
import Foundation
import LocalAuthentication
import os
import Security

enum VaultFaceID {
    static let timing = OSSignposter(subsystem: "com.stexor.controlcenter", category: "VaultReveal")
    private static let signingQueue = DispatchQueue(label: "com.stexor.controlcenter.vault-sign", qos: .userInitiated)
    private static var keyQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.stexor.controlcenter.vault-face-id",
            kSecAttrAccount as String: ServiceConfiguration.relyingParty
        ]
    }

    @MainActor static func preparePublicKey() throws -> String {
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

    @MainActor static func confirm(reason: String) async throws {
        let context = try faceIDContext()
        defer { context.invalidate() }
        try await authenticate(context, reason: reason)
    }

    @concurrent
    static func sign(
        requestingChallenge: @MainActor @Sendable () async throws -> String
    ) async throws -> (challenge: String, signature: String) {
        async let pendingChallenge = requestingChallenge()
        let context = try faceIDContext()
        defer { context.invalidate() }
        context.localizedReason = "Mostra il valore del secret."
        guard let data = try loadKeyData() else { throw VaultFaceIDError.credentialUnavailable }
        guard let key = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data, authenticationContext: context) else {
            throw VaultFaceIDError.credentialUnavailable
        }

        let challenge = try await pendingChallenge
        try Task.checkCancellation()
        guard let bytes = Data(base64URL: challenge), bytes.count == 32, bytes.base64URL == challenge else {
            throw VaultFaceIDError.invalidChallenge
        }

        // The fresh context is used by the key's biometryCurrentSet ACL. The
        // protected signature itself is the only interactive authorization.
        let message = Data("platform-vault-reveal-v1\n\(challenge)".utf8)
        let interval = timing.beginInterval("Secure Enclave signature")
        defer { timing.endInterval("Secure Enclave signature", interval) }
        let cancellation = SigningCancellation(context)
        do {
            let signature = try await withTaskCancellationHandler {
                try Task.checkCancellation()
                return try await withCheckedThrowingContinuation { continuation in
                    signingQueue.async {
                        continuation.resume(with: Result {
                            try key.signature(for: message).derRepresentation.base64URL
                        })
                    }
                }
            } onCancel: {
                cancellation.invalidate()
            }
            try Task.checkCancellation()
            return (challenge, signature)
        } catch {
            try Task.checkCancellation()
            throw signingError(error)
        }
    }

    private static func signingError(_ error: Error) -> Error {
        let failure = error as NSError
        switch failure.domain {
        case LAError.errorDomain:
            switch LAError.Code(rawValue: failure.code) {
            case .userCancel, .appCancel, .systemCancel: return CancellationError()
            case .biometryLockout: return VaultFaceIDError.locked
            case .biometryNotAvailable, .biometryNotEnrolled: return VaultFaceIDError.unavailable
            default: return VaultFaceIDError.failed
            }
        case NSOSStatusErrorDomain:
            switch failure.code {
            case Int(errSecUserCanceled): return CancellationError()
            case Int(errSecItemNotFound), Int(errSecDecode): return VaultFaceIDError.credentialUnavailable
            default: return VaultFaceIDError.failed
            }
        default:
            return VaultFaceIDError.failed
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

// The only operation shared with the cancellation handler is the terminal
// invalidation LocalAuthentication provides for an in-flight evaluation.
private struct SigningCancellation: @unchecked Sendable {
    private let context: LAContext

    init(_ context: LAContext) { self.context = context }

    func invalidate() { context.invalidate() }
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
