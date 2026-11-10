import AuthenticationServices
import UIKit

@MainActor
final class PasskeyCoordinator: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    private var continuation: CheckedContinuation<JSONValue, Error>?
    private var controller: ASAuthorizationController?
    private var anchor: UIWindow?

    func assertion(options: JSONValue) async throws -> JSONValue {
        guard continuation == nil else { throw APIError(status: 409, message: "Una richiesta passkey è già aperta.") }
        let rpID = options["rpId"].text
        guard rpID == ServiceConfiguration.relyingParty,
              let challenge = Data(base64URL: options["challenge"].text), !challenge.isEmpty else {
            throw APIError(status: 0, message: "La richiesta passkey del server non è valida.")
        }
        let request = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpID).createCredentialAssertionRequest(challenge: challenge)
        request.userVerificationPreference = .required
        request.allowedCredentials = options["allowCredentials"].arrayValue.compactMap {
            guard let id = Data(base64URL: $0["id"].text) else { return nil }
            return ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: id)
        }
        return try await perform(request)
    }

    func registration(options: JSONValue) async throws -> JSONValue {
        guard continuation == nil,
              options["rp"]["id"].text == ServiceConfiguration.relyingParty,
              let challenge = Data(base64URL: options["challenge"].text), !challenge.isEmpty,
              let userID = Data(base64URL: options["user"]["id"].text), !userID.isEmpty else {
            throw APIError(status: 0, message: "La richiesta di registrazione passkey non è valida.")
        }
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: options["rp"]["id"].text)
        let request = provider.createCredentialRegistrationRequest(challenge: challenge, name: options["user"]["name"].text, userID: userID)
        request.userVerificationPreference = .required
        return try await perform(request)
    }

    private func perform(_ request: ASAuthorizationRequest) async throws -> JSONValue {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        guard let window = scenes.first(where: { $0.activationState == .foregroundActive })?.windows.first(where: { $0.isKeyWindow }) else {
            throw APIError(status: 0, message: "Apri l’app per completare la verifica passkey.")
        }
        anchor = window
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let controller = ASAuthorizationController(authorizationRequests: [request])
            self.controller = controller
            controller.delegate = self
            controller.presentationContextProvider = self
            controller.performRequests()
        }
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        if let registration = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration,
           let attestation = registration.rawAttestationObject {
            finish(.success(.object(["id": .string(registration.credentialID.base64URL), "rawId": .string(registration.credentialID.base64URL), "type": .string("public-key"), "response": .object(["clientDataJSON": .string(registration.rawClientDataJSON.base64URL), "attestationObject": .string(attestation.base64URL), "transports": .array([.string("internal")])]), "clientExtensionResults": .object([:])])))
            return
        }
        guard let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion else {
            finish(.failure(APIError(status: 0, message: "La passkey non ha prodotto una firma valida."))); return
        }
        var response: [String: JSONValue] = ["clientDataJSON": .string(credential.rawClientDataJSON.base64URL), "authenticatorData": .string(credential.rawAuthenticatorData.base64URL), "signature": .string(credential.signature.base64URL)]
        if !credential.userID.isEmpty { response["userHandle"] = .string(credential.userID.base64URL) }
        finish(.success(.object([
            "id": .string(credential.credentialID.base64URL), "rawId": .string(credential.credentialID.base64URL), "type": .string("public-key"),
            "response": .object(response), "clientExtensionResults": .object([:])
        ])))
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        if (error as? ASAuthorizationError)?.code == .canceled {
            finish(.failure(CancellationError()))
        } else { finish(.failure(error)) }
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        // A foreground key window is captured before starting the ceremony.
        anchor!
    }

    private func finish(_ result: Result<JSONValue, Error>) {
        let pending = continuation
        continuation = nil
        controller = nil
        anchor = nil
        pending?.resume(with: result)
    }
}
