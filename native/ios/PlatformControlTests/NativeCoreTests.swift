import XCTest
@testable import PlatformControl

final class NativeCoreTests: XCTestCase {
    func testBase64URLRoundTrip() throws {
        for size in [0, 1, 2, 3, 31, 64, 255] {
            let data = Data((0..<size).map { UInt8($0 % 256) })
            XCTAssertEqual(Data(base64URL: data.base64URL), data)
            XCTAssertFalse(data.base64URL.contains("="))
        }
    }

    func testJSONPreservesTypesAndMissingValues() throws {
        let data = Data(#"{"bool":true,"zero":0,"false":false,"null":null,"array":[1,"two"]}"#.utf8)
        let value = try JSONDecoder().decode(JSONValue.self, from: data)
        XCTAssertEqual(value["bool"].boolValue, true)
        XCTAssertNil(value["zero"].boolValue)
        XCTAssertEqual(value["zero"].intValue, 0)
        XCTAssertEqual(value["false"].boolValue, false)
        XCTAssertEqual(value["missing"], .null)
        XCTAssertEqual(value["array"].arrayValue.count, 2)
        XCTAssertEqual(try JSONDecoder().decode(JSONValue.self, from: JSONEncoder().encode(value)), value)
    }

    func testTransportRejectsCrossOriginAndInsecureTargetsBeforeSending() async {
        let api = APIClient(persistCredentials: false)
        for path in ["http://portal.stexor.com/control/vault", "//evil.example/control/vault", "https://evil.example/", "control/vault", "/control/vault#fragment"] {
            do { _ = try await api.request(path); XCTFail("Accepted unsafe path: \(path)") }
            catch let error as APIError { XCTAssertEqual(error.status, 0) }
            catch { XCTFail("Unexpected error: \(error)") }
        }
    }

    func testFaviconCandidatesUseTheSiteOrigin() throws {
        let page = try XCTUnwrap(URL(string: "https://site.example.test/app/home"))
        let html = """
            <link rel="icon" href="https://other.example.test/icon.png">
            <LINK HREF="../icon.png?v=1&amp;color=blue" REL='shortcut icon'>
            <link rel=apple-touch-icon href=/touch.png>
            <link rel="icon" href="http://site.example.test/unsafe.png">
            <link rel="icon" href="https://site.example.test:8443/another-origin.png">
            <link rel="canonical" href="/not-an-icon.png">
            """
        XCTAssertEqual(FaviconLinks.candidates(in: html, relativeTo: page).map(\.absoluteString), [
            "https://site.example.test/icon.png?v=1&color=blue",
            "https://site.example.test/touch.png"
        ])
        XCTAssertFalse(FaviconLinks.sameOrigin(try XCTUnwrap(URL(string: "https://user@site.example.test/icon.png")), as: page))
        XCTAssertEqual(applicationSiteURL(.object(["href": .string("/relative"), "host": .string("site.example.test")])), URL(string: "https://site.example.test"))
    }

    func testFixtureIsolationAndHonestUnknownMutations() async throws {
        let api = APIClient(fixture: true)
        let bootstrap = try await api.request("/api/native/v1/bootstrap")
        XCTAssertEqual(bootstrap["session"]["displayName"].text, "Ambiente di prova")
        do { _ = try await api.request("/unimplemented-dangerous-operation", method: "POST"); XCTFail("Unknown mutation must fail") }
        catch let error as APIError { XCTAssertEqual(error.status, 404) }
        let apps = try await api.request("/api/native/v1/applications")
        XCTAssertEqual(apps["projects"].arrayValue.count, 1)
        _ = try await api.request("/control/project-folders", method: "POST", body: .object(["name": .string("QA")]))
        let updated = try await api.request("/api/native/v1/applications")
        XCTAssertEqual(updated["folders"]["folders"].arrayValue.count, 3)
    }

    @MainActor func testAppBootstrapsDirectlyAndSignsOutWithoutDashboard() async throws {
        let model = AppModel(testEnvironment: true)
        await model.connect()
        XCTAssertTrue(model.authenticated)
        XCTAssertFalse(model.isConnecting)
        try await model.logout()
        XCTAssertFalse(model.authenticated)
        XCTAssertEqual(model.bootstrap, .null)
    }

    @MainActor func testPageMetadataReuseAndMutationInvalidation() async throws {
        let model = AppModel(testEnvironment: true)
        await model.connect()
        let path = "/api/native/v1/applications"
        let original = try await model.readPage(path)
        // Change the fixture through the transport to exercise a genuinely retained read.
        _ = try await model.api.request("/control/project-folders", method: "POST", body: .object(["name": .string("Esterno")]))
        let reused = try await model.readPage(path, maxAge: .seconds(8))
        XCTAssertEqual(reused, original)
        let fresh = try await model.readPage(path)
        XCTAssertEqual(fresh["folders"]["folders"].arrayValue.count, original["folders"]["folders"].arrayValue.count + 1)
        _ = try await model.post("/control/project-folders", body: .object(["name": .string("Nuova")]))
        XCTAssertNil(model.cachedPage(path))
        let afterMutation = try await model.readPage(path, maxAge: .seconds(8))
        XCTAssertEqual(afterMutation["folders"]["folders"].arrayValue.count, original["folders"]["folders"].arrayValue.count + 2)
    }

    @MainActor func testPageCacheExcludesRevealedValuesAndClearsOnLogout() async throws {
        let model = AppModel(testEnvironment: true)
        await model.connect()
        _ = try await model.readPage("/control/v1/vault")
        XCTAssertNotNil(model.cachedPage("/control/v1/vault"))
        let reveal = "/api/native/v1/vault/secrets/fixture-secret/reveal"
        _ = try await model.post(reveal)
        XCTAssertNil(model.cachedPage(reveal))
        await model.applicationStore.load(model)
        XCTAssertFalse(model.applicationStore.projects.isEmpty)
        try await model.logout()
        XCTAssertNil(model.cachedPage("/control/v1/vault"))
        XCTAssertFalse(model.applicationStore.hasLoaded)
        XCTAssertTrue(model.applicationStore.projects.isEmpty)
    }
}
