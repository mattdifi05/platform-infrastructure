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
}
