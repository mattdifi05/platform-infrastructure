import Foundation
import XCTest
@testable import PlatformControl

final class PageLoadingConcurrencyTests: XCTestCase, @unchecked Sendable {
    @MainActor
    func testConcurrentStoreReloadAfterMutationKeepsFreshCatalog() async throws {
        let (model, transport) = makeModel()
        model.authenticated = true
        let path = "/api/native/v1/applications?view=catalog"
        let firstStarted = expectation(description: "Original catalog request")
        let secondStarted = expectation(description: "Post-mutation catalog request")
        transport.expect(path, occurrence: 1, fulfillment: firstStarted)
        transport.expect(path, occurrence: 2, fulfillment: secondStarted)
        transport.respondAutomatically(path, after: 1, body: catalog(named: "Fresh"))

        let first = Task { await model.applicationStore.load(model) }
        await fulfillment(of: [firstStarted], timeout: 3)
        _ = try await model.post("/control/project-folders")
        let second = Task { await model.applicationStore.load(model) }
        await fulfillment(of: [secondStarted], timeout: 3)

        await second.value
        try transport.respond(path, occurrence: 1, body: catalog(named: "Old"))
        await first.value

        XCTAssertTrue(model.applicationStore.hasLoaded)
        XCTAssertFalse(model.applicationStore.isLoading)
        XCTAssertNil(model.applicationStore.error)
        XCTAssertEqual(model.applicationStore.projects.first?["name"].text, "Fresh")
    }

    @MainActor
    func testDetailCompletionPreservesNewerCatalogAndFolderMetadata() async throws {
        let (model, transport) = makeModel()
        model.authenticated = true
        let list = "/api/native/v1/applications?view=catalog"
        let full = "/api/native/v1/applications"
        transport.respondAutomatically(list, after: 0, body: catalog(named: "Current"))
        await model.applicationStore.load(model)
        let started = expectation(description: "Full detail request")
        transport.expect(full, occurrence: 1, fulfillment: started)
        let details = Task { await model.applicationStore.loadDetails(model) }
        await fulfillment(of: [started], timeout: 3)
        try transport.respond(full, occurrence: 1, body: #"{"projects":[{"id":"app","name":"Old"}],"folders":{"memberships":{"project:app":"old-folder"}},"databases":[],"resources":{"projectUsage":[]},"redis":{}}"#)
        await details.value
        XCTAssertEqual(model.applicationStore.projects.first?["name"].text, "Current")
        XCTAssertNil(model.applicationStore.memberships["project:app"].stringValue)
        XCTAssertTrue(model.applicationStore.hasLoadedDetails)
        try await model.logout()
        XCTAssertFalse(model.applicationStore.hasLoadedDetails)
        XCTAssertEqual(model.applicationStore.catalog["resources"], .null)
    }

    @MainActor
    func testPendingFullResponseCannotCommitAfterCatalogRefresh() async throws {
        let (model, transport) = makeModel()
        model.authenticated = true
        let list = "/api/native/v1/applications?view=catalog"
        let full = "/api/native/v1/applications"
        transport.respondAutomatically(list, after: 0, body: catalog(named: "Before"))
        await model.applicationStore.load(model)
        let started = expectation(description: "Old full detail request")
        transport.expect(full, occurrence: 1, fulfillment: started)
        let details = Task { await model.applicationStore.loadDetails(model) }
        await fulfillment(of: [started], timeout: 3)
        transport.respondAutomatically(list, after: 0, body: catalog(named: "After"))
        await model.applicationStore.load(model)
        try transport.respond(full, occurrence: 1, body: #"{"databases":[],"resources":{"revision":"old"},"redis":{}}"#)
        await details.value
        XCTAssertEqual(model.applicationStore.projects.first?["name"].text, "After")
        XCTAssertFalse(model.applicationStore.hasLoadedDetails)
        XCTAssertEqual(model.applicationStore.catalog["resources"], .null)
        XCTAssertFalse(model.applicationStore.isLoadingDetails)
    }

    @MainActor
    func testDetailRevisionRestartsReadAfterCatalogInvalidation() async throws {
        let (model, transport) = makeModel()
        model.authenticated = true
        let list = "/api/native/v1/applications?view=catalog"
        let full = "/api/native/v1/applications"
        transport.respondAutomatically(list, after: 0, body: catalog(named: "Current"))
        await model.applicationStore.load(model)
        let revision = model.applicationStore.detailsRevision
        let started = expectation(description: "Full detail request before invalidation")
        transport.expect(full, occurrence: 1, fulfillment: started)
        let oldDetails = Task { await model.applicationStore.loadDetails(model) }
        await fulfillment(of: [started], timeout: 3)
        await model.applicationStore.load(model)
        XCTAssertNotEqual(model.applicationStore.detailsRevision, revision)
        oldDetails.cancel()
        transport.respondAutomatically(full, after: 1, body: #"{"databases":[],"resources":{"revision":"fresh"},"redis":{}}"#)
        let replacement = Task { await model.applicationStore.loadDetails(model) }
        await Task.yield()
        try transport.respond(full, occurrence: 1, body: #"{"databases":[],"resources":{"revision":"fresh"},"redis":{}}"#)
        await oldDetails.value
        await replacement.value
        XCTAssertTrue(model.applicationStore.hasLoadedDetails)
        XCTAssertFalse(model.applicationStore.isLoadingDetails)
        XCTAssertEqual(model.applicationStore.catalog["resources"]["revision"].text, "fresh")
    }

    @MainActor
    func testInFlightPageReadRetriesAfterMutationInvalidation() async throws {
        let (model, transport) = makeModel()
        model.authenticated = true
        let path = "/control/server-events"
        let firstStarted = expectation(description: "Original events request")
        let retryStarted = expectation(description: "Invalidated read retried")
        transport.expect(path, occurrence: 1, fulfillment: firstStarted)
        transport.expect(path, occurrence: 2, fulfillment: retryStarted)

        let read = Task { try await model.readPage(path) }
        await fulfillment(of: [firstStarted], timeout: 3)
        _ = try await model.post("/control/project-folders")
        try transport.respond(path, occurrence: 1, body: #"{"issues":[],"revision":"old"}"#)
        await fulfillment(of: [retryStarted], timeout: 3)
        try transport.respond(path, occurrence: 2, body: #"{"issues":[{"id":"new"}],"revision":"fresh"}"#)

        let result = try await read.value
        XCTAssertEqual(result["revision"].text, "fresh")
        XCTAssertEqual(model.cachedPage(path)?["revision"].text, "fresh")
        XCTAssertEqual(model.unreadWarnings, 1)
    }

    @MainActor
    func testOldSessionUnauthorizedResponsePreservesReplacementSession() async throws {
        let (model, transport) = makeModel()
        model.authenticated = true
        let path = "/control/held-old-session"
        let started = expectation(description: "Old-session request")
        transport.expect(path, occurrence: 1, fulfillment: started)
        let oldRead = Task { try await model.get(path) }
        await fulfillment(of: [started], timeout: 3)

        try await model.logout()
        await model.connect()
        XCTAssertTrue(model.authenticated)
        try transport.respond(path, occurrence: 1, status: 401, body: #"{"message":"Expired old session"}"#)
        do {
            _ = try await oldRead.value
            XCTFail("The old authentication epoch must be discarded")
        } catch is CancellationError {
        } catch {
            XCTFail("Expected cancellation of obsolete authentication, received \(error)")
        }
        XCTAssertTrue(model.authenticated)
        XCTAssertEqual(model.bootstrap["session"]["subject"].text, "replacement")
    }

    @MainActor
    private func makeModel() -> (AppModel, PageTestTransport) {
        let transport = PageTestTransport()
        let host = UUID().uuidString.lowercased() + ".example.invalid"
        PageTestURLProtocol.registry.register(transport, host: host)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [PageTestURLProtocol.self]
        let client = APIClient(
            baseURL: URL(string: "https://" + host)!,
            configuration: configuration,
            persistCredentials: false
        )
        return (AppModel(apiClient: client), transport)
    }

    private func catalog(named name: String) -> String {
        """
        {"projects":[{"id":"app","slug":"app","name":"\(name)"}],"observed":[],"folders":{"folders":[],"memberships":{}}}
        """
    }
}

private final class PageTestRegistry: @unchecked Sendable {
    private let lock = NSLock()
    private var transports: [String: PageTestTransport] = [:]

    func register(_ transport: PageTestTransport, host: String) {
        lock.lock()
        defer { lock.unlock() }
        transports[host] = transport
    }

    func transport(for host: String) -> PageTestTransport? {
        lock.lock()
        defer { lock.unlock() }
        return transports[host]
    }
}

private final class PageTestTransport: @unchecked Sendable {
    private let lock = NSLock()
    private var requests: [String: [PageTestURLProtocol]] = [:]
    private var expectations: [String: [Int: XCTestExpectation]] = [:]
    private var automaticResponses: [String: (after: Int, body: String)] = [:]

    func respondAutomatically(_ path: String, after occurrence: Int, body: String) {
        lock.lock()
        defer { lock.unlock() }
        automaticResponses[path] = (occurrence, body)
    }

    func expect(_ path: String, occurrence: Int, fulfillment: XCTestExpectation) {
        lock.lock()
        defer { lock.unlock() }
        expectations[path, default: [:]][occurrence] = fulfillment
    }

    func start(_ request: PageTestURLProtocol) {
        let url = request.request.url!
        let path = url.path + (url.query.map { "?" + $0 } ?? "")
        if request.request.httpMethod == "POST" {
            request.complete(status: 200, body: "{}")
            return
        }
        if path == "/api/native/v1/bootstrap" {
            request.complete(status: 200, body: #"{"schemaVersion":1,"session":{"subject":"replacement"}}"#)
            return
        }
        lock.lock()
        requests[path, default: []].append(request)
        let occurrence = requests[path]!.count
        let expectation = expectations[path]?[occurrence]
        let automatic = automaticResponses[path]
        lock.unlock()
        expectation?.fulfill()
        if let automatic, occurrence > automatic.after {
            request.complete(status: 200, body: automatic.body)
        }
    }

    func respond(_ path: String, occurrence: Int, status: Int = 200, body: String) throws {
        lock.lock()
        let matches = requests[path, default: []]
        let request = matches.indices.contains(occurrence - 1) ? matches[occurrence - 1] : nil
        lock.unlock()
        try XCTUnwrap(request, "Missing held request \(path), occurrence \(occurrence)")
            .complete(status: status, body: body)
    }
}

private final class PageTestURLProtocol: URLProtocol, @unchecked Sendable {
    static let registry = PageTestRegistry()

    override class func canInit(with request: URLRequest) -> Bool {
        request.url?.host.flatMap { registry.transport(for: $0) } != nil
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let host = request.url?.host, let transport = Self.registry.transport(for: host) else {
            client?.urlProtocol(self, didFailWithError: URLError(.unsupportedURL))
            return
        }
        transport.start(self)
    }

    override func stopLoading() {}

    func complete(status: Int, body: String) {
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
}
