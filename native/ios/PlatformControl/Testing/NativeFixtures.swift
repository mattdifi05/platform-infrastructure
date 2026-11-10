#if DEBUG
import Foundation

// Available only to DEBUG builds launched explicitly with --ui-testing.
// These synthetic values never fall back from a failed production request.
actor NativeFixtures {
    private var folders: [JSONValue] = [.object(["id": .string("stexor"), "name": .string("Stexor"), "canDelete": .bool(false)]), .object(["id": .string("empty"), "name": .string("Da organizzare"), "canDelete": .bool(true)])]
    private let revision = "fixture-revision-1"
    private var jobs: [String: JSONValue] = [:]

    func response(path: String, method: String, body: JSONValue?) throws -> JSONValue {
        let canonical = path.replacingOccurrences(of: "/control/v1/", with: "/control/").components(separatedBy: "?")[0]
        if canonical == "/api/native/v1/bootstrap" { return parse(#"{"schemaVersion":1,"authentication":{"vaultFaceIDSupported":true},"session":{"subject":"test-owner","displayName":"Ambiente di prova","role":"owner","vaultFaceIDRegistered":true},"csrfToken":"fixture-csrf","capabilities":[]}"#) }
        if canonical == "/control/resources/host" {
            return parse(#"{"scope":"host","freshness":{"available":true},"cpu":{"available":true,"usedPercent":17.4,"cores":4},"memory":{"available":true,"usedPercent":32.8,"usedBytes":2817508540,"totalBytes":8589934592},"disk":{"available":true,"usedPercent":26.4,"usedBytes":56693568307,"totalBytes":214748364800},"swap":{"usedBytes":0,"totalBytes":2147483648},"network":{"totals":{"rxBytesPerSecond":38400,"txBytesPerSecond":12800}},"diskIo":{"totals":{"readBytesPerSecond":24000,"writeBytesPerSecond":128000}},"inodes":{"usedPercent":3.1},"load":{"one":0.4,"five":0.3,"fifteen":0.2},"uptimeSeconds":102400}"#)
        }
        if canonical == "/api/native/v1/applications" {
            return .object(["projects": .array([parse(#"{"id":"sample","slug":"sample","name":"Applicazione di prova","host":"local.example.test","href":"https://local.example.test","runtime":"php","type":"PHP","enabled":true,"status":"active"}"#)]), "applications": .array([]), "observed": .array([]), "folders": .object(["folders": .array(folders), "memberships": .object(["project:sample": .string("stexor")])]), "databases": .array([]), "engines": .array([]), "resources": .object([:]), "redis": .object([:])])
        }
        if canonical == "/control/project-folders", method == "POST" {
            let folder = JSONValue.object(["id": .string(UUID().uuidString), "name": body?["name"] ?? .string("Nuova cartella"), "canDelete": .bool(true)])
            folders.append(folder)
            return .object(["ok": .bool(true), "folders": .array(folders)])
        }
        if canonical.hasSuffix("/rename"), canonical.contains("project-folders") { return .object(["ok": .bool(true)]) }
        if canonical.hasSuffix("/delete"), canonical.contains("project-folders") { return .object(["ok": .bool(true)]) }
        if canonical.hasSuffix("/hosting-status") { return parse(#"{"available":true,"mode":"private","visibility":"private","revision":"fixture-hosting","clone":{"available":true},"modes":["public","private","offline"]}"#) }
        if canonical == "/control/vault" {
            return .object(["revision": .string(revision), "items": .array([parse(#"{"id":"fixture-secret","itemKey":"Esempio","label":"Credenziale di prova","projectId":"sample","environment":"production","kind":"api-key","createdAt":"2026-11-10T10:00:00Z","updatedAt":"2026-11-10T11:30:00Z","rotationDays":90,"versions":[{"versionId":"v1","createdAt":"2026-11-10T10:00:00Z"}],"currentVersionId":"v1"}"#)]), "projects": .array([.object(["slug": .string("sample"), "name": .string("Applicazione di prova")])]), "runtime": .object(["bindings": .array([]), "available": .bool(true)])])
        }
        if canonical.hasSuffix("/reveal") { return .object(["value": .string("fixture-secret-value"), "expiresAt": .string(ISO8601DateFormatter().string(from: Date.now.addingTimeInterval(30)))]) }
        if canonical.hasPrefix("/control/vault/"), method == "POST" { return .object(["ok": .bool(true), "dryRun": .bool(false)]) }
        if canonical == "/control/runtime-updates/system" {
            return parse(#"{"schema":"host-updates/v1","available":true,"revision":"fixture-host","checkedAt":"2026-11-10T10:00:00Z","updateCount":1,"autoremoveCount":1,"canCheck":true,"canApply":true,"canReboot":true,"rebootRequired":true,"packages":[{"name":"openssl","currentVersion":"3.0.1","targetVersion":"3.0.2"}],"operations":[]}"#)
        }
        if canonical == "/control/runtime-updates" {
            return parse(#"{"schema":"runtime-updates/v1","available":true,"canCheck":true,"canApply":true,"revision":"fixture-runtime","components":[{"id":"php","label":"PHP","category":"Runtime","current":{"version":"8.5.12","versions":["8.5.12"]},"latestStable":{"version":"8.5.13"},"candidateRelease":{"version":"8.5.13"},"status":"update-available","canUpdate":true,"services":["application-test"],"installed":true}],"operations":[]}"#)
        }
        if canonical.hasPrefix("/control/runtime-updates/"), canonical.hasSuffix("/plan") {
            let target = String(canonical.split(separator: "/").dropLast().last ?? "")
            let host = target == "system" || target == "reboot"
            let rebootAfter = body?["rebootAfter"].boolValue == true
            let confirmation = target == "reboot" ? "REBOOT" : rebootAfter ? "UPDATE_AND_REBOOT" : "UPDATE"
            let kind = target == "reboot" ? "host-reboot" : host ? "host-upgrade" : target == "all" ? "batch" : "runtime"
            return .object([
                "planId": .string("fixture-plan"), "revision": body?["revision"] ?? .string(revision),
                "expiresAt": .string(ISO8601DateFormatter().string(from: .now.addingTimeInterval(240))),
                "kind": .string(kind), "rebootAfter": .bool(rebootAfter), "confirmationRequired": .string(confirmation),
                "packages": .array([parse(#"{"name":"openssl","currentVersion":"3.0.1","targetVersion":"3.0.2"}"#)]),
                "autoremoveCount": .number(1), "componentId": .string(target), "targetVersion": .string("8.5.13"),
                "targetDigest": .string("sha256:fixture"), "components": .array([parse(#"{"id":"php","label":"PHP","targetVersion":"8.5.13"}"#)])
            ])
        }
        if canonical.hasPrefix("/control/runtime-updates/"), canonical.hasSuffix("/apply") || canonical.hasSuffix("/check") {
            let id = UUID().uuidString
            jobs[id] = .object(["id": .string(id), "status": .string("succeeded"), "stage": .string("Verifica completata"), "completedSteps": .number(3), "totalSteps": .number(3), "recoveryRequired": .bool(false), "serviceResults": .array([])])
            return .object(["operationId": .string(id), "status": .string("queued")])
        }
        if canonical.contains("/runtime-updates/operations/") { return jobs[String(canonical.split(separator: "/").last ?? "")] ?? .null }
        if canonical == "/control/server-events" { return parse(#"{"schema":"server-events/v1","available":true,"partial":false,"issues":[],"events":[{"id":"test-event","severity":"warning","service":"Servizio di prova","message":"Questo è un evento sintetico dell’ambiente di prova.","source":"systemd","code":"fixture","count":1,"firstSeen":"2026-11-10T10:00:00Z","lastSeen":"2026-11-10T10:00:00Z"}],"sources":[{"id":"host","available":true},{"id":"systemd","available":true},{"id":"docker","available":true},{"id":"updates","available":true},{"id":"journal","available":true}]}"#) }
        if canonical == "/control/backups/control" { return parse(#"{"control":{"available":true,"enabled":false,"revision":"fixture-backup"},"controlQueueActive":true,"request":null}"#) }
        if canonical == "/control/backups/vps" { return parse(#"{"catalog":{"enabled":false,"manifests":[]}}"#) }
        if canonical == "/logout" { return .object(["ok": .bool(true)]) }
        if method == "GET", canonical.hasPrefix("/control/") { return .object(["available": .bool(true), "environment": .string("Test isolato")]) }
        throw APIError(status: 404, message: "Operazione non prevista dall’ambiente di prova.")
    }

    private func parse(_ text: String) -> JSONValue { (try? JSONDecoder().decode(JSONValue.self, from: Data(text.utf8))) ?? .null }
}
#endif
