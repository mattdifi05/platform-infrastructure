import XCTest

/// Every launch uses the isolated in-process fixture client. These tests never
/// sign in to the live service or confirm a production mutation.
@MainActor
final class PlatformControlUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    private func launchFixtures() -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = ["--ui-testing"]
        app.launch()
        XCTAssertTrue(app.tabBars.buttons["Home"].waitForExistence(timeout: 15))
        return app
    }

    func testFourTabsInOrderAndGlobalToolbarPositions() {
        let app = launchFixtures()
        let labels = ["Home", "App", "Secrets", "Aggiornamenti"]
        XCTAssertEqual(app.tabBars.buttons.count, labels.count)
        var previousX = -CGFloat.infinity
        for label in labels {
            let tab = app.tabBars.buttons[label]
            XCTAssertTrue(tab.exists, "Missing tab: \(label)")
            XCTAssertGreaterThan(tab.frame.midX, previousX, "Unexpected tab order")
            previousX = tab.frame.midX
            tab.tap()
            let settings = app.buttons["global.settings"]
            let alerts = app.buttons["global.alerts"]
            XCTAssertTrue(settings.waitForExistence(timeout: 5))
            XCTAssertTrue(alerts.waitForExistence(timeout: 5))
            XCTAssertLessThan(settings.frame.midX, alerts.frame.midX)
            XCTAssertLessThan(abs(settings.frame.midY - alerts.frame.midY), 30)
        }
        attachScreenshot(app, name: "Four native tabs")
    }

    func testNativeSettingsAndAlertsSheetsFromEveryTab() {
        let app = launchFixtures()
        for label in ["Home", "App", "Secrets", "Aggiornamenti"] {
            app.tabBars.buttons[label].tap()
            app.buttons["global.settings"].tap()
            XCTAssertTrue(app.navigationBars["Impostazioni"].waitForExistence(timeout: 5))
            XCTAssertTrue(app.switches["Backup del server"].exists)
            app.buttons["Fine"].firstMatch.tap()
            XCTAssertTrue(app.buttons["global.alerts"].waitForExistence(timeout: 5))
            app.buttons["global.alerts"].tap()
            XCTAssertTrue(app.navigationBars["Avvisi"].waitForExistence(timeout: 5))
            app.buttons["Fine"].firstMatch.tap()
        }
    }

    func testApplicationFolderReviewCanBeCancelledBeforeMutation() {
        let app = launchFixtures()
        app.tabBars.buttons["App"].tap()
        XCTAssertTrue(app.staticTexts["Applicazione di prova"].waitForExistence(timeout: 10))
        app.buttons["Aggiungi"].tap()
        app.buttons["Nuova cartella"].tap()
        XCTAssertTrue(app.navigationBars["Nuova cartella"].waitForExistence(timeout: 5))
        let name = app.textFields["Nome cartella"]
        XCTAssertTrue(name.exists)
        name.tap()
        name.typeText("Cartella da annullare")
        app.buttons["Rivedi operazione"].tap()
        XCTAssertTrue(app.buttons["Conferma"].waitForExistence(timeout: 5))
        attachScreenshot(app, name: "Folder review before confirmation")
        let reviewedName = app.descendants(matching: .any)["application.review.name"].firstMatch
        XCTAssertTrue(reviewedName.waitForExistence(timeout: 5))
        XCTAssertEqual(reviewedName.value as? String, "Cartella da annullare")
        // Deliberately cancel: no write request is made by this test.
        app.buttons["Annulla"].firstMatch.tap()
        XCTAssertTrue(app.navigationBars["Applicazioni"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.staticTexts["Cartella da annullare"].exists)
        XCTAssertTrue(app.staticTexts["Applicazione di prova"].exists)
    }

    func testSecretMetadataNavigationDoesNotRevealValue() {
        let app = launchFixtures()
        app.tabBars.buttons["Secrets"].tap()
        let entry = app.staticTexts["Credenziale di prova"]
        XCTAssertTrue(entry.waitForExistence(timeout: 10))
        XCTAssertFalse(app.staticTexts["fixture-secret-value"].exists)
        entry.tap()
        XCTAssertTrue(app.navigationBars["Credenziale di prova"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["Mostra con passkey"].exists)
        XCTAssertFalse(app.staticTexts["fixture-secret-value"].exists)
        XCTAssertEqual(app.secureTextFields.count, 0)
        attachScreenshot(app, name: "Secret metadata with concealed value")
        // Reveal, copy, edit and delete actions are intentionally not invoked.
    }

    private func attachScreenshot(_ app: XCUIApplication, name: String) {
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
