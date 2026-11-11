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
            let title = label == "App" ? "Applicazioni" : label
            XCTAssertTrue(app.navigationBars[title].waitForExistence(timeout: 5))
            let settings = app.buttons["global.settings"]
            let alerts = app.buttons["global.alerts"]
            XCTAssertTrue(settings.waitForExistence(timeout: 5))
            XCTAssertTrue(alerts.waitForExistence(timeout: 5))
            XCTAssertLessThan(settings.frame.midX, alerts.frame.midX)
            XCTAssertLessThan(abs(settings.frame.midY - alerts.frame.midY), 30)
            if label == "Home" {
                XCTAssertTrue(app.staticTexts["Le risorse del tuo server"].exists)
                XCTAssertTrue(app.descendants(matching: .any)["home.chart.cpu"].firstMatch.waitForExistence(timeout: 5))
                XCTAssertFalse(app.staticTexts["Stexor VPS"].exists)
                XCTAssertFalse(app.staticTexts["Operativo"].exists)
                attachScreenshot(app, name: "Home with resource charts")
            }
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
        let application = app.buttons["application.row.project:sample"]
        XCTAssertTrue(application.waitForExistence(timeout: 10))
        XCTAssertFalse(app.buttons["Nuova applicazione"].exists)
        XCTAssertTrue(app.staticTexts["Da organizzare"].exists)
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
        XCTAssertTrue(application.exists)
    }

    func testApplicationDetailShowsHostingResourcesAndScopedDatabases() {
        let app = launchFixtures()
        app.tabBars.buttons["App"].tap()
        let application = app.buttons["application.row.project:sample"]
        XCTAssertTrue(application.waitForExistence(timeout: 10))
        application.tap()
        XCTAssertTrue(app.navigationBars["Applicazione di prova"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.descendants(matching: .any)["application.site"].firstMatch.exists)
        XCTAssertTrue(accessibleText("PHP", in: app).exists)
        XCTAssertTrue(accessibleText("Pubblica", in: app).waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["Crea copia privata"].exists)

        let resources = accessibleText("Spazio dei file", in: app)
        if !resources.isHittable { app.swipeUp() }
        XCTAssertTrue(resources.exists)
        let postgres = app.buttons["application.database.fixture-postgres"]
        if !postgres.isHittable { app.swipeUp() }
        XCTAssertTrue(postgres.waitForExistence(timeout: 5))
        XCTAssertTrue(accessibleText("phpMyAdmin", in: app).exists)
        postgres.tap()
        XCTAssertTrue(app.navigationBars["Archivio di prova"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.descendants(matching: .any)["application.database.admin"].firstMatch.exists)
        XCTAssertFalse(app.buttons["Elimina database"].exists)
    }

    func testSecretMetadataNavigationDoesNotRevealValue() {
        let app = launchFixtures()
        app.tabBars.buttons["Secrets"].tap()
        let entry = app.staticTexts["Credenziale di prova"]
        XCTAssertTrue(entry.waitForExistence(timeout: 10))
        XCTAssertFalse(app.staticTexts["fixture-secret-value"].exists)
        entry.tap()
        XCTAssertTrue(app.navigationBars["Credenziale di prova"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["Mostra con Face ID"].exists)
        XCTAssertTrue(accessibleText("Applicazione di prova", in: app).exists)
        XCTAssertTrue(accessibleText("Aggiornato", in: app).exists)
        XCTAssertFalse(app.staticTexts["Cronologia versioni"].exists)
        XCTAssertFalse(app.staticTexts["fixture-secret-value"].exists)
        XCTAssertEqual(app.secureTextFields.count, 0)
        attachScreenshot(app, name: "Secret metadata with concealed value")
        // Reveal, copy, edit and delete actions are intentionally not invoked.
    }

    func testUpdatesShowVersionsAndReviewRestartAndBatch() {
        let app = launchFixtures()
        app.tabBars.buttons["Aggiornamenti"].tap()
        XCTAssertTrue(app.buttons["updates.system.check"].waitForExistence(timeout: 10))
        let package = app.staticTexts.containing(NSPredicate(format: "label CONTAINS %@", "openssl")).firstMatch
        XCTAssertTrue(package.exists)
        app.buttons["Aggiorna e riavvia"].firstMatch.tap()
        XCTAssertTrue(app.buttons["updates.confirm"].waitForExistence(timeout: 5))
        XCTAssertEqual(app.buttons["updates.confirm"].label, "Aggiorna e riavvia")
        XCTAssertTrue(app.staticTexts["Il server sarà temporaneamente irraggiungibile durante il riavvio."].exists)
        XCTAssertEqual(app.textFields.count, 0)
        app.buttons["Annulla"].tap()

        let updateAll = app.buttons["Aggiorna tutti"]
        if !updateAll.isHittable { app.swipeUp() }
        XCTAssertTrue(updateAll.isHittable)
        updateAll.tap()
        XCTAssertTrue(app.buttons["updates.confirm"].waitForExistence(timeout: 5))
        XCTAssertEqual(app.buttons["updates.confirm"].label, "Aggiorna tutti")
        XCTAssertTrue(accessibleText("8.5.13", in: app).exists)
        XCTAssertTrue(app.staticTexts["I servizi aggiornati si riavvieranno automaticamente."].exists)
        app.buttons["Annulla"].tap()
    }

    private func accessibleText(_ text: String, in app: XCUIApplication) -> XCUIElement {
        app.descendants(matching: .any)
            .matching(NSPredicate(format: "label CONTAINS %@ OR value CONTAINS %@", text, text)).firstMatch
    }

    private func attachScreenshot(_ app: XCUIApplication, name: String) {
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
