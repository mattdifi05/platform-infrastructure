import SwiftUI

@main
struct PlatformControlApp: App {
    @State private var model: AppModel
    @AppStorage("appearance") private var appearance = "system"

    init() {
        #if DEBUG
        _model = State(initialValue: AppModel(testEnvironment: ProcessInfo.processInfo.arguments.contains("--ui-testing")))
        #else
        _model = State(initialValue: AppModel())
        #endif
    }

    var body: some Scene {
        WindowGroup {
            RootView().environment(model).tint(.indigo)
                .preferredColorScheme(appearance == "light" ? .light : appearance == "dark" ? .dark : nil)
        }
    }
}
