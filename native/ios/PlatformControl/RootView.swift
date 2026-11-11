import SwiftUI

private enum ControlTab: String, CaseIterable { case home, applications, secrets, updates }
private enum GlobalSheet: Hashable, Identifiable {
    case settings(ControlTab)
    case alerts(ControlTab)

    var id: Self { self }
}

struct RootView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Namespace private var toolbarTransition
    @State private var tab: ControlTab = .home
    @State private var sheet: GlobalSheet?

    var body: some View {
        Group {
            if model.isConnecting { LoadingState(title: "Connessione al server…") }
            else if model.authenticated { authenticatedContent }
            else { LoginView() }
        }
        .overlay {
            if scenePhase == .background { Rectangle().fill(.regularMaterial).ignoresSafeArea().overlay { Image(systemName: "lock.shield").font(.largeTitle).foregroundStyle(.secondary) } }
        }
        .task { await model.connect() }
        .onChange(of: model.authenticated) { _, authenticated in if !authenticated { sheet = nil; tab = .home } }
        .sheet(item: $sheet) { destination in
            if reduceMotion {
                globalSheet(destination)
            } else {
                globalSheet(destination)
                    .navigationTransition(.zoom(sourceID: destination, in: toolbarTransition))
            }
        }
    }

    private func globalSheet(_ destination: GlobalSheet) -> some View {
        NavigationStack {
            Group {
                switch destination {
                case .settings: SettingsView()
                case .alerts: AlertsView()
                }
            }
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Fine", systemImage: "checkmark") { sheet = nil }
                        .labelStyle(.iconOnly)
                }
            }
        }
    }

    private var authenticatedContent: some View {
        TabView(selection: $tab) {
            Tab("Home", systemImage: "square.grid.2x2", value: .home) {
                tabStack(.home) { HomeView(isActive: tab == .home && scenePhase == .active) }
            }
            Tab("App", systemImage: "square.stack.3d.up", value: .applications) {
                tabStack(.applications) { ApplicationsView() }
            }
            Tab("Secrets", systemImage: "key.horizontal", value: .secrets) {
                tabStack(.secrets) { SecretsView() }
            }
            Tab("Aggiornamenti", systemImage: "arrow.triangle.2.circlepath", value: .updates) {
                tabStack(.updates) { UpdatesView() }
            }
        }
        .task(id: scenePhase) {
            guard scenePhase == .active else { return }
            while !Task.isCancelled {
                if let value = try? await model.get("/control/server-events") { model.unreadWarnings = value["issues"].arrayValue.count }
                try? await Task.sleep(for: .seconds(30))
                if Task.isCancelled { break }
            }
        }
    }

    private func tabStack<Content: View>(_ tab: ControlTab, @ViewBuilder content: () -> Content) -> some View {
        NavigationStack {
            content()
                .navigationBarTitleDisplayMode(.inline)
                .modifier(GlobalToolbar(sheet: $sheet, tab: tab, transition: toolbarTransition, warnings: model.unreadWarnings))
        }
    }

    private struct GlobalToolbar: ViewModifier {
        @Environment(\.accessibilityReduceMotion) private var reduceMotion
        @Binding var sheet: GlobalSheet?
        let tab: ControlTab
        let transition: Namespace.ID
        let warnings: Int

        private var hasWarnings: Bool { warnings > 0 }

        func body(content: Content) -> some View {
            content.toolbar {
                ToolbarItem(id: "global.settings", placement: .topBarLeading) {
                    Button("Impostazioni", systemImage: "gearshape") { sheet = .settings(tab) }
                        .labelStyle(.iconOnly)
                        .accessibilityIdentifier("global.settings")
                }
                .matchedTransitionSource(id: GlobalSheet.settings(tab), in: transition)

                ToolbarItem(id: "global.alerts", placement: .topBarTrailing) {
                    Button { sheet = .alerts(tab) } label: {
                        Image(systemName: hasWarnings ? "bell.badge" : "bell")
                            .symbolRenderingMode(.palette)
                            .foregroundStyle(hasWarnings ? Color.orange : Color.primary, Color.primary)
                            .contentTransition(reduceMotion ? .identity : .symbolEffect(.replace))
                            .animation(reduceMotion ? nil : .default, value: hasWarnings)
                    }
                    .accessibilityLabel(hasWarnings ? "Avvisi, \(warnings) attivi" : "Avvisi")
                    .accessibilityIdentifier("global.alerts")
                }
                .matchedTransitionSource(id: GlobalSheet.alerts(tab), in: transition)
            }
        }
    }
}

private struct LoginView: View {
    @Environment(AppModel.self) private var model
    @State private var bootstrapToken = ""
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 28) {
                    Image(systemName: "server.rack").font(.system(size: 58, weight: .light)).foregroundStyle(.indigo).padding(30).background(.indigo.opacity(0.07), in: RoundedRectangle(cornerRadius: 30))
                    VStack(spacing: 10) {
                        Text("Il tuo server.\nSempre con te.").font(.largeTitle.bold()).multilineTextAlignment(.center)
                        Text("Accedi a Platform con la tua passkey.").foregroundStyle(.secondary).multilineTextAlignment(.center)
                    }
                    if let error = model.connectionError { ErrorNotice(message: error) { Task { await model.connect() } } }
                    if model.enrollmentRequired {
                        SecureField("Codice di configurazione iniziale", text: $bootstrapToken).textInputAutocapitalization(.never).autocorrectionDisabled().textFieldStyle(.roundedBorder)
                        Button {
                            Task { await model.enroll(bootstrapToken: bootstrapToken); bootstrapToken = "" }
                        } label: {
                            passkeyLabel("Configura passkey")
                        }
                        .buttonStyle(.glassProminent).disabled(model.isAuthenticating || bootstrapToken.isEmpty)
                    } else {
                        Button { Task { await model.login() } } label: {
                            passkeyLabel("Accedi con passkey")
                        }
                        .buttonStyle(.glassProminent).disabled(model.isAuthenticating).accessibilityIdentifier("login.passkey")
                    }
                    Label("portal.stexor.com", systemImage: "lock.shield").font(.footnote).foregroundStyle(.secondary)
                }.padding(28).padding(.top, 70)
            }.navigationTitle("Platform").navigationBarTitleDisplayMode(.inline)
                .onDisappear { bootstrapToken = "" }
        }
    }

    private func passkeyLabel(_ title: String) -> some View {
        ZStack {
            Label(title, systemImage: "person.badge.key")
                .opacity(model.isAuthenticating ? 0 : 1)
                .accessibilityHidden(model.isAuthenticating)
            if model.isAuthenticating {
                LoadingState(title: "Autenticazione in corso…", style: .inline)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
    }

}
