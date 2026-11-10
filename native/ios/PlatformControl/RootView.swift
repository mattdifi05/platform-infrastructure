import SwiftUI

private enum ControlTab: String, CaseIterable { case home, applications, secrets, updates }
private enum GlobalSheet: String, Identifiable { case settings, alerts; var id: String { rawValue } }

struct RootView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase
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
            NavigationStack {
                Group {
                    switch destination {
                    case .settings: SettingsView()
                    case .alerts: AlertsView()
                    }
                }
                .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Fine", systemImage: "checkmark") { sheet = nil }.labelStyle(.iconOnly) } }
            }
        }
    }

    private var authenticatedContent: some View {
        TabView(selection: $tab) {
            Tab("Home", systemImage: "square.grid.2x2", value: .home) {
                NavigationStack { HomeView(isActive: tab == .home && scenePhase == .active).modifier(GlobalToolbar(sheet: $sheet, warnings: model.unreadWarnings)) }
            }
            Tab("App", systemImage: "square.stack.3d.up", value: .applications) {
                NavigationStack { ApplicationsView().modifier(GlobalToolbar(sheet: $sheet, warnings: model.unreadWarnings)) }
            }
            Tab("Secrets", systemImage: "key.horizontal", value: .secrets) {
                NavigationStack { SecretsView().modifier(GlobalToolbar(sheet: $sheet, warnings: model.unreadWarnings)) }
            }
            Tab("Aggiornamenti", systemImage: "arrow.triangle.2.circlepath", value: .updates) {
                NavigationStack { UpdatesView().modifier(GlobalToolbar(sheet: $sheet, warnings: model.unreadWarnings)) }
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

    private struct GlobalToolbar: ViewModifier {
        @Binding var sheet: GlobalSheet?
        let warnings: Int
        func body(content: Content) -> some View {
            content.toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Impostazioni", systemImage: "gearshape") { sheet = .settings }.labelStyle(.iconOnly).accessibilityIdentifier("global.settings")
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button { sheet = .alerts } label: {
                        Image(systemName: warnings > 0 ? "bell.badge" : "bell")
                            .symbolRenderingMode(.palette).foregroundStyle(warnings > 0 ? Color.orange : Color.primary, Color.primary)
                    }.accessibilityLabel(warnings > 0 ? "Avvisi, \(warnings) attivi" : "Avvisi").accessibilityIdentifier("global.alerts")
                }
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
                        Button("Configura passkey", systemImage: "person.badge.key") { Task { await model.enroll(bootstrapToken: bootstrapToken); bootstrapToken = "" } }
                            .buttonStyle(.glassProminent).disabled(model.isAuthenticating || bootstrapToken.isEmpty)
                    } else {
                    Button { Task { await model.login() } } label: {
                        HStack { if model.isAuthenticating { ProgressView().tint(.white) }; Label("Accedi con passkey", systemImage: "person.badge.key") }.frame(maxWidth: .infinity).padding(.vertical, 8)
                    }.buttonStyle(.glassProminent).disabled(model.isAuthenticating).accessibilityIdentifier("login.passkey")
                    }
                    Label("portal.stexor.com", systemImage: "lock.shield").font(.footnote).foregroundStyle(.secondary)
                }.padding(28).padding(.top, 70)
            }.navigationTitle("Platform").navigationBarTitleDisplayMode(.inline)
                .onDisappear { bootstrapToken = "" }
        }
    }
}
