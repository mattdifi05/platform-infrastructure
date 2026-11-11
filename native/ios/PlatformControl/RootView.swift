import SwiftUI
import Observation

private enum ControlTab: String, CaseIterable {
    case home, applications, secrets, updates

    var title: String {
        switch self {
        case .home: "Home"
        case .applications: "Applicazioni"
        case .secrets: "Secrets"
        case .updates: "Aggiornamenti"
        }
    }
}
private enum GlobalSheet: Hashable, Identifiable {
    case settings
    case alerts

    var id: Self { self }
}

struct RootView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Namespace private var toolbarTransition
    @State private var tab: ControlTab = .home
    @State private var sheet: GlobalSheet?
    @State private var pageToolbar = NativePageToolbar()

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
        .onChange(of: model.authenticated) { _, authenticated in if !authenticated { sheet = nil; tab = .home; pageToolbar.reset() } }
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
        NavigationStack {
            TabView(selection: $tab) {
                Tab("Home", systemImage: "square.grid.2x2", value: .home) {
                    HomeView(isActive: tab == .home && scenePhase == .active)
                }
                Tab("App", systemImage: "square.stack.3d.up", value: .applications) {
                    ApplicationsView()
                }
                Tab("Secrets", systemImage: "key.horizontal", value: .secrets) {
                    SecretsView()
                }
                Tab("Aggiornamenti", systemImage: "arrow.triangle.2.circlepath", value: .updates) {
                    UpdatesView()
                }
            }
            .navigationTitle(tab.title)
            .navigationSubtitle(tab == .home ? "Le risorse del tuo server" : "")
            .navigationBarTitleDisplayMode(.inline)
            .animation(reduceMotion ? nil : .default, value: tab)
            .modifier(GlobalToolbar(sheet: $sheet, tab: tab, transition: toolbarTransition, warnings: model.unreadWarnings))
        }
        .environment(pageToolbar)
        .environment(\.toolbarPresentationNamespace, toolbarTransition)
        .task(id: scenePhase) {
            guard scenePhase == .active else { return }
            await model.preparePages()
            while !Task.isCancelled {
                if let value = try? await model.readPage("/control/server-events", maxAge: .seconds(8)) { model.unreadWarnings = value["issues"].arrayValue.count }
                try? await Task.sleep(for: .seconds(30))
                if Task.isCancelled { break }
            }
        }
    }

    private struct GlobalToolbar: ViewModifier {
        @Environment(\.accessibilityReduceMotion) private var reduceMotion
        @Environment(NativePageToolbar.self) private var pageToolbar
        @Binding var sheet: GlobalSheet?
        let tab: ControlTab
        let transition: Namespace.ID
        let warnings: Int

        private var hasWarnings: Bool { warnings > 0 }
        private var hasCreationAction: Bool { tab == .applications || tab == .secrets }
        private var createTitle: String { tab == .applications ? "Nuova cartella" : "Nuovo secret" }
        private var createSymbol: String { tab == .applications ? "folder.badge.plus" : "plus" }
        private var createID: NativeToolbarAction { tab == .applications ? .createApplicationFolder : .createSecret }
        private var createAction: (@MainActor () -> Void)? {
            tab == .applications ? pageToolbar.folderAction : pageToolbar.secretAction
        }

        func body(content: Content) -> some View {
            content.toolbar {
                ToolbarItem(id: "global.settings", placement: .topBarLeading) {
                    Button("Impostazioni", systemImage: "gearshape") { sheet = .settings }
                        .labelStyle(.iconOnly)
                        .accessibilityIdentifier("global.settings")
                }
                .matchedTransitionSource(id: GlobalSheet.settings, in: transition)

                ToolbarItem(id: "global.actions", placement: .primaryAction) {
                    GlassEffectContainer(spacing: 12) {
                        HStack(spacing: 16) {
                            Button { sheet = .alerts } label: {
                                Image(systemName: hasWarnings ? "bell.badge" : "bell")
                                    .symbolRenderingMode(.palette)
                                    .foregroundStyle(hasWarnings ? Color.orange : Color.primary, Color.primary)
                                    .contentTransition(reduceMotion ? .identity : .symbolEffect(.replace))
                                    .animation(reduceMotion ? nil : .default, value: hasWarnings)
                                    .frame(width: 44, height: 44)
                                    .contentShape(.circle)
                            }
                            .buttonStyle(.plain)
                            .frame(width: 44, height: 44)
                            .contentShape(.circle)
                            .glassEffect(.regular.interactive(), in: .circle)
                            .glassEffectID("global.alerts", in: transition)
                            .glassEffectTransition(reduceMotion ? .identity : .matchedGeometry)
                            .matchedTransitionSource(id: GlobalSheet.alerts, in: transition)
                            .accessibilityElement(children: .ignore)
                            .accessibilityAddTraits(.isButton)
                            .accessibilityLabel(hasWarnings ? "Avvisi, \(warnings) attivi" : "Avvisi")
                            .accessibilityIdentifier("global.alerts")
                            .accessibilityAction { sheet = .alerts }

                            if hasCreationAction {
                                Button { createAction?() } label: {
                                    Image(systemName: createSymbol)
                                        .contentTransition(reduceMotion ? .identity : .symbolEffect(.replace))
                                        .animation(reduceMotion ? nil : .default, value: tab)
                                        .frame(width: 44, height: 44)
                                        .contentShape(.circle)
                                }
                                .buttonStyle(.plain)
                                .frame(width: 44, height: 44)
                                .contentShape(.circle)
                                .glassEffect(.regular.interactive(), in: .circle)
                                .glassEffectID("page.create", in: transition)
                                .glassEffectTransition(reduceMotion ? .identity : .matchedGeometry)
                                .matchedTransitionSource(id: createID, in: transition)
                                .accessibilityElement(children: .ignore)
                                .accessibilityAddTraits(.isButton)
                                .accessibilityLabel(createTitle)
                                .accessibilityIdentifier("page.create")
                                .accessibilityAction { createAction?() }
                                .disabled(createAction == nil)
                            }
                        }
                        .font(.body.weight(.semibold))
                        .accessibilityElement(children: .contain)
                    }
                    .fixedSize()
                    .animation(reduceMotion ? nil : .smooth(duration: 0.4), value: hasCreationAction)
                    .animation(reduceMotion ? nil : .smooth(duration: 0.4), value: createAction != nil)
                }
                .sharedBackgroundVisibility(.hidden)
            }
        }
    }
}

@MainActor @Observable
final class NativePageToolbar {
    var folderAction: (@MainActor () -> Void)?
    var secretAction: (@MainActor () -> Void)?

    func reset() {
        folderAction = nil
        secretAction = nil
    }
}

enum NativeToolbarAction: Hashable {
    case createApplicationFolder
    case createSecret
}

extension EnvironmentValues {
    @Entry var toolbarPresentationNamespace: Namespace.ID? = nil
}

extension View {
    func nativeToolbarPresentation(_ action: NativeToolbarAction?) -> some View {
        modifier(NativeToolbarPresentation(action: action))
    }
}

private struct NativeToolbarPresentation: ViewModifier {
    @Environment(\.toolbarPresentationNamespace) private var namespace
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let action: NativeToolbarAction?

    @ViewBuilder
    func body(content: Content) -> some View {
        if let namespace, let action, !reduceMotion {
            content.navigationTransition(.zoom(sourceID: action, in: namespace))
        } else {
            content
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
        Label(title, systemImage: "person.badge.key")
        .contentSkeleton(model.isAuthenticating, title: "Autenticazione in corso…")
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
    }

}
