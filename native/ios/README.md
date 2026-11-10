# Platform for iOS

Native SwiftUI app for iPhone and iPad, iOS 26 and later. Open
`PlatformControl.xcodeproj`, select the shared `PlatformControl` scheme, and
choose the physical iPhone in Xcode. It uses the native tab bar and navigation
toolbars. The tabs are Home, App, Secrets and Aggiornamenti. Settings opens from
the upper left; server warnings open from the upper right.

The app sends HTTPS JSON requests directly to the Control Center service. It
does not load any dashboard page or embed a browser. Keep the JSON API and
WebAuthn endpoints when retiring the web dashboard. The application file manager
is intentionally absent. Existing external database administration tools may
still open separately in Safari; they do not provide the app's login or its
native database management.

| Area | Native functionality |
| --- | --- |
| Home | Live host CPU, RAM, disk, swap, network and I/O, plus status and audit details |
| App | App and folder management, visibility, private clones, deployment plans, database lifecycle and Redis |
| Secrets | Vault metadata, import, create, version, delete, temporary reveal, app delivery and rollback |
| Aggiornamenti | OS checks, update with autoremove, reboot plans, runtime checks, individual/batch plans and progress |
| Impostazioni | Session, display preferences, backup state, capture and reviewed restore |
| Avvisi | Active warnings, recent events and collection source health |

## Signing and service association

The project uses bundle ID `com.stexor.controlcenter`, the configured Apple
development team, and `webcredentials:portal.stexor.com`. The `application-identifier`
in the signed product must appear in the exact host's HTTPS association file.
Set `CONTROL_CENTER_APPLE_ASSOCIATED_APP_IDS` to that explicit identifier; use
`compose.native-ios.yaml` as an optional overlay or retain the environment in
the deployment's existing Control Center overlay. See
[the native API contract](../../control-center/NATIVE-API.md) for the endpoint,
cookie, CSRF and passkey requirements.

Existing owners sign in with a passkey available on their device. Initial
enrollment uses the server's existing first-configuration authorization and
short-lived code. Sensitive operations retain the server's reviewed plan,
explicit confirmation and fresh authentication requirements. Session cookies
are stored in this device's Keychain; revealed secret values are kept in memory
and cleared on expiry, dismissal or backgrounding.

## Verification

Use the shared scheme's tests on a connected iPhone, or on a supported simulator.
The UI tests explicitly launch a Debug-only fixture client with `--ui-testing`;
that client never sends mutations to the real server. A release build omits the
fixture implementation. Test navigation separately from an actual passkey login
and production API readback. A successful build or simulated authentication
does not qualify real-device passkey association.
