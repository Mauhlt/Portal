# Native iPhone app (branch feat/ios-native)

**Owner decisions (2026-11-12):**
* Assume the toolchain exists: the iOS SDK (Xcode) and the ability to sign and
  install on the owner's iPhone, so Vulkan runs on the iPhone through
  MoltenVK.
* **One code path, branching per device only where a device really differs.**
  One renderer (Vulkan, the owner's Renderer), one UI, one network client.
  The iPhone section adds only what iOS needs: MoltenVK, a UIKit window
  backend, the app bundle and signing.
* The Safari/wasm browser app and the Renderer CPU backend are dropped
  (the browser client is removed).

## Structure: shared core, thin device sections

```
Portal UI (shared, every device)      top bar + tabs, conversation/terminal,
                                      data, interaction bar, theme, panels
        │ draw list (quads, glyphs, images)
Renderer (owner's repo)
  Instanced2D (Vulkan)                one renderer everywhere
  Font                                one font stack
  Window  ── win32 (../Windows) │ wayland (../Wayland) │ macos (../MacOS) │ ios (UIKit)
        │ Vulkan
  Vulkan loader ── Windows/Linux: system loader │ macOS + iOS: MoltenVK
Network client (shared)               TLS pinning, pairing, rotating credential,
                                      WebSocket, sync (client/src)
Per-device glue (small)               desk: ConPTY + server │ laptop/macOS/Linux:
                                      `portal connect` │ iPhone: app entry, Keychain,
                                      passkey (AuthenticationServices)
```

Rules:
* A feature is written once in the shared layer. A device section contains
  only OS bindings and lifecycle glue, never UI or protocol logic.
* Per-device choices are a `switch (builtin.os.tag)` at one seam (Window
  backend, Vulkan loader, credential store), not scattered `if`s.
* The iPhone section never forks shared code; if iOS needs something
  different from shared code, the shared code gets a parameter.

## iPhone section

1. **Build:** Zig cross-compiles `aarch64-ios` against the iOS SDK
   (`--sysroot` to the SDK; frameworks UIKit, QuartzCore, Metal, Foundation,
   Security, AuthenticationServices). No Swift. `zig build ios` produces the
   `.app` bundle (Info.plist, entry, launch screen, icon) with MoltenVK
   embedded as Apple requires (`Frameworks/`), plus a signing step that takes
   the owner's identity/profile from the environment. A CI workflow builds the
   same on a hosted macOS runner.
2. **Vulkan on iOS:** the Renderer's Vulkan loader opens the embedded MoltenVK
   (`libMoltenVK.dylib` / framework) instead of a system loader; the surface is
   `VK_EXT_metal_surface` from a CAMetalLayer (`SurfaceSource.metal`, shared
   with macOS). MoltenVK portability: enable
   `VK_KHR_portability_enumeration` / `_subset` where required.
3. **Window backend `ios` in the Renderer's Window module** (UIKit via the
   Objective-C runtime, same style as the macOS backend on ../MacOS):
   UIApplicationMain + app/scene delegate classes registered at runtime,
   UIWindow + a UIView whose layer is CAMetalLayer, touches → pointer/tap
   events (and scroll by pan), safe-area insets, keyboard show/hide with the
   inset it takes, content scale, background/foreground events (stop drawing
   in background), wake from other threads via a main-queue dispatch.
   Event-driven only. Same interface as every other backend (checkInterface).
4. **Text input + dictation:** a real UITextView placed over the
   interaction bar's input slot, so Apple dictation and the keyboard work; its
   text flows into the shared input logic. Must be verified on the phone.
5. **Credentials:** the device credential and CA pin in the iOS Keychain
   (shared credstore interface, iOS implementation). Passkey / Face ID via
   AuthenticationServices on sign-in.
6. **Tunnel:** the app's own per-app tunnel (owner addition below), a
   packet tunnel extension in Zig running the owner's Zig WireGuard;
   without the paid-account entitlement, the WireGuard app + Shortcuts
   automations (pairing page shows them) as before.

## What is shared vs per device (target)

| Concern | Shared | Desk (Windows) | Laptop (Win/Linux/macOS) | iPhone |
|---|---|---|---|---|
| UI + theme | ✓ | – | – | – |
| Drawing | Renderer Instanced2D (Vulkan) | system loader | system loader / MoltenVK on macOS | MoltenVK |
| Window | Renderer Window interface | win32 | win32 / wayland / macos | ios |
| Network client | ✓ | (server instead) | ✓ | ✓ |
| Credentials | interface | DPAPI | Credential Manager / libsecret / Keychain | Keychain |
| Session | – | ConPTY + server | – | – |

## Owner additions (2026-11-12): all on by default, nothing to configure

| # | Decision | Where | State |
|---|---|---|---|
| 1 | No CA profile: the app pins the Portal CA itself | shared `connect.zig` / `net/pin.zig` (same as `portal connect`) | done |
| 2 | Credential in the Keychain: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` + `SecAccessControl` `.biometryCurrentSet` (Face ID on every read, never iCloud/backup); replaces the web passkey | `client/src/credstore.zig` (`.ios` branch of the Apple store) | done, unverified on device |
| 3 | Third-party keyboards refused | Renderer `Window/ios.zig` (`application:shouldAllowExtensionPointIdentifier:` on the runtime app delegate), `AppOptions.block_keyboard_extensions` | done |
| 4 | Lock on leave: cover before the app-switcher snapshot, cover while `UIScreen.isCaptured`, drop the connection in the background, Face ID before showing anything on return | Renderer `Window/ios.zig` (cover, lock, `.background`), shared `Presenter.isSuspended` -> `Client.setPaused`, `client/src/ios/device.zig` (LocalAuthentication) | done |
| 5 | QR pairing: desk shows address + CA SHA-256, the phone scans, pins, requests pairing, the owner approves the code at the desk | `shared/pairqr.zig` (text format), `ui/qr.zig` (Zig QR encoder, `portal_ui.qr`), `ui/panels/desk.zig` (Pair panel), `ui/frame.zig` `Panel.qr`, `ui/panels/setup.zig` (Scan QR code), `client/src/ios/scan.zig` (AVFoundation) | done |
| 6 | Per-app tunnel on the owner's own Zig WireGuard (../WireGuard) | `client/src/ios/tunnel_ext` (extension), `client/src/ios/tunnel.zig` (app side), `client/src/ios/wgkey.zig` | extension + app side done; key delivery to the desk not yet |

### 4. Lock on leave, in detail

* Launch: the window starts locked (`ios.lock()`); the app thread waits
  for Face ID (`device.waitUnlocked`) before the viewer opens, so nothing
  is shown or fetched first. The evaluated `LAContext` is handed to the
  Keychain read (`kSecUseAuthenticationContext`): one Face ID, not two.
* Resign active (app switcher, Control Center, a call): opaque cover
  (`cover_when_inactive`), set synchronously on the main thread, so the
  snapshot shows the cover.
* Screen recorded / mirrored: cover while `UIScreen.isCaptured`
  (`UIScreenCapturedDidChangeNotification`).
* Background: `.background` reaches the shared loop, which stops drawing
  (`Presenter.suspended`) and calls `Client.setPaused(true)`: the stream is
  aborted through its watchdog and the network thread sleeps on an event.
  The Keychain authentication context is dropped and the lock set.
* Return: `.foreground`; the cover stays until Face ID succeeds (the
  window calls the unlock handler once per activation while locked, so a
  cancelled Face ID sheet does not loop, and on every tap on the cover);
  only then does the app thread resume, unpause the client and redraw.
  The launch lock is `AppOptions.start_locked`, set before UIKit starts,
  so the first activation asks too.
* Face ID unavailable (off for Portal, not enrolled, no passcode): the
  app stays locked and the cover says how to turn it on
  (`device.lockMessage`). The credential stays bound to Face ID
  (biometryCurrentSet); the passcode is used only to end a Face ID
  lockout.
* Errors that end the app, std.log and panics go to the system log
  (syslog; Console.app, process "Portal"): client/src/ios/main.zig.

### 5. QR pairing

* Text (shared/pairqr.zig): `portal-pair 2 <IP:PORT> <CA SHA-256 hex>
  <endpoint> <desk key> <device address>`. Public values only: the QR
  grants nothing by itself (the desk lets in only the device key the
  owner approved there), and the CA the server sends is only trusted if
  its SHA-256 matches.
* Desk: "Pair a device" shows the QR under the instructions when Portal
  serves TLS (`ui/panels/desk.zig` `Bufs.pairQr`). Encoder: ui/qr.zig (byte mode,
  level M, versions 1-10, mask by penalty; checked module-for-module
  against a reference encoder for every block layout it uses).
* Phone: the first-run screen offers **Scan QR code**; a scan fills address
  and fingerprint and pairs at once (ui/panels/setup.zig `fromQr`, connect.zig
  `Platform.take_scanned`). Camera permission: NSCameraUsageDescription;
  checked before the camera opens, and a denied or restricted camera
  becomes the setup screen's note (`Platform.take_scan_note`).

### 6. Per-app tunnel (owner's Zig WireGuard)

* **Extension** `PortalTunnel.appex` (client/src/ios/tunnel_ext, Zig, no
  Swift): `PortalPacketTunnelProvider` (an NEPacketTunnelProvider
  subclass registered at runtime, then `NSExtensionMain`). `startTunnel`
  reads `providerConfiguration["wgQuickConfig"]`, parses it with
  WireGuard's config parser, applies NEPacketTunnelNetworkSettings
  (IPv4 addresses, the peers' AllowedIPs as routes, MTU, the desk as
  remote address), starts `WireGuard.device.Device` on
  `tun.PacketFlowTun` (its own event loop thread), and re-arms
  `packetFlow.readPackets` from each completion (no polling).
* **One seam:** `TunnelBackend` (tunnel_ext/backend.zig: configure /
  start / deliver / stop). Only `ZigBackend` is compiled in. If the
  security review or live interop of ../WireGuard fails, a fallback
  backend (e.g. wireguard-go via WireGuardKit's C entry points
  `wgTurnOn` / `wgTurnOff`) goes in a sibling `backend_<name>.zig`
  implementing the same four calls, selected by a build option; the
  provider code and the app stay unchanged. Nothing of wireguard-go or
  WireGuardKit is in the repository, and there is no longer a Go
  exception to the all-Zig rule.
* **App side** (client/src/ios/tunnel.zig): `start()` when Portal comes
  on screen, `stop()` when it goes to the background
  (NETunnelProviderManager, from the lifecycle hooks). Background, not
  every resign-active: a pulled-down Control Center would otherwise drop
  and re-handshake the tunnel each time.
* **Build:** `-Dios-tunnel=true` builds the extension into
  `Portal.app/PlugIns` and signs it with
  `com.apple.developer.networking.networkextension = packet-tunnel-provider`.
  Needs a **paid Apple Developer account** (the Network Extension
  entitlement; App IDs for the app and `<bundle id>.tunnel`, both with the
  Network Extensions capability, and profiles for both). With a free
  Apple ID build without it: the app works unchanged over the WireGuard
  app.
* **Keys:** the phone generates its X25519 pair (wgkey.zig); the private
  key never leaves it.
* **Not done yet (design):**
  1. *Key delivery.* First pairing happens over an already trusted path
     (the home LAN, or the WireGuard app's tunnel): the TLS-pinned,
     desk-approved pairing request carries the phone's WireGuard public key
     (new optional field in `POST /pair`; docs/protocol.md to be extended).
  2. *Desk confirm step.* Portal must not edit the desktop's WireGuard
     configuration silently: after approving the device, the desk shows
     "Add this iPhone as a WireGuard peer?" with the public key, the
     tunnel address it would get and the exact `[Peer]` block; on
     **Add**, Portal appends it (or, if the WireGuard service is not
     Portal's to edit, shows the block to paste). Then the desk answers
     the phone with its own public key, endpoint and the phone's tunnel
     address.
  3. The phone writes the wg-quick text (`wgkey.wgQuick`) and calls
     `tunnel.configure`; iOS asks once to allow the VPN configuration.
     From then on the app switches to its own tunnel (the WireGuard app's
     on-demand rule for Portal's address can be removed).
  4. The private key belongs in the Keychain in an access group shared
     with the extension (`keychain-access-groups`, no Face ID: the
     extension runs while the phone is locked) instead of the provider
     configuration; the extension then reads it by reference.
  5. IPv6 tunnel addresses (NEIPv6Settings).

## Implementation: seams

* **Window** (Renderer `src/Window`, branch `ios-window`): `ios.zig` is the
  UIKit backend behind the same interface as win32/wayland/cocoa. The
  interface grew only what a touch device needs, implemented everywhere
  (no-ops on desktops): `insets()`, the native text field
  (`showTextInput` / `hideTextInput` / `textInputText` /
  `setTextInputText`), events `.insets`, `.background`, `.foreground`,
  `.text_input`. See the Renderer's CHANGES-ios.md.
* **Inverted control:** `Window.runApp(options, entry, ctx)`. Desktops call
  `entry` directly; on iOS it enters UIApplicationMain and runs `entry` on
  an app thread once the scene's window exists. The app's loop
  (`connect.main`: `pollEvents`, draw, `waitEvents`) is unchanged; UIKit
  callbacks feed the same event queue and wake a condition variable;
  UIKit calls go to the main queue. No callback-style fork of app logic.
* **Vulkan loader** (Vulkan, branch `moltenvk`): iOS opens
  `@executable_path/Frameworks/libMoltenVK.dylib` (or
  `MoltenVK.framework/MoltenVK`); macOS prefers the Khronos loader, then
  MoltenVK. Instanced2D already enables portability enumeration/subset and
  VK_EXT_metal_surface.
* **Credential store:** `credstore.zig`'s `impl` switch; iOS shares the
  Apple Keychain code with macOS, with the Face ID access control.
* **Device hooks:** `connect.Platform` (sync on/off, suspend/resume,
  QR scan). The iPhone section (`client/src/ios`) fills them; everything
  they drive is shared.
* **Shared UI** (module `portal_ui`, ui/): layout inside `Frame.insets`,
  the focused field as `Frame.text_slot` (`frame.textEdit` turns the
  native field's edits into Backspace/characters, Return = Enter),
  `Panel.qr`, grid rows scrolled back with `Frame.scrollRows`. The
  Presenter (client/src/view/Presenter.zig) binds them to the Window:
  `insets()` before each build, show/hide/set the native text field after
  each present, `.background`/`.foreground` -> no drawing (`isSuspended`,
  which connect.zig turns into `Client.setPaused`), `.scroll` (a drag on
  the phone) -> `scrollRows`.

## Zig on iOS: the stock lib dir

Zig 0.18.0-dev.4's `std.Io.Threaded` did not compile for iOS
(`getDevNullFd` read `null_file.fd`, which the iOS `NullFile` lacked; it
is reached from process spawning and from the default panic handler), so
the iOS builds once compiled against a patched copy of the Zig lib dir.
Zig 0.18.0-dev.1005 has the fix upstream (only wasi, tvOS and watchOS keep
the fd-less `NullFile`), so `zig build ios` / `ios-check` now use the
stock Zig lib dir, and the app and the extension keep std's default panic
handler.

## Build, sign, install (owner's Mac)

Prerequisites: Xcode (iOS SDK), the Zig build in build.zig.zon, the
sibling checkouts Portal builds against (../Renderer, ../Vulkan,
../Image, ../MacOS, ../Windows, ../Wayland, ../WireGuard), with the
Renderer's iOS Window backend (branch `ios-window`) and the Vulkan
package's MoltenVK loader (branch `moltenvk`, generated by TranslateVulkan
`moltenvk`) merged into those checkouts.

1. **MoltenVK for iOS** (not committed): either the LunarG Vulkan SDK for
   macOS (`<SDK>/MoltenVK/dynamic/dylib/iOS/libMoltenVK.dylib`, or the
   xcframework's `ios-arm64/MoltenVK.framework`), or
   `curl -LO https://github.com/KhronosGroup/MoltenVK/releases/download/v1.4.2/MoltenVK-ios.tar && tar xf MoltenVK-ios.tar`
   (`MoltenVK/MoltenVK/dynamic/MoltenVK.xcframework/ios-arm64/MoltenVK.framework`).
2. **Build:**
   `zig build ios -Doptimize=ReleaseSafe -Dios-bundle-id=<your.bundle.id> -Dmoltenvk=<path>`
   (add `-Dios-tunnel=true` with a paid account) -> `zig-out/ios/Portal.app`.
   The SDK path comes from `xcrun --sdk iphoneos --show-sdk-path`
   (override: `-Dios-sdk=` / `IOS_SDK`).
3. **Signing identity and profile:** in Xcode, Settings > Accounts, add
   the Apple ID; create a development certificate. Make a provisioning
   profile for the bundle id with the iPhone registered (paid account:
   developer.apple.com > Profiles; free Apple ID: create any Xcode iOS
   app with the same bundle id once and run it on the phone, then use
   `~/Library/Developer/Xcode/UserData/Provisioning Profiles/*.mobileprovision`).
   With the tunnel (`-Dios-tunnel=true`): two explicit App IDs, both with
   the Network Extensions capability, `<your.bundle.id>` and
   `<your.bundle.id>.tunnel`, and an iOS App Development profile for each.
4. **Sign:**
   ```
   export PORTAL_SIGN_IDENTITY="Apple Development: Your Name (XXXXXXXXXX)"   # security find-identity -v -p codesigning
   export PORTAL_PROVISIONING_PROFILE=~/path/to/Portal.mobileprovision
   export PORTAL_TUNNEL_PROVISIONING_PROFILE=~/path/to/PortalTunnel.mobileprovision   # with the tunnel
   export PORTAL_TEAM_ID=XXXXXXXXXX
   zig build ios-sign -Doptimize=ReleaseSafe -Dios-bundle-id=<your.bundle.id> -Dmoltenvk=<path>
   ```
   The signer (src/tools/ios_sign.zig) checks each profile (development,
   App ID, Network Extensions), embeds the app's at
   `Portal.app/embedded.mobileprovision` and the extension's at
   `Portal.app/PlugIns/PortalTunnel.appex/embedded.mobileprovision`, and
   signs with development entitlements: `application-identifier`
   (`<team>.<bundle id>`, resp. `.tunnel`), `com.apple.developer.team-identifier`,
   `get-task-allow`, one `keychain-access-groups` entry
   `<team>.<your.bundle.id>` shared by app and extension, and with the
   tunnel `com.apple.developer.networking.networkextension` =
   `[packet-tunnel-provider]` on both.
5. **Install** (iPhone connected or paired, Developer Mode on):
   `xcrun devicectl list devices` then
   `xcrun devicectl device install app --device <id> zig-out/ios/Portal.app`.
   Launch: `xcrun devicectl device process launch --console --device <id> <your.bundle.id>`.
   Logs: Console.app, filter on the device and "Portal". Pre-install
   checks (otool, codesign) and the system processes to search for when
   install or launch fails: docs/ios-kit-readme.txt (the kit's README).
6. **First run:** Face ID, then the first-run screen: at the desk open
   Pair a device, tap **Scan QR code**, point at the QR, approve the
   request code at the desk.

## Build on another computer, sign + install on the Mac

The pinned Zig has no macOS build, so the Mac may have no Zig: build on
the Windows PC (or any host) and carry a kit to the Mac.

1. **The iPhoneOS SDK from the Mac**, copied as a tarball. Symlinks are
   dereferenced (`-h`): Windows tar cannot create them (it fails on them),
   and the SDK's usr/lib uses them (`libobjc.tbd -> libobjc.A.tbd`,
   `libSystem.tbd -> libSystem.B.tbd`, ...). The build only reads link
   stubs, so the small tarball is enough (`.tbd` files of the public and
   private frameworks and of usr/lib, plus usr/include, which the libc
   file names):
   ```
   cd "$(xcrun --sdk iphoneos --show-sdk-path)/.."
   { find -L iPhoneOS.sdk/System/Library/Frameworks iPhoneOS.sdk/System/Library/PrivateFrameworks iPhoneOS.sdk/usr/lib -name '*.tbd'
     echo iPhoneOS.sdk/usr/include; echo iPhoneOS.sdk/SDKSettings.json; } \
     | tar -czhf ~/Desktop/iPhoneOS-sdk.tgz -T -
   ```
   (The whole SDK also works: `tar -czhf ~/Desktop/iPhoneOS-sdk.tgz iPhoneOS.sdk`.)
   Extract it outside the repo (e.g. `..\ios-deps\`) with `tar -xzf`.
   NTFS is case-insensitive; the build looks every stub up by its exact
   name, so that only matters if extraction reports two names that differ
   only in case.
2. **MoltenVK:** the `MoltenVK-ios.tar` above, extracted the same way
   (its only symlink, `MoltenVK/MoltenVK/dylib`, points at nothing in the
   iOS tar and fails harmlessly on Windows; the framework is flat).
3. **Kit:**
   `zig build ios-kit -Doptimize=ReleaseSafe -Dios-sdk=<...\iPhoneOS.sdk> -Dios-bundle-id=<your.bundle.id> -Dmoltenvk=<...\MoltenVK.xcframework\ios-arm64\MoltenVK.framework> -Dios-tunnel=true`
   -> `zig-out/ios-kit/`: the unsigned `Portal.app`, `portal-ios-sign`
   (the signer for aarch64-macos, ad-hoc signed by Zig's linker; no macOS
   SDK needed) and `README.txt` (docs/ios-kit-readme.txt with the bundle
   id filled in). The linker also searches the SDK's PrivateFrameworks and
   usr/lib/system: without a sysroot it finds re-exported libraries
   (UIKit -> UIKitCore, libSystem -> libsystem_*) only by name there.
4. Copy `ios-kit` to the Mac (zip, AirDrop, USB) and follow its
   README.txt: remove the quarantine, `chmod +x portal-ios-sign`, set the
   environment of step 4 above, run `ios-kit/portal-ios-sign` (from any
   directory; it signs a copy into `ios-kit/signed/Portal.app` and sets
   the executables' mode bits that a copy from Windows loses), then
   `xcrun devicectl` as in step 5.

CI: `.github/workflows/ios.yml` (a hosted macOS runner: `ios-check` and an
unsigned Portal.app artifact). It is YAML because GitHub Actions only reads
YAML: configuration, the stated exception to the all-Zig rule; every step
only runs `zig build`.

## To verify on the phone

Touch mapping (tap vs pan scroll), keyboard insets, dictation into the
native field, the background hand-off (no GPU use after `.background`),
the cover in the app switcher and during screen recording, Face ID +
Keychain single prompt, QR scanning, the font file CoreText names for
Menlo (Renderer `Font/fontset.zig`; a failure reports the paths tried),
Local Network prompt and its note, syslog lines reaching Console.app,
MoltenVK loading from the bundle, and with a paid
account the tunnel extension against the desk.

## What is left (ordered)

1. Run on the iPhone; fix what the list above finds.
2. WireGuard key delivery + desk confirm step (section 6), then
   `tunnel.configure` from pairing.
3. Flip build.zig.zon back to ../Renderer when `ios-window` is merged.
