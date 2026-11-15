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
| 5 | QR pairing: the phone shows its key and check code, the desk pairs it, then shows the pairing code (address, CA SHA-256, endpoint, desk key) as a QR the phone scans and pins | `shared/pairqr.zig` (text format), `ui/qr.zig` (Zig QR encoder, `portal_ui.qr`), `ui/panels/desk.zig` (Pair panel), `ui/frame.zig` `Panel.qr`, `ui/panels/setup.zig` (Scan QR code), `client/src/ios/scan.zig` (AVFoundation) | done |
| 6 | Per-app tunnel on the owner's own Zig WireGuard (../WireGuard) | `client/src/ios/tunnel_ext` (extension), `client/src/ios/tunnel.zig` + `tunnel_note.zig` (app side), `devicelink.wgQuick` | done: configured from pairing and every later launch, started on screen, stopped in the background; unverified on device |
| 7 | Dictation on the phone itself: stt.Local on Core ML, the bundled base.en model (the desk's own), the shared input line's 🎤; home's personal adapter applied, training samples sent home | `client/src/ios/speech.zig`, `client/src/ios/mic.zig`, `connect.Platform.speech` / `speech_sync` | done, compile-checked only |

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
  reads `providerConfiguration["wgQuickConfig"]` (no private key in it),
  puts back the private key from the Keychain item named in
  `providerConfiguration["privateKeyRef"]` (tunnel_ext/keyref.zig), parses it with
  WireGuard's config parser, applies NEPacketTunnelNetworkSettings
  (IPv4 addresses, the peers' AllowedIPs as routes, MTU, the desk as
  remote address), starts `WireGuard.device.Device` on
  `tun.PacketFlowTun` (its own event loop thread), and re-arms
  `packetFlow.readPackets` from each completion (no polling). Packets
  read after `stopTunnel` began are dropped, and the backend serialises
  deliver with stop (they arrive on different queues).
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
  Apple ID build without it: the app then runs the same tunnel in its own
  process (client/src/tunnel, as `portal connect` does), while it is on
  screen.
* **Wiring (connect.Platform.system_tunnel):** once the pairing code is
  known (right after pairing, and on every later launch from the stored
  code), connect.zig builds the same tunnel as wg-quick text
  (`devicelink.wgQuick`: this phone at its 10.8.0.x/32, the desk as the
  one peer with AllowedIPs 10.8.0.1/32, the endpoint from the code and
  the 25 s keepalive) and offers it to the device. With
  `-Dios-tunnel=true` `tunnel.configure` takes it and the viewer dials
  10.8.0.1:8420 with plain OS sockets (iOS routes them into the
  extension's tunnel). Without it, or when the key cannot be put in the
  Keychain, it says no and the viewer starts the in-process tunnel as
  before. The VPN configuration is saved only when it changed
  (`tunnel_note.needsSave`), so a normal launch does not rewrite the
  system's VPN preferences; a DNS-name endpoint is resolved by the
  extension's WireGuard (zwg's `PeerConfig.fromConfig`, as the in-process
  tunnel does), and looked up again while the desk is silent.
* **Status line (connect.Platform.note):** every completion handler and
  NEVPNStatusDidChangeNotification (main queue, no polling) sets a short
  note that the shared status line shows (`Viewer.note`): connecting, not
  allowed ("reopen Portal and tap Allow"), turned off by another VPN,
  the extension did not start, or the system's own error text. It is
  empty while the tunnel is up and while Portal is in the background.
* **Keys:** the phone's key is the device key every Portal device has
  (client/src/tunnel/keys.zig, in the Keychain behind Face ID); the private
  key never leaves it. `tunnel.configure` takes it out of the wg-quick
  text before the VPN configuration is saved (that lives in the system's
  VPN preferences, which can reach backups and diagnostics) and stores it
  with `credstore.saveUnattended`: Keychain item
  `Portal-tunnel/packet-tunnel-key`, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
  (never in a backup or iCloud Keychain), no Face ID ACL so the extension
  can read it without UI, in the app's default Keychain group
  `<team>.<bundle id>`, which the extension's entitlements also list
  (ios_sign.zig): no other process can read it. WhenUnlocked, not
  AfterFirstUnlock: the app brings the tunnel up only while it is on
  screen, so the extension never needs the key while the phone is locked.
* **Key delivery** is desk-approved pairing (docs/pairing.md): the phone
  shows its public key and check code, the owner pairs it at the desk
  (which adds it to the desk's in-process tunnel), and the pairing code
  carries the desk's key, endpoint and the phone's tunnel address back.
* **IPv6 inside the tunnel: not done, on purpose.** The desk hands out
  IPv4 tunnel addresses only (shared/tunnelnet.zig: 10.8.0.0/24, the desk
  10.8.0.1, the pairing code's device address is a dotted quad), and every
  Portal service is on 10.8.0.1. The owner's WireGuard netstack can carry
  fd0a:8::/64, but using it would need an IPv6 address on the desk's
  in-process tunnel, IPv6 AllowedIPs per device, a new pairing code
  version and IPv6 in the client's dialing, for no reachable service.
  The **outer** connection is not affected: the desk's endpoint may be an
  IPv6 address or a name that resolves to one, which works today
  (NEIPv6Settings only concern addresses inside the tunnel).

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
* **Device hooks:** `connect.Platform` (sync off / full / only some
  packages, `speech_sync`, suspend/resume,
  QR scan, `system_tunnel`, the status `note`, `speech`). The iPhone
  section (`client/src/ios`) fills them; everything they drive is shared.
* **Shared UI** (module `portal_ui`, ui/): layout inside `Frame.insets`,
  the focused field as `Frame.text_slot` (`frame.textEdit` turns the
  native field's edits into Backspace/characters, Return = Enter),
  `Panel.qr`, grid rows scrolled back with `Frame.scrollRows`. The
  Presenter (client/src/view/Presenter.zig) binds them to the Window:
  `insets()` before each build, show/hide/set the native text field after
  each present, `.background`/`.foreground` -> no drawing (`isSuspended`,
  which connect.zig turns into `Client.setPaused`), `.scroll` (a drag on
  the phone) -> `scrollRows`.

## Dictation on the phone (stt Core ML)

* **Seam:** `connect.Platform.speech` gives the shared input line the
  same `ui.shell.Dictation` hooks the desk's engine fills (start, stop,
  cancel), plus a per-frame `frame` that hands a finished transcript to
  `Shell.dictated` and sets the 🎤's state (`transcribing`, `mic_label`,
  `speech_off`, `setSpeechReady`). So the 🎤 Dictate / Listening /
  Transcribing row, the hint text and the line work as on the desk, and
  so does stt's feedback: `sent` / `cleared` go through ui/dictation.zig
  (edited then sent: the correction is learned; cleared: discarded;
  unchanged: silence confirms it after 60 s).
* **Microphone (client/src/ios/mic.zig):** AVAudioSession (category
  Record, Bluetooth hands-free allowed) and an AVAudioEngine tap on the
  input node, event-driven (the tap's callback). The input is chosen with
  the desk's headset-first rule: the session's available inputs mapped
  by `mics.fromApplePort` into src/speech/mics.zig and `mics.choose`.
  The tap keeps the first channel at the hardware rate; stop resamples
  to 16 kHz mono f32 with `stt.audio.resample` (stt's own resampler).
  120 s at most (stt's limit): then the 🎤 goes off by itself.
  Permission: NSMicrophoneUsageDescription; iOS 17's AVAudioApplication
  asks on the first Dictate; a denial becomes the 🎤's hint.
  The desk's `capture.Backend` is not reused below this level: it is
  shaped around Win32 events (WaitForMultipleObjects) and the WASAPI
  device list; the shared parts are the selection rule, the limits and
  the input-line API.
* **Engine (client/src/ios/speech.zig):** `stt.Local` with backend
  `.coreml` (`cpu_and_neural_engine`, cache `Library/Caches/stt-coreml`),
  on one worker thread (never the UIKit main thread, never the app
  thread), asleep on an Io.Condition until there is work or a deadline.
  The first Dictate starts loading in parallel with the recording (the
  model `Portal.app/stt/ggml-base.en.bin`, then the Core ML programs:
  generated and compiled the first time, seconds; later from the cache).
  A clip loses its leading and trailing silence first (src/speech/trim.zig,
  20 ms frames against the clip's loudest, 200 ms margin; nothing voiced
  means nothing heard, no stt call). "Transcribing (cancel)" drops the
  result (stt cannot stop mid-clip) and tells stt it was wrong.
* **Energy:** the engine (model, Core ML programs, profile) is released
  60 s after the last dictation: the worker sleeps until that deadline,
  or stt's own 60 s silence confirm if sooner (`Condition.waitTimeout`,
  no polling), and closes it when nothing is pending. Off screen
  (`onSuspend`) a recording is stopped and dropped, a pending result
  dropped, and the engine released at once (stt confirms what is pending
  first): iOS reclaims memory from background apps first.
* **Trained at home, better everywhere:** the desk's GPU trains the
  personal adapter from every device's corrections; the phone runs it.
  * *Adapter in:* the sync worker (connect.zig) runs on the phone for one
    package only, `stt-adapter` (`Platform.sync = .only`,
    `sync.engine.Options.allow`): the same checks as the laptop (manifest
    SHA-256 = index line, Ed25519 signature by the release key pinned at
    pairing, strict parse, a sequence above anything installed: no
    downgrade, no replay), data only (an executable, or any other package,
    is refused even when signed), files verified in staging, installed
    read-only in the per-desktop store. No approval panels, no voice
    offer, nothing else is fetched. A pass runs on every connect and on
    the desk's `{"t":"updates"}` (subscribe the phone at the desk:
    Devices, P on its row, `stt-adapter`; or `portalctl sync subscribe
    <phone> stt-adapter`). The package holds `update.bin` (stt's update:
    adapter + rules + vocabulary, from `Home.exportUpdate`) or a raw
    `adapter.bin` whose package version is the adapter version
    (`portalctl publish stt-adapter <folder> --kind data --version N`).
    An update is swapped into the open engine at once
    (`Local.importUpdate`: only the Core ML decoder is rebuilt, the model
    stays loaded) or imported into the profile for the next load; a raw
    adapter is used from the next load (the engine closes at the next
    idle moment). The Dictate button shows `your voice vN` once an
    adapter is in use.
  * *Samples out:* with learning on (the default; `speech_learning = off`
    in the device settings file turns it off: then stt keeps no audio and
    nothing is sent), after each sync pass and after every learned
    correction (`connect.requestSync`) the phone sends its pending samples
    home as stt bundles (at most 2 MiB each, 16 a pass) with `put bundle`
    on the bulk WebSocket, inside the tunnel and the CA-pinned TLS. The
    desk answers "ok" only once stt.Home stored them; only then are they
    deleted on the phone. The desk's limits apply (src/speech/inbox.zig,
    gate.zig: 2 devices at once, 5 MiB a bundle, 100 MiB and 500 clips a
    day per device); a refusal keeps them for a later pass.
  * *Storage:* the stt profile (samples, rules, vocabulary, the adapter)
    is `Library/Application Support/Portal/stt-local`, the sync store
    `.../Portal/sync`, both and the Core ML cache with iOS file protection
    Complete (readable only while the phone is unlocked), the class of
    the device key's Keychain item (WhenUnlockedThisDeviceOnly). One
    thread (the speech worker) touches the profile.
* **Model:** the desk's own base model, pinned once in
  src/speech/model_pin.zig: the whisper.cpp project's `ggml-base.en.bin`
  on Hugging Face at commit 5359861, 147,964,211 bytes, SHA-256
  a03779c8...d002, byte for byte the file the desk's stt.Home trains on
  (an adapter fits only the base model it was trained on). Zig's package
  fetcher accepts only archives and git repositories, so the single file
  is fetched by src/tools/fetch_file.zig, which keeps it only if size and
  hash match. Only the steps that build the app run it (`ios`,
  `ios-sign`, `ios-kit`), never `ios-check` or `test`, and the build
  cache keeps it; it is never in git. `-Dios-model=<file>` bundles a
  local copy instead (it must be that same file). Its MIT notices are in
  `Portal.app/Licenses.txt` (docs/ios-licenses.txt).
* **One Objective-C binding:** the window (the Renderer's IosObjC) and
  stt's Core ML backend (TranslateCoreML) both build on the MacOS
  package's types and its `msgSend` signature builder. They asked for it
  with different optimize modes, which gave two "MacOS" modules over the
  same files, and Zig refuses that. build.zig `iosStt` gives the Core ML
  module the Renderer's MacOS, so the app has one. Portal's own iOS
  files use that binding through `view.Window.ios.objc` (IosObjC).

## iOS 17

The deployment target (build.zig `ios_min_major`) and both Info.plists'
`MinimumOSVersion` are iOS 17: the dictation engine's Core ML programs
target iOS 17 (stt's `mil.Target.ios17`), and the microphone permission
uses iOS 17's AVAudioApplication.

## Release build check

A release build (`-Doptimize=ReleaseSafe` or another non-Debug mode)
strips the app's and the extension's executables, and
src/tools/machocheck.zig checks them before `zig build ios` / `ios-kit`
finish: a 64-bit arm64 Mach-O, no __DWARF segment, no __debug_*
section, no debug-map (stab) symbols, and no absolute path of the build
machine (the same kind of check as ZVC's check-dist).

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

The owner's step-by-step session (what to enter, what success looks
like) is docs/mac-session-portal.md; this section is the reference.

Prerequisites: Xcode (iOS SDK) and the Zig in build.zig.zon. The sibling
repos are pinned URL dependencies (build.zig.zon), fetched by the build;
`--fork=<checkout>` builds against a local one. The first app build also
downloads the dictation model (148 MB, src/speech/model_pin.zig).

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
3. **Apple account, certificate, profiles:** as in docs/ios-kit-readme.txt
   (the kit's README), section 2. Paid account with the tunnel
   (`-Dios-tunnel=true`): two explicit App IDs, `<your.bundle.id>` and
   `<your.bundle.id>.tunnel`, both with the Network Extensions
   capability, an iOS App Development profile for each, downloaded with
   Xcode > Settings > Accounts > Download Manual Profiles. Free Apple ID:
   make any Xcode iOS app with the same bundle id once and run it on the
   phone; Xcode keeps the profile.
4. **Settings:** copy docs/portal-ios.conf.example to `portal-ios.conf`
   (the repo root when signing with `zig build ios-sign`; next to
   `portal-ios-sign` in the kit; git ignores the name) and fill in
   `team_id` and `account` (paid or free). The rest is found when left
   empty. The environment still works underneath it: `PORTAL_TEAM_ID`,
   `PORTAL_ACCOUNT`, `PORTAL_SIGN_IDENTITY`, `PORTAL_PROVISIONING_PROFILE`,
   `PORTAL_TUNNEL_PROVISIONING_PROFILE`.
5. **Sign and install:** `zig build ios-sign -Doptimize=ReleaseSafe
   -Dios-bundle-id=<your.bundle.id> -Dmoltenvk=<path>` signs
   zig-out/ios/Portal.app; `zig build ios-kit ...` then
   `zig-out/ios-kit/portal-ios-sign --install` signs and installs in one
   command (`--launch` also starts it). The signer
   (src/tools/ios_sign.zig) picks the iPhone (`xcrun devicectl list
   devices`: the only connected one, or `device =`), the profiles (the
   newest valid ones in ~/Library/MobileDevice/Provisioning Profiles and
   ~/Library/Developer/Xcode/UserData/Provisioning Profiles, or
   `profile =` / `tunnel_profile =`) and the identity (`security
   find-identity`: the Apple Development certificate the profile was made
   for, signed by its SHA-1). Each profile must be a development profile
   of the team whose App ID covers the bundle id (resp. `.tunnel`), not
   expired, made for that certificate, listing the iPhone, with
   keychain-access-groups covering `<team>.<your.bundle.id>` and, for the
   tunnel, packet-tunnel-provider; it says which check failed for each
   near miss and how to get a profile. It embeds the app's profile at
   `Portal.app/embedded.mobileprovision` and the extension's at
   `Portal.app/PlugIns/PortalTunnel.appex/embedded.mobileprovision`,
   clears extended attributes, and signs Frameworks/, the extension, then
   the app (sealing Info.plist, the icons, `stt/ggml-tiny.en.bin` and
   `Licenses.txt` as resources) with development entitlements:
   `application-identifier` (`<team>.<bundle id>`, resp. `.tunnel`),
   `com.apple.developer.team-identifier`, `get-task-allow`, one
   `keychain-access-groups` entry `<team>.<your.bundle.id>` shared by app
   and extension, and with the tunnel
   `com.apple.developer.networking.networkextension` =
   `[packet-tunnel-provider]` on both. Then `codesign --verify --deep
   --strict`, `xcrun devicectl device install app --device <id>`, and the
   next steps. To watch the app's stderr: `xcrun devicectl device process
   launch --console --device <id> <your.bundle.id>`. Logs, the otool and
   codesign checks, and the system processes to search for when install
   or launch fails: the kit's README, sections 6 and 7.
6. **First run:** Face ID, then the first-run screen shows the phone's
   key and check code: pair it at the desk (Pair a device, check the
   code), then tap **Scan QR code**, point at the desk's pairing code QR,
   compare the desk's check code and tap **Connect**.

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
   (the signer for arm64 macOS, ad-hoc signed by Zig's linker; no macOS
   SDK needed), `portal-ios-sign-x86_64` (Intel Macs),
   `portal-ios.conf.example` and `README.txt` (docs/ios-kit-readme.txt
   with the bundle id filled in). The linker also searches the SDK's
   PrivateFrameworks and usr/lib/system: without a sysroot it finds
   re-exported libraries (UIKit -> UIKitCore, libSystem -> libsystem_*)
   only by name there.
4. Copy `ios-kit` to the Mac (zip, AirDrop, USB) and follow its
   README.txt: remove the quarantine, `chmod +x portal-ios-sign`, copy
   `portal-ios.conf.example` to `portal-ios.conf` and fill in `team_id`
   and `account`, then `./portal-ios-sign --install`. It signs a copy into
   `ios-kit/signed/Portal.app` (setting the executables' mode bits that a
   copy from Windows loses) and installs it on the connected iPhone.

CI: `.github/workflows/ios.yml` (a hosted macOS runner: `ios-check` and an
unsigned Portal.app artifact). It is YAML because GitHub Actions only reads
YAML: configuration, the stated exception to the all-Zig rule; every step
only runs `zig build`.

## To verify on the phone

Touch mapping (tap vs pan scroll), keyboard insets, dictation into the
native field (Apple's keyboard dictation) and Portal's own 🎤 (stt on
Core ML), the background tunnel (VPN prompt, up on screen, down in the
background), the background hand-off (no GPU use after `.background`),
the cover in the app switcher and during screen recording, Face ID +
Keychain single prompt, QR scanning, the font file CoreText names for
Menlo (Renderer `Font/fontset.zig`; a failure reports the paths tried),
Local Network prompt and its note, syslog lines reaching Console.app,
MoltenVK loading from the bundle, and with a paid
account the tunnel extension against the desk.

## What is left (ordered)

1. Run on the iPhone (docs/mac-session-portal.md); fix what it finds.
