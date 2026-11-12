# Native iPhone app (branch feat/ios-native)

**Owner decisions (2026-11-12):**
* Assume the toolchain exists: the iOS SDK (Xcode) and the ability to sign and
  install on the owner's iPhone, so Vulkan runs on the iPhone through
  MoltenVK.
* **One code path, branching per device only where a device really differs.**
  One renderer (Vulkan, the owner's Renderer), one UI, one network client.
  The iPhone section adds only what iOS needs: MoltenVK, a UIKit window
  backend, the app bundle and signing.
* The Safari/wasm browser app and the Renderer CPU backend are dropped. The
  browser app stays only until the native app is installed on the phone, then
  `src/wasm/` and the web app assets are removed.

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
6. **Tunnel:** iOS has no per-app VPN without MDM; keep the Shortcuts
   automations (pairing page shows them).

## What is shared vs per device (target)

| Concern | Shared | Desk (Windows) | Laptop (Win/Linux/macOS) | iPhone |
|---|---|---|---|---|
| UI + theme | ✓ | – | – | – |
| Drawing | Renderer Instanced2D (Vulkan) | system loader | system loader / MoltenVK on macOS | MoltenVK |
| Window | Renderer Window interface | win32 | win32 / wayland / macos | ios |
| Network client | ✓ | (server instead) | ✓ | ✓ |
| Credentials | interface | DPAPI | Credential Manager / libsecret / Keychain | Keychain |
| Session | – | ConPTY + server | – | – |
