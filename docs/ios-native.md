# Native iPhone app (branch feat/ios-native)

**Status (2026-11-12):** planned. Waiting on the owner's toolchain choice
(below). Until it exists the iPhone uses the browser app, which runs the same
shared UI on the Renderer's CPU backend.

## Why native

The browser can't reach the iPhone's GPU through Vulkan. A native app can:
MoltenVK translates Vulkan to Metal, so the owner's Renderer (Instanced2D,
Window, Font) runs unchanged on the GPU, with the same shared Portal UI as the
desktop and laptop. It also gets Face ID / passkeys directly and could later
run the owner's own speech model on-device.

## Getting the kit (owner)

Xcode, and with it the iOS SDK, only runs on macOS. Pick one way to get a Mac
and one way to sign:

| Build on | Cost | Notes |
|---|---|---|
| Used Mac mini (M1 or newer) | one-off | Simplest; cable to the iPhone for install and debugging. |
| Cloud Mac (MacinCloud, AWS EC2 Mac, Scaleway) | monthly / hourly | Remote desktop to a real Mac. |
| Hosted CI (GitHub Actions macOS runner, Codemagic) | free tier / minutes | No Mac at all; every push builds an `.ipa`. |

| Sign / install with | Cost | Notes |
|---|---|---|
| Free Apple ID + SideStore | free | App must be re-signed every 7 days (SideStore does it on the phone over Wi-Fi); max 3 sideloaded apps. First install from Windows via AltServer. |
| Apple Developer Program + TestFlight | $99/year | 1-year signatures; install and update over the air; works with hosted CI. |

No jailbreak: none exists for iPhone 16 / iOS 18+, it wouldn't provide the SDK,
and it would break the sandbox and Secure Enclave guarantees Portal's iPhone
security relies on.

## What gets built (once the kit exists)

1. **Toolchain:** Zig cross-compiles for `aarch64-ios` against the iOS SDK from
   Xcode (`--sysroot` to the SDK; no Swift). A minimal app bundle: Info.plist,
   entry point, launch screen, icon. Build step `zig build ios` (+ a CI
   workflow for the hosted-Mac route that produces the `.ipa`).
2. **Window:** an iOS backend in the Renderer's Window module (UIKit via the
   Objective-C runtime, like the macOS backend on ../MacOS): UIWindow +
   CAMetalLayer surface, touch → pointer/tap events, safe-area insets,
   keyboard show/hide, wake via a posted event; event-driven only.
3. **GPU:** MoltenVK (bundled in the app, as Apple requires) behind the
   Renderer's existing Vulkan path; `SurfaceSource.metal` already exists.
4. **App:** the same shared Portal UI as every other device (top bar + tabs,
   Conversation view by default, Data slice, big interaction bar), the same
   network client as `portal connect` (TLS pinning, pairing, rotating
   credential), credentials in the iOS Keychain, passkey/Face ID via
   AuthenticationServices.
5. **Speech:** keep Apple dictation in the input field first (needs a native
   UITextField/UITextView bridged into the Renderer's input slot — verify
   dictation works there). Owner's on-device model later, as an option.
6. **Tunnel:** iOS still has no per-app VPN without MDM; keep the Shortcuts
   automations (see docs/wireguard.md / pairing page).

## Open questions

* Which build/sign route the owner picks (drives the CI workflow).
* Whether Apple dictation works in a native text view composited over the
  Renderer's surface (expected yes; must be tested on the phone).
* App Store distribution is out of scope (personal use).
