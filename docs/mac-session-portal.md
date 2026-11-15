# Mac session, Portal side: build, sign, install, test on the iPhone

Everything below except signing, installing and running was built and
checked on Windows. That covers the compile checks for aarch64-ios with
and without the tunnel extension, the host tests, the release
executables' strip and path check, and the model download against its
pinned hash. This session signs the app, installs it and checks it on the
phone. Work through it top to bottom and keep the output of every step
marked **record**.

The Core ML engine's own Mac and iPhone checks (probe, coreml-dev,
SttCoreML.app) are in SpeechToText's
[docs/mac-session.md](https://github.com/Mauhlt/SpeechToText/blob/main/docs/mac-session.md).
Run them first, or at least its step 4 (SttCoreML.app on the iPhone), so
a dictation failure here is not a Core ML surprise.

## Only on the Mac or the phone

This is everything that cannot be done or checked on Windows:

1. **Signing:** the development certificate in the Mac's keychain, the
   App IDs and provisioning profiles, and `codesign` itself.
2. **Install and launch:** `xcrun devicectl`, Developer Mode on the
   iPhone, and whether dyld loads the app and MoltenVK.
3. **Face ID:** the lock cover, one Face ID prompt for both the unlock
   and the Keychain read, and the cover in the app switcher and during
   screen recording.
4. **Camera:** the camera permission prompt and scanning the desk's
   pairing QR code.
5. **The background tunnel** (paid account): the "Allow VPN
   configuration" prompt, the extension starting (process
   PortalTunnel), the tunnel up while Portal is on screen and down in
   the background, and the status line.
6. **Dictation:** the microphone prompt, AVAudioEngine capture, a
   headset microphone chosen over the built-in one, Core ML on the Neural
   Engine, and the Core ML cache in Library/Caches.
7. **Screen shape:** safe-area insets, the keyboard pushing the input
   line up, rotation, and tap versus drag on the real touch screen.
8. **Logs:** syslog reaching Console.app.

## What the owner enters

| What | Where it comes from | Used for |
|---|---|---|
| Bundle ID, e.g. `com.<you>.portal` | your choice; must match the App ID | the build (`-Dios-bundle-id`) and the profiles |
| Team ID (10 characters) | developer.apple.com > Account > Membership details | signing |
| Signing identity | `security find-identity -v -p codesigning` | signing |
| App profile (`.mobileprovision`) | developer.apple.com > Profiles (paid), or the one Xcode made (free) | signing |
| Extension profile | developer.apple.com, App ID `<bundle id>.tunnel` (paid only) | signing with the tunnel |
| Paid or free account | your Apple Developer membership | with or without `-Dios-tunnel=true` |

Only the team ID and paid or free go into the kit's `portal-ios.conf`
(copied from `portal-ios.conf.example`, next to `portal-ios-sign`). The
bundle ID is the app's own; the signer finds the identity, the profiles
and the iPhone, and says what is missing when it cannot. Each can also be
set in the file or by a flag (`./portal-ios-sign --help`).

## 0. Before the session (on Windows)

1. The iPhoneOS SDK tarball from the Mac (docs/ios-native.md, "Build on
   another computer", step 1), extracted outside the repo, and MoltenVK
   for iOS (step 2).
2. Build the kit. With a paid account:
   ```
   zig build ios-kit -Doptimize=ReleaseSafe -Dios-sdk=<...\iPhoneOS.sdk> -Dmoltenvk=<...\MoltenVK.framework> -Dios-bundle-id=<bundle id> -Dios-tunnel=true
   ```
   With a free account, the same without `-Dios-tunnel=true`.

   **Success:** the build ends without errors and prints one
   `machocheck: <name>: stripped, arm64, no build paths` line for
   `Portal` and, with the tunnel, one for `PortalTunnel`. `zig-out/ios-kit/`
   holds `Portal.app` (with `stt/ggml-tiny.en.bin`, about 74 MB, and
   `Licenses.txt`), `portal-ios-sign`, `portal-ios-sign-x86_64`,
   `portal-ios.conf.example` and `README.txt`.
   The first build downloads the model and checks its size and SHA-256.
   A `fetch_file` error means the download or the pin is wrong.
   **Record** the build output.
3. Copy `zig-out/ios-kit` to the Mac.

## 1. Sign and install: one command

Follow the kit's README.txt, sections 1 to 4 (Xcode, the Apple account,
Developer Mode, the kit), then in `ios-kit`:

```
cp portal-ios.conf.example portal-ios.conf    # fill in team_id and account
./portal-ios-sign --install                   # Intel Mac: ./portal-ios-sign-x86_64 --install
```

It signs `ios-kit/signed/Portal.app` and installs it on the connected
iPhone. Add `--launch` to start it too.

* **Paid account, with the extension:** two App IDs with Network
  Extensions (`<bundle id>` and `<bundle id>.tunnel`), and a profile for
  each.
* **Free account, in-app tunnel:** build the kit without
  `-Dios-tunnel=true`. Use the profile Xcode makes for the bundle ID
  (create any iOS app with that bundle ID once and run it on the phone).
  No extension profile is needed.

**Success:**
* The signer ends with the verified signature.
* `otool -L` lists only `/System/Library/` and `/usr/lib/` entries.
* `LC_BUILD_VERSION` shows platform 2 with **minos 17.0**.
* The entitlements are as the README lists them.
* The install reports the bundle ID.

The README's section 6 has the otool and codesign checks, and section 7
the logs. **Record** the signer's output and `codesign -d --entitlements :-`.

## 2. Launch

```
xcrun devicectl device process launch --console --device <id> <bundle id>
```

(`<id>` is the one the signer printed, or see `xcrun devicectl list devices`.)

Keep Console.app streaming from the iPhone, filtered on "Portal"
(processes Portal and PortalTunnel).

**Success:** the app launches to
the lock cover ("Portal is locked. Tap to unlock with Face ID.").
iOS 16 or older refuses the install: Portal needs iOS 17.

## 3. First run: Face ID, QR scan, pairing

1. **Face ID:** iOS asks once whether Portal may use Face ID. Allow it.
   The cover lifts after one Face ID. Leave the app and come back: the
   cover is up in the app switcher, and Face ID is asked again.
2. **Key:** the first-run screen shows the phone's tunnel key and check
   code.
3. **Pair at the desk:** Pair a device, name `iphone`, enter the key, and
   compare the check code with the phone (docs/pairing.md, section 3).
4. **QR scan:** tap **Scan QR code**. iOS asks for the camera once. Point
   the phone at the desk's pairing code QR, compare the desk's check code
   and tap **Connect**.

**Success:** the setup screen closes and the status line goes from
connecting to connected. The desk's Devices list shows `iphone` at
`10.8.0.3`. **Record** what Console.app shows for Portal during these
steps.

## 4. The tunnel

**In-app (free account, or a kit without the extension):** the app runs
the in-process tunnel while it is on screen.
* Lock the phone or switch apps, then come back. After Face ID it
  reconnects.

**Background (paid account, kit with `-Dios-tunnel=true`):**
1. Right after pairing, iOS asks to **Allow** the VPN configuration
   "Portal". Allow it (passcode). Settings > VPN now lists Portal.
2. The status line says "Background tunnel: connecting" briefly, then
   the note disappears and the status is connected. Settings > VPN shows
   Portal as Connected.
3. Send Portal to the background: within seconds Settings > VPN shows it
   disconnected. Open Portal again: after Face ID it is connected again.
4. Quit and relaunch Portal. There is no second VPN prompt, because an
   unchanged configuration is not saved again. The tunnel comes up.
5. Deny test (optional): delete the Portal VPN in Settings > VPN,
   relaunch, and tap **Don't Allow**. The status line says the VPN
   configuration was not allowed and to reopen Portal and tap Allow.
   Reopen, allow, and it connects.

**Success:** the steps above behave as described. Console shows
PortalTunnel starting and stopping with no `tunnel:` errors.
**Record** the PortalTunnel lines and any status line text you saw.

## 5. Dictation

1. Open a tab whose desktop session takes instructions, then tap
   **🎤 Instruct**. The panel opens and tries to record straight away.
   The first time, iOS asks for the microphone instead: allow it, then
   tap **🎤 Dictate**.
2. While recording, the row shows **● Listening… (stop) · iPhone
   Microphone**. With a wired or Bluetooth headset connected, it shows
   the headset's name instead.
3. Say "Run the tests and show me the failures", then tap the row to
   stop. It shows **… Transcribing (cancel)**. The text then lands in the
   input line for review. Do not send it unless you mean to.
4. The first dictation after installing builds the Core ML programs. It
   takes seconds, and the hint says "Loading the speech model…". A
   second dictation is fast.
5. Send Portal to the background and back, then dictate again. The model
   reloads from Library/Caches, which is quicker than the first time.

**Success:**
* The transcript in the line matches what you said. A one-word
  difference is acceptable; empty or garbled text is a failure.
* The headset microphone is chosen when one is connected.
* Console shows no `dictation:` errors.

On failure the 🎤 hint shows the reason, for example "Speech could not
start on this iPhone (...)". **Record** that text and the Console lines
for Portal.

## 6. Screen shape and touch

* Portrait and landscape: the top bar stays clear of the notch and
  Dynamic Island, and the bottom row clears the home indicator.
* Tap the input line: the keyboard rises and the line moves above it.
  The line hides again when the keyboard does.
* Drag to scroll the terminal and the conversation. A tap is not taken
  as a drag.
* Hold a tab for about half a second to open its menu ("Hide this
  tab"). Tap "⋯ N hidden" to bring it back.
* Projects (start and stop), the usage bar, "•••", For you (swipe a
  card, tap its buttons, Recap): all of them work by touch.

**Record** anything that does not fit on screen or needs a second tap.

## 7. What to send back

* The step 0 build output.
* The signer output and the entitlements.
* Console.app output for the first run, the tunnel and dictation.
* The status line texts you saw.
* A note on anything in steps 3 to 6 that did not behave as written.
