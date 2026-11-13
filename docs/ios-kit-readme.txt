This folder (made by `zig build ios-kit` on another computer) signs and
installs Portal on your iPhone from a Mac with Xcode. The Mac needs no Zig.

  Portal.app        the app, unsigned
  portal-ios-sign   the signer (arm64 macOS; Apple silicon Macs)
  README.txt        this file

All commands run in Terminal on the Mac. Replace <...> with your values.

First install: use a kit built WITHOUT -Dios-tunnel (the first line of
this file says which this is). The tunnel extension cannot start until
the desk delivers the phone's WireGuard key (not implemented yet), so
leaving it out keeps the first run to the app itself: one App ID, one
profile, fewer entitlements to get wrong. Reach the desktop on the LAN
or through the WireGuard app meanwhile; iOS asks once whether Portal may
use the local network: allow it. Add the extension on a second install
(kit rebuilt with -Dios-tunnel=true, PORTAL_TUNNEL_PROVISIONING_PROFILE
set).

1. Once: certificate, App IDs, profiles (developer.apple.com, paid account)

   - Xcode > Settings > Accounts: add your Apple ID; Manage Certificates >
     + > Apple Development (its private key stays in this Mac's keychain).
   - Team ID: developer.apple.com > Account > Membership details (10
     characters). It is not the code in brackets after your name in the
     certificate.
   - Identifiers > + > App IDs > App: explicit Bundle ID @BUNDLE_ID@,
     capability "Network Extensions".
     With the tunnel extension, a second one: @BUNDLE_ID@.tunnel, also
     "Network Extensions".
   - Devices: register the iPhone's UDID (connect it by cable, then
     `xcrun devicectl list devices` or Xcode > Window > Devices).
   - Profiles > + > iOS App Development: App ID @BUNDLE_ID@, your
     certificate, your iPhone -> download (e.g. ~/Portal.mobileprovision).
     With the tunnel extension, a second one for @BUNDLE_ID@.tunnel
     (e.g. ~/PortalTunnel.mobileprovision).
   - On the iPhone: connect it by cable and tap Trust; then Settings >
     Privacy & Security > Developer Mode > on (restart, confirm).

2. Unpack this folder, then in Terminal:

   cd <folder that contains ios-kit>
   xattr -dr com.apple.quarantine ios-kit
   chmod +x ios-kit/portal-ios-sign

   (If codesign later complains about "resource fork, Finder information,
   or similar detritus", run `xattr -cr ios-kit` and sign again.)

3. Find the signing identity:

   security find-identity -v -p codesigning

   Use the quoted name, e.g. "Apple Development: Your Name (ABCDE12345)".

4. Sign (works from any directory; writes ios-kit/signed/Portal.app):

   export PORTAL_SIGN_IDENTITY="Apple Development: <Your Name> (<XXXXXXXXXX>)"
   export PORTAL_TEAM_ID=<team id>
   export PORTAL_PROVISIONING_PROFILE=~/Portal.mobileprovision
   export PORTAL_TUNNEL_PROVISIONING_PROFILE=~/PortalTunnel.mobileprovision   # with the tunnel extension
   ios-kit/portal-ios-sign

   The signer checks each profile first (development profile, App ID
   <team id>.@BUNDLE_ID@ resp. .tunnel, Network Extensions) and says
   which one is wrong. To look at the result:
   codesign -d --entitlements :- ios-kit/signed/Portal.app

5. Check before installing (each of these failures otherwise shows up
   only as an app that will not install or dies at launch):

   a. Linked libraries: only entries under /System/Library/ or /usr/lib/.
      Anything else (a path from the build computer, /Users/..., C:\...)
      makes dyld kill the app at launch. MoltenVK is not listed: the app
      opens Frameworks/ at run time.

      otool -L ios-kit/signed/Portal.app/Portal
      otool -L ios-kit/signed/Portal.app/PlugIns/PortalTunnel.appex/PortalTunnel   # with the tunnel extension

   b. Platform: LC_BUILD_VERSION must say platform 2 (iOS), minos 16.0,
      and an sdk version (not 0.0 or n/a). Same for the extension and for
      Frameworks/MoltenVK.framework/MoltenVK (or libMoltenVK.dylib).

      otool -l ios-kit/signed/Portal.app/Portal | grep -A5 LC_BUILD_VERSION
      otool -l ios-kit/signed/Portal.app/PlugIns/PortalTunnel.appex/PortalTunnel | grep -A5 LC_BUILD_VERSION

   c. Signature and entitlements: application-identifier
      <team id>.@BUNDLE_ID@, com.apple.developer.team-identifier,
      get-task-allow true (development), keychain-access-groups
      <team id>.@BUNDLE_ID@; with the tunnel extension also
      com.apple.developer.networking.networkextension = packet-tunnel-provider
      (and <team id>.@BUNDLE_ID@.tunnel on the extension).

      codesign --verify --deep --strict --verbose=2 ios-kit/signed/Portal.app
      codesign -d --entitlements :- ios-kit/signed/Portal.app
      codesign -d --entitlements :- ios-kit/signed/Portal.app/PlugIns/PortalTunnel.appex   # with the tunnel extension

6. Install and launch (iPhone connected or paired, unlocked):

   xcrun devicectl list devices
   xcrun devicectl device install app --device <identifier> ios-kit/signed/Portal.app
   xcrun devicectl device process launch --console --device <identifier> @BUNDLE_ID@

   --console keeps Terminal attached to the app and shows what it prints
   (stderr) until it exits; Ctrl-C detaches.

7. Logs: open Console.app, select the iPhone in the sidebar, press Start
   streaming, and search for "Portal" (the app; the tunnel extension
   runs as "PortalTunnel"). Every message that ends the app, std.log
   output and panics go to the system log as process Portal. Why an
   install or launch failed is usually logged by a system process; search
   for one at a time (type it, then pick "Process" in the search field):

     installd    install refused (profile, bundle id, entitlements)
     amfid       code signature or provisioning profile rejected at launch
     dyld        a library or symbol missing at launch
     Sandbox     a file the app may not read (e.g. a system font)
     coreauthd   Face ID (LocalAuthentication)
     securityd   Keychain (the device credential behind Face ID)
     tccd        permissions: camera, Face ID, Local Network

