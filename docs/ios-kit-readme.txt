This folder (made by `zig build ios-kit` on another computer) signs and
installs Portal on your iPhone from a Mac with Xcode. The Mac needs no Zig.

  Portal.app        the app, unsigned
  portal-ios-sign   the signer (arm64 macOS; Apple silicon Macs)
  README.txt        this file

All commands run in Terminal on the Mac. Replace <...> with your values.

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

5. Install and launch (iPhone connected or paired, unlocked):

   xcrun devicectl list devices
   xcrun devicectl device install app --device <identifier> ios-kit/signed/Portal.app
   xcrun devicectl device process launch --device <identifier> @BUNDLE_ID@

6. Logs: open Console.app, select the iPhone in the sidebar, press Start
   streaming, and search for "Portal" (the app; the tunnel extension
   runs as "PortalTunnel").
