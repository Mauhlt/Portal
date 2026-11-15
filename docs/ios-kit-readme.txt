This folder (made by `zig build ios-kit`) signs Portal and installs it on
your iPhone from a Mac. The Mac needs no Zig. The first line of this file
says whether the kit holds the background tunnel extension.

  Portal.app               the app, unsigned
  portal-ios-sign          the signer (arm64 macOS: Apple silicon Macs)
  portal-ios-sign-x86_64   the same for Intel Macs
  portal-ios.conf.example  its settings, to copy to portal-ios.conf
  README.txt               this file

Everything runs in Terminal on the Mac. The iPhone needs iOS 17 or later.

1. The Mac (once)

   Install Xcode from the App Store and open it once (it finishes
   installing its parts). The command-line tools alone can sign but not
   install: `xcrun devicectl` comes with Xcode.

2. The Apple account (once)

   Xcode > Settings > Accounts: add your Apple ID.

   Paid account (Apple Developer Program), kit WITH the tunnel extension:
   - Same window: Manage Certificates > + > Apple Development.
   - developer.apple.com > Identifiers > + > App IDs > App, explicit
     Bundle ID @BUNDLE_ID@, capability Network Extensions. A second
     one, @BUNDLE_ID@.tunnel, also with Network Extensions.
   - Devices > +: the iPhone's UDID (`xcrun devicectl list devices`
     with the phone connected, or Xcode > Window > Devices).
   - Profiles > + > iOS App Development, one for each App ID, with your
     certificate and the iPhone.
   - Xcode > Settings > Accounts > your team > Download Manual Profiles.
     The signer finds them there; no need to move files.

   Free account (no Developer Program), kit WITHOUT the extension:
   - Xcode > File > New > Project > iOS App, bundle identifier
     @BUNDLE_ID@ (the bundle id must be yours alone: build the kit with
     your own -Dios-bundle-id, e.g. com.<you>.portal). Signing &
     Capabilities: Automatically manage signing, team = your Personal
     Team. Connect the iPhone, pick it, press Run once. Xcode then holds
     a certificate and a profile for that bundle id.
   - Free profiles last 7 days: run the signer again after that.

3. The iPhone (once)

   Connect it by cable, unlock it and tap Trust. Settings > Privacy &
   Security > Developer Mode: on (it restarts; confirm).

4. The kit

   cd <the folder that holds ios-kit>/ios-kit
   xattr -dr com.apple.quarantine .
   chmod +x portal-ios-sign portal-ios-sign-x86_64
   cp portal-ios.conf.example portal-ios.conf
   open -e portal-ios.conf

   Fill in team_id and account (paid or free). Everything else is found
   when left empty: the comments in the file say how.

5. Sign and install: the one command

   ./portal-ios-sign --install           (Intel Mac: ./portal-ios-sign-x86_64 --install)

   --launch also starts Portal; --help lists the flags. The signer reads
   portal-ios.conf, picks the iPhone, the signing identity and the
   profiles, checks each profile (development, team and App ID, not
   expired, made for the identity's certificate, lists the iPhone, the
   Keychain group, Network Extensions for the tunnel), signs a copy into
   signed/Portal.app, verifies it and installs it. When something is
   missing it says what and where to put it, then stops.

   Success: it prints the identity and profiles it used, "signed
   .../signed/Portal.app", devicectl's install output with the bundle
   id, then "Installed Portal on the iPhone." and the next steps: open
   Portal (Face ID), pair it at the desk (Pair a device, compare the
   check code), then on the phone Scan QR code and Connect.

6. If the app will not install or dies at launch

   otool -L signed/Portal.app/Portal
     only /System/Library/ and /usr/lib/ entries (MoltenVK is opened
     from Frameworks/ at run time and is not listed)
   otool -l signed/Portal.app/Portal | grep -A5 LC_BUILD_VERSION
     platform 2 (iOS), minos 17.0, an sdk version (not 0.0); the same
     for PlugIns/PortalTunnel.appex/PortalTunnel and the MoltenVK binary
   codesign -d --entitlements :- signed/Portal.app
     application-identifier <team>.@BUNDLE_ID@, team-identifier,
     get-task-allow true, keychain-access-groups <team>.@BUNDLE_ID@;
     with the tunnel also networkextension = packet-tunnel-provider (and
     on the extension application-identifier <team>.@BUNDLE_ID@.tunnel
     with the app's Keychain group)
   If codesign complains about "resource fork, Finder information, or
   similar detritus": `xattr -cr .` and run the signer again.

7. Logs

   Console.app > the iPhone in the sidebar > Start streaming, search
   "Portal" (the app; the extension runs as "PortalTunnel"). Why an
   install or launch failed is usually logged by a system process
   (search it, then pick "Process"):

     installd    install refused (profile, bundle id, entitlements)
     amfid       code signature or profile rejected at launch
     dyld        a library or symbol missing at launch
     Sandbox     a file the app may not read
     coreauthd   Face ID
     securityd   Keychain (the device credential, the tunnel key)
     tccd        permissions: camera, microphone, Face ID, Local Network
     nesessionmanager  the VPN session of the tunnel extension
