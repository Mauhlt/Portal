Which folder goes where
-----------------------
  portal-x86_64-windows   the desktop (the hub, WireGuard 10.8.0.1)
  portal-aarch64-windows  the Snapdragon X laptop (10.8.0.2) and the
                          Surface (10.8.0.4)
  iPhone (10.8.0.3)       no folder: the Portal app (zig build ios)

What is in it
-------------
  portal.exe       the Portal window (desk) and `portal connect`, the
                   remote viewer (laptop, Surface). Never opens a console.
  portalctl.exe    console tool: pair, devices, unpair, ca, version, sync.
  portal-show.exe  shows a PNG inside a session (must stay next to portal.exe).
  The icon is built into the exes. Nothing else is needed: no installer,
  no DLLs. The tunnel is the official WireGuard for Windows app
  (https://www.wireguard.com/install/), which brings its own driver.
  The window needs a Vulkan GPU driver (current Windows GPU drivers,
  including Qualcomm Adreno on Snapdragon X, include it).

Install (each Windows device)
-----------------------------
  1. Copy this folder anywhere, for example
     %LOCALAPPDATA%\Programs\Portal  (keep the three exes together).
  2. Check it:   portalctl version
  3. Optional: pin portal.exe to Start, or put the folder on PATH.
  Settings, devices and certificates live in %LOCALAPPDATA%\Portal, not in
  this folder, so replacing the folder with a newer package keeps them.
  On the desktop, `zig build release` (in the source tree) remains the
  usual way to install and update; this folder is the portable copy.

Pairing, in order (full steps: docs/pairing.md in the source tree)
----------------------------------------------------------------------
  1. Desktop: WireGuard tunnel up (10.8.0.1, UDP 51820 forwarded), firewall
     rule for TCP 8420,8421 from 10.8.0.2,10.8.0.3,10.8.0.4 only. Start
     portal.exe; first run: Listen address 10.8.0.1:8420, the program to
     run, Start.
  2. Laptop (tunnel 10.8.0.2 on): at the desk click Pair a device...
     (Ctrl+Shift+P), name `laptop`, Open pairing. On the laptop run
     `portal connect`, enter 10.8.0.1:8420 and the SHA-256 the desk shows,
     click Pair. At the desk check address 10.8.0.2 and the request code,
     Approve.
  3. Surface (tunnel 10.8.0.4 on): the same, named `surface`.
  4. iPhone (tunnel 10.8.0.3 on): Pair a device, name `iphone`. In the
     Portal app: Scan QR code on the desk's Pair panel. Approve at the desk.
  Approve only when the address and the code match the device in your hand.
