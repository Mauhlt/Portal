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
  no DLLs, no WireGuard app or driver (Portal runs its own WireGuard
  tunnel inside the process). The window needs a Vulkan GPU driver (current Windows GPU drivers,
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
  1. Desktop: forward UDP 51820 to it and add the one inbound UDP firewall
     rule (docs/wireguard.md). Start portal.exe; first run: the program to
     run, Start. In Settings, set the tunnel endpoint devices reach.
  2. Laptop: run `portal connect`; it shows its key and check code. At the
     desk: Pair a device... (Ctrl+Shift+P), name `laptop`, type the key,
     Check key, and approve only if the check code matches the laptop's.
     Enter the pairing code the desk then shows on the laptop, compare the
     desk's check code, Connect.
  3. Surface: the same, named `surface`.
  4. iPhone: the Portal app shows its key and check code; pair it at the
     desk as above (name `iphone`), then Scan QR code on the desk's
     pairing code and Connect.
