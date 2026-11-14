# Installing and pairing the owner's devices

The order matters: the desktop first (it is the hub every device pairs
with), then the laptop, the Surface and the iPhone. Each device is paired
once, approved at the desk; nothing secret is ever typed on a device.

| Device | Package | WireGuard address | Pair name |
|---|---|---|---|
| Desktop (hub) | `zig-out/portal-x86_64-windows` (or `zig build release`) | `10.8.0.1` | (none: it is the desk) |
| Snapdragon X laptop | `zig-out/portal-aarch64-windows` | `10.8.0.2` | `laptop` |
| iPhone | Safari, or the Portal app (`zig build ios`, docs/ios-native.md) | `10.8.0.3` | `iphone` |
| Surface | `zig-out/portal-aarch64-windows` | `10.8.0.4` | `surface` |

## Building the packages

```powershell
zig build package
```

builds ReleaseSafe and writes one folder per machine type:

* `zig-out/portal-x86_64-windows/` for the desktop;
* `zig-out/portal-aarch64-windows/` for the laptop and the Surface.

Each folder has `portal.exe`, `portalctl.exe`, `portal-show.exe`, a
`README.txt` and `licenses/`. The icon is inside the exes; there are no
DLLs (the tunnel is the WireGuard app's own driver, and Vulkan comes with
the GPU driver). The build checks every exe's PE machine type and
subsystem and writes `zig-out/portal-<arch>-windows-check.txt`.

Copy a folder anywhere on the device (for example
`%LOCALAPPDATA%\Programs\Portal`), keeping the three exes together, and
check it with `portalctl version`. State (settings, paired devices, the
CA, pinned certificates) lives in `%LOCALAPPDATA%\Portal`, so a newer
folder can replace an older one.

## 1. Desktop (10.8.0.1)

1. **WireGuard**: the desktop tunnel as in [wireguard.md](wireguard.md):
   `Address = 10.8.0.1/24`, `ListenPort = 51820`, one `[Peer]` per device
   with its own key (`AllowedIPs = 10.8.0.2/32`, `10.8.0.3/32`,
   `10.8.0.4/32`). Router: forward UDP 51820 to the desktop, nothing else.
2. **Firewall** (Terminal as administrator, with the tunnel up). Windows
   usually files a new WireGuard adapter under **Public** networks, and a
   firewall prompt answered with "Private" adds a *Block* rule for Public
   that beats any Allow rule. So first mark the tunnel Private, then allow
   Portal's ports from the devices' tunnel addresses only:

   ```powershell
   Set-NetConnectionProfile -InterfaceAlias "<your tunnel name>" -NetworkCategory Private
   New-NetFirewallRule -DisplayName "Portal (WireGuard only)" -Direction Inbound `
     -Protocol TCP -LocalPort 8420,8421 -LocalAddress 10.8.0.1 `
     -RemoteAddress 10.8.0.2,10.8.0.3,10.8.0.4 `
     -InterfaceAlias "<your tunnel name>" -Profile Private -Action Allow
   ```

   Check with `Get-NetConnectionProfile`: the tunnel must say Private.
   If Windows asks about `portal.exe` (it can again after each update,
   since every release runs from its own folder), tick **Private networks**
   only and click Allow; never Cancel (that blocks Portal on the tunnel
   too). Leave other networks (Ethernet, Wi-Fi) as they are: Portal
   listens on 10.8.0.1 only.
3. **Install**: `zig build release` (the usual way: tests, promotes, and
   installs launchers in `%LOCALAPPDATA%\Portal\bin`), or copy
   `portal-x86_64-windows`.
4. **Start**: with the tunnel up, start `portal.exe`. On the first run,
   set **Listen address** `10.8.0.1:8420`, the **Program to run**, and
   click **Start**. The first start creates the Portal CA (only valid for
   `10.8.0.0/24` and `127.0.0.1`) and the sync release key.

## 2. Laptop (10.8.0.2)

1. Install WireGuard for Windows (it has an ARM64 build). Tunnel:
   `Address = 10.8.0.2/24`; `[Peer]` the desktop with
   `Endpoint = <home IP or DDNS name>:51820`, `AllowedIPs = 10.8.0.1/32`,
   `PersistentKeepalive = 25`. Turn it on.
2. Copy `portal-aarch64-windows` to the laptop.
3. At the desk: **Pair a device…** (Ctrl+Shift+P), name `laptop`,
   **Open pairing**. The panel shows the CA's SHA-256 and whether the
   certificate download (`http://10.8.0.1:8421/`) is up. The window stays
   open 2 minutes.
4. On the laptop: run `portal connect` (or `portal connect --server
   10.8.0.1:8420`). In **Connect to a Portal** enter `10.8.0.1:8420` and,
   as the certificate, the SHA-256 the desk shows (or the path to an
   exported `portal-ca.pem`). Click **Pair**. The laptop pins that CA for
   this desktop; it never trusts on first use.
5. The laptop shows a request code; the desk asks
   `Pair 'laptop' from 10.8.0.2, code 7f3a?`. Approve only if the address
   is `10.8.0.2` and the code matches (Deny has the focus; `y` approves).
   The laptop signs in by itself and keeps its credential in the Windows
   credential store.
6. If the desk publishes packages the laptop is subscribed to (the voice
   model), the laptop asks "Install voice model?" right after pairing.

Approving a request closes the pairing window, so each device needs its
own **Open pairing**.

## 3. Surface (10.8.0.4)

The same as the laptop, with its own WireGuard key, `Address =
10.8.0.4/24`, the same `portal-aarch64-windows` folder, and the name
`surface`. At the desk check that the request comes from `10.8.0.4`.

## 4. iPhone (10.8.0.3)

1. WireGuard from the App Store; its own key pair, `Address =
   10.8.0.3/32`, `[Peer]` the desktop as above. Turn it on.
2. At the desk: **Pair a device…**, name `iphone`, **Open pairing**.
3. Then either:
   * **Safari**: first trust the Portal CA: open `http://10.8.0.1:8421/`,
     tap *install profile*, then Settings > General > VPN & Device
     Management > install the Portal profile, and Settings > General >
     About > Certificate Trust Settings > **enable full trust** for
     "Portal Local CA". Compare the fingerprint with the one the desk
     shows (the download page is plain HTTP; only that comparison proves
     it is Portal's). Then open `https://10.8.0.1:8420/` and tap **Pair
     this device**. Optional: Share > **Add to Home Screen**.
   * **Portal app** (if installed): on its first-run screen tap **Scan QR
     code** and point it at the QR in the desk's Pair panel. The QR holds
     only the address and the CA's SHA-256 (`portal-pair 1 <IP:PORT>
     <SHA-256>`), nothing secret; the app downloads the CA, checks it
     against that SHA-256 and requests pairing.
4. Approve at the desk when it shows `from 10.8.0.3` and the phone's code.

## Afterwards

* **Devices** (Ctrl+Shift+D, or `portalctl devices`) lists paired devices
  with address and last use. **Unpair** (or `portalctl unpair <name>`)
  revokes one and disconnects its viewers at once. A lost device: unpair
  it and delete its `[Peer]` block on the desktop.
* Pairing again under a name or from an address already in use removes
  the old record outright and ends its sessions; nothing carries over.
* A device that forgets the desktop (Packages > Forget this desktop) is
  removed at the desk too; a device the desk unpaired forgets that
  desktop the next time it connects.
* Devices unused for 90 days are forgotten.
* Always pair through the WireGuard address, even at home: that is the
  address the device uses when away, and credentials are bound to it.
