# Installing and pairing the owner's devices

The desktop first (it is the hub every device pairs with), then the laptop,
the Surface and the iPhone. Each device is paired once, approved at the
desk. A device *is* its WireGuard key: there are no passwords, cookies or
sign-in, and nothing secret is ever typed or copied.

| Device | Package | Tunnel address | Pair name |
|---|---|---|---|
| Desktop (hub) | `zig-out/portal-x86_64-windows` (or `zig build release`) | `10.8.0.1` | (none: it is the desk) |
| Snapdragon X laptop | `zig-out/portal-aarch64-windows` | `10.8.0.2` | `laptop` |
| iPhone | the Portal app (`zig build ios`, docs/ios-native.md) | `10.8.0.3` | `iphone` |
| Surface | `zig-out/portal-aarch64-windows` | `10.8.0.4` | `surface` |

Addresses are given in pairing order (pair in this order to get these).

## Building the packages

```powershell
zig build package
```

builds ReleaseSafe and writes one folder per machine type:
`zig-out/portal-x86_64-windows/` for the desktop and
`zig-out/portal-aarch64-windows/` for the laptop and the Surface. Each folder
has `portal.exe`, `portalctl.exe`, `portal-show.exe`, a `README.txt` and
`licenses/`. Copy a folder anywhere on the device (for example
`%LOCALAPPDATA%\Programs\Portal`) and check it with `portalctl version`.

## 1. Desktop (10.8.0.1)

1. **Router**: forward UDP 51820 to the desktop (docs/wireguard.md).
2. **Firewall** (administrator, once): the one inbound UDP rule in
   docs/wireguard.md, "Firewall". This is the only step that needs an
   administrator.
3. **Install**: `zig build release`, or copy `portal-x86_64-windows`.
4. **Start** `portal.exe` (not as administrator). On the first run set the
   **Program to run** (and the tunnel port if not 51820) and click
   **Start**. The first start creates the desk's tunnel key, the Portal CA
   and the sync release key.
5. **Settings**: set **Tunnel endpoint for devices** to your public address
   or dynamic-DNS name and the forwarded port, e.g. `home.example.org:51820`.

## 2. Laptop (10.8.0.2), and the Surface (10.8.0.4) the same way

1. Copy `portal-aarch64-windows` to the laptop and run `portal connect`.
   The window shows **this device's tunnel key** and its **check code**
   (`portal connect --key` prints them too). A check code is 16
   characters in 4 groups, like `ABCD-EFGH-JKMN-PQRS` (80 bits of the
   key's hash): compare every group, not just the first.
2. At the desk: **Pair a device…** (Ctrl+Shift+P): name `laptop`, and the
   key as the laptop shows it (type it; it is 44 characters). Click
   **Check key**: the desk shows the check code of what you typed.
   **Approve only if it is the code the laptop shows.** (Console:
   `portalctl pair laptop <key>`.)
3. The desk then shows the **pairing code** (text and QR):
   `portal-pair 2 10.8.0.1:8420 <CA SHA-256> <endpoint> <desk key> 10.8.0.2`.
   On the laptop, enter it in **Pairing code from the desk** (everything
   after `10.8.0.1:8420` is enough) and press **Connect**.
4. The laptop shows the desk key's check code from that code: press
   **Connect** again only if it is the one Settings shows at the desk.
5. The laptop brings its tunnel up, pins the Portal CA by the SHA-256 in
   the code, pins the release key, and connects. From then on
   `portal connect` needs nothing.

For the Surface, the name `surface`; it gets `10.8.0.4`.

## 3. iPhone (10.8.0.3)

The Portal app runs the same in-process tunnel. On its first-run screen it
shows its key and check code; pair it at the desk as above (name
`iphone`), then tap **Scan QR code** and point it at the pairing code's QR
on the desk, compare the desk's check code, and tap **Connect**.

## Afterwards

* **Devices** (Ctrl+Shift+D, or `portalctl devices`) lists paired devices
  with address, key check code and last use. **Unpair** (or `portalctl
  unpair <name>`) ends its connections at once (the device gets a
  `logout` and forgets this desktop) and takes its key out of the tunnel.
  A device that is offline then only finds the desktop unreachable; forget
  the desktop there yourself (Packages > Forget this desktop, or `portal
  connect --forget`).
* Pairing again under a name, or with a key, already in use removes the
  old record outright; nothing carries over (a re-paired name keeps its
  address).
* A device that forgets the desktop (Packages > Forget this desktop)
  tells the desk through the tunnel, and its record goes there too.
* A device keeps its own key across desktops and re-pairings; `portalctl
  sync-device --drop-key` deletes it (a device reset).
* Devices unused for 90 days are forgotten.
* One desktop per device for now (every desk is `10.8.0.1` inside its own
  tunnel).
