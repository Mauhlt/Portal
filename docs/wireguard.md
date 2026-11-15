# Portal's tunnel: WireGuard inside Portal

Portal carries its own WireGuard: the owner's Zig WireGuard (`../WireGuard`,
module `WireGuard`) and its userspace TCP/IP stack (`netstack`) run inside
`portal.exe` (the desk) and inside `portal connect` / the iPhone app (the
devices). There is no WireGuard app, no Wintun adapter, no driver and no
administrator right involved, and it is Portal's **only** network path:

```
device: portal connect                         desk: portal.exe
  TLS 1.3 + WebSocket (client/src/net)            web.zig (TLS 1.3 + WebSocket)
  netstack TCP, 10.8.0.x  --dial 10.8.0.1:8420->  netstack TCP, 10.8.0.1:8420
  zwg device (one peer: the desk)                 zwg device (one peer per paired device)
  UDP, any port  <------------- internet ------>  UDP 51820 (configurable)
```

* **Addresses** (`shared/tunnelnet.zig`, the one definition): the tunnel is
  `10.8.0.0/24`; the desk is `10.8.0.1` and serves only `10.8.0.1:8420`
  inside the tunnel; devices get `10.8.0.2`, `.3`, ... in pairing order
  (the laptop `.2`, the iPhone `.3`, the Surface `.4` when paired in that
  order). A re-paired device keeps its address.
* **Peers**: the desk's peer table is derived from the device store
  (`devices.txt`): every paired device's public key, allowed only its own
  `/32`. Nothing else is ever let in. Pairing, Unpair and a device's
  Forget change it at once (`Device.setPeers`; sessions of the other
  devices are kept).
* **Keys**: the desk's private key is DPAPI-protected like Portal's other
  private keys (`%LOCALAPPDATA%\Portal\tunnel\desk.key`, public half in
  `desk.pub`). A device's private key lives in its OS credential store:
  Windows Credential Manager, the macOS Keychain, on Linux a 0600 file in
  a 0700 directory (`$XDG_DATA_HOME/portal/secrets`, refused unless both
  are this user's and private). Private keys never leave their machine and
  are wiped from memory after use.
* **Identity**: WireGuard's allowed-IPs check binds a device's address to
  its key, so the desk knows a connection from `10.8.0.x` is that device.
  TLS 1.3 with the pinned Portal CA stays on top, as defence in depth.
* **Event-driven**: the zwg device and the netstack each run one thread
  that sleeps on its sockets, rings and real deadlines; Portal's own
  threads wait for stream readiness in cancelable waits signalled by the
  stack's ready callback (client/src/tunnel/root.zig). Nothing polls.
* **Priorities**: the interactive WebSocket (`/ws`) and the bulk one
  (`/ws/bulk`, sync packages in 16 KiB chunks) are separate TCP
  connections with the stack's `.interactive` and `.bulk` priorities.

## Router

Forward **UDP 51820** (or the port in Settings) to the desktop, and give
the desktop a DHCP reservation so that address doesn't change. Forward
nothing else. Disable UPnP.

Plain WireGuard needs your router to have a public IPv4 address: if the
router's WAN address starts with `100.64`-`100.127`, `10.`,
`172.16`-`172.31` or `192.168.`, you are behind CGNAT and port forwarding
cannot work (ask the ISP for a public address). If the public address
changes, use a dynamic-DNS name: devices look it up again when the desk
stops answering.

## Firewall (one rule, added with one administrator prompt)

The desk's UDP socket is owned by `portal.exe`. Windows asks about it the
first time Portal starts; an answer of "Private" leaves the Public profile
blocked, and the desktop's internet adapter is usually Public. Portal uses
one inbound rule instead, named **Portal tunnel (WireGuard)**: UDP on the
tunnel port, inbound, every profile, allow. Any of these adds it:

* the installer (`portal-setup`, desk): one administrator prompt;
* **Settings → Windows Firewall** (Ctrl+Shift+S): shows whether the rule
  allows the port the tunnel listens on now (read without an
  administrator); a click adds it, or replaces it after a port move, with
  one administrator prompt;
* `portalctl firewall add [--port N]` (`status` and `remove` too);
* by hand, in an **administrator** PowerShell:

```powershell
New-NetFirewallRule -DisplayName "Portal tunnel (WireGuard)" -Direction Inbound `
  -Protocol UDP -LocalPort 51820 -Profile Any -Action Allow
```

The first three are the same code (src/firewall.zig): the Windows
Firewall COM API (INetFwPolicy2), run by this release's `portalctl.exe`
relaunched as administrator (ShellExecuteEx "runas", `--no-elevate` so
it never asks twice). It is idempotent: a matching rule is left alone; a
rule of that name that differs (another port, disabled, a block rule) is
replaced. If you decline the prompt, nothing changes and Portal shows the
command above. Portal changes the rule only when you ask, and never any
other rule. Uninstalling the desk removes it (one prompt).

It is deliberately not tied to a program (every release runs from its own
folder) and covers all profiles: every packet on that port is checked by
WireGuard (only paired keys' handshakes are answered at all). If Windows
still shows its prompt, choose Allow (never Cancel: that adds a Block
rule, which beats the Allow rule).

Nothing else needs an inbound rule: there is no TCP listener on any
adapter (8420 exists only inside the tunnel).

## Settings (desk)

**Settings** (Ctrl+Shift+S) has the tunnel section:

* this desktop's tunnel key and its check code (devices show and compare
  it after entering their pairing code);
* **Tunnel UDP port** (default 51820; a change applies when you save,
  after a confirmation: see "Changing the port");
* **Tunnel endpoint for devices**: `HOST:PORT` as devices reach the desk,
  e.g. `home.example.org:51820`. It goes into every pairing code; Portal
  cannot know your public address itself, and never asks a service on the
  internet (privacy: no third-party lookups). While it is empty, Settings
  opens when the desk starts and lists the router steps (above) next
  to it, and an address on your own network or behind CGNAT is warned
  about;
* **Windows Firewall**: the rule's state for the live port, with Add /
  Replace (see "Firewall");
* the peers: every paired device with its address and key check code.

`settings.txt`: `tunnel_port = 51820`, `tunnel_endpoint = home.example.org:51820`.

**Port clash with another WireGuard.** Portal claims its UDP port
exclusively. If another program holds it (often the official WireGuard
client, which also likes 51820; its tunnels can show up as "System"),
Portal still starts: the window works for local sessions, and Settings
opens with a plain message: the port, the program holding it (Windows
tells the owning process; the name is shown at the desk and in its log
only, never sent to devices) and what to do, "Choose another port in
Settings → Tunnel UDP port, and forward it on your router". The status
line says so until the tunnel listens. Portal never picks another port
by itself. Or give the other tunnel another port (its `ListenPort =
51821`, with its own router forward).

## Changing the port

Only the desk changes the desk's port and endpoint (Settings, or
`portalctl tunnel-port <port> [--endpoint HOST:PORT] --router-forwarded`).
No device message can change, request or influence them.

1. Forward the new UDP port on your router to the desktop **before**
   switching; after the switch, Settings → Windows Firewall shows the rule
   is for the old port and replaces it (one administrator prompt). Portal never changes
   the router: no UPnP, no NAT-PMP.
2. Save Settings with the new port (and/or endpoint). The desk asks to
   confirm ("Forward UDP <new port> on your router before switching").
   If you left the endpoint as it was and its port was the old one, the
   endpoint's port follows the new port.
3. The desk tries the new port first (a taken port stops here, nothing
   told). Then it tells every connected paired device, over its
   authenticated WebSocket, `{"t":"endpoint","endpoint":"host:port","seq":N}`
   (docs/protocol.md, 3i). Each saves it in its pairing code and
   acknowledges; then the desk moves its UDP socket. Keys, addresses,
   peers and sessions stay; devices follow to the new endpoint.
4. Settings shows each paired device: moved, or not yet (offline). A
   device that missed it shows "Desktop offline" with **Change where this
   device finds the desktop**: enter the new port (or HOST:PORT). That
   changes only where that device looks; no pairing again.

The new port and endpoint are saved in `settings.txt` once they took
effect (`--tunnel-port` on the command line still wins at the next start).
On the iPhone with the packet tunnel extension the saved endpoint is used
when the app next hands the tunnel to iOS (its next start).

## Tests

The e2e suite runs the same tunnel over UDP on `127.0.0.1` only
(`portalctl run --console --tunnel-loopback`): no adapter, no firewall
prompt, nothing reachable from the network. Its devices are in-process
tunnels (tests/e2e/link.zig) and `portalctl sync-device`.
