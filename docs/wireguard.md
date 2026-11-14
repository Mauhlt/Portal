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

## Firewall (one rule, added once by an administrator)

The desk's UDP socket is owned by `portal.exe`. Windows asks about it the
first time Portal starts; an answer of "Private" leaves the Public profile
blocked, and the desktop's internet adapter is usually Public. Add one
inbound rule instead, in an **administrator** PowerShell, once:

```powershell
New-NetFirewallRule -DisplayName "Portal tunnel (WireGuard)" -Direction Inbound `
  -Protocol UDP -LocalPort 51820 -Profile Any -Action Allow
```

It is deliberately not tied to a program (every release runs from its own
folder) and covers all profiles: every packet on that port is checked by
WireGuard (only paired keys' handshakes are answered at all). Use your own
port if you changed it in Settings. Portal itself never adds, changes or
removes firewall rules. If Windows still shows its prompt, choose Allow
(never Cancel: that adds a Block rule, which beats the Allow rule).

Nothing else needs an inbound rule: there is no TCP listener on any
adapter (8420 exists only inside the tunnel).

## Settings (desk)

**Settings** (Ctrl+Shift+S) has the tunnel section:

* this desktop's tunnel key and its check code (devices show and compare
  it after entering their pairing code);
* **Tunnel UDP port** (default 51820; a change applies at the next start);
* **Tunnel endpoint for devices**: `HOST:PORT` as devices reach the desk,
  e.g. `home.example.org:51820`. It goes into every pairing code; Portal
  cannot know your public address itself;
* the peers: every paired device with its address and key check code.

`settings.txt`: `tunnel_port = 51820`, `tunnel_endpoint = home.example.org:51820`.

## Tests

The e2e suite runs the same tunnel over UDP on `127.0.0.1` only
(`portalctl run --console --tunnel-loopback`): no adapter, no firewall
prompt, nothing reachable from the network. Its devices are in-process
tunnels (tests/e2e/link.zig) and `portalctl sync-device`.
