# WireGuard setup for Portal (Windows desktop + laptop)

WireGuard is free and open source. You need the official app on both machines:
<https://www.wireguard.com/install/>.

## 0. Check you can receive inbound connections

Plain WireGuard needs your home router to have a public IPv4 address.

1. Look up your public IP from the desktop (for example, search "what is my IP").
2. Compare it with the WAN IP shown on your router's status page.
3. If they differ, or the router's WAN IP starts with `100.64`–`100.127`, `10.`,
   `172.16`–`172.31` or `192.168.`, you are behind **CGNAT**. Port forwarding will
   not work. Ask your ISP for a public IP, or fall back to Tailscale's free
   plan; Portal works the same either way.

If your public IP changes over time, set up a free dynamic DNS name (many
routers have DuckDNS/No-IP built in) and use that name as the laptop's
`Endpoint`.

## 1. Desktop tunnel ("server")

WireGuard app, **Add Tunnel, Add empty tunnel…**. It generates the key pair. Edit it to:

```ini
[Interface]
PrivateKey = <generated, keep>
Address = 10.8.0.1/24
ListenPort = 51820

[Peer]
# laptop
PublicKey = <laptop's public key>
AllowedIPs = 10.8.0.2/32
```

## 2. Laptop tunnel ("client")

```ini
[Interface]
PrivateKey = <generated, keep>
Address = 10.8.0.2/24

[Peer]
# desktop
PublicKey = <desktop's public key>
Endpoint = <home public IP or DDNS name>:51820
AllowedIPs = 10.8.0.1/32
PersistentKeepalive = 25
```

`AllowedIPs = 10.8.0.1/32` sends only Portal traffic through the tunnel; the
rest of your laptop's browsing is unaffected.

## 3. Router

Forward **UDP 51820** to the desktop's LAN IP. Give the desktop a DHCP
reservation so that IP doesn't change. Do **not** forward 8420; Portal is
only reachable through the tunnel. Disable UPnP on the router.

Use a separate WireGuard key pair for each device, so you can revoke one
(e.g. a lost laptop) by deleting its `[Peer]` block.

## 4. Windows firewall on the desktop

Allow Portal's port only from the laptop's tunnel address:

```powershell
New-NetFirewallRule -DisplayName "Portal (WireGuard only)" -Direction Inbound `
  -Protocol TCP -LocalPort 8420 -LocalAddress 10.8.0.1 -RemoteAddress 10.8.0.2 `
  -InterfaceAlias "<your tunnel name>" -Action Allow
```

Each release has its own `portal.exe` path, so Windows may prompt for every
new release. Do **not** click Cancel: that silently creates a *Block* rule for
that exe, and block rules override the allow rule above. Tick **Private
networks** only and click Allow. To list stale per-release rules later:
`Get-NetFirewallApplicationFilter | Where-Object Program -like '*Portal\releases*'`.
The WireGuard app adds its own rule for UDP 51820.

From another machine on your home LAN, confirm `http://<desktop LAN IP>:8420/`
does **not** connect.

## 5. Keep the desktop reachable

* Set the WireGuard tunnel to start automatically, and start `portal run`
  only after the tunnel is up (otherwise binding 10.8.0.1 fails).
* Settings, System, Power: set sleep to **Never** while plugged in (or Portal
  disappears when the desktop sleeps).

## 6. Test

1. Turn the laptop's Wi-Fi off and tether to your phone, so you are genuinely
   outside the home network.
2. Activate the tunnel and open `http://10.8.0.1:8420/`.
3. Sign in; the desktop console title should change to
   `Portal - 1 REMOTE VIEWER CONNECTED`.
