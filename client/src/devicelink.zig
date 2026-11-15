//! A device's link to its desktop: the pairing code the desk showed
//! (shared/pairqr.zig, version 2), kept on this device, and from it the
//! in-process tunnel (tunnel/root.zig) and the client's dialer and trust.
//! Shared by `portal connect` (connect.zig) and the headless
//! `portalctl sync-device` (src/sync_cli.zig).
//!
//! The code is public data (the desk's public key and where to reach it,
//! the CA's SHA-256, this device's tunnel address): it is kept next to the
//! pinned CA (net/pin.zig) as `tunnel.txt`. Its authenticity is the owner
//! carrying it from the desk's screen (QR or typing) and comparing the
//! desk key's check code on both screens; the device's own key never
//! leaves this machine (tunnel/keys.zig).
//!
//! Where the desk is (the code's ENDPOINT) can change without pairing
//! again; the keys and addresses never do. Only the desk announces a
//! move, `{"t":"endpoint","endpoint":"host:port","seq":N}` on its
//! authenticated WebSocket (`takeAnnouncement`), and the owner can change
//! where THIS device looks (`editedEndpoint`, the "Desktop offline"
//! screen). Both rewrite only the endpoint of the saved code; the desk's
//! last announcement number is kept with it (`endpoint_seq`), so an older
//! announcement replayed later is refused. Nothing a device sends can
//! move the desk.

const std = @import("std");
const Io = std.Io;
const shared = @import("shared");
const pairqr = shared.pairqr;
const tunnelnet = shared.tunnelnet;
const wg = @import("WireGuard");
const tunnel = @import("tunnel/root.zig");
const pin_mod = @import("net/pin.zig");
const x509check = @import("net/x509check.zig");
const client_mod = @import("net/client.zig");
const store_mod = @import("sync/store.zig");

/// The desktop's address inside the tunnel: the same for every desk.
pub const server = tunnelnet.desk_server;

pub const Code = struct {
    text_buf: [pairqr.max_len_tunnel]u8 = undefined,
    text_len: usize = 0,
    desk_key: tunnel.Key,
    ca_sha256: [32]u8,
    device_ip: tunnelnet.Ip4,
    /// "host:port": where in text_buf (the struct is copied by value, so no
    /// slice into itself).
    endpoint_at: usize = 0,
    endpoint_len: usize = 0,
    /// The desk's last endpoint announcement this device took (0: none).
    endpoint_seq: u64 = 0,

    pub fn endpoint(c: *const Code) []const u8 {
        return c.text_buf[c.endpoint_at..][0..c.endpoint_len];
    }

    pub fn text(c: *const Code) []const u8 {
        return c.text_buf[0..c.text_len];
    }

    /// The desk key's check code, for the owner to compare with the desk.
    pub fn deskCheck(c: *const Code) [tunnelnet.check_code_len]u8 {
        return tunnelnet.checkCode(&c.desk_key);
    }

    /// The endpoint is on this machine (tests): bind the UDP socket to
    /// loopback only.
    pub fn loopback(c: *const Code) bool {
        const e = wg.device.config.Endpoint.parse(c.endpoint()) catch return false;
        return std.mem.eql(u8, e.host, "127.0.0.1") or std.mem.eql(u8, e.host, "::1");
    }
};

pub const ParseError = error{ NotPortal, UnsupportedVersion, Malformed, NoTunnel, BadDeskKey, BadEndpoint, BadAddress, BadFingerprint, WrongServer };

/// Parses and checks a pairing code as typed, pasted or scanned. The
/// fixed start ("portal-pair 2 10.8.0.1:8420") may be left out when typing.
pub fn parse(input: []const u8) ParseError!Code {
    var c: Code = .{ .desk_key = undefined, .ca_sha256 = undefined, .device_ip = undefined };
    const t = std.mem.trim(u8, input, " \t\r\n");
    const full = if (std.mem.startsWith(u8, t, pairqr.prefix))
        std.fmt.bufPrint(&c.text_buf, "{s}", .{t})
    else
        std.fmt.bufPrint(&c.text_buf, pairqr.prefix ++ " " ++ pairqr.version_tunnel ++ " " ++ server ++ " {s}", .{t});
    c.text_len = (full catch return error.Malformed).len;
    const p = try pairqr.parse(c.text());
    const tn = p.tunnel orelse return error.NoTunnel;
    if (!std.mem.eql(u8, p.server, server)) return error.WrongServer;
    c.ca_sha256 = pairqr.parseFingerprint(p.ca_sha256) orelse return error.BadFingerprint;
    c.desk_key = wg.device.keys.decode(tn.desk_key) catch return error.BadDeskKey;
    _ = wg.device.config.Endpoint.parse(tn.endpoint) catch return error.BadEndpoint;
    c.endpoint_at = @intFromPtr(tn.endpoint.ptr) - @intFromPtr(&c.text_buf);
    c.endpoint_len = tn.endpoint.len;
    c.device_ip = tunnelnet.parseIp(tn.device_ip) orelse return error.BadAddress;
    if (!tunnelnet.isDeviceIp(c.device_ip)) return error.BadAddress;
    return c;
}

pub fn describe(err: ParseError) []const u8 {
    return switch (err) {
        error.NotPortal, error.Malformed => "That is not a Portal pairing code. Enter the code Pair a device shows at the desk.",
        error.UnsupportedVersion, error.NoTunnel => "That pairing code is for another Portal version: pair again at the desk.",
        error.BadDeskKey => "The desktop's key in the code is damaged: check it against the desk.",
        error.BadEndpoint => "The desktop's endpoint in the code is not HOST:PORT: set it in the desk's Settings and pair again.",
        error.BadAddress => "This device's tunnel address in the code is damaged.",
        error.BadFingerprint => "The certificate's SHA-256 in the code is damaged.",
        error.WrongServer => "That code is not for Portal's tunnel address.",
    };
}

fn path(buf: *[pin_mod.max_path]u8) ![]const u8 {
    var dir_buf: [pin_mod.max_path]u8 = undefined;
    const sdir = try pin_mod.serversDir(&dir_buf);
    return std.fmt.bufPrint(buf, "{s}" ++ std.fs.path.sep_str ++ "tunnel.txt", .{sdir}) catch error.PathTooLong;
}

/// tunnel.txt: the code, then (once the desk announced a move) a line
/// `endpoint_seq N`.
const seq_key = "endpoint_seq ";
const max_file = pairqr.max_len_tunnel + 2 + seq_key.len + 20 + 2;

/// The file's text back to a code (null: damaged).
pub fn parseFile(data: []const u8) ?Code {
    var it = std.mem.splitScalar(u8, data, '\n');
    var c = parse(it.next() orelse return null) catch return null;
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        if (!std.mem.startsWith(u8, line, seq_key)) return null;
        c.endpoint_seq = std.fmt.parseInt(u64, line[seq_key.len..], 10) catch return null;
    }
    return c;
}

pub fn formatFile(c: *const Code, buf: *[max_file]u8) []const u8 {
    if (c.endpoint_seq == 0) return std.fmt.bufPrint(buf, "{s}\n", .{c.text()}) catch unreachable;
    return std.fmt.bufPrint(buf, "{s}\n" ++ seq_key ++ "{d}\n", .{ c.text(), c.endpoint_seq }) catch unreachable;
}

/// The saved pairing code, if this device is paired.
pub fn load(io: Io) ?Code {
    var pb: [pin_mod.max_path]u8 = undefined;
    const p = path(&pb) catch return null;
    var buf: [max_file]u8 = undefined;
    const data = Io.Dir.cwd().readFile(io, p, &buf) catch return null;
    return parseFile(data);
}

/// Saved atomically: a crash leaves the old code or the new one.
pub fn save(io: Io, c: *const Code) !void {
    var pb: [pin_mod.max_path]u8 = undefined;
    const p = try path(&pb);
    if (std.fs.path.dirname(p)) |d| try Io.Dir.cwd().createDirPath(io, d);
    var fb: [max_file]u8 = undefined;
    var ab: [8192]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&ab);
    try store_mod.writeAtomic(fba.allocator(), io, p, formatFile(c, &fb));
}

// ------------------------------------------------------- endpoint moves

/// A "host:port" this device may dial: WireGuard's own parser, a port
/// 1-65535, and only host characters (the code is one line of
/// space-separated fields).
pub fn validEndpoint(text: []const u8) bool {
    if (text.len == 0 or text.len > pairqr.max_endpoint) return false;
    for (text) |ch| switch (ch) {
        'a'...'z', 'A'...'Z', '0'...'9', '.', '-', ':', '[', ']', '%', '_' => {},
        else => return false,
    };
    const e = wg.device.config.Endpoint.parse(text) catch return false;
    return e.port != 0 and e.host.len > 0;
}

/// `c` with only its endpoint replaced (keys, addresses, CA unchanged);
/// error.BadEndpoint unless `validEndpoint`.
pub fn withEndpoint(c: *const Code, endpoint: []const u8) ParseError!Code {
    if (!validEndpoint(endpoint)) return error.BadEndpoint;
    const p = pairqr.parse(c.text()) catch return error.Malformed;
    const tn = p.tunnel orelse return error.NoTunnel;
    var buf: [pairqr.max_len_tunnel]u8 = undefined;
    const text = pairqr.formatTunnel(&buf, p.server, c.ca_sha256, .{ .endpoint = endpoint, .desk_key = tn.desk_key, .device_ip = tn.device_ip }) catch return error.Malformed;
    var out = try parse(text);
    // Nothing but the endpoint may differ.
    if (!std.mem.eql(u8, &out.desk_key, &c.desk_key) or !std.mem.eql(u8, &out.device_ip, &c.device_ip) or
        !std.mem.eql(u8, &out.ca_sha256, &c.ca_sha256)) return error.Malformed;
    out.endpoint_seq = c.endpoint_seq;
    return out;
}

/// The owner's "Change where this device finds the desktop": a port
/// (the host stays) or HOST:PORT, as an endpoint in `buf`; null if not
/// usable. Only this device's own saved code changes with it.
pub fn editedEndpoint(c: *const Code, typed: []const u8, buf: *[pairqr.max_endpoint]u8) ?[]const u8 {
    const t = std.mem.trim(u8, typed, " \t\r\n");
    if (t.len > 0 and t.len <= 5 and std.mem.indexOfNone(u8, t, "0123456789") == null) {
        const port = std.fmt.parseInt(u16, t, 10) catch return null;
        if (port == 0) return null;
        const e = wg.device.config.Endpoint.parse(c.endpoint()) catch return null;
        const v6 = std.mem.indexOfScalar(u8, e.host, ':') != null;
        const out = (if (v6)
            std.fmt.bufPrint(buf, "[{s}]:{d}", .{ e.host, port })
        else
            std.fmt.bufPrint(buf, "{s}:{d}", .{ e.host, port })) catch return null;
        return if (validEndpoint(out)) out else null;
    }
    if (!validEndpoint(t)) return null;
    @memcpy(buf[0..t.len], t);
    return buf[0..t.len];
}

/// The desk's announcement, parsed strictly: exactly `t`, `endpoint` and
/// `seq` (unknown or repeated fields refuse it), so it can never carry a
/// key or an address.
pub const EndpointMessage = struct {
    endpoint_buf: [pairqr.max_endpoint]u8 = undefined,
    endpoint_len: usize = 0,
    seq: u64,

    pub fn endpoint(m: *const EndpointMessage) []const u8 {
        return m.endpoint_buf[0..m.endpoint_len];
    }
};

pub const max_endpoint_message = 512;

pub fn parseEndpointMessage(text: []const u8) ?EndpointMessage {
    if (text.len > max_endpoint_message) return null;
    var buf: [4096]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&buf);
    const Raw = struct { t: []const u8, endpoint: []const u8, seq: u64 };
    const raw = std.json.parseFromSliceLeaky(Raw, fba.allocator(), text, .{ .ignore_unknown_fields = false, .duplicate_field_behavior = .@"error" }) catch return null;
    if (!std.mem.eql(u8, raw.t, "endpoint") or raw.seq == 0 or !validEndpoint(raw.endpoint)) return null;
    var m: EndpointMessage = .{ .seq = raw.seq };
    @memcpy(m.endpoint_buf[0..raw.endpoint.len], raw.endpoint);
    m.endpoint_len = raw.endpoint.len;
    return m;
}

pub const Move = union(enum) {
    /// To save: the code with the new endpoint and seq.
    moved: Code,
    /// The same announcement again (already saved): acknowledged again.
    same,
    /// An older announcement (a replay), or another endpoint under a
    /// number already taken: refused, nothing changes, no ack.
    stale,
};

/// What announcement `m` does to code `c` (pure).
pub fn acceptMove(c: *const Code, m: *const EndpointMessage) Move {
    if (m.seq < c.endpoint_seq) return .stale;
    if (m.seq == c.endpoint_seq) return if (std.mem.eql(u8, m.endpoint(), c.endpoint())) .same else .stale;
    var out = withEndpoint(c, m.endpoint()) catch return .stale;
    out.endpoint_seq = m.seq;
    return .{ .moved = out };
}

/// An announcement taken: acknowledge `seq`; `code` is what is saved now.
pub const Taken = struct { seq: u64, code: Code };

/// The desk announced `text` on its authenticated stream (the caller only
/// passes what arrived there): a valid announcement newer than the saved
/// one is saved, durably, before it may be acknowledged. Null: refused
/// (or not saved), no ack.
pub fn takeAnnouncement(io: Io, text: []const u8) ?Taken {
    const m = parseEndpointMessage(text) orelse return null;
    const c = load(io) orelse return null;
    return switch (acceptMove(&c, &m)) {
        .stale => null,
        .same => .{ .seq = m.seq, .code = c },
        .moved => |n| blk: {
            save(io, &n) catch break :blk null;
            break :blk .{ .seq = m.seq, .code = n };
        },
    };
}

pub fn delete(io: Io) !void {
    var pb: [pin_mod.max_path]u8 = undefined;
    const p = try path(&pb);
    Io.Dir.cwd().deleteFile(io, p) catch |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    };
}

/// Starts this device's tunnel for `c` with `key` (copied in; the caller
/// wipes its own copy): the desk as its only peer, allowed only 10.8.0.1,
/// a keepalive so NAT mappings stay open.
pub fn startTunnel(gpa: std.mem.Allocator, io: Io, c: *const Code, key: *const tunnel.keys.KeyPair) !*tunnel.Tunnel {
    return tunnel.Tunnel.start(gpa, io, .{
        .private_key = key.private,
        .address = c.device_ip,
        .loopback_only = c.loopback(),
        .peers = &.{deskPeer(c)},
    });
}

/// Keeps this device's tunnel pointed where the saved code says the desk
/// is: after the desk's announcement (Client.on_endpoint) and after the
/// owner changed it on this device (`setEndpoint`). Keys and addresses
/// never change; only the tunnel peer's endpoint.
pub const Follower = struct {
    io: Io,
    /// The in-process tunnel; null when the OS runs it (the iPhone's
    /// packet tunnel extension), where the saved endpoint applies when
    /// the app hands it the tunnel next (its next start).
    tun: ?*tunnel.Tunnel,
    /// Bumped by every switch, so an older scheduled one never wins.
    gen: std.atomic.Value(u64) = .init(0),

    /// After an announcement the device keeps the old endpoint this long,
    /// so its acknowledgement still reaches the desk at the old port; the
    /// desk moves once every connected device has acknowledged.
    pub const switch_delay_ms = 1000;

    /// Client.on_endpoint: validated and saved (takeAnnouncement), then the
    /// tunnel follows after `switch_delay_ms`. Returns the seq to ack.
    pub fn onEndpoint(ctx: *anyopaque, text: []const u8) ?u64 {
        const f: *Follower = @ptrCast(@alignCast(ctx));
        const t = takeAnnouncement(f.io, text) orelse return null;
        const g = f.gen.fetchAdd(1, .acq_rel) + 1;
        if (f.tun != null) {
            const th = std.Thread.spawn(.{}, later, .{ f, g, t.code }) catch {
                f.apply(&t.code);
                return t.seq;
            };
            th.detach();
        }
        return t.seq;
    }

    fn later(f: *Follower, g: u64, c: Code) void {
        f.io.sleep(.fromMilliseconds(switch_delay_ms), .awake) catch {};
        if (f.gen.load(.acquire) != g) return;
        f.apply(&c);
    }

    fn apply(f: *Follower, c: *const Code) void {
        const t = f.tun orelse return;
        t.setPeers(&.{deskPeer(c)}) catch |err| std.log.err("tunnel: cannot use the desk's new endpoint now ({t}); it is saved for the next start", .{err});
    }

    pub const SetError = error{ NotPaired, BadEndpoint, SaveFailed };

    /// The owner's "Change where this device finds the desktop": `typed`
    /// is a port or HOST:PORT (editedEndpoint). Changes only this
    /// device's saved code and its tunnel, at once; the desktop is not
    /// asked or told anything. Returns the endpoint now used.
    pub fn setEndpoint(f: *Follower, typed: []const u8) SetError!Code {
        const c = load(f.io) orelse return error.NotPaired;
        var eb: [pairqr.max_endpoint]u8 = undefined;
        const ep = editedEndpoint(&c, typed, &eb) orelse return error.BadEndpoint;
        const n = withEndpoint(&c, ep) catch return error.BadEndpoint;
        save(f.io, &n) catch return error.SaveFailed;
        _ = f.gen.fetchAdd(1, .acq_rel);
        f.apply(&n);
        return n;
    }
};

/// The tunnel's one peer, the desk at `c`'s endpoint: what `startTunnel`
/// configures, and what Tunnel.setPeers gets after a move (same key, same
/// address; only the endpoint differs).
pub fn deskPeer(c: *const Code) tunnel.Peer {
    return .{
        .public_key = c.desk_key,
        .address = tunnelnet.desk_ip,
        .endpoint = c.endpoint(),
        .persistent_keepalive = tunnelnet.persistent_keepalive_s,
    };
}

/// The longest `wgQuick` text (the longest endpoint and the fixed parts).
pub const max_wg_quick = 640;

/// The same tunnel as `startTunnel`, as a wg-quick configuration for a
/// tunnel the OS runs (the iPhone's packet tunnel extension): this device
/// at its tunnel address, the desk as the one peer, allowed only
/// 10.8.0.1, with the keepalive. It holds the private key: the caller
/// wipes `buf` (the iPhone app moves the key to the Keychain first,
/// ios/tunnel_ext/keyref.zig).
pub fn wgQuick(c: *const Code, key: *const tunnel.keys.KeyPair, buf: []u8) error{NoSpaceLeft}![]const u8 {
    var private = wg.device.keys.encode(&key.private);
    defer std.crypto.secureZero(u8, &private);
    const desk = wg.device.keys.encode(&c.desk_key);
    var ib: [tunnelnet.max_ip_text]u8 = undefined;
    var db: [tunnelnet.max_ip_text]u8 = undefined;
    return std.fmt.bufPrint(buf,
        \\[Interface]
        \\PrivateKey = {s}
        \\Address = {s}/32
        \\
        \\[Peer]
        \\PublicKey = {s}
        \\Endpoint = {s}
        \\AllowedIPs = {s}/32
        \\PersistentKeepalive = {d}
        \\
    , .{ &private, tunnelnet.formatIp(c.device_ip, &ib), &desk, c.endpoint(), tunnelnet.formatIp(tunnelnet.desk_ip, &db), tunnelnet.persistent_keepalive_s });
}

/// How the client checks the desktop's certificate: the CA pinned for it,
/// or (first connection after pairing) the SHA-256 from the code. `buf`
/// holds the pinned DER.
pub fn trust(io: Io, c: *const Code, buf: *[x509check.max_cert_len]u8) client_mod.Trust {
    if (pin_mod.Pin.forHost(server)) |p| {
        if (p.load(io, buf) catch null) |der| {
            // A pin for another CA (an earlier pairing): the code wins.
            if (std.mem.eql(u8, &x509check.fingerprint(der), &c.ca_sha256)) return .{ .pinned = der };
        }
    } else |_| {}
    return .{ .fingerprint = c.ca_sha256 };
}

/// Saves the CA a first connection checked by its fingerprint
/// (Client.on_pinned).
pub fn savePin(ctx: *anyopaque, ca_der: []const u8) void {
    const io: *const Io = @ptrCast(@alignCast(ctx));
    const p = pin_mod.Pin.forHost(server) catch return;
    p.save(io.*, ca_der) catch |err| std.debug.print("portal connect: cannot save the pinned CA to {s}: {t}\n", .{ p.path(), err });
}

const testing = std.testing;

test "pairing codes: full, typed without the fixed start, and refused ones" {
    const key = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";
    const fp = "00070E151C232A31383F464D545B626970777E858C939AA1A8AFB6BDC4CBD2D9";
    const c = try parse("portal-pair 2 10.8.0.1:8420 " ++ fp ++ " home.example.org:51820 " ++ key ++ " 10.8.0.2\r\n");
    try testing.expectEqual(tunnelnet.Ip4{ 10, 8, 0, 2 }, c.device_ip);
    try testing.expectEqualStrings("home.example.org:51820", c.endpoint());
    try testing.expect(!c.loopback());
    const short = try parse(fp ++ " 127.0.0.1:51999 " ++ key ++ " 10.8.0.3");
    try testing.expect(short.loopback());
    try testing.expectEqualSlices(u8, &c.desk_key, &short.desk_key);
    try testing.expectError(error.NoTunnel, parse("portal-pair 1 10.8.0.1:8420 " ++ fp));
    try testing.expectError(error.BadAddress, parse(fp ++ " h:1 " ++ key ++ " 10.8.0.1"));
    try testing.expectError(error.BadEndpoint, parse(fp ++ " h " ++ key ++ " 10.8.0.2"));
    try testing.expectError(error.WrongServer, parse("portal-pair 2 10.8.0.9:8420 " ++ fp ++ " h:1 " ++ key ++ " 10.8.0.2"));
    try testing.expectEqualSlices(u8, &tunnelnet.checkCode(&c.desk_key), &c.deskCheck());
}

test "wg-quick text for an OS-run tunnel: parses back to the in-process tunnel's settings" {
    const desk = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";
    const fp = "00070E151C232A31383F464D545B626970777E858C939AA1A8AFB6BDC4CBD2D9";
    const c = try parse(fp ++ " home.example.org:51820 " ++ desk ++ " 10.8.0.3");
    var priv: tunnel.Key = undefined;
    _ = try std.fmt.hexToBytes(&priv, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    const kp = tunnel.keys.KeyPair.fromPrivate(priv);
    var buf: [max_wg_quick]u8 = undefined;
    const text = try wgQuick(&c, &kp, &buf);
    var diag: wg.device.config.Diagnostic = .{};
    var cfg = try wg.device.config.parse(testing.allocator, text, &diag);
    defer cfg.deinit();
    try testing.expectEqualSlices(u8, &priv, &cfg.interface.private_key);
    try testing.expectEqual(@as(usize, 1), cfg.interface.addresses.len);
    try testing.expectEqual(@as(u8, 32), cfg.interface.addresses[0].prefix);
    try testing.expectEqual(@as(usize, 1), cfg.peers.len);
    const p = cfg.peers[0];
    try testing.expectEqualSlices(u8, &c.desk_key, &p.public_key);
    try testing.expectEqualStrings("home.example.org", p.endpoint.?.host);
    try testing.expectEqual(@as(u16, 51820), p.endpoint.?.port);
    try testing.expectEqual(tunnelnet.persistent_keepalive_s, p.persistent_keepalive);
    try testing.expectEqual(@as(usize, 1), p.allowed_ips.len);
    try testing.expect(std.mem.indexOf(u8, text, "Address = 10.8.0.3/32\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "AllowedIPs = 10.8.0.1/32\n") != null);
    // The longest endpoint a pairing code carries still fits.
    try testing.expect(max_wg_quick >= text.len - c.endpoint().len + pairqr.max_endpoint);
    var small: [16]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, wgQuick(&c, &kp, &small));
}

test "endpoint announcement: strict parsing, nothing but the endpoint and seq" {
    const m = parseEndpointMessage("{\"t\":\"endpoint\",\"endpoint\":\"home.example.org:51821\",\"seq\":7}").?;
    try testing.expectEqualStrings("home.example.org:51821", m.endpoint());
    try testing.expectEqual(@as(u64, 7), m.seq);
    try testing.expect(parseEndpointMessage("{\"t\":\"endpoint\",\"endpoint\":\"[2001:db8::1]:51821\",\"seq\":1}") != null);
    const bad = [_][]const u8{
        // Anything that could carry more than the endpoint is refused whole.
        "{\"t\":\"endpoint\",\"endpoint\":\"h:1\",\"seq\":2,\"key\":\"hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=\"}",
        "{\"t\":\"endpoint\",\"endpoint\":\"h:1\",\"seq\":2,\"address\":\"10.8.0.9\"}",
        "{\"t\":\"endpoint\",\"endpoint\":\"h:1\",\"endpoint\":\"x:2\",\"seq\":2}",
        // Not an endpoint, a port out of range, a host that breaks the code.
        "{\"t\":\"endpoint\",\"endpoint\":\"h\",\"seq\":2}",
        "{\"t\":\"endpoint\",\"endpoint\":\"h:0\",\"seq\":2}",
        "{\"t\":\"endpoint\",\"endpoint\":\"h:65536\",\"seq\":2}",
        "{\"t\":\"endpoint\",\"endpoint\":\"h x:1\",\"seq\":2}",
        "{\"t\":\"endpoint\",\"endpoint\":\"h\n10.8.0.9:1\",\"seq\":2}",
        "{\"t\":\"endpoint\",\"endpoint\":\"\",\"seq\":2}",
        // No or a zero sequence number, another message, junk.
        "{\"t\":\"endpoint\",\"endpoint\":\"h:1\"}",
        "{\"t\":\"endpoint\",\"endpoint\":\"h:1\",\"seq\":0}",
        "{\"t\":\"endpoint\",\"endpoint\":\"h:1\",\"seq\":-3}",
        "{\"t\":\"logout\",\"endpoint\":\"h:1\",\"seq\":2}",
        "not json",
    };
    for (bad) |b| try testing.expect(parseEndpointMessage(b) == null);
}

test "endpoint moves: only the endpoint changes; a replayed older announcement is refused" {
    const key = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";
    const fp = "00070E151C232A31383F464D545B626970777E858C939AA1A8AFB6BDC4CBD2D9";
    const c = try parse(fp ++ " home.example.org:51820 " ++ key ++ " 10.8.0.2");
    const m5 = parseEndpointMessage("{\"t\":\"endpoint\",\"endpoint\":\"home.example.org:51821\",\"seq\":5}").?;
    const moved = acceptMove(&c, &m5).moved;
    try testing.expectEqualStrings("home.example.org:51821", moved.endpoint());
    try testing.expectEqual(@as(u64, 5), moved.endpoint_seq);
    try testing.expectEqualSlices(u8, &c.desk_key, &moved.desk_key);
    try testing.expectEqualSlices(u8, &c.ca_sha256, &moved.ca_sha256);
    try testing.expectEqual(c.device_ip, moved.device_ip);
    // Saved and read back with its number.
    var fb: [max_file]u8 = undefined;
    const back = parseFile(formatFile(&moved, &fb)).?;
    try testing.expectEqualStrings("home.example.org:51821", back.endpoint());
    try testing.expectEqual(@as(u64, 5), back.endpoint_seq);
    // A file from before moves existed (the code alone) still reads.
    try testing.expectEqual(@as(u64, 0), parseFile(c.text()).?.endpoint_seq);
    try testing.expect(parseFile("garbage") == null);
    // The same announcement again: acknowledged, nothing to save.
    try testing.expect(acceptMove(&back, &m5) == .same);
    // A replay of an older one, or another endpoint under the same number.
    const m4 = parseEndpointMessage("{\"t\":\"endpoint\",\"endpoint\":\"evil.example.net:1\",\"seq\":4}").?;
    try testing.expect(acceptMove(&back, &m4) == .stale);
    const m5b = parseEndpointMessage("{\"t\":\"endpoint\",\"endpoint\":\"evil.example.net:1\",\"seq\":5}").?;
    try testing.expect(acceptMove(&back, &m5b) == .stale);
    const m6 = parseEndpointMessage("{\"t\":\"endpoint\",\"endpoint\":\"203.0.113.7:4000\",\"seq\":6}").?;
    const again = acceptMove(&back, &m6).moved;
    try testing.expectEqualStrings("203.0.113.7:4000", again.endpoint());
    // The tunnel's peer follows the code: same key and address, new endpoint.
    const p = deskPeer(&again);
    try testing.expectEqualStrings("203.0.113.7:4000", p.endpoint.?);
    try testing.expectEqualSlices(u8, &c.desk_key, &p.public_key);
    try testing.expectEqual(tunnelnet.desk_ip, p.address);
}

test "changing where this device finds the desktop: a port or HOST:PORT, nothing else" {
    const key = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";
    const fp = "00070E151C232A31383F464D545B626970777E858C939AA1A8AFB6BDC4CBD2D9";
    const c = try parse(fp ++ " home.example.org:51820 " ++ key ++ " 10.8.0.2");
    var eb: [pairqr.max_endpoint]u8 = undefined;
    try testing.expectEqualStrings("home.example.org:51900", editedEndpoint(&c, " 51900 ", &eb).?);
    try testing.expectEqualStrings("other.example.org:4000", editedEndpoint(&c, "other.example.org:4000", &eb).?);
    try testing.expect(editedEndpoint(&c, "0", &eb) == null);
    try testing.expect(editedEndpoint(&c, "99999", &eb) == null);
    try testing.expect(editedEndpoint(&c, "other.example.org", &eb) == null);
    try testing.expect(editedEndpoint(&c, "a b:1", &eb) == null);
    const v6 = try parse(fp ++ " [2001:db8::1]:51820 " ++ key ++ " 10.8.0.2");
    try testing.expectEqualStrings("[2001:db8::1]:51901", editedEndpoint(&v6, "51901", &eb).?);
    const n = try withEndpoint(&c, "home.example.org:51900");
    try testing.expectEqualStrings("home.example.org:51900", n.endpoint());
    try testing.expectError(error.BadEndpoint, withEndpoint(&c, "home.example.org"));
}
