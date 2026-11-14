//! One connection to the Portal server: TCP, then (by default) TLS 1.3 with
//! the server certificate pinned to the Portal CA imported for that server.
//!
//! The TLS protocol itself is std.crypto.tls.Client, configured with
//! `.host = .{ .explicit = "<bare IP>" }` and `.ca = .{ .bundle = ... }`
//! holding only the pinned CA. Two gaps in std are closed here by a "gate"
//! between the socket and std's TLS reader, which hands std the server's
//! handshake one record at a time and holds back the encrypted flight until
//! it has checked the certificate itself:
//!
//!  * On Windows, when the pinned bundle does not contain the issuer, std
//!    falls back to the OS chain engine (crypt32, the Windows root store) and
//!    accepts any certificate Windows trusts, then swaps the system roots
//!    into our bundle. A server with a certificate from some other CA the
//!    user trusts (another Portal's CA installed for a browser, a corporate
//!    TLS-inspection root, a public CA) would be accepted.
//!  * std's certificate parser is not bounds-checked (see x509check.zig):
//!    a malformed certificate from an unauthenticated server can crash it.
//!
//! The gate decrypts the server's handshake records with the handshake
//! traffic secret std reports through its `ssl_key_log` hook (kept in
//! memory only, wiped after the handshake), finds the Certificate message
//! and checks the leaf with bounds-checked code: signed by exactly the pinned
//! CA, valid now, subjectAltName = the server IP, ECDSA P-256. Only then does
//! std get those records. std then checks the same leaf against the same
//! bundle and verifies CertificateVerify / Finished with the leaf's key, so
//! the handshake only completes with the holder of a pinned-CA certificate
//! for this IP. Only TLS 1.3 with TLS_AES_128_GCM_SHA256 or
//! TLS_CHACHA20_POLY1305_SHA256 (what Portal's server offers) is accepted.
//!
//! Every error is returned, never a panic; every buffer is fixed-size.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const tls = std.crypto.tls;
const TlsClient = tls.Client;
const Certificate = std.crypto.Certificate;
const x509check = @import("x509check.zig");
/// The stream seam: an OS socket or the in-process tunnel (shared/transport.zig).
pub const transport = @import("shared").transport;
/// Record protection and the byte cursor: the server's own code
/// (shared/tls13.zig).
const tls13 = @import("shared").tls13;
const Cursor = tls13.Cursor;

const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

const record_len_max = tls.max_ciphertext_len; // 2^14 + 256
const rec_header = tls.record_header_len;
/// Raw handshake bytes held back while the certificate is checked.
const pend_cap = 3 * tls.max_ciphertext_record_len;
/// Decrypted handshake messages up to and including the Certificate.
const hs_cap = 24 * 1024;

pub const Security = union(enum) {
    /// `--insecure-plain-http`: no TLS at all.
    plain,
    tls: Pinned,

    pub const Pinned = struct {
        /// DER of the pinned Portal CA; empty on the first connection after
        /// pairing, when only `ca_sha256` is known.
        ca_der: []const u8,
        /// Bare IP the certificate must name ("10.8.0.1", "::1").
        ip: []const u8,
        /// First connection: the SHA-256 of the Portal CA from the pairing
        /// code. The server sends its CA in the chain; only a certificate
        /// with exactly this fingerprint is taken as the CA (and pinned by
        /// the caller afterwards, Conn.caDer). Never trust on first use.
        ca_sha256: ?[32]u8 = null,
    };
};

pub const GateError = error{
    NotTls13,
    UnsupportedCipherSuite,
    HelloRetryRequest,
    TlsHandshakeMalformed,
    TlsHandshakeTooLarge,
    NoHandshakeSecret,
    NoServerCertificate,
    /// A handshake message whose lengths do not add up.
    TlsDecodeError,
} || x509check.PinError;

/// Releases socket bytes to std's TLS reader (as its `input`). In plain mode
/// and after the certificate check it passes bytes straight through.
const Gate = struct {
    interface: Io.Reader,
    io: Io,
    stream: transport.Stream,
    read_err: ?anyerror = null,
    gate_err: ?GateError = null,
    /// The watchdog's stop flag (Conn.openWatched) and this connection's
    /// own (Conn.halt): once either is set no read or write blocks again,
    /// so a swallowed cancelation cannot leave a task stuck.
    stop: ?*const std.atomic.Value(bool) = null,
    halted: std.atomic.Value(bool) = .init(false),
    /// Sticky: once failed, every later read fails too.
    failed: bool = false,
    buf: [tls.max_ciphertext_record_len]u8 = undefined,

    gating: bool,
    insp: Inspector = .{},
    /// std's bundle, filled from the chain on a first connection
    /// (Security.Pinned.ca_sha256).
    bundle: ?*Certificate.Bundle = null,
    gpa: std.mem.Allocator = undefined,
    /// Bytes read from the socket and not yet handed to std.
    pend: [pend_cap]u8 = undefined,
    pend_len: usize = 0,
    /// pend[0..allowed] may be released; pend[0..inspected] has been looked at.
    allowed: usize = 0,
    inspected: usize = 0,

    const vtable: Io.Reader.VTable = .{ .stream = streamFn, .readVec = readVecFn };

    fn init(g: *Gate, io: Io, stream: transport.Stream, gating: bool) void {
        g.* = .{
            .interface = .{ .vtable = &vtable, .buffer = undefined, .seek = 0, .end = 0 },
            .io = io,
            .stream = stream,
            .gating = gating,
        };
        g.interface.buffer = &g.buf;
    }

    fn streamFn(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        _ = w;
        _ = limit;
        try fillSome(r);
        return 0;
    }

    fn readVecFn(r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        _ = data;
        try fillSome(r);
        return 0;
    }

    fn fail(g: *Gate, err: GateError) error{ReadFailed} {
        g.gate_err = err;
        g.failed = true;
        return error.ReadFailed;
    }

    /// Adds at least one byte to `r.buffer`, or fails.
    fn fillSome(r: *Io.Reader) Io.Reader.Error!void {
        const g: *Gate = @alignCast(@fieldParentPtr("interface", r));
        if (g.failed) return error.ReadFailed;
        if (r.seek == r.end) {
            r.seek = 0;
            r.end = 0;
        } else if (r.end == r.buffer.len) {
            const n = r.end - r.seek;
            std.mem.copyForwards(u8, r.buffer[0..n], r.buffer[r.seek..r.end]);
            r.seek = 0;
            r.end = n;
        }
        const space = r.buffer[r.end..];
        if (space.len == 0) return error.ReadFailed; // cannot happen: std rebases first
        while (true) {
            if (g.gating) g.insp.run(g) catch |err| return g.fail(err);
            if (g.allowed > 0) {
                const n = @min(g.allowed, space.len);
                @memcpy(space[0..n], g.pend[0..n]);
                std.mem.copyForwards(u8, g.pend[0 .. g.pend_len - n], g.pend[n..g.pend_len]);
                g.pend_len -= n;
                g.allowed -= n;
                g.inspected -= @min(g.inspected, n);
                r.end += n;
                return;
            }
            if (!g.gating) {
                // Pass-through (pend is empty here).
                const n = try g.sockRead(space);
                r.end += n;
                return;
            }
            // Gating and nothing releasable: std is waiting for records we
            // hold. Without the handshake secret we can never release them.
            if (g.insp.stage == .encrypted and !g.insp.haveKey()) return g.fail(error.NoHandshakeSecret);
            if (g.pend_len == g.pend.len) return g.fail(error.TlsHandshakeTooLarge);
            g.pend_len += try g.sockRead(g.pend[g.pend_len..]);
        }
    }

    fn stopped(g: *const Gate) bool {
        if (g.halted.load(.seq_cst)) return true;
        if (g.stop) |s| return s.load(.seq_cst);
        return false;
    }

    fn sockRead(g: *Gate, dest: []u8) Io.Reader.Error!usize {
        if (g.stopped()) {
            g.read_err = error.Canceled;
            return error.ReadFailed;
        }
        const n = g.stream.read(g.io, dest) catch |err| {
            g.read_err = err;
            return error.ReadFailed;
        };
        if (n == 0) return error.EndOfStream;
        return n;
    }
};

/// Follows the server's first flight: ServerHello (cleartext), then the
/// encrypted EncryptedExtensions and Certificate.
const Inspector = struct {
    stage: enum { hello, encrypted, done } = .hello,
    suite: tls13.Suite = .aes_128_gcm_sha256,
    keylog_buf: [512]u8 = undefined,
    keylog: Io.Writer = undefined,
    /// The server's handshake traffic protection, once `key_ready`.
    traffic: tls13.Traffic = undefined,
    key_ready: bool = false,
    hs: [hs_cap]u8 = undefined,
    hs_len: usize = 0,
    hs_pos: usize = 0,
    seen_ee: bool = false,
    pin: Security.Pinned = .{ .ca_der = "", .ip = "" },
    now_sec: i64 = 0,
    /// The CA found in the chain by its fingerprint (first connection).
    found_ca: [x509check.max_cert_len]u8 = undefined,
    found_ca_len: usize = 0,

    fn haveKey(i: *Inspector) bool {
        if (i.key_ready) return true;
        i.loadKey() catch return false;
        return true;
    }

    fn wipe(i: *Inspector) void {
        std.crypto.secureZero(u8, &i.keylog_buf);
        if (i.key_ready) i.traffic.wipe();
        std.crypto.secureZero(u8, &i.hs);
        i.key_ready = false;
    }

    /// "SERVER_HANDSHAKE_TRAFFIC_SECRET <client random hex> <secret hex>\n"
    fn loadKey(i: *Inspector) error{NoHandshakeSecret}!void {
        const text = i.keylog.buffered();
        const label = "SERVER_HANDSHAKE_TRAFFIC_SECRET ";
        const at = std.mem.indexOf(u8, text, label) orelse return error.NoHandshakeSecret;
        const rest = text[at + label.len ..];
        if (rest.len < 64 + 1 + 64 + 1 or rest[64] != ' ' or rest[64 + 1 + 64] != '\n') return error.NoHandshakeSecret;
        var secret: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &secret);
        _ = std.fmt.hexToBytes(&secret, rest[65..][0..64]) catch return error.NoHandshakeSecret;
        i.traffic = .init(i.suite, secret);
        i.key_ready = true;
    }

    /// Inspects complete records after `g.inspected` and moves `g.allowed`.
    fn run(i: *Inspector, g: *Gate) GateError!void {
        while (g.gating) {
            const avail = g.pend[g.inspected..g.pend_len];
            if (avail.len < rec_header) return;
            const ct = avail[0];
            const len = std.mem.readInt(u16, avail[3..5], .big);
            if (len > record_len_max) return error.TlsHandshakeMalformed;
            if (avail.len < rec_header + len) return;
            const header = avail[0..rec_header];
            const body = avail[rec_header..][0..len];
            const rec_end = g.inspected + rec_header + len;
            switch (i.stage) {
                .hello => switch (ct) {
                    22 => {
                        try i.serverHello(body);
                        i.stage = .encrypted;
                        g.allowed = rec_end;
                    },
                    21 => g.allowed = rec_end, // alert: std reports it
                    else => return error.TlsHandshakeMalformed,
                },
                .encrypted => switch (ct) {
                    20 => { // legacy change_cipher_spec
                        if (len != 1 or body[0] != 1) return error.TlsHandshakeMalformed;
                        if (g.allowed == g.inspected) g.allowed = rec_end;
                    },
                    21 => { // cleartext alert: let std report it; nothing after it is used
                        g.allowed = rec_end;
                        g.gating = false;
                        g.pend_len = rec_end;
                        return;
                    },
                    23 => {
                        if (!i.haveKey()) return; // std has not processed ServerHello yet
                        const inner = try i.decrypt(header, body);
                        switch (inner) {
                            22 => {},
                            21 => { // encrypted alert: std decrypts and reports it
                                g.allowed = rec_end;
                                g.gating = false;
                                g.pend_len = rec_end;
                                return;
                            },
                            else => return error.TlsHandshakeMalformed,
                        }
                        g.inspected = rec_end;
                        if (try i.messages()) {
                            // A CA taken from the chain by its fingerprint
                            // goes into std's (still empty) bundle before
                            // std sees the Certificate message.
                            if (i.found_ca_len > 0) if (g.bundle) |b| {
                                b.bytes.appendSlice(g.gpa, i.found_ca[0..i.found_ca_len]) catch return error.TlsHandshakeTooLarge;
                                b.parseCert(g.gpa, 0, i.now_sec) catch return error.NotIssuedByPinnedCa;
                            };
                            i.stage = .done;
                            i.wipe();
                            g.allowed = g.pend_len;
                            g.gating = false;
                        }
                        continue;
                    },
                    else => return error.TlsHandshakeMalformed,
                },
                .done => return,
            }
            g.inspected = rec_end;
        }
    }

    fn serverHello(i: *Inspector, body: []const u8) GateError!void {
        var d: Cursor = .{ .b = body };
        if (try d.int(u8) != 2) return error.TlsHandshakeMalformed; // server_hello
        const mlen = try d.int(u24);
        if (mlen != d.left()) return error.TlsHandshakeMalformed; // one message, whole
        _ = try d.int(u16); // legacy_version
        const random = try d.bytes(32);
        if (std.mem.eql(u8, random, &tls.hello_retry_request_sequence)) return error.HelloRetryRequest;
        _ = try d.vec(u8); // legacy_session_id_echo (std checks it)
        const suite = try d.int(u16);
        _ = try d.int(u8); // compression
        var ext: Cursor = .{ .b = try d.vec(u16) };
        if (d.left() != 0) return error.TlsHandshakeMalformed;
        var version: ?u16 = null;
        while (ext.left() > 0) {
            const et = try ext.int(u16);
            var e: Cursor = .{ .b = try ext.vec(u16) };
            if (et == 43) { // supported_versions
                if (version != null) return error.TlsHandshakeMalformed;
                version = try e.int(u16);
            }
        }
        if (version != 0x0304) return error.NotTls13;
        i.suite = tls13.Suite.fromCode(suite) orelse return error.UnsupportedCipherSuite;
    }

    /// Decrypts one record into `hs` (with the server's own record code,
    /// shared/tls13.zig); returns the inner content type.
    fn decrypt(i: *Inspector, header: *const [5]u8, body: []const u8) GateError!u8 {
        if (body.len < tls13.tag_len + 1) return error.TlsHandshakeMalformed;
        if (hs_cap - i.hs_len < body.len - tls13.tag_len) return error.TlsHandshakeTooLarge;
        const o = i.traffic.open(header, body, i.hs[i.hs_len..]) catch return error.TlsHandshakeMalformed;
        if (o.content_type == 22) i.hs_len += o.len;
        return o.content_type;
    }

    /// Processes complete handshake messages; true once the certificate
    /// has been checked.
    fn messages(i: *Inspector) GateError!bool {
        while (true) {
            const avail = i.hs[i.hs_pos..i.hs_len];
            if (avail.len < 4) return false;
            const mlen = std.mem.readInt(u24, avail[1..4], .big);
            if (mlen > hs_cap - 4) return error.TlsHandshakeTooLarge;
            if (avail.len < 4 + mlen) return false;
            const body = avail[4..][0..mlen];
            switch (avail[0]) {
                8 => { // encrypted_extensions
                    if (i.seen_ee) return error.TlsHandshakeMalformed;
                    i.seen_ee = true;
                },
                13 => if (!i.seen_ee) return error.TlsHandshakeMalformed, // certificate_request
                11 => {
                    if (!i.seen_ee) return error.TlsHandshakeMalformed;
                    try i.certificate(body);
                    return true;
                },
                else => return error.NoServerCertificate,
            }
            i.hs_pos += 4 + mlen;
        }
    }

    fn certificate(i: *Inspector, body: []const u8) GateError!void {
        var d: Cursor = .{ .b = body };
        if (try d.int(u8) != 0) return error.TlsHandshakeMalformed; // certificate_request_context
        var list: Cursor = .{ .b = try d.vec(u24) };
        if (d.left() != 0) return error.TlsHandshakeMalformed;
        if (list.left() == 0) return error.NoServerCertificate;
        const leaf = try list.vec(u24);
        _ = try list.vec(u16); // extensions
        // Further entries (the Portal CA itself) are allowed; std walks them
        // only after the leaf, which it must also find signed by the
        // pinned CA.
        while (list.left() > 0) {
            const cert = try list.vec(u24);
            try x509check.validateCertificate(cert);
            _ = try list.vec(u16);
            if (i.pin.ca_der.len == 0) if (i.pin.ca_sha256) |want| {
                if (std.mem.eql(u8, &x509check.fingerprint(cert), &want) and cert.len <= i.found_ca.len) {
                    @memcpy(i.found_ca[0..cert.len], cert);
                    i.found_ca_len = cert.len;
                }
            };
        }
        if (i.pin.ca_der.len == 0) {
            if (i.found_ca_len == 0) return error.NotIssuedByPinnedCa;
            i.pin.ca_der = i.found_ca[0..i.found_ca_len];
        }
        try x509check.verifyLeaf(leaf, i.pin.ca_der, i.pin.ip, i.now_sec);
    }
};

pub const Conn = struct {
    io: Io,
    stream: transport.Stream,
    gate: Gate,
    sock_writer: transport.Writer,
    out_buf: [tls.max_ciphertext_record_len]u8,
    tls_read_buf: [tls.max_ciphertext_record_len]u8,
    tls_write_buf: [tls.max_ciphertext_record_len]u8,
    client: ?TlsClient,
    key_log: TlsClient.SslKeyLog,
    bundle: Certificate.Bundle,
    bundle_lock: Io.RwLock,

    pub const OpenError = error{ TlsHandshakeFailed, OutOfMemory, NoEntropy } ||
        GateError || TlsClient.InitError || transport.DialError;

    /// Connects (through `dialer`: an OS socket or the in-process tunnel)
    /// and, unless `security` is `.plain`, completes the TLS handshake.
    pub fn open(gpa: std.mem.Allocator, io: Io, dialer: transport.Dialer, addr: net.IpAddress, security: Security) OpenError!*Conn {
        return openWatched(gpa, io, dialer, addr, security, null);
    }

    /// `open` for a task under a watchdog: `stop` is its `stopped` flag
    /// (watchdog.zig); once set, every read and write of the connection
    /// fails with error.Canceled instead of blocking.
    pub fn openWatched(gpa: std.mem.Allocator, io: Io, dialer: transport.Dialer, addr: net.IpAddress, security: Security, stop: ?*const std.atomic.Value(bool)) OpenError!*Conn {
        const stream = try dialer.dial(io, addr);
        errdefer stream.close(io);
        const c = try gpa.create(Conn);
        errdefer gpa.destroy(c);
        c.io = io;
        c.stream = stream;
        c.client = null;
        c.bundle = .empty;
        c.bundle_lock = .init;
        c.gate.init(io, stream, security == .tls);
        c.gate.stop = stop;
        c.sock_writer = stream.writer(io, &c.out_buf);
        const pin = switch (security) {
            .plain => return c,
            .tls => |p| p,
        };
        errdefer c.bundle.deinit(gpa);
        errdefer c.gate.insp.wipe();

        const now = Io.Clock.real.now(io);
        const insp = &c.gate.insp;
        insp.pin = pin;
        insp.now_sec = now.toSeconds();
        insp.keylog = .fixed(&insp.keylog_buf);
        c.key_log = .{ .client_key_seq = 0, .server_key_seq = 0, .client_random = undefined, .writer = &insp.keylog };

        // A fresh bundle holding only the pinned CA (std may replace a
        // bundle's contents on Windows; see the file comment). On a first
        // connection the gate adds the CA it found by fingerprint.
        if (pin.ca_der.len > 0) {
            _ = x509check.parse(pin.ca_der) catch |err| return err;
            try c.bundle.bytes.appendSlice(gpa, pin.ca_der);
            c.bundle.parseCert(gpa, 0, insp.now_sec) catch return error.CaExpired;
            if (c.bundle.map.count() != 1) return error.CaExpired; // std drops expired CAs
        } else if (pin.ca_sha256 == null) return error.NotIssuedByPinnedCa;
        c.gate.bundle = &c.bundle;
        c.gate.gpa = gpa;

        var entropy: [TlsClient.Options.entropy_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &entropy);
        io.randomSecure(&entropy) catch return error.NoEntropy;

        var alert: tls.Alert = undefined;
        c.client = TlsClient.init(&c.gate.interface, c.sock_writer.interface(), .{
            .host = .{ .explicit = pin.ip },
            .ca = .{ .bundle = .{ .gpa = gpa, .io = io, .lock = &c.bundle_lock, .bundle = &c.bundle } },
            .write_buffer = &c.tls_write_buf,
            .read_buffer = &c.tls_read_buf,
            .entropy = &entropy,
            .realtime_now = now,
            .ssl_key_log = &c.key_log,
            .alert = &alert,
        }) catch |err| {
            if (c.gate.gate_err) |g| return g;
            if (c.gate.read_err) |r| if (r == error.Canceled) return error.Canceled;
            if (c.sock_writer.err()) |e| if (e == error.Canceled) return error.Canceled;
            return err;
        };
        // The certificate must have gone through the gate, and std must
        // have checked it against exactly one CA.
        if (c.gate.insp.stage != .done or c.bundle.map.count() != 1) {
            c.client = null;
            return error.NoServerCertificate;
        }
        c.client.?.ssl_key_log = null;
        c.gate.insp.wipe();
        return c;
    }

    /// The CA the server's certificate was checked against (DER): on a
    /// first connection, the one found by its fingerprint, for the caller
    /// to pin.
    pub fn caDer(c: *const Conn) []const u8 {
        return c.bundle.bytes.items;
    }

    /// Writes and flushes all of `bytes`.
    pub fn writeAll(c: *Conn, bytes: []const u8) error{ WriteFailed, Canceled }!void {
        if (c.gate.stopped()) return error.Canceled;
        c.writeAllInner(bytes) catch {
            if (c.sock_writer.err()) |e| if (e == error.Canceled) return error.Canceled;
            return error.WriteFailed;
        };
    }

    fn writeAllInner(c: *Conn, bytes: []const u8) Io.Writer.Error!void {
        if (c.client) |*cl| {
            try cl.writer.writeAll(bytes);
            try cl.writer.flush();
        } else {
            try c.sock_writer.interface().writeAll(bytes);
        }
        try c.sock_writer.interface().flush();
    }

    /// Reads what is available (at least one byte); 0 at end of stream.
    pub fn read(c: *Conn, buf: []u8) error{ ReadFailed, Canceled }!usize {
        if (buf.len == 0) return 0;
        if (c.gate.stopped()) return error.Canceled;
        const r: *Io.Reader = if (c.client) |*cl| &cl.reader else &c.gate.interface;
        while (r.bufferedLen() == 0) {
            r.fillMore() catch |err| switch (err) {
                error.EndOfStream => return 0,
                error.ReadFailed => {
                    if (c.gate.read_err) |e| if (e == error.Canceled) return error.Canceled;
                    return error.ReadFailed;
                },
            };
        }
        const n = @min(buf.len, r.bufferedLen());
        @memcpy(buf[0..n], r.buffered()[0..n]);
        r.toss(n);
        return n;
    }

    /// Makes every later read and write fail with error.Canceled instead
    /// of blocking (any thread); used with a cancel of the task doing them.
    pub fn halt(c: *Conn) void {
        c.gate.halted.store(true, .seq_cst);
    }

    pub fn stopped(c: *const Conn) bool {
        return c.gate.stopped();
    }

    /// Closes the socket and frees the connection (not thread-safe with
    /// concurrent reads/writes: the caller stops those first).
    pub fn close(c: *Conn, gpa: std.mem.Allocator) void {
        // No close_notify: a send to a stalled server could block here.
        c.stream.close(c.io);
        c.bundle.deinit(gpa);
        // Everything: the buffers, and std's TlsClient state with the
        // application traffic keys.
        std.crypto.secureZero(u8, std.mem.asBytes(c));
        gpa.destroy(c);
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;
const testdata = @import("testdata.zig");

/// Builds a server flight (ServerHello + CCS + encrypted EE/Certificate)
/// and runs it through the inspector the way the gate does.
const FakeFlight = struct {
    buf: [8192]u8 = undefined,
    len: usize = 0,
    secret: [32]u8 = @splat(0x42),
    seq: u64 = 0,

    fn add(f: *FakeFlight, bytes: []const u8) void {
        @memcpy(f.buf[f.len..][0..bytes.len], bytes);
        f.len += bytes.len;
    }

    fn serverHello(f: *FakeFlight, suite: u16, version: u16, random: [32]u8) void {
        var b: [128]u8 = undefined;
        var w: Io.Writer = .fixed(&b);
        w.writeInt(u16, 0x0303, .big) catch unreachable;
        w.writeAll(&random) catch unreachable;
        w.writeByte(0) catch unreachable;
        w.writeInt(u16, suite, .big) catch unreachable;
        w.writeByte(0) catch unreachable;
        w.writeInt(u16, 6, .big) catch unreachable;
        w.writeInt(u16, 43, .big) catch unreachable;
        w.writeInt(u16, 2, .big) catch unreachable;
        w.writeInt(u16, version, .big) catch unreachable;
        const body = w.buffered();
        f.add(&.{ 22, 3, 3 });
        var l: [2]u8 = undefined;
        std.mem.writeInt(u16, &l, @intCast(body.len + 4), .big);
        f.add(&l);
        f.add(&.{ 2, 0, 0, @intCast(body.len) });
        f.add(body);
    }

    fn encrypted(f: *FakeFlight, inner_type: u8, plain: []const u8) void {
        const key = tls.hkdfExpandLabel(Hkdf, f.secret, "key", "", 16);
        const iv = tls.hkdfExpandLabel(Hkdf, f.secret, "iv", "", 12);
        var nonce = iv;
        var seq_be: [8]u8 = undefined;
        std.mem.writeInt(u64, &seq_be, f.seq, .big);
        for (0..8) |k| nonce[4 + k] ^= seq_be[k];
        f.seq += 1;
        var inner: [4096]u8 = undefined;
        @memcpy(inner[0..plain.len], plain);
        inner[plain.len] = inner_type;
        const n = plain.len + 1;
        var header: [5]u8 = .{ 23, 3, 3, 0, 0 };
        std.mem.writeInt(u16, header[3..5], @intCast(n + 16), .big);
        f.add(&header);
        var tag: [16]u8 = undefined;
        Aes128Gcm.encrypt(f.buf[f.len..][0..n], &tag, inner[0..n], &header, nonce, key);
        f.len += n;
        f.add(&tag);
    }

    fn certMessage(out: []u8, cert: []const u8) []const u8 {
        const body_len = 1 + 3 + 3 + cert.len + 2;
        out[0] = 11;
        std.mem.writeInt(u24, out[1..4], @intCast(body_len), .big);
        out[4] = 0;
        std.mem.writeInt(u24, out[5..8], @intCast(3 + cert.len + 2), .big);
        std.mem.writeInt(u24, out[8..11], @intCast(cert.len), .big);
        @memcpy(out[11..][0..cert.len], cert);
        out[11 + cert.len] = 0;
        out[12 + cert.len] = 0;
        return out[0 .. 4 + body_len];
    }

    /// Feeds the flight in `chunk`-sized pieces; returns the gate result
    /// once all records are inspected, plus how many bytes were released.
    fn run(f: *FakeFlight, pin: Security.Pinned, chunk: usize) !usize {
        var g: Gate = undefined;
        g.init(testing.io, undefined, true);
        g.insp.pin = pin;
        g.insp.now_sec = testdata.now_sec;
        g.insp.keylog = .fixed(&g.insp.keylog_buf);
        var off: usize = 0;
        var released: usize = 0;
        while (off < f.len) {
            const n = @min(chunk, f.len - off);
            @memcpy(g.pend[g.pend_len..][0..n], f.buf[off..][0..n]);
            g.pend_len += n;
            off += n;
            try g.insp.run(&g);
            // Releasing ServerHello lets "std" derive and log the secret.
            if (g.allowed > 0 and !g.insp.key_ready and g.insp.stage == .encrypted) {
                g.insp.keylog.print("SERVER_HANDSHAKE_TRAFFIC_SECRET {x} {x}\n", .{ @as([32]u8, @splat(7)), f.secret }) catch unreachable;
                try g.insp.run(&g);
            }
            if (!g.gating) g.allowed = g.pend_len; // pass-through
            released += g.allowed;
            std.mem.copyForwards(u8, g.pend[0 .. g.pend_len - g.allowed], g.pend[g.allowed..g.pend_len]);
            g.pend_len -= g.allowed;
            g.inspected -= @min(g.inspected, g.allowed);
            g.allowed = 0;
        }
        if (g.gating) return error.StillGating;
        return released;
    }
};

const pin_ok: Security.Pinned = .{ .ca_der = testdata.ca_der, .ip = testdata.leaf_ip };

fn flight(f: *FakeFlight, leaf: []const u8) void {
    f.serverHello(0x1301, 0x0304, @splat(1));
    f.add(&.{ 20, 3, 3, 0, 1, 1 });
    f.encrypted(22, &.{ 8, 0, 0, 2, 0, 0 });
    var m: [2048]u8 = undefined;
    f.encrypted(22, FakeFlight.certMessage(&m, leaf));
    f.encrypted(22, &.{ 15, 0, 0, 0 }); // CertificateVerify placeholder: passed on unchecked
}

test "gate: a pinned-CA certificate passes, in any chunking" {
    for ([_]usize{ 1, 3, 7, 64, 100000 }) |chunk| {
        var f: FakeFlight = .{};
        flight(&f, testdata.leaf_der);
        try testing.expectEqual(f.len, try f.run(pin_ok, chunk));
    }
}

test "gate: wrong CA, wrong IP, bad TLS parameters are refused before std sees the certificate" {
    var f: FakeFlight = .{};
    flight(&f, testdata.leaf_der);
    try testing.expectError(error.NotIssuedByPinnedCa, f.run(.{ .ca_der = testdata.other_ca_der, .ip = testdata.leaf_ip }, 4096));
    try testing.expectError(error.HostMismatch, f.run(.{ .ca_der = testdata.ca_der, .ip = "10.8.0.1" }, 4096));

    var v12: FakeFlight = .{};
    v12.serverHello(0x1301, 0x0303, @splat(1));
    try testing.expectError(error.NotTls13, v12.run(pin_ok, 4096));
    var suite: FakeFlight = .{};
    suite.serverHello(0x1302, 0x0304, @splat(1));
    try testing.expectError(error.UnsupportedCipherSuite, suite.run(pin_ok, 4096));
    var hrr: FakeFlight = .{};
    hrr.serverHello(0x1301, 0x0304, tls.hello_retry_request_sequence);
    try testing.expectError(error.HelloRetryRequest, hrr.run(pin_ok, 4096));

    // Finished without a certificate (PSK-style flight).
    var nocert: FakeFlight = .{};
    nocert.serverHello(0x1301, 0x0304, @splat(1));
    nocert.encrypted(22, &.{ 8, 0, 0, 2, 0, 0 });
    nocert.encrypted(22, &.{ 20, 0, 0, 0 });
    try testing.expectError(error.NoServerCertificate, nocert.run(pin_ok, 4096));

    // A self-signed certificate is not the pinned CA.
    var self: FakeFlight = .{};
    flight(&self, testdata.other_ca_der);
    try testing.expectError(error.NotIssuedByPinnedCa, self.run(pin_ok, 4096));
}

test "fuzz: gate never panics on random or mutated flights" {
    var prng = std.Random.DefaultPrng.init(5);
    const rand = prng.random();
    var base: FakeFlight = .{};
    flight(&base, testdata.leaf_der);
    for (0..3000) |round| {
        var f = base;
        if (round % 2 == 0) {
            for (0..1 + rand.uintLessThan(usize, 4)) |_| f.buf[rand.uintLessThan(usize, f.len)] = rand.int(u8);
        } else {
            f.len = rand.uintLessThan(usize, 300);
            rand.bytes(f.buf[0..f.len]);
            if (f.len > 5) f.buf[0] = 22;
        }
        _ = f.run(pin_ok, 1 + rand.uintLessThan(usize, 200)) catch {};
    }
}

const watchdog = @import("watchdog.zig");

/// A local TCP server that accepts one connection and then either says
/// nothing (stall) or answers like a plain-HTTP Portal.
const FakeServer = struct {
    server: net.Server,
    behaviour: enum { stall, plain_http },

    fn serve(s: *FakeServer, io: Io) void {
        const conn = s.server.accept(io) catch return;
        defer conn.close(io);
        var b: [512]u8 = undefined;
        var vec = [_][]u8{&b};
        _ = conn.readWithControl(io, &vec, &.{}) catch return;
        switch (s.behaviour) {
            .stall => io.sleep(.fromSeconds(20), .awake) catch {},
            .plain_http => {
                var wb: [64]u8 = undefined;
                var w = conn.writer(io, &wb);
                w.interface.writeAll("HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n") catch {};
                w.interface.flush() catch {};
            },
        }
    }

    fn openThroughWatchdog(gpa: std.mem.Allocator, io: Io, addr: net.IpAddress, wd: *watchdog.Watchdog) Conn.OpenError!*Conn {
        _ = wd;
        return Conn.open(gpa, io, .os, addr, .{ .tls = pin_ok });
    }
};

test "live socket: a stalled TLS handshake is canceled; a plain-HTTP server is refused" {
    const io = testing.io;
    const gpa = testing.allocator;
    for ([_]@FieldType(FakeServer, "behaviour"){ .stall, .plain_http }) |b| {
        var addr: net.IpAddress = try .parseLiteral("127.0.0.1:0");
        var fs: FakeServer = .{ .server = try addr.listen(io, .{}), .behaviour = b };
        defer fs.server.deinit(io);
        addr = fs.server.socket.address;
        var srv = try io.concurrent(FakeServer.serve, .{ &fs, io });
        defer srv.cancel(io);
        var wd: watchdog.Watchdog = .{ .io = io };
        wd.extend(1000);
        const t0 = watchdog.nowMs(io);
        const r = wd.run(FakeServer.openThroughWatchdog, .{ gpa, io, addr, &wd }, null);
        if (r) |c| {
            c.close(gpa);
            return error.TestUnexpectedResult;
        } else |err| switch (b) {
            .stall => {
                try testing.expectEqual(error.Canceled, err);
                try testing.expect(wd.expired.load(.acquire));
                try testing.expect(watchdog.nowMs(io) - t0 < 5000);
            },
            .plain_http => try testing.expectEqual(error.TlsHandshakeMalformed, err),
        }
    }
}
