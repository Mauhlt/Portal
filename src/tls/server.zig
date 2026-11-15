//! Minimal TLS 1.3 server (RFC 8446), built only from std's primitives:
//! X25519, AES-128-GCM / ChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256,
//! SHA-256 and ECDSA P-256. Constants come from std.crypto.tls.
//!
//! Supported:
//!   * TLS 1.3 only (supported_versions must offer 0x0304)
//!   * TLS_AES_128_GCM_SHA256 (preferred), TLS_CHACHA20_POLY1305_SHA256
//!   * x25519 key exchange; HelloRetryRequest when the client lists x25519
//!     but sent no x25519 key share (no cookie)
//!   * ecdsa_secp256r1_sha256 CertificateVerify
//!   * ALPN: "http/1.1" selected when offered; any ALPN list without it is
//!     refused (no_application_protocol)
//!   * legacy_session_id echo; legacy ChangeCipherSpec records accepted
//!     (and dropped) during the handshake, as RFC 8446 D.4 requires
//!   * record layer: 16 KiB plaintext limit, padding removal, per-direction
//!     sequence numbers, incoming KeyUpdate (answered with our own when
//!     requested), our own KeyUpdate before AES-GCM usage limits, close_notify;
//!     after the handshake every record must be protected (a plaintext
//!     alert is refused with unexpected_message)
//!
//! Refused (fatal alert): TLS <= 1.2, PSK/resumption is ignored (we never
//! issue tickets), early data (0-RTT) offers, client certificates (never
//! requested), renegotiation (does not exist in 1.3), compression, any
//! unexpected message or malformed field.
//!
//! Nothing here asserts on peer data: every length is bounded and checked,
//! and every failure is an error (after a fatal alert where one is due).
//!
//! Threading: after the handshake the read side (`readSome` / `reader`) and
//! the write side (`writer`) may be used from two different tasks at once,
//! as web.zig's WebSocket reader and writer do. They share no state except
//! two atomics: `key_update_due` (reader asks the writer to send a
//! KeyUpdate) and `write_busy` (the reader only sends a fatal alert if the
//! write side is idle; otherwise the connection just ends).

const std = @import("std");
const Io = std.Io;
const tls = std.crypto.tls;
const crypto = std.crypto;

const Sha256 = crypto.hash.sha2.Sha256;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const Hkdf = crypto.kdf.hkdf.HkdfSha256;
const X25519 = crypto.dh.X25519;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
pub const Ecdsa = crypto.sign.ecdsa.EcdsaP256Sha256;
/// Record protection, suites, HKDF-Expand-Label and the byte cursor are
/// shared with the native client's handshake inspector (shared/tls13.zig).
const tls13 = @import("shared").tls13;
pub const Suite = tls13.Suite;
pub const Traffic = tls13.Traffic;
pub const Cursor = tls13.Cursor;
pub const expandLabel = tls13.expandLabel;

const ContentType = tls.ContentType;
const HandshakeType = tls.HandshakeType;
pub const AlertDescription = tls.Alert.Description;

pub const record_header_len = tls13.record_header_len;
/// Largest TLSPlaintext / TLSInnerPlaintext content.
pub const max_plaintext = tls13.max_plaintext; // 2^14
/// Content + inner content type (we never add padding; peers may).
pub const max_inner = tls13.max_inner;
pub const tag_len = tls13.tag_len;
/// Largest TLSCiphertext.length a peer may send (2^14 + 256).
pub const max_ciphertext = tls.max_ciphertext_len;
/// The raw socket reader must buffer one whole record.
pub const min_input_buffer = record_header_len + max_ciphertext;
/// The raw socket writer must hold one whole outgoing record.
pub const min_output_buffer = record_header_len + max_inner + tag_len;
/// Bound on a (possibly fragmented) ClientHello.
pub const max_client_hello = 16 * 1024;
/// Server random, X25519 seed, ECDSA signing noise.
pub const entropy_len = 96;
/// Before AES-GCM's per-key limit (2^24.5 records, RFC 8446 5.5) we rotate
/// our sending key with a KeyUpdate.
pub const key_update_after = 1 << 23;

pub const Credentials = struct {
    /// DER certificates, leaf first.
    chain: []const []const u8,
    key: Ecdsa.KeyPair,
};

pub const Error = error{
    /// The transport failed or the task was cancelled (see the socket
    /// reader/writer for details).
    ReadFailed,
    WriteFailed,
    /// The peer closed the TCP connection without close_notify.
    EndOfStream,
    /// The first bytes were not a TLS record (`diag.http_on_tls` is set if
    /// they looked like a plain HTTP request).
    TlsNotTls,
    /// The peer sent an alert (`diag.received_alert`).
    TlsAlertReceived,
    TlsUnexpectedMessage,
    TlsDecodeError,
    TlsIllegalParameter,
    TlsHandshakeFailure,
    TlsProtocolVersion,
    TlsMissingExtension,
    TlsNoApplicationProtocol,
    TlsBadRecordMac,
    TlsRecordOverflow,
    TlsDecryptError,
    TlsInternalError,
    /// Socket buffers smaller than `min_input_buffer` / `min_output_buffer`,
    /// or a certificate chain too large for one flight.
    BufferTooSmall,
};

/// Printable name of an alert. Peer-supplied descriptions can be values
/// without a name; `{t}` / @tagName on those is illegal behaviour (a panic
/// in safe builds), so always format alerts through this.
pub fn alertName(desc: AlertDescription) []const u8 {
    return std.enums.tagName(AlertDescription, desc) orelse "unknown";
}

fn errorFor(desc: AlertDescription) Error {
    return switch (desc) {
        .unexpected_message => error.TlsUnexpectedMessage,
        .bad_record_mac => error.TlsBadRecordMac,
        .record_overflow => error.TlsRecordOverflow,
        .handshake_failure => error.TlsHandshakeFailure,
        .illegal_parameter => error.TlsIllegalParameter,
        .decode_error => error.TlsDecodeError,
        .decrypt_error => error.TlsDecryptError,
        .protocol_version => error.TlsProtocolVersion,
        .missing_extension => error.TlsMissingExtension,
        .no_application_protocol => error.TlsNoApplicationProtocol,
        else => error.TlsInternalError,
    };
}

// ------------------------------------------------------------ key schedule

pub fn emptyHash() [32]u8 {
    return tls.emptyHash(Sha256);
}

/// RFC 8446 7.1 without PSK: early secret from zeros, then (EC)DHE.
pub const KeySchedule = struct {
    handshake_secret: [32]u8,
    master_secret: [32]u8,
    client_handshake: [32]u8,
    server_handshake: [32]u8,

    /// `hello_hash` = Transcript-Hash(ClientHello..ServerHello).
    pub fn init(shared_secret: []const u8, hello_hash: [32]u8) KeySchedule {
        const zeroes: [32]u8 = @splat(0);
        const early = Hkdf.extract(&.{}, &zeroes);
        const empty = emptyHash();
        const derived_hs = expandLabel(early, "derived", &empty, 32);
        const hs = Hkdf.extract(&derived_hs, shared_secret);
        const derived_ms = expandLabel(hs, "derived", &empty, 32);
        return .{
            .handshake_secret = hs,
            .master_secret = Hkdf.extract(&derived_ms, &zeroes),
            .client_handshake = expandLabel(hs, "c hs traffic", &hello_hash, 32),
            .server_handshake = expandLabel(hs, "s hs traffic", &hello_hash, 32),
        };
    }

    /// `finished_hash` = Transcript-Hash(ClientHello..server Finished).
    pub fn application(ks: *const KeySchedule, finished_hash: [32]u8) struct { client: [32]u8, server: [32]u8 } {
        return .{
            .client = expandLabel(ks.master_secret, "c ap traffic", &finished_hash, 32),
            .server = expandLabel(ks.master_secret, "s ap traffic", &finished_hash, 32),
        };
    }

    pub fn wipe(ks: *KeySchedule) void {
        crypto.secureZero(u8, std.mem.asBytes(ks));
    }
};

/// verify_data for a Finished message (RFC 8446 4.4.4).
pub fn finishedVerifyData(traffic_secret: [32]u8, transcript_hash: [32]u8) [32]u8 {
    var key = expandLabel(traffic_secret, "finished", "", 32);
    defer crypto.secureZero(u8, &key);
    var out: [32]u8 = undefined;
    HmacSha256.create(&out, &transcript_hash, &key);
    return out;
}

/// Content covered by a server CertificateVerify signature (RFC 8446 4.4.3).
pub fn certificateVerifyContent(transcript_hash: [32]u8) [64 + 33 + 1 + 32]u8 {
    const pad: [64]u8 = @splat(0x20);
    return pad ++ "TLS 1.3, server CertificateVerify".* ++ [1]u8{0} ++ transcript_hash;
}

// ------------------------------------------------------- ClientHello parse

pub const ClientHello = struct {
    random: [32]u8 = @splat(0),
    session_id: [32]u8 = @splat(0),
    session_id_len: u8 = 0,
    offers_aes: bool = false,
    offers_chacha: bool = false,
    compression_ok: bool = false,
    has_extensions: bool = false,
    supported_versions: bool = false,
    tls13: bool = false,
    supported_groups: bool = false,
    group_x25519: bool = false,
    signature_algorithms: bool = false,
    sig_ecdsa_p256: bool = false,
    key_share: bool = false,
    x25519: ?[32]u8 = null,
    alpn: bool = false,
    alpn_http11: bool = false,
    early_data: bool = false,
    psk: bool = false,

    pub fn sessionId(ch: *const ClientHello) []const u8 {
        return ch.session_id[0..ch.session_id_len];
    }
};

const max_extensions = 64;
const max_key_shares = 16;

pub const ParseError = error{ TlsDecodeError, TlsIllegalParameter };

/// Parses a ClientHello body (after the 4-byte handshake header).
/// Total for any input: never panics, never reads out of bounds.
pub fn parseClientHello(body: []const u8) ParseError!ClientHello {
    var ch: ClientHello = .{};
    var c: Cursor = .{ .b = body };
    _ = try c.int(u16); // legacy_version: ignored in favour of supported_versions
    ch.random = (try c.bytes(32))[0..32].*;
    const sid = try c.vec(u8);
    if (sid.len > 32) return error.TlsIllegalParameter;
    @memcpy(ch.session_id[0..sid.len], sid);
    ch.session_id_len = @intCast(sid.len);

    const suites = try c.vec(u16);
    if (suites.len < 2 or suites.len % 2 != 0) return error.TlsDecodeError;
    var sc: Cursor = .{ .b = suites };
    while (!sc.done()) switch (try sc.int(u16)) {
        0x1301 => ch.offers_aes = true,
        0x1303 => ch.offers_chacha = true,
        else => {},
    };

    const comp = try c.vec(u8);
    if (comp.len == 0) return error.TlsDecodeError;
    ch.compression_ok = comp.len == 1 and comp[0] == 0;

    if (c.done()) return ch; // no extensions: not TLS 1.3
    ch.has_extensions = true;
    const exts = try c.vec(u16);
    if (!c.done()) return error.TlsDecodeError;

    var seen: [max_extensions]u16 = undefined;
    var n_seen: usize = 0;
    var ec: Cursor = .{ .b = exts };
    while (!ec.done()) {
        const et = try ec.int(u16);
        const data = try ec.vec(u16);
        // pre_shared_key must be the last extension (RFC 8446 4.2.11).
        if (ch.psk) return error.TlsIllegalParameter;
        for (seen[0..n_seen]) |s| if (s == et) return error.TlsIllegalParameter;
        if (n_seen == seen.len) return error.TlsDecodeError;
        seen[n_seen] = et;
        n_seen += 1;

        var d: Cursor = .{ .b = data };
        switch (et) {
            @backingInt(tls.ExtensionType.supported_versions) => {
                ch.supported_versions = true;
                const list = try d.vec(u8);
                if (list.len < 2 or list.len % 2 != 0) return error.TlsDecodeError;
                var lc: Cursor = .{ .b = list };
                while (!lc.done()) {
                    if (try lc.int(u16) == 0x0304) ch.tls13 = true;
                }
            },
            @backingInt(tls.ExtensionType.supported_groups) => {
                ch.supported_groups = true;
                const list = try d.vec(u16);
                if (list.len < 2 or list.len % 2 != 0) return error.TlsDecodeError;
                var lc: Cursor = .{ .b = list };
                while (!lc.done()) {
                    if (try lc.int(u16) == @backingInt(tls.NamedGroup.x25519)) ch.group_x25519 = true;
                }
            },
            @backingInt(tls.ExtensionType.signature_algorithms) => {
                ch.signature_algorithms = true;
                const list = try d.vec(u16);
                if (list.len < 2 or list.len % 2 != 0) return error.TlsDecodeError;
                var lc: Cursor = .{ .b = list };
                while (!lc.done()) {
                    if (try lc.int(u16) == @backingInt(tls.SignatureScheme.ecdsa_secp256r1_sha256)) ch.sig_ecdsa_p256 = true;
                }
            },
            @backingInt(tls.ExtensionType.key_share) => {
                ch.key_share = true;
                const list = try d.vec(u16); // may be empty (client asks for HRR)
                var groups: [max_key_shares]u16 = undefined;
                var n_groups: usize = 0;
                var lc: Cursor = .{ .b = list };
                while (!lc.done()) {
                    const group = try lc.int(u16);
                    const key = try lc.vec(u16);
                    if (key.len == 0) return error.TlsDecodeError;
                    for (groups[0..n_groups]) |g| if (g == group) return error.TlsIllegalParameter;
                    if (n_groups == groups.len) return error.TlsDecodeError;
                    groups[n_groups] = group;
                    n_groups += 1;
                    if (group == @backingInt(tls.NamedGroup.x25519)) {
                        if (key.len != 32) return error.TlsIllegalParameter;
                        ch.x25519 = key[0..32].*;
                    }
                }
            },
            @backingInt(tls.ExtensionType.application_layer_protocol_negotiation) => {
                ch.alpn = true;
                const list = try d.vec(u16);
                if (list.len == 0) return error.TlsDecodeError;
                var lc: Cursor = .{ .b = list };
                while (!lc.done()) {
                    const proto = try lc.vec(u8);
                    if (proto.len == 0) return error.TlsDecodeError;
                    if (std.mem.eql(u8, proto, "http/1.1")) ch.alpn_http11 = true;
                }
            },
            @backingInt(tls.ExtensionType.early_data) => {
                ch.early_data = true;
                d.i = data.len;
            },
            @backingInt(tls.ExtensionType.pre_shared_key) => {
                ch.psk = true;
                d.i = data.len;
            },
            else => d.i = data.len, // ignored (server_name, cookie, padding, GREASE...)
        }
        if (!d.done()) return error.TlsDecodeError;
    }
    return ch;
}

pub const Decision = union(enum) {
    /// Proceed with this suite and the client's x25519 share.
    accept: Suite,
    /// Ask for an x25519 key share.
    retry: Suite,
    /// Refuse with this alert.
    refuse: AlertDescription,
};

/// Server policy for a parsed ClientHello. `second` is true for the
/// ClientHello that follows our HelloRetryRequest.
pub fn decide(ch: *const ClientHello, second: bool) Decision {
    if (!ch.has_extensions or !ch.supported_versions or !ch.tls13) return .{ .refuse = .protocol_version };
    if (!ch.compression_ok) return .{ .refuse = .illegal_parameter };
    if (!ch.signature_algorithms or !ch.supported_groups or !ch.key_share) return .{ .refuse = .missing_extension };
    // We never issue tickets, so no PSK can be valid and 0-RTT data can
    // never be accepted; refuse rather than skip unreadable records.
    if (ch.early_data) return .{ .refuse = .illegal_parameter };
    const suite: Suite = if (ch.offers_aes) .aes_128_gcm_sha256 else if (ch.offers_chacha) .chacha20_poly1305_sha256 else return .{ .refuse = .handshake_failure };
    if (!ch.sig_ecdsa_p256) return .{ .refuse = .handshake_failure };
    if (ch.alpn and !ch.alpn_http11) return .{ .refuse = .no_application_protocol };
    if (ch.x25519 != null) {
        // A key share must be for a group the client listed.
        if (!ch.group_x25519) return .{ .refuse = .illegal_parameter };
        return .{ .accept = suite };
    }
    if (!ch.group_x25519) return .{ .refuse = .handshake_failure };
    if (second) return .{ .refuse = .illegal_parameter };
    return .{ .retry = suite };
}

// -------------------------------------------------------- message builders

/// Bounded appender over a caller buffer.
pub const Out = struct {
    buf: []u8,
    len: usize = 0,

    pub fn put(o: *Out, bytes: []const u8) Error!void {
        if (o.buf.len - o.len < bytes.len) return error.BufferTooSmall;
        @memcpy(o.buf[o.len..][0..bytes.len], bytes);
        o.len += bytes.len;
    }
    pub fn int(o: *Out, comptime T: type, v: T) Error!void {
        var b: [@divExact(@bitSizeOf(T), 8)]u8 = undefined;
        std.mem.writeInt(T, &b, v, .big);
        try o.put(&b);
    }
    /// Reserves a length prefix to be filled by `endLen`.
    pub fn beginLen(o: *Out, comptime T: type) Error!usize {
        const at = o.len;
        try o.int(T, 0);
        return at;
    }
    pub fn endLen(o: *Out, comptime T: type, at: usize) Error!void {
        const n = @divExact(@bitSizeOf(T), 8);
        const len = o.len - at - n;
        if (len > std.math.maxInt(T)) return error.BufferTooSmall;
        std.mem.writeInt(T, o.buf[at..][0..n], @intCast(len), .big);
    }
    pub fn written(o: *const Out) []u8 {
        return o.buf[0..o.len];
    }
};

/// ServerHello, or HelloRetryRequest when `server_share` is null.
pub fn writeServerHello(o: *Out, random: *const [32]u8, session_id: []const u8, suite: Suite, server_share: ?*const [32]u8) Error!void {
    try o.int(u8, @backingInt(HandshakeType.server_hello));
    const len_at = try o.beginLen(u24);
    try o.int(u16, 0x0303);
    if (server_share) |_| try o.put(random) else try o.put(&tls.hello_retry_request_sequence);
    try o.int(u8, @intCast(session_id.len));
    try o.put(session_id);
    try o.int(u16, suite.code());
    try o.int(u8, 0); // legacy_compression_method
    const ext_at = try o.beginLen(u16);
    try o.int(u16, @backingInt(tls.ExtensionType.key_share));
    if (server_share) |pk| {
        try o.int(u16, 36);
        try o.int(u16, @backingInt(tls.NamedGroup.x25519));
        try o.int(u16, 32);
        try o.put(pk);
    } else {
        try o.int(u16, 2);
        try o.int(u16, @backingInt(tls.NamedGroup.x25519));
    }
    try o.int(u16, @backingInt(tls.ExtensionType.supported_versions));
    try o.int(u16, 2);
    try o.int(u16, 0x0304);
    try o.endLen(u16, ext_at);
    try o.endLen(u24, len_at);
}

fn writeEncryptedExtensions(o: *Out, alpn: bool) Error!void {
    try o.int(u8, @backingInt(HandshakeType.encrypted_extensions));
    const len_at = try o.beginLen(u24);
    const ext_at = try o.beginLen(u16);
    if (alpn) {
        try o.int(u16, @backingInt(tls.ExtensionType.application_layer_protocol_negotiation));
        try o.int(u16, 11);
        try o.int(u16, 9);
        try o.int(u8, 8);
        try o.put("http/1.1");
    }
    try o.endLen(u16, ext_at);
    try o.endLen(u24, len_at);
}

fn writeCertificate(o: *Out, chain: []const []const u8) Error!void {
    try o.int(u8, @backingInt(HandshakeType.certificate));
    const len_at = try o.beginLen(u24);
    try o.int(u8, 0); // certificate_request_context
    const list_at = try o.beginLen(u24);
    for (chain) |cert| {
        if (cert.len == 0 or cert.len > 0xffff) return error.BufferTooSmall;
        try o.int(u24, @intCast(cert.len));
        try o.put(cert);
        try o.int(u16, 0); // no per-certificate extensions
    }
    try o.endLen(u24, list_at);
    try o.endLen(u24, len_at);
}

// --------------------------------------------------------------- connection

pub const Diagnostics = struct {
    sent_alert: ?AlertDescription = null,
    received_alert: ?AlertDescription = null,
    suite: ?Suite = null,
    hello_retry: bool = false,
    alpn: bool = false,
    /// The first bytes looked like a plain-text HTTP request.
    http_on_tls: bool = false,
};

pub const Options = struct {
    credentials: *const Credentials,
    /// Fresh secure random bytes (io.randomSecure), used once.
    entropy: *const [entropy_len]u8,
    /// Plaintext buffer behind `reader` (any size; may be empty if only
    /// `readSome` is used).
    read_buffer: []u8,
    /// Plaintext buffer behind `writer` (records are cut at 16 KiB).
    write_buffer: []u8,
};

pub const Connection = struct {
    /// Raw socket input; buffer >= min_input_buffer.
    input: *Io.Reader,
    /// Raw socket output; buffer >= min_output_buffer.
    output: *Io.Writer,
    /// Decrypted application data from the client.
    reader: Io.Reader,
    /// Application data to the client (encrypted on drain/flush).
    writer: Io.Writer,

    diag: Diagnostics = .{},

    // ---- read side (one task at a time)
    read_keys: Traffic = undefined,
    read_protected: bool = false,
    plain: [max_inner]u8 = undefined,
    plain_pos: usize = 0,
    plain_end: usize = 0,
    received_close: bool = false,
    read_failed: bool = false,

    // ---- write side (guarded by write_busy)
    write_keys: Traffic = undefined,
    write_protected: bool = false,
    write_dead: bool = false,
    write_scratch: [max_inner]u8 = undefined,
    write_busy: std.atomic.Value(bool) = .init(false),
    key_update_due: std.atomic.Value(bool) = .init(false),

    // ---- handshake only
    hs: [max_client_hello + 4]u8 = undefined,
    ccs_allowed: bool = false,
    ccs_seen: u8 = 0,

    pub const reader_vtable: *const Io.Reader.VTable = &.{ .stream = readerStream, .discard = readerDiscard, .readVec = readerReadVec };
    pub const writer_vtable: *const Io.Writer.VTable = &.{ .drain = writerDrain, .flush = writerFlush };

    /// Performs the server handshake on `c` (which must stay at this
    /// address afterwards: `reader`/`writer` point back into it).
    pub fn handshake(c: *Connection, input: *Io.Reader, output: *Io.Writer, opts: Options) Error!void {
        c.input = input;
        c.output = output;
        c.reader = .{
            .vtable = reader_vtable,
            .buffer = opts.read_buffer,
            .seek = 0,
            .end = 0,
        };
        c.writer = .{
            .vtable = writer_vtable,
            .buffer = opts.write_buffer,
        };
        c.diag = .{};
        c.read_protected = false;
        c.write_protected = false;
        c.write_dead = false;
        c.plain_pos = 0;
        c.plain_end = 0;
        c.received_close = false;
        c.read_failed = false;
        c.write_busy = .init(false);
        c.key_update_due = .init(false);
        c.ccs_allowed = false;
        c.ccs_seen = 0;
        if (input.buffer.len < min_input_buffer or output.buffer.len < min_output_buffer)
            return error.BufferTooSmall;
        c.handshakeInner(opts) catch |err| {
            c.read_failed = true;
            c.write_dead = true;
            return err;
        };
    }

    fn handshakeInner(c: *Connection, opts: Options) Error!void {
        // Not TLS at all? (Plain HTTP on this port.)
        const first = c.input.peekArray(1) catch |err| return mapReadErr(err);
        if (first[0] != @backingInt(ContentType.handshake)) {
            if (first[0] >= 'A' and first[0] <= 'Z') c.diag.http_on_tls = true;
            return error.TlsNotTls;
        }

        var transcript: Sha256 = .init(.{});
        var sent_ccs = false;
        var msg = try c.readHandshake(max_client_hello);
        if (msg.typ != @backingInt(HandshakeType.client_hello)) return c.fail(.unexpected_message);
        c.ccs_allowed = true;
        var ch = parseClientHello(msg.body) catch |err| return c.fail(switch (err) {
            error.TlsDecodeError => .decode_error,
            error.TlsIllegalParameter => .illegal_parameter,
        });
        var suite: Suite = undefined;
        switch (decide(&ch, false)) {
            .refuse => |a| return c.fail(a),
            .accept => |s| {
                suite = s;
                transcript.update(msg.raw);
            },
            .retry => |s| {
                suite = s;
                c.diag.hello_retry = true;
                // Transcript restarts with message_hash(ClientHello1).
                var ch1_hash: [32]u8 = undefined;
                Sha256.hash(msg.raw, &ch1_hash, .{});
                transcript.update(&.{ @backingInt(HandshakeType.message_hash), 0, 0, 32 });
                transcript.update(&ch1_hash);
                var o: Out = .{ .buf = &c.hs };
                try writeServerHello(&o, opts.entropy[0..32], ch.sessionId(), suite, null);
                transcript.update(o.written());
                try c.writePlainRecord(.handshake, o.written());
                // RFC 8446 D.4: a client in middlebox-compatibility mode
                // (non-empty legacy_session_id) gets one dummy CCS right
                // after our first handshake message. std's TLS client
                // depends on it.
                if (ch.session_id_len > 0) try c.writePlainRecord(.change_cipher_spec, &.{1});
                sent_ccs = true;
                c.output.flush() catch return error.WriteFailed;

                msg = try c.readHandshake(max_client_hello);
                if (msg.typ != @backingInt(HandshakeType.client_hello)) return c.fail(.unexpected_message);
                const ch2 = parseClientHello(msg.body) catch |err| return c.fail(switch (err) {
                    error.TlsDecodeError => .decode_error,
                    error.TlsIllegalParameter => .illegal_parameter,
                });
                switch (decide(&ch2, true)) {
                    .refuse => |a| return c.fail(a),
                    .retry => return c.fail(.illegal_parameter),
                    .accept => |s2| if (s2 != suite) return c.fail(.illegal_parameter),
                }
                if (!std.mem.eql(u8, ch2.sessionId(), ch.sessionId())) return c.fail(.illegal_parameter);
                ch = ch2;
                transcript.update(msg.raw);
            },
        }
        c.diag.suite = suite;
        c.diag.alpn = ch.alpn;

        // ServerHello and the handshake keys.
        const client_share = ch.x25519 orelse return c.fail(.internal_error);
        var kx = X25519.KeyPair.generateDeterministic(opts.entropy[32..64].*);
        defer crypto.secureZero(u8, &kx.secret_key);
        var shared = X25519.scalarmult(kx.secret_key, client_share) catch return c.fail(.illegal_parameter);
        defer crypto.secureZero(u8, &shared);

        var o: Out = .{ .buf = &c.hs };
        try writeServerHello(&o, opts.entropy[0..32], ch.sessionId(), suite, &kx.public_key);
        transcript.update(o.written());
        try c.writePlainRecord(.handshake, o.written());
        if (!sent_ccs and ch.session_id_len > 0) try c.writePlainRecord(.change_cipher_spec, &.{1});

        var ks = KeySchedule.init(&shared, transcript.peek());
        defer ks.wipe();
        c.write_keys = .init(suite, ks.server_handshake);
        c.write_protected = true;
        c.read_keys = .init(suite, ks.client_handshake);
        c.read_protected = true;

        // EncryptedExtensions, Certificate, CertificateVerify, Finished.
        o = .{ .buf = &c.hs };
        writeEncryptedExtensions(&o, ch.alpn) catch return c.fail(.internal_error);
        writeCertificate(&o, opts.credentials.chain) catch return c.fail(.internal_error);
        transcript.update(o.written());
        {
            const content = certificateVerifyContent(transcript.peek());
            const sig = opts.credentials.key.sign(&content, opts.entropy[64..96].*) catch return c.fail(.internal_error);
            var der_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
            const sig_der = sig.toDer(&der_buf);
            const start = o.len;
            o.int(u8, @backingInt(HandshakeType.certificate_verify)) catch return c.fail(.internal_error);
            o.int(u24, @intCast(4 + sig_der.len)) catch return c.fail(.internal_error);
            o.int(u16, @backingInt(tls.SignatureScheme.ecdsa_secp256r1_sha256)) catch return c.fail(.internal_error);
            o.int(u16, @intCast(sig_der.len)) catch return c.fail(.internal_error);
            o.put(sig_der) catch return c.fail(.internal_error);
            transcript.update(o.buf[start..o.len]);
        }
        {
            const verify = finishedVerifyData(ks.server_handshake, transcript.peek());
            const start = o.len;
            o.put(&.{ @backingInt(HandshakeType.finished), 0, 0, 32 }) catch return c.fail(.internal_error);
            o.put(&verify) catch return c.fail(.internal_error);
            transcript.update(o.buf[start..o.len]);
        }
        try c.writeProtected(.handshake, o.written());
        c.output.flush() catch return error.WriteFailed;

        const finished_hash = transcript.peek();
        var app = ks.application(finished_hash);
        defer crypto.secureZero(u8, std.mem.asBytes(&app));
        c.write_keys.wipe();
        c.write_keys = .init(suite, app.server);
        var expected = finishedVerifyData(ks.client_handshake, finished_hash);
        defer crypto.secureZero(u8, &expected);

        // Client Finished (protected with the client handshake key).
        msg = try c.readHandshake(32);
        if (msg.typ != @backingInt(HandshakeType.finished)) return c.fail(.unexpected_message);
        if (msg.body.len != 32) return c.fail(.decode_error);
        if (!crypto.timing_safe.eql([32]u8, expected, msg.body[0..32].*)) return c.fail(.decrypt_error);
        c.ccs_allowed = false;
        c.read_keys.wipe();
        c.read_keys = .init(suite, app.client);
        crypto.secureZero(u8, &c.hs);
    }

    // ------------------------------------------------------ reading

    const Record = struct { ct: u8, data: []const u8, protected: bool };

    fn mapReadErr(err: Io.Reader.Error) Error {
        return switch (err) {
            error.EndOfStream => error.EndOfStream,
            error.ReadFailed => error.ReadFailed,
        };
    }

    /// Reads one record. Protected records are decrypted into `plain`;
    /// plaintext ones point into the input buffer (valid until the next
    /// read). Sends the fatal alert itself on protocol errors.
    fn readRecord(c: *Connection) Error!Record {
        const hdr = (c.input.peekArray(record_header_len) catch |err| return mapReadErr(err)).*;
        const ct = hdr[0];
        const len = std.mem.readInt(u16, hdr[3..5], .big);
        if (hdr[1] != 0x03) return c.fail(.decode_error);
        switch (ct) {
            @backingInt(ContentType.change_cipher_spec),
            @backingInt(ContentType.alert),
            @backingInt(ContentType.handshake),
            @backingInt(ContentType.application_data),
            => {},
            else => return c.fail(.unexpected_message),
        }
        if (len > max_ciphertext) return c.fail(.record_overflow);
        const rec = c.input.take(record_header_len + len) catch |err| return mapReadErr(err);
        const body = rec[record_header_len..];

        if (!c.read_protected or ct != @backingInt(ContentType.application_data)) {
            // Plaintext. Once protection is on, only the legacy CCS and
            // (unauthenticated, terminal) alerts may appear in the clear,
            // and only during the handshake: nextRecord refuses both.
            if (c.read_protected and ct == @backingInt(ContentType.handshake)) return c.fail(.unexpected_message);
            if (ct == @backingInt(ContentType.application_data)) return c.fail(.unexpected_message);
            if (len > max_plaintext) return c.fail(.record_overflow);
            if (len == 0) return c.fail(.unexpected_message);
            return .{ .ct = ct, .data = body, .protected = false };
        }
        const opened = c.read_keys.open(&hdr, body, &c.plain) catch |err| return c.fail(switch (err) {
            error.BadRecordMac => .bad_record_mac,
            error.RecordOverflow => .record_overflow,
            error.NoContentType => .unexpected_message,
            error.SequenceOverflow => .internal_error,
        });
        switch (opened.content_type) {
            @backingInt(ContentType.alert),
            @backingInt(ContentType.handshake),
            @backingInt(ContentType.application_data),
            => {},
            else => return c.fail(.unexpected_message),
        }
        if (opened.len == 0 and opened.content_type != @backingInt(ContentType.application_data))
            return c.fail(.unexpected_message);
        return .{ .ct = opened.content_type, .data = c.plain[0..opened.len], .protected = true };
    }

    const Message = struct { typ: u8, body: []const u8, raw: []const u8 };

    /// Reads one handshake message of at most `max_body` bytes into `hs`.
    /// The message must end at a record boundary: every message we read
    /// (ClientHello, Finished) precedes a key change (RFC 8446 5.1).
    fn readHandshake(c: *Connection, max_body: usize) Error!Message {
        var have: usize = 0;
        while (true) {
            if (have >= 4) {
                const blen = std.mem.readInt(u24, c.hs[1..4], .big);
                if (blen > max_body) return c.fail(.decode_error);
                const total = 4 + @as(usize, blen);
                if (have > total) return c.fail(.unexpected_message);
                if (have == total) return .{ .typ = c.hs[0], .body = c.hs[4..total], .raw = c.hs[0..total] };
            }
            const rec = try c.readRecord();
            switch (rec.ct) {
                @backingInt(ContentType.handshake) => {
                    if (rec.data.len > c.hs.len - have) return c.fail(.decode_error);
                    @memcpy(c.hs[have..][0..rec.data.len], rec.data);
                    have += rec.data.len;
                },
                @backingInt(ContentType.change_cipher_spec) => {
                    if (!c.ccs_allowed or rec.protected or have != 0 or c.ccs_seen >= 2 or
                        rec.data.len != 1 or rec.data[0] != 1) return c.fail(.unexpected_message);
                    c.ccs_seen += 1;
                },
                @backingInt(ContentType.alert) => return c.alertReceived(rec.data),
                else => return c.fail(.unexpected_message),
            }
        }
    }

    fn alertReceived(c: *Connection, data: []const u8) Error {
        if (data.len == 2) c.diag.received_alert = @fromBackingInt(data[1]);
        c.read_failed = true;
        // The peer is gone; don't answer. (Only if the write side is idle:
        // `write_dead` belongs to whoever holds the write lock.)
        if (c.lockWrite()) {
            c.write_dead = true;
            c.unlockWrite();
        }
        return error.TlsAlertReceived;
    }

    /// Reads the next record after the handshake and acts on it.
    fn nextRecord(c: *Connection) Error!void {
        errdefer c.read_failed = true;
        const rec = try c.readRecord();
        // After the handshake every record must be protected, alerts
        // included (RFC 8446 5, 6). A plaintext alert here is
        // unauthenticated: anyone on the path could inject one to tear the
        // connection down with a forged reason. Plaintext alerts stay
        // accepted during the handshake (readHandshake), where a client may
        // not have keys yet.
        if (!rec.protected) return c.fail(.unexpected_message);
        switch (rec.ct) {
            @backingInt(ContentType.application_data) => {
                c.plain_pos = 0;
                c.plain_end = rec.data.len;
            },
            @backingInt(ContentType.alert) => {
                if (rec.data.len != 2) return c.fail(.decode_error);
                const desc: AlertDescription = @fromBackingInt(rec.data[1]);
                if (desc == .close_notify or desc == .user_canceled) {
                    c.received_close = true;
                    return;
                }
                // A fatal alert: the peer is gone, as for a plaintext one
                // during the handshake (no reply, the write side is dead).
                return c.alertReceived(rec.data);
            },
            @backingInt(ContentType.handshake) => {
                // Only KeyUpdate is valid after the handshake (no client
                // auth, no tickets from a client). It precedes a key change,
                // so it must be alone in its record: a KeyUpdate split
                // across records, or followed by more data in its record,
                // is unexpected_message (RFC 8446 5.1); a wrong length
                // field is decode_error.
                if (rec.data.len < 4) return c.fail(.unexpected_message);
                if (rec.data[0] != @backingInt(HandshakeType.key_update)) return c.fail(.unexpected_message);
                const blen = std.mem.readInt(u24, rec.data[1..4], .big);
                if (blen != 1) return c.fail(.decode_error);
                if (rec.data.len != 5) return c.fail(.unexpected_message);
                switch (rec.data[4]) {
                    0 => {},
                    1 => c.key_update_due.store(true, .release),
                    else => return c.fail(.illegal_parameter),
                }
                c.read_keys.update();
            },
            else => return c.fail(.unexpected_message),
        }
    }

    /// Reads application data into `dest`. Returns 0 once the client sent
    /// close_notify. Any error ends the connection.
    pub fn readSome(c: *Connection, dest: []u8) Error!usize {
        if (dest.len == 0) return 0;
        while (true) {
            if (c.plain_pos < c.plain_end) {
                const n = @min(dest.len, c.plain_end - c.plain_pos);
                @memcpy(dest[0..n], c.plain[c.plain_pos..][0..n]);
                c.plain_pos += n;
                return n;
            }
            if (c.received_close) return 0;
            if (c.read_failed) return error.ReadFailed;
            try c.nextRecord();
        }
    }

    // `reader` interface. Decrypted bytes wait in `plain`; each vtable call
    // either hands some of them out or reads one more record (which may
    // carry no data: a KeyUpdate, an empty record). Either way it makes
    // progress, so no caller loop can spin.

    /// Pending plaintext, reading records until there is some, or returns
    /// an empty slice after one record without data.
    fn pendingPlain(c: *Connection) Io.Reader.Error![]const u8 {
        if (c.plain_pos == c.plain_end) {
            if (c.received_close) return error.EndOfStream;
            if (c.read_failed) return error.ReadFailed;
            c.nextRecord() catch return error.ReadFailed;
            if (c.received_close) return error.EndOfStream;
        }
        return c.plain[c.plain_pos..c.plain_end];
    }

    fn readerStream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const c: *Connection = @alignCast(@fieldParentPtr("reader", r));
        const pending = limit.sliceConst(try c.pendingPlain());
        if (pending.len == 0) return 0;
        const n = try w.write(pending);
        c.plain_pos += n;
        return n;
    }

    fn readerDiscard(r: *Io.Reader, limit: Io.Limit) Io.Reader.Error!usize {
        const c: *Connection = @alignCast(@fieldParentPtr("reader", r));
        const n = limit.minInt((try c.pendingPlain()).len);
        c.plain_pos += n;
        return n;
    }

    /// Copies into `data` first; only when that has no room (data[0] empty:
    /// a fill/peek) into `reader.buffer`, moving buffered bytes to the front
    /// if the free tail is full. With no room anywhere (a zero-length or
    /// full buffer and no destination) it fails rather than returning 0
    /// forever.
    fn readerReadVec(r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        const c: *Connection = @alignCast(@fieldParentPtr("reader", r));
        const pending = try c.pendingPlain();
        if (pending.len == 0) return 0;
        var n: usize = 0;
        for (data) |d| {
            const k = @min(d.len, pending.len - n);
            @memcpy(d[0..k], pending[n..][0..k]);
            n += k;
            if (n == pending.len) break;
        }
        if (n > 0) {
            c.plain_pos += n;
            return n;
        }
        if (r.end == r.buffer.len and r.seek > 0) {
            const keep = r.end - r.seek;
            std.mem.copyForwards(u8, r.buffer[0..keep], r.buffer[r.seek..r.end]);
            r.seek = 0;
            r.end = keep;
        }
        const k = @min(r.buffer.len - r.end, pending.len);
        if (k == 0) return error.ReadFailed;
        @memcpy(r.buffer[r.end..][0..k], pending[0..k]);
        r.end += k;
        c.plain_pos += k;
        return 0;
    }

    // ------------------------------------------------------ writing

    fn lockWrite(c: *Connection) bool {
        return c.write_busy.cmpxchgStrong(false, true, .acquire, .monotonic) == null;
    }

    fn unlockWrite(c: *Connection) void {
        c.write_busy.store(false, .release);
    }

    fn writePlainRecord(c: *Connection, ct: ContentType, data: []const u8) Error!void {
        var rest = data;
        while (rest.len > 0) {
            const n = @min(rest.len, max_plaintext);
            const out = c.output.writableSliceGreedy(record_header_len + n) catch return error.WriteFailed;
            out[0] = @backingInt(ct);
            out[1] = 0x03;
            out[2] = 0x03;
            std.mem.writeInt(u16, out[3..5], @intCast(n), .big);
            @memcpy(out[record_header_len..][0..n], rest[0..n]);
            c.output.advance(record_header_len + n);
            rest = rest[n..];
        }
    }

    /// Seals `data` as records of inner type `ct` into the output buffer.
    fn writeProtected(c: *Connection, ct: ContentType, data: []const u8) Error!void {
        var rest = data;
        while (rest.len > 0) {
            const n = @min(rest.len, max_plaintext);
            try c.sealOne(ct, rest[0..n]);
            rest = rest[n..];
        }
    }

    fn sealOne(c: *Connection, ct: ContentType, chunk: []const u8) Error!void {
        @memcpy(c.write_scratch[0..chunk.len], chunk);
        c.write_scratch[chunk.len] = @backingInt(ct);
        const need = record_header_len + chunk.len + 1 + tag_len;
        const out = c.output.writableSliceGreedy(need) catch return error.WriteFailed;
        const n = try c.write_keys.seal(out, c.write_scratch[0 .. chunk.len + 1]);
        c.output.advance(n);
    }

    /// Application data, preceded by a KeyUpdate when one is due.
    fn writeAppData(c: *Connection, data: []const u8) Error!void {
        if (c.write_dead) return error.WriteFailed;
        var rest = data;
        while (rest.len > 0) {
            try c.maybeKeyUpdate();
            const n = @min(rest.len, max_plaintext);
            try c.sealOne(.application_data, rest[0..n]);
            rest = rest[n..];
        }
    }

    fn maybeKeyUpdate(c: *Connection) Error!void {
        const requested = c.key_update_due.swap(false, .acq_rel);
        if (!requested and c.write_keys.seq < key_update_after) return;
        // Always update_not_requested (the trailing 0), also when answering
        // the peer's update_requested. Portal must keep it that way: std's
        // TLS client (the native client) mishandles update_requested while
        // it reads and writes concurrently (its reader would rotate the
        // write keys under its writer).
        try c.sealOne(.handshake, &.{ @backingInt(HandshakeType.key_update), 0, 0, 1, 0 });
        c.write_keys.update();
    }

    fn writerDrain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const c: *Connection = @alignCast(@fieldParentPtr("writer", w));
        if (!c.lockWrite()) return error.WriteFailed;
        defer c.unlockWrite();
        errdefer c.write_dead = true;
        c.writeAppData(w.buffered()) catch return error.WriteFailed;
        w.end = 0;
        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            c.writeAppData(d) catch return error.WriteFailed;
            consumed += d.len;
        }
        const last = data[data.len - 1];
        var k: usize = 0;
        while (k < splat and last.len > 0) : (k += 1) {
            c.writeAppData(last) catch return error.WriteFailed;
            consumed += last.len;
            if (consumed >= 64 * 1024) break; // partial progress is allowed
        }
        return consumed;
    }

    fn writerFlush(w: *Io.Writer) Io.Writer.Error!void {
        const c: *Connection = @alignCast(@fieldParentPtr("writer", w));
        if (!c.lockWrite()) return error.WriteFailed;
        defer c.unlockWrite();
        errdefer c.write_dead = true;
        c.writeAppData(w.buffered()) catch return error.WriteFailed;
        w.end = 0;
        if (c.key_update_due.load(.acquire)) c.maybeKeyUpdate() catch return error.WriteFailed;
        c.output.flush() catch return error.WriteFailed;
    }

    /// Sends a fatal alert (best effort: only if the write side is idle)
    /// and returns the matching error.
    fn fail(c: *Connection, desc: AlertDescription) Error {
        c.diag.sent_alert = desc;
        c.read_failed = true;
        if (c.lockWrite()) {
            defer c.unlockWrite();
            if (!c.write_dead) {
                c.write_dead = true;
                c.writeAlert(desc) catch {};
            }
        }
        return errorFor(desc);
    }

    fn writeAlert(c: *Connection, desc: AlertDescription) Error!void {
        const level: u8 = if (desc == .close_notify) 1 else 2;
        const body = [2]u8{ level, @backingInt(desc) };
        if (c.write_protected) try c.sealOne(.alert, &body) else try c.writePlainRecord(.alert, &body);
        c.output.flush() catch return error.WriteFailed;
    }

    /// Sends close_notify after any buffered data. Best effort; call only
    /// when nothing else is writing and the peer is expected to be
    /// reading (it can block on a full socket until the task is cancelled).
    pub fn close(c: *Connection) void {
        if (!c.lockWrite()) return;
        defer c.unlockWrite();
        if (c.write_dead or !c.write_protected) return;
        c.writeAppData(c.writer.buffered()) catch {
            c.write_dead = true;
            return;
        };
        c.writer.end = 0;
        c.write_dead = true;
        c.writeAlert(.close_notify) catch {};
    }

    /// Erases key material. Call once the connection is finished.
    pub fn wipe(c: *Connection) void {
        c.read_keys.wipe();
        c.write_keys.wipe();
        crypto.secureZero(u8, &c.plain);
        crypto.secureZero(u8, &c.write_scratch);
        crypto.secureZero(u8, &c.hs);
    }
};

test {
    _ = @import("server_test.zig");
}
