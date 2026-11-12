//! Tests for server.zig: RFC 8448 vectors, record layer, ClientHello
//! parser fuzzing, and interop over loopback with std.crypto.tls.Client
//! and with a small test-only TLS 1.3 client (for paths std's client does
//! not exercise: HelloRetryRequest, ChaCha20, KeyUpdate, ALPN refusal).

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const testing = std.testing;
const crypto = std.crypto;
const Sha256 = crypto.hash.sha2.Sha256;
const X25519 = crypto.dh.X25519;

const server = @import("server.zig");
const x509 = @import("x509.zig");
const Connection = server.Connection;
const Traffic = server.Traffic;
const KeySchedule = server.KeySchedule;
const Suite = server.Suite;
const Out = server.Out;
const Ecdsa = server.Ecdsa;

fn hexLen(comptime s: []const u8) usize {
    @setEvalBranchQuota(1_000_000);
    var n: usize = 0;
    for (s) |ch| {
        if (std.ascii.isHex(ch)) n += 1;
    }
    return n / 2;
}

/// Hex string (whitespace ignored) to bytes, at compile time.
fn hx(comptime s: []const u8) [hexLen(s)]u8 {
    @setEvalBranchQuota(1_000_000);
    comptime {
        var out: [hexLen(s)]u8 = undefined;
        var i: usize = 0;
        var hi: ?u8 = null;
        for (s) |ch| {
            const v = std.fmt.charToDigit(ch, 16) catch continue;
            if (hi) |h| {
                out[i] = h * 16 + v;
                i += 1;
                hi = null;
            } else hi = v;
        }
        const result = out;
        return result;
    }
}

// --------------------------------------------- RFC 8448 section 3 vectors
// "Simple 1-RTT Handshake" (https://www.rfc-editor.org/rfc/rfc8448#section-3)

const rfc_client_private = hx("49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005");
const rfc_server_private = hx("b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e");
const rfc_server_public = hx("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f");
const rfc_server_random = hx("a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e26928");
const rfc_ikm = hx("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
const rfc_handshake_secret = hx("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
const rfc_hello_hash = hx("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
const rfc_c_hs = hx("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
const rfc_s_hs = hx("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
const rfc_master = hx("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919");
const rfc_s_hs_key = hx("3fce516009c21727d0f2e4e86ee403bc");
const rfc_s_hs_iv = hx("5d313eb2671276ee13000b30");
const rfc_c_hs_key = hx("dbfaa693d1762c5b666af5d950258d01");
const rfc_c_hs_iv = hx("5bd3c71b836e0b76bb73265f");
const rfc_server_finished = hx("9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718");
const rfc_finished_hash = hx("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
const rfc_c_ap = hx("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5");
const rfc_s_ap = hx("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643");
const rfc_s_ap_key = hx("9f02283b6c9c07efc26bb9f2ac92e356");
const rfc_s_ap_iv = hx("cf782b88dd83549aadf1e984");
const rfc_c_ap_key = hx("17422dda596ed5d9acd890e3c63f5051");
const rfc_c_ap_iv = hx("5b78923dee08579033e523d9");
const rfc_client_finished = hx("a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61");

const rfc_ch_record = hx(
    \\16 03 01 00 c4 01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99
    \\12 ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00 09 00 00
    \\06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02
    \\01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d
    \\ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04
    \\03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00
    \\02 01 01 00 1c 00 02 40 01
);
const rfc_sh_record = hx(
    \\16 03 03 00 5a 02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb
    \\14 34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88 76 11 20 95
    \\fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04
);
const rfc_server_flight = hx(
    \\08 00 00 24 00 22 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c
    \\00 02 40 01 00 00 00 00 0b 00 01 b9 00 00 01 b5 00 01 b0 30 82 01 ac 30 82 01 15 a0 03 02 01 02
    \\02 01 02 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04 03 13 03 72
    \\73 61 30 1e 17 0d 31 36 30 37 33 30 30 31 32 33 35 39 5a 17 0d 32 36 30 37 33 30 30 31 32 33 35
    \\39 5a 30 0e 31 0c 30 0a 06 03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86 48 86 f7 0d 01
    \\01 01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49 8f 82 79 30 3d 98 08 36 39 9b 36 c6 98 8c
    \\0c 68 de 55 e1 bd b8 26 d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c 1a f1 9e
    \\aa 6a f9 8c 7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52 4b 1b 01 8c 3e 0b 63 26 4d 44 9a 6d 38 e2
    \\2a 5f da 43 08 46 74 80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0 3e 2b d1 93 ef f0 ab 9a
    \\80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03 01 00 01 a3 1a 30 18 30 09 06 03 55 1d 13 04
    \\02 30 00 30 0b 06 03 55 1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03
    \\81 81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a 72 67 17 06 18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94
    \\36 54 17 f2 ea e8 f8 a5 8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a 03 01 51 56 72 60 96 fd
    \\33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be c1 fc 63 a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9 b9 eb
    \\2b d5 20 3b 1c 3b 84 e0 a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8 f8 96 12 29 ac 91 87 b4
    \\2b 4d e1 00 00 0f 00 00 84 08 04 00 80 5a 74 7c 5d 88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82
    \\4c d4 84 14 5a b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a 07 86 53 fa 6b ef 78
    \\0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b be 8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71
    \\45 9e 46 44 5c 9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15 2a 3d a5 04 3e 06 3d da
    \\65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3 14 00 00 20 9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4 de
    \\da 4a b4 2c 30 95 72 cb 7f ff ee 54 54 b7 8f 07 18
);
const rfc_server_flight_record = hx(
    \\17 03 03 02 a2 d1 ff 33 4a 56 f5 bf f6 59 4a 07 cc 87 b5 80 23 3f 50 0f 45 e4 89 e7 f3 3a f3 5e
    \\df 78 69 fc f4 0a a4 0a a2 b8 ea 73 f8 48 a7 ca 07 61 2e f9 f9 45 cb 96 0b 40 68 90 51 23 ea 78
    \\b1 11 b4 29 ba 91 91 cd 05 d2 a3 89 28 0f 52 61 34 aa dc 7f c7 8c 4b 72 9d f8 28 b5 ec f7 b1 3b
    \\d9 ae fb 0e 57 f2 71 58 5b 8e a9 bb 35 5c 7c 79 02 07 16 cf b9 b1 18 3e f3 ab 20 e3 7d 57 a6 b9
    \\d7 47 76 09 ae e6 e1 22 a4 cf 51 42 73 25 25 0c 7d 0e 50 92 89 44 4c 9b 3a 64 8f 1d 71 03 5d 2e
    \\d6 5b 0e 3c dd 0c ba e8 bf 2d 0b 22 78 12 cb b3 60 98 72 55 cc 74 41 10 c4 53 ba a4 fc d6 10 92
    \\8d 80 98 10 e4 b7 ed 1a 8f d9 91 f0 6a a6 24 82 04 79 7e 36 a6 a7 3b 70 a2 55 9c 09 ea d6 86 94
    \\5b a2 46 ab 66 e5 ed d8 04 4b 4c 6d e3 fc f2 a8 94 41 ac 66 27 2f d8 fb 33 0e f8 19 05 79 b3 68
    \\45 96 c9 60 bd 59 6e ea 52 0a 56 a8 d6 50 f5 63 aa d2 74 09 96 0d ca 63 d3 e6 88 61 1e a5 e2 2f
    \\44 15 cf 95 38 d5 1a 20 0c 27 03 42 72 96 8a 26 4e d6 54 0c 84 83 8d 89 f7 2c 24 46 1a ad 6d 26
    \\f5 9e ca ba 9a cb bb 31 7b 66 d9 02 f4 f2 92 a3 6a c1 b6 39 c6 37 ce 34 31 17 b6 59 62 22 45 31
    \\7b 49 ee da 0c 62 58 f1 00 d7 d9 61 ff b1 38 64 7e 92 ea 33 0f ae ea 6d fa 31 c7 a8 4d c3 bd 7e
    \\1b 7a 6c 71 78 af 36 87 90 18 e3 f2 52 10 7f 24 3d 24 3d c7 33 9d 56 84 c8 b0 37 8b f3 02 44 da
    \\8c 87 c8 43 f5 e5 6e b4 c5 e8 28 0a 2b 48 05 2c f9 3b 16 49 9a 66 db 7c ca 71 e4 59 94 26 f7 d4
    \\61 e6 6f 99 88 2b d8 9f c5 08 00 be cc a6 2d 6c 74 11 6d bd 29 72 fd a1 fa 80 f8 5d f8 81 ed be
    \\5a 37 66 89 36 b3 35 58 3b 59 91 86 dc 5c 69 18 a3 96 fa 48 a1 81 d6 b6 fa 4f 9d 62 d5 13 af bb
    \\99 2f 2b 99 2f 67 f8 af e6 7f 76 91 3f a3 88 cb 56 30 c8 ca 01 e0 c6 5d 11 c6 6a 1e 2a c4 c8 59
    \\77 b7 c7 a6 99 9b bf 10 dc 35 ae 69 f5 51 56 14 63 6c 0b 9b 68 c1 9e d2 e3 1c 0b 3b 66 76 30 38
    \\eb ba 42 f3 b3 8e dc 03 99 f3 a9 f2 3f aa 63 97 8c 31 7f c9 fa 66 a7 3f 60 f0 50 4d e9 3b 5b 84
    \\5e 27 55 92 c1 23 35 ee 34 0b bc 4f dd d5 02 78 40 16 e4 b3 be 7e f0 4d da 49 f4 b4 40 a3 0c b5
    \\d2 af 93 98 28 fd 4a e3 79 4e 44 f9 4d f5 a6 31 ed e4 2c 17 19 bf da bf 02 53 fe 51 75 be 89 8e
    \\75 0e dc 53 37 0d 2b
);
const rfc_client_finished_record = hx(
    \\17 03 03 00 35 75 ec 4d c2 38 cc e6 0b 29 80 44 a7 1e 21 9c 56 cc 77 b0 51 7f e9 b9 3c 7a 4b fc
    \\44 d8 7f 38 f8 03 38 ac 98 fc 46 de b3 84 bd 1c ae ac ab 68 67 d7 26 c4 05 46
);
const rfc_app_payload = hx(
    \\00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
    \\20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31
);
const rfc_client_app_record = hx(
    \\17 03 03 00 43 a2 3f 70 54 b6 2c 94 d0 af fa fe 82 28 ba 55 cb ef ac ea 42 f9 14 aa 66 bc ab 3f
    \\2b 98 19 a8 a5 b4 6b 39 5b d5 4a 9a 20 44 1e 2b 62 97 4e 1f 5a 62 92 a2 97 70 14 bd 1e 3d ea e6
    \\3a ee bb 21 69 49 15 e4
);
const rfc_server_app_record = hx(
    \\17 03 03 00 43 2e 93 7e 11 ef 4a c7 40 e5 38 ad 36 00 5f c4 a4 69 32 fc 32 25 d0 5f 82 aa 1b 36
    \\e3 0e fa f9 7d 90 e6 df fc 60 2d cb 50 1a 59 a8 fc c4 9c 4b f2 e5 f0 a2 1c 00 47 c2 ab f3 32 54
    \\0d d0 32 e1 67 c2 95 5d
);
const rfc_client_alert_record = hx(
    \\17 03 03 00 13 c9 87 27 60 65 56 66 b7 4d 7f f1 15 3e fd 6d b6 d0 b0 e3
);
const rfc_server_alert_record = hx(
    \\17 03 03 00 13 b5 8f d6 71 66 eb f5 99 d2 47 20 cf be 7e fa 7a 88 64 a9
);

const rfc_ch = rfc_ch_record[5..];
const rfc_sh = rfc_sh_record[5..];

test "rfc8448: key schedule" {
    const shared = try X25519.scalarmult(rfc_server_private, X25519.recoverPublicKey(rfc_client_private));
    try testing.expectEqualSlices(u8, &rfc_ikm, &shared);
    try testing.expectEqualSlices(u8, &rfc_server_public, &X25519.recoverPublicKey(rfc_server_private));

    var t: Sha256 = .init(.{});
    t.update(rfc_ch);
    t.update(rfc_sh);
    try testing.expectEqualSlices(u8, &rfc_hello_hash, &t.peek());

    const ks = KeySchedule.init(&shared, t.peek());
    try testing.expectEqualSlices(u8, &rfc_handshake_secret, &ks.handshake_secret);
    try testing.expectEqualSlices(u8, &rfc_c_hs, &ks.client_handshake);
    try testing.expectEqualSlices(u8, &rfc_s_hs, &ks.server_handshake);
    try testing.expectEqualSlices(u8, &rfc_master, &ks.master_secret);

    const s_hs = Traffic.init(.aes_128_gcm_sha256, ks.server_handshake);
    try testing.expectEqualSlices(u8, &rfc_s_hs_key, s_hs.key[0..16]);
    try testing.expectEqualSlices(u8, &rfc_s_hs_iv, &s_hs.iv);
    const c_hs = Traffic.init(.aes_128_gcm_sha256, ks.client_handshake);
    try testing.expectEqualSlices(u8, &rfc_c_hs_key, c_hs.key[0..16]);
    try testing.expectEqualSlices(u8, &rfc_c_hs_iv, &c_hs.iv);

    // Server Finished covers ClientHello..CertificateVerify: the flight
    // payload minus its trailing 36-byte Finished message.
    t.update(rfc_server_flight[0 .. rfc_server_flight.len - 36]);
    const sfin = server.finishedVerifyData(ks.server_handshake, t.peek());
    try testing.expectEqualSlices(u8, &rfc_server_finished, &sfin);
    try testing.expectEqualSlices(u8, &([_]u8{ 0x14, 0, 0, 0x20 } ++ rfc_server_finished), rfc_server_flight[rfc_server_flight.len - 36 ..]);
    t.update(rfc_server_flight[rfc_server_flight.len - 36 ..]);
    try testing.expectEqualSlices(u8, &rfc_finished_hash, &t.peek());

    const cfin = server.finishedVerifyData(ks.client_handshake, t.peek());
    try testing.expectEqualSlices(u8, &rfc_client_finished, &cfin);

    const app = ks.application(t.peek());
    try testing.expectEqualSlices(u8, &rfc_c_ap, &app.client);
    try testing.expectEqualSlices(u8, &rfc_s_ap, &app.server);
    const s_ap = Traffic.init(.aes_128_gcm_sha256, app.server);
    try testing.expectEqualSlices(u8, &rfc_s_ap_key, s_ap.key[0..16]);
    try testing.expectEqualSlices(u8, &rfc_s_ap_iv, &s_ap.iv);
    const c_ap = Traffic.init(.aes_128_gcm_sha256, app.client);
    try testing.expectEqualSlices(u8, &rfc_c_ap_key, c_ap.key[0..16]);
    try testing.expectEqualSlices(u8, &rfc_c_ap_iv, &c_ap.iv);
}

test "rfc8448: record protection" {
    var out: [1024]u8 = undefined;
    var inner: [1024]u8 = undefined;

    // Server handshake flight: one record, seq 0, server handshake key.
    var s_hs = Traffic.init(.aes_128_gcm_sha256, rfc_s_hs);
    @memcpy(inner[0..rfc_server_flight.len], &rfc_server_flight);
    inner[rfc_server_flight.len] = 22;
    const n1 = try s_hs.seal(&out, inner[0 .. rfc_server_flight.len + 1]);
    try testing.expectEqualSlices(u8, &rfc_server_flight_record, out[0..n1]);

    // Client Finished, decrypted with the client handshake key.
    var c_hs = Traffic.init(.aes_128_gcm_sha256, rfc_c_hs);
    var plain: [server.max_inner]u8 = undefined;
    const r = rfc_client_finished_record;
    const o1 = try c_hs.open(r[0..5], r[5..], &plain);
    try testing.expectEqual(@as(u8, 22), o1.content_type);
    try testing.expectEqualSlices(u8, &([_]u8{ 0x14, 0, 0, 0x20 } ++ rfc_client_finished), plain[0..o1.len]);

    // Application data. The server's first application record (seq 0)
    // was its NewSessionTicket, so its data record is seq 1.
    var c_ap = Traffic.init(.aes_128_gcm_sha256, rfc_c_ap);
    const o2 = try c_ap.open(rfc_client_app_record[0..5], rfc_client_app_record[5..], &plain);
    try testing.expectEqual(@as(u8, 23), o2.content_type);
    try testing.expectEqualSlices(u8, &rfc_app_payload, plain[0..o2.len]);
    var s_ap = Traffic.init(.aes_128_gcm_sha256, rfc_s_ap);
    s_ap.seq = 1;
    @memcpy(inner[0..rfc_app_payload.len], &rfc_app_payload);
    inner[rfc_app_payload.len] = 23;
    const n2 = try s_ap.seal(&out, inner[0 .. rfc_app_payload.len + 1]);
    try testing.expectEqualSlices(u8, &rfc_server_app_record, out[0..n2]);

    // close_notify alerts (client seq 1, server seq 2).
    const o3 = try c_ap.open(rfc_client_alert_record[0..5], rfc_client_alert_record[5..], &plain);
    try testing.expectEqual(@as(u8, 21), o3.content_type);
    try testing.expectEqualSlices(u8, &.{ 1, 0 }, plain[0..o3.len]);
    const n3 = try s_ap.seal(&out, &.{ 1, 0, 21 });
    try testing.expectEqualSlices(u8, &rfc_server_alert_record, out[0..n3]);

    // A flipped bit anywhere fails authentication.
    var bad = rfc_client_app_record;
    bad[30] ^= 1;
    var c_ap2 = Traffic.init(.aes_128_gcm_sha256, rfc_c_ap);
    try testing.expectError(error.BadRecordMac, c_ap2.open(bad[0..5], bad[5..], &plain));
    // Wrong sequence number fails too.
    var c_ap3 = Traffic.init(.aes_128_gcm_sha256, rfc_c_ap);
    c_ap3.seq = 1;
    try testing.expectError(error.BadRecordMac, c_ap3.open(rfc_client_app_record[0..5], rfc_client_app_record[5..], &plain));
}

/// A reader over fixed bytes with a buffer big enough for the server.
const FixedInput = struct {
    buf: []u8,
    reader: Io.Reader,

    fn init(gpa: std.mem.Allocator, data: []const u8) !FixedInput {
        const buf = try gpa.alloc(u8, @max(data.len, server.min_input_buffer));
        @memcpy(buf[0..data.len], data);
        return .{ .buf = buf, .reader = .{
            .vtable = &.{ .stream = endStream },
            .buffer = buf,
            .seek = 0,
            .end = data.len,
        } };
    }
    fn deinit(f: *FixedInput, gpa: std.mem.Allocator) void {
        gpa.free(f.buf);
    }
    fn endStream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        _ = r;
        _ = w;
        _ = limit;
        return error.EndOfStream;
    }
};

const Harness = struct {
    conn: Connection,
    out_buf: [64 * 1024]u8,
    rbuf: [4096]u8,
    wbuf: [4096]u8,
};

fn testCredentials(pki: *const x509.TestPki, chain: *[2][]const u8) server.Credentials {
    chain.* = .{ pki.leaf_der, pki.ca_der };
    return .{ .chain = chain, .key = pki.leaf_key };
}

test "rfc8448: server reproduces the ServerHello and handshake keys" {
    const gpa = testing.allocator;
    var pki = try x509.TestPki.init(gpa, 1_790_000_000, &.{x509.ip4(127, 0, 0, 1)});
    defer pki.deinit(gpa);
    var chain: [2][]const u8 = undefined;
    const creds = testCredentials(&pki, &chain);
    const entropy = rfc_server_random ++ rfc_server_private ++ @as([32]u8, @splat(5));

    const h = try gpa.create(Harness);
    defer gpa.destroy(h);
    var in = try FixedInput.init(gpa, &rfc_ch_record);
    defer in.deinit(gpa);
    var out: Io.Writer = .fixed(&h.out_buf);
    // The canned input ends before the client Finished.
    try testing.expectError(error.EndOfStream, h.conn.handshake(&in.reader, &out, .{
        .credentials = &creds,
        .entropy = &entropy,
        .read_buffer = &h.rbuf,
        .write_buffer = &h.wbuf,
    }));
    const sent = out.buffered();
    // Byte-identical ServerHello record.
    try testing.expectEqualSlices(u8, &rfc_sh_record, sent[0..rfc_sh_record.len]);
    try testing.expectEqual(server.Suite.aes_128_gcm_sha256, h.conn.diag.suite.?);
    try testing.expect(!h.conn.diag.hello_retry);
    // The next record decrypts with RFC 8448's server handshake key and
    // starts with EncryptedExtensions.
    const rec = sent[rfc_sh_record.len..];
    try testing.expectEqual(@as(u8, 23), rec[0]);
    const len = std.mem.readInt(u16, rec[3..5], .big);
    var s_hs = Traffic.init(.aes_128_gcm_sha256, rfc_s_hs);
    var plain: [server.max_inner]u8 = undefined;
    const o = try s_hs.open(rec[0..5], rec[5..][0..len], &plain);
    try testing.expectEqual(@as(u8, 22), o.content_type);
    try testing.expectEqual(@as(u8, 8), plain[0]); // encrypted_extensions
    // EE, Certificate (our chain), CertificateVerify, Finished.
    var c: server.Cursor = .{ .b = plain[0..o.len] };
    const want = [_]u8{ 8, 11, 15, 20 };
    for (want) |t| {
        try testing.expectEqual(t, try c.int(u8));
        _ = try c.bytes(try c.int(u24));
    }
    try testing.expect(c.done());
    h.conn.wipe();
}

// ------------------------------------------------------- parser / fuzzing

test "alert names never panic on unnamed values" {
    try testing.expectEqualStrings("unknown", server.alertName(@fromBackingInt(200)));
    try testing.expectEqualStrings("bad_certificate", server.alertName(.bad_certificate));
}

test "ClientHello parser: RFC 8448 hello" {
    const ch = try server.parseClientHello(rfc_ch[4..]);
    try testing.expect(ch.tls13 and ch.offers_aes and ch.offers_chacha and ch.group_x25519 and ch.sig_ecdsa_p256);
    try testing.expect(ch.x25519 != null and !ch.alpn and !ch.early_data and !ch.psk);
    try testing.expectEqual(@as(u8, 0), ch.session_id_len);
    try testing.expectEqual(server.Decision{ .accept = .aes_128_gcm_sha256 }, server.decide(&ch, false));
}

/// Builds a ClientHello body for tests.
const HelloSpec = struct {
    suites: []const u16 = &.{ 0x1301, 0x1303 },
    groups: []const u16 = &.{ 0x001d, 0x0017 },
    versions: []const u16 = &.{0x0304},
    sig_algs: []const u16 = &.{ 0x0403, 0x0804 },
    x25519_share: ?[32]u8 = @splat(9),
    /// Raw ALPN protocol_name_list content, e.g. "\x08http/1.1".
    alpn: ?[]const u8 = null,
    session_id: []const u8 = &@as([32]u8, @splat(0xab)),
    early_data: bool = false,
    duplicate_ext: bool = false,
    compression: []const u8 = &.{0},
};

fn buildHello(o: *Out, s: HelloSpec) !void {
    try o.int(u8, 1);
    const len_at = try o.beginLen(u24);
    try o.int(u16, 0x0303);
    try o.put(&@as([32]u8, @splat(0x11)));
    try o.int(u8, @intCast(s.session_id.len));
    try o.put(s.session_id);
    try o.int(u16, @intCast(s.suites.len * 2));
    for (s.suites) |x| try o.int(u16, x);
    try o.int(u8, @intCast(s.compression.len));
    try o.put(s.compression);
    const ext_at = try o.beginLen(u16);
    // server_name "localhost"
    try o.put(&.{ 0x00, 0x00, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x00, 0x09 });
    try o.put("localhost");
    try o.int(u16, 43);
    try o.int(u16, @intCast(1 + s.versions.len * 2));
    try o.int(u8, @intCast(s.versions.len * 2));
    for (s.versions) |v| try o.int(u16, v);
    try o.int(u16, 10);
    try o.int(u16, @intCast(2 + s.groups.len * 2));
    try o.int(u16, @intCast(s.groups.len * 2));
    for (s.groups) |g| try o.int(u16, g);
    try o.int(u16, 13);
    try o.int(u16, @intCast(2 + s.sig_algs.len * 2));
    try o.int(u16, @intCast(s.sig_algs.len * 2));
    for (s.sig_algs) |a| try o.int(u16, a);
    if (s.alpn) |a| {
        try o.int(u16, 16);
        try o.int(u16, @intCast(2 + a.len));
        try o.int(u16, @intCast(a.len));
        try o.put(a);
    }
    try o.int(u16, 51);
    if (s.x25519_share) |k| {
        try o.int(u16, 2 + 4 + 32);
        try o.int(u16, 4 + 32);
        try o.int(u16, 0x001d);
        try o.int(u16, 32);
        try o.put(&k);
    } else {
        try o.int(u16, 2);
        try o.int(u16, 0);
    }
    if (s.early_data) try o.put(&.{ 0x00, 0x2a, 0x00, 0x00 });
    if (s.duplicate_ext) try o.put(&.{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 });
    try o.endLen(u16, ext_at);
    try o.endLen(u24, len_at);
}

fn decideFor(s: HelloSpec) !server.Decision {
    var buf: [1024]u8 = undefined;
    var o: Out = .{ .buf = &buf };
    try buildHello(&o, s);
    const ch = try server.parseClientHello(o.written()[4..]);
    return server.decide(&ch, false);
}

test "ClientHello policy" {
    try testing.expectEqual(server.Decision{ .accept = .aes_128_gcm_sha256 }, try decideFor(.{}));
    try testing.expectEqual(server.Decision{ .accept = .chacha20_poly1305_sha256 }, try decideFor(.{ .suites = &.{ 0x1302, 0x1303 } }));
    try testing.expectEqual(server.Decision{ .refuse = .handshake_failure }, try decideFor(.{ .suites = &.{0x1302} }));
    try testing.expectEqual(server.Decision{ .refuse = .protocol_version }, try decideFor(.{ .versions = &.{ 0x0303, 0x0302 } }));
    try testing.expectEqual(server.Decision{ .refuse = .handshake_failure }, try decideFor(.{ .sig_algs = &.{0x0804} }));
    try testing.expectEqual(server.Decision{ .retry = .aes_128_gcm_sha256 }, try decideFor(.{ .x25519_share = null }));
    try testing.expectEqual(server.Decision{ .refuse = .handshake_failure }, try decideFor(.{ .x25519_share = null, .groups = &.{0x0017} }));
    try testing.expectEqual(server.Decision{ .refuse = .illegal_parameter }, try decideFor(.{ .groups = &.{0x0017} })); // share for an unlisted group
    try testing.expectEqual(server.Decision{ .refuse = .no_application_protocol }, try decideFor(.{ .alpn = "\x02h2" }));
    try testing.expectEqual(server.Decision{ .accept = .aes_128_gcm_sha256 }, try decideFor(.{ .alpn = "\x02h2\x08http/1.1" }));
    try testing.expectEqual(server.Decision{ .refuse = .illegal_parameter }, try decideFor(.{ .early_data = true }));
    try testing.expectEqual(server.Decision{ .refuse = .illegal_parameter }, try decideFor(.{ .compression = &.{ 1, 0 } }));
    try testing.expectError(error.TlsIllegalParameter, decideFor(.{ .duplicate_ext = true }));
    try testing.expectError(error.TlsIllegalParameter, decideFor(.{ .session_id = &@as([33]u8, @splat(1)) }));
    // HRR'd hello still without x25519: refused.
    {
        var buf: [1024]u8 = undefined;
        var o: Out = .{ .buf = &buf };
        try buildHello(&o, .{ .x25519_share = null });
        const ch = try server.parseClientHello(o.written()[4..]);
        try testing.expectEqual(server.Decision{ .refuse = .illegal_parameter }, server.decide(&ch, true));
    }
}

test "ClientHello parser fuzz: random, truncated and mutated input never panics" {
    var prng: std.Random.DefaultPrng = .init(0xc11e17);
    const rand = prng.random();
    var buf: [2048]u8 = undefined;
    for (0..50_000) |_| {
        const n = rand.uintLessThan(usize, 600);
        rand.bytes(buf[0..n]);
        if (server.parseClientHello(buf[0..n])) |ch| _ = server.decide(&ch, rand.boolean()) else |_| {}
    }
    var good: [1024]u8 = undefined;
    var o: Out = .{ .buf = &good };
    try buildHello(&o, .{ .alpn = "\x08http/1.1" });
    const samples = [_][]const u8{ rfc_ch[4..], o.written()[4..] };
    for (samples) |body| {
        for (0..body.len + 1) |cut| _ = server.parseClientHello(body[0..cut]) catch {};
        for (0..20_000) |_| {
            @memcpy(buf[0..body.len], body);
            const flips = rand.uintLessThan(usize, 6) + 1;
            for (0..flips) |_| buf[rand.uintLessThan(usize, body.len)] = rand.int(u8);
            if (server.parseClientHello(buf[0..body.len])) |ch| _ = server.decide(&ch, false) else |_| {}
        }
    }
}

test "handshake fuzz: mutated record streams end in an error, never a panic" {
    const gpa = testing.allocator;
    var pki = try x509.TestPki.init(gpa, 1_790_000_000, &.{x509.ip4(127, 0, 0, 1)});
    defer pki.deinit(gpa);
    var chain: [2][]const u8 = undefined;
    const creds = testCredentials(&pki, &chain);
    const entropy: [server.entropy_len]u8 = @splat(0x33);
    const h = try gpa.create(Harness);
    defer gpa.destroy(h);

    var prng: std.Random.DefaultPrng = .init(0xf022);
    const rand = prng.random();
    var buf: [4096]u8 = undefined;
    const base = rfc_ch_record ++ [_]u8{ 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 } ++ rfc_client_finished_record;
    for (0..3000) |i| {
        var n = base.len;
        @memcpy(buf[0..n], &base);
        switch (i % 4) {
            0 => n = rand.uintLessThan(usize, base.len + 1), // truncate
            1 => for (0..rand.uintLessThan(usize, 4) + 1) |_| {
                buf[rand.uintLessThan(usize, n)] = rand.int(u8);
            },
            2 => { // corrupt a length field
                const offsets = [_]usize{ 3, 4, 6, 7, 8 };
                const at = offsets[rand.uintLessThan(usize, offsets.len)];
                buf[at] = rand.int(u8);
            },
            else => { // random record soup
                n = rand.uintLessThan(usize, 300);
                rand.bytes(buf[0..n]);
                if (n > 0) buf[0] = 22;
            },
        }
        var in = try FixedInput.init(gpa, buf[0..n]);
        defer in.deinit(gpa);
        var out: Io.Writer = .fixed(&h.out_buf);
        if (h.conn.handshake(&in.reader, &out, .{
            .credentials = &creds,
            .entropy = &entropy,
            .read_buffer = &h.rbuf,
            .write_buffer = &h.wbuf,
        })) |_| {
            return error.UnexpectedSuccess; // no valid client Finished is possible
        } else |_| {}
    }

    // Specific refusals produce the right alert on the wire.
    const cases = [_]struct { spec: HelloSpec, alert: server.AlertDescription }{
        .{ .spec = .{ .alpn = "\x02h2" }, .alert = .no_application_protocol },
        .{ .spec = .{ .versions = &.{0x0303} }, .alert = .protocol_version },
        .{ .spec = .{ .suites = &.{0x1302} }, .alert = .handshake_failure },
        .{ .spec = .{ .early_data = true }, .alert = .illegal_parameter },
    };
    for (cases) |case| {
        var hb: [1024]u8 = undefined;
        var o: Out = .{ .buf = hb[5..] };
        try buildHello(&o, case.spec);
        hb[0..5].* = .{ 22, 3, 1, @intCast(o.len >> 8), @intCast(o.len & 0xff) };
        var in = try FixedInput.init(gpa, hb[0 .. 5 + o.len]);
        defer in.deinit(gpa);
        var out: Io.Writer = .fixed(&h.out_buf);
        _ = h.conn.handshake(&in.reader, &out, .{ .credentials = &creds, .entropy = &entropy, .read_buffer = &h.rbuf, .write_buffer = &h.wbuf }) catch {};
        try testing.expectEqual(case.alert, h.conn.diag.sent_alert.?);
        try testing.expectEqualSlices(u8, &.{ 21, 3, 3, 0, 2, 2, @backingInt(case.alert) }, out.buffered());
    }

    // Plain HTTP on the TLS port is recognised.
    {
        var in = try FixedInput.init(gpa, "GET / HTTP/1.1\r\n\r\n");
        defer in.deinit(gpa);
        var out: Io.Writer = .fixed(&h.out_buf);
        try testing.expectError(error.TlsNotTls, h.conn.handshake(&in.reader, &out, .{ .credentials = &creds, .entropy = &entropy, .read_buffer = &h.rbuf, .write_buffer = &h.wbuf }));
        try testing.expect(h.conn.diag.http_on_tls);
    }
    // Undersized socket buffers are refused, not asserted on.
    {
        var small: [100]u8 = undefined;
        var in: Io.Reader = .fixed(&rfc_ch_record);
        var out: Io.Writer = .fixed(&small);
        try testing.expectError(error.BufferTooSmall, h.conn.handshake(&in, &out, .{ .credentials = &creds, .entropy = &entropy, .read_buffer = &h.rbuf, .write_buffer = &h.wbuf }));
    }
}

// ------------------------------------------------------------ record layer

/// A connection placed directly in the application phase, reading `input`.
fn appConn(gpa: std.mem.Allocator, h: *Harness, in: *FixedInput, out: *Io.Writer, client_secret: [32]u8, server_secret: [32]u8) void {
    _ = gpa;
    h.conn.input = &in.reader;
    h.conn.output = out;
    h.conn.reader = .{ .vtable = Connection.reader_vtable, .buffer = &h.rbuf, .seek = 0, .end = 0 };
    h.conn.writer = .{ .vtable = Connection.writer_vtable, .buffer = &h.wbuf };
    h.conn.diag = .{};
    h.conn.read_keys = .init(.aes_128_gcm_sha256, client_secret);
    h.conn.write_keys = .init(.aes_128_gcm_sha256, server_secret);
    h.conn.read_protected = true;
    h.conn.write_protected = true;
    h.conn.write_dead = false;
    h.conn.read_failed = false;
    h.conn.received_close = false;
    h.conn.plain_pos = 0;
    h.conn.plain_end = 0;
    h.conn.write_busy = .init(false);
    h.conn.key_update_due = .init(false);
}

fn sealInto(list: *std.ArrayList(u8), gpa: std.mem.Allocator, t: *Traffic, content: []const u8, ct: u8, padding: usize) !void {
    var inner: [server.max_inner + 300]u8 = undefined;
    @memcpy(inner[0..content.len], content);
    inner[content.len] = ct;
    @memset(inner[content.len + 1 ..][0..padding], 0);
    var rec: [server.min_input_buffer + 300]u8 = undefined;
    // Traffic.seal refuses oversize inner plaintext, so build big ones by hand.
    const ilen = content.len + 1 + padding;
    if (ilen > server.max_inner) {
        rec[0..5].* = .{ 23, 3, 3, @intCast((ilen + 16) >> 8), @intCast((ilen + 16) & 0xff) };
        @memset(rec[5..][0 .. ilen + 16], 0x5a);
        try list.appendSlice(gpa, rec[0 .. 5 + ilen + 16]);
        return;
    }
    const n = try t.seal(&rec, inner[0..ilen]);
    try list.appendSlice(gpa, rec[0..n]);
}

test "record layer: padding, key update, close_notify, and bad records" {
    const gpa = testing.allocator;
    const h = try gpa.create(Harness);
    defer gpa.destroy(h);
    const cs: [32]u8 = @splat(1);
    const ss: [32]u8 = @splat(2);

    // Padding stripped; zero-length records skipped; KeyUpdate with
    // update_requested switches the read key and schedules our own.
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        var client = Traffic.init(.aes_128_gcm_sha256, cs);
        try sealInto(&list, gpa, &client, "hello", 23, 100);
        try sealInto(&list, gpa, &client, "", 23, 0);
        try sealInto(&list, gpa, &client, &.{ 24, 0, 0, 1, 1 }, 22, 3);
        client.update();
        try sealInto(&list, gpa, &client, " world", 23, 0);
        try sealInto(&list, gpa, &client, &.{ 1, 0 }, 21, 0);
        var in = try FixedInput.init(gpa, list.items);
        defer in.deinit(gpa);
        var out: Io.Writer = .fixed(&h.out_buf);
        appConn(gpa, h, &in, &out, cs, ss);
        var got: [64]u8 = undefined;
        var n: usize = 0;
        while (true) {
            const k = try h.conn.readSome(got[n..]);
            if (k == 0) break;
            n += k;
        }
        try testing.expectEqualStrings("hello world", got[0..n]);
        try testing.expect(h.conn.received_close);
        try testing.expect(h.conn.key_update_due.load(.acquire));

        // Our next write starts with a KeyUpdate, then data under the new key.
        try h.conn.writer.writeAll("pong");
        try h.conn.writer.flush();
        const sent = out.buffered();
        var peer = Traffic.init(.aes_128_gcm_sha256, ss);
        var plain: [server.max_inner]u8 = undefined;
        const l1 = std.mem.readInt(u16, sent[3..5], .big);
        const o1 = try peer.open(sent[0..5], sent[5..][0..l1], &plain);
        try testing.expectEqual(@as(u8, 22), o1.content_type);
        try testing.expectEqualSlices(u8, &.{ 24, 0, 0, 1, 0 }, plain[0..o1.len]);
        peer.update();
        const rest = sent[5 + l1 ..];
        const l2 = std.mem.readInt(u16, rest[3..5], .big);
        const o2 = try peer.open(rest[0..5], rest[5..][0..l2], &plain);
        try testing.expectEqual(@as(u8, 23), o2.content_type);
        try testing.expectEqualStrings("pong", plain[0..o2.len]);
    }

    // Each malformed stream ends with the right error and alert.
    const Bad = struct { kind: u8, err: anyerror, alert: ?server.AlertDescription };
    const bads = [_]Bad{
        .{ .kind = 0, .err = error.TlsRecordOverflow, .alert = .record_overflow }, // inner > 2^14+1
        .{ .kind = 1, .err = error.TlsBadRecordMac, .alert = .bad_record_mac }, // tampered
        .{ .kind = 2, .err = error.EndOfStream, .alert = null }, // truncated
        .{ .kind = 3, .err = error.TlsUnexpectedMessage, .alert = .unexpected_message }, // all padding
        .{ .kind = 4, .err = error.TlsUnexpectedMessage, .alert = .unexpected_message }, // plaintext handshake
        .{ .kind = 5, .err = error.TlsRecordOverflow, .alert = .record_overflow }, // length > 2^14+256
        .{ .kind = 6, .err = error.TlsUnexpectedMessage, .alert = .unexpected_message }, // NewSessionTicket from client
        .{ .kind = 7, .err = error.TlsDecodeError, .alert = .decode_error }, // malformed KeyUpdate
        .{ .kind = 8, .err = error.TlsAlertReceived, .alert = null }, // fatal alert from peer
        .{ .kind = 9, .err = error.TlsUnexpectedMessage, .alert = .unexpected_message }, // CCS after handshake
        .{ .kind = 10, .err = error.TlsUnexpectedMessage, .alert = .unexpected_message }, // unknown record type
        .{ .kind = 11, .err = error.TlsUnexpectedMessage, .alert = .unexpected_message }, // plaintext alert after handshake
        .{ .kind = 12, .err = error.TlsUnexpectedMessage, .alert = .unexpected_message }, // KeyUpdate split: 3 + 2 bytes
        .{ .kind = 13, .err = error.TlsUnexpectedMessage, .alert = .unexpected_message }, // KeyUpdate split: header, then body
        .{ .kind = 14, .err = error.TlsUnexpectedMessage, .alert = .unexpected_message }, // KeyUpdate + more in its record
    };
    for (bads) |b| {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        var client = Traffic.init(.aes_128_gcm_sha256, cs);
        switch (b.kind) {
            0 => try sealInto(&list, gpa, &client, &@as([server.max_plaintext]u8, @splat(1)), 23, 1),
            1 => {
                try sealInto(&list, gpa, &client, "data", 23, 0);
                list.items[8] ^= 0x40;
            },
            2 => {
                try sealInto(&list, gpa, &client, "data", 23, 0);
                list.items.len -= 3;
            },
            3 => try sealInto(&list, gpa, &client, "", 0, 20),
            4 => try list.appendSlice(gpa, &.{ 22, 3, 3, 0, 4, 20, 0, 0, 0 }),
            5 => try list.appendSlice(gpa, &.{ 23, 3, 3, 0x41, 0x01 }),
            6 => try sealInto(&list, gpa, &client, &.{ 4, 0, 0, 0 }, 22, 0),
            7 => try sealInto(&list, gpa, &client, &.{ 24, 0, 0, 2, 0, 0 }, 22, 0),
            8 => try sealInto(&list, gpa, &client, &.{ 2, 40 }, 21, 0),
            9 => try list.appendSlice(gpa, &.{ 20, 3, 3, 0, 1, 1 }),
            10 => try list.appendSlice(gpa, &.{ 99, 3, 3, 0, 1, 1 }),
            11 => try list.appendSlice(gpa, &.{ 21, 3, 3, 0, 2, 2, 40 }),
            12 => {
                try sealInto(&list, gpa, &client, &.{ 24, 0, 0 }, 22, 0);
                try sealInto(&list, gpa, &client, &.{ 1, 0 }, 22, 0);
            },
            13 => {
                try sealInto(&list, gpa, &client, &.{ 24, 0, 0, 1 }, 22, 0);
                try sealInto(&list, gpa, &client, &.{0}, 22, 0);
            },
            14 => try sealInto(&list, gpa, &client, &.{ 24, 0, 0, 1, 0, 24, 0, 0, 1, 0 }, 22, 0),
            else => unreachable,
        }
        var in = try FixedInput.init(gpa, list.items);
        defer in.deinit(gpa);
        var out: Io.Writer = .fixed(&h.out_buf);
        appConn(gpa, h, &in, &out, cs, ss);
        var got: [64]u8 = undefined;
        try testing.expectError(b.err, h.conn.readSome(&got));
        try testing.expectEqual(b.alert, h.conn.diag.sent_alert);
        if (b.alert) |a| {
            // The alert went out encrypted under the server's key.
            const sent = out.buffered();
            var peer = Traffic.init(.aes_128_gcm_sha256, ss);
            var plain: [64]u8 = undefined;
            const o = try peer.open(sent[0..5], sent[5..], &plain);
            try testing.expectEqual(@as(u8, 21), o.content_type);
            try testing.expectEqualSlices(u8, &.{ 2, @backingInt(a) }, plain[0..o.len]);
        }
        // Further reads keep failing.
        try testing.expectError(error.ReadFailed, h.conn.readSome(&got));
    }

    // A protected close_notify is still a clean end; a protected fatal
    // alert is reported (and not answered).
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        var client = Traffic.init(.aes_128_gcm_sha256, cs);
        try sealInto(&list, gpa, &client, "x", 23, 0);
        try sealInto(&list, gpa, &client, &.{ 1, 0 }, 21, 0);
        var in = try FixedInput.init(gpa, list.items);
        defer in.deinit(gpa);
        var out: Io.Writer = .fixed(&h.out_buf);
        appConn(gpa, h, &in, &out, cs, ss);
        var got: [8]u8 = undefined;
        try testing.expectEqual(@as(usize, 1), try h.conn.readSome(&got));
        try testing.expectEqual(@as(usize, 0), try h.conn.readSome(&got));
    }

    // Random record soup never panics.
    var prng: std.Random.DefaultPrng = .init(0xdec0de);
    const rand = prng.random();
    var soup: [2048]u8 = undefined;
    for (0..5000) |_| {
        const n = rand.uintLessThan(usize, soup.len);
        rand.bytes(soup[0..n]);
        if (n > 3 and rand.boolean()) soup[0..3].* = .{ 23, 3, 3 };
        var in = try FixedInput.init(gpa, soup[0..n]);
        defer in.deinit(gpa);
        var out: Io.Writer = .fixed(&h.out_buf);
        appConn(gpa, h, &in, &out, cs, ss);
        var got: [64]u8 = undefined;
        while (true) {
            const k = h.conn.readSome(&got) catch break;
            if (k == 0) break;
        }
    }
}


test "reader interface: std.Io.Reader end to end, any buffer size, no spin" {
    const gpa = testing.allocator;
    const h = try gpa.create(Harness);
    defer gpa.destroy(h);
    const cs: [32]u8 = @splat(1);
    const ss: [32]u8 = @splat(2);

    // Records: 6000 bytes (more than h.rbuf), an empty record, a KeyUpdate,
    // a line, then close_notify.
    var big: [6000]u8 = undefined;
    for (&big, 0..) |*b, i| b.* = 'a' + @as(u8, @intCast(i % 26));
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    var client = Traffic.init(.aes_128_gcm_sha256, cs);
    try sealInto(&list, gpa, &client, &big, 23, 0);
    try sealInto(&list, gpa, &client, "", 23, 0);
    try sealInto(&list, gpa, &client, &.{ 24, 0, 0, 1, 0 }, 22, 0);
    client.update();
    try sealInto(&list, gpa, &client, "line one\nline two\n", 23, 5);
    try sealInto(&list, gpa, &client, &.{ 1, 0 }, 21, 0);
    const expected = big ++ "line one\nline two\n".*;

    const Mode = enum { alloc_remaining, read_slice, take_lines, discard, tiny_buffer, no_buffer };
    for (std.enums.values(Mode)) |mode| {
        var in = try FixedInput.init(gpa, list.items);
        defer in.deinit(gpa);
        var out: Io.Writer = .fixed(&h.out_buf);
        appConn(gpa, h, &in, &out, cs, ss);
        var tiny: [7]u8 = undefined;
        switch (mode) {
            .tiny_buffer => h.conn.reader.buffer = &tiny,
            .no_buffer => h.conn.reader.buffer = &.{},
            else => {},
        }
        const r = &h.conn.reader;
        switch (mode) {
            .alloc_remaining, .tiny_buffer, .no_buffer => {
                // stream() path (Writer.Allocating), and readVec with data
                // for the no-buffer reader.
                const all = try r.allocRemaining(gpa, .unlimited);
                defer gpa.free(all);
                try testing.expectEqualSlices(u8, &expected, all);
                if (mode == .no_buffer) {
                    var one: [1]u8 = undefined;
                    try testing.expectEqual(@as(usize, 0), try r.readSliceShort(&one));
                }
            },
            .read_slice => {
                // readVec with a destination larger and smaller than a record.
                var got: [expected.len]u8 = undefined;
                try r.readSliceAll(got[0..100]);
                try r.readSliceAll(got[100..]);
                try testing.expectEqualSlices(u8, &expected, &got);
                try testing.expectError(error.EndOfStream, r.takeByte());
            },
            .take_lines => {
                // fill/peek path: readVec with an empty data[0] fills `buffer`.
                try r.discardAll(big.len);
                try testing.expectEqualStrings("line one", (try r.takeDelimiter('\n')).?);
                try testing.expectEqualStrings("line two", (try r.takeDelimiter('\n')).?);
                try testing.expectEqual(@as(?[]u8, null), try r.takeDelimiter('\n'));
            },
            .discard => {
                try testing.expectEqual(expected.len, try r.discardRemaining());
            },
        }
        try testing.expect(h.conn.received_close);
    }

    // A full buffer with nothing consumed and no destination: an error,
    // not a zero-progress loop.
    {
        var in = try FixedInput.init(gpa, list.items);
        defer in.deinit(gpa);
        var out: Io.Writer = .fixed(&h.out_buf);
        appConn(gpa, h, &in, &out, cs, ss);
        var tiny: [4]u8 = undefined;
        h.conn.reader.buffer = &tiny;
        try h.conn.reader.fill(4);
        var none: [1][]u8 = .{""};
        try testing.expectError(error.ReadFailed, Connection.reader_vtable.readVec(&h.conn.reader, &none));
        // A consumed prefix is moved out of the way instead.
        h.conn.reader.toss(3);
        try testing.expectEqual(@as(usize, 0), try Connection.reader_vtable.readVec(&h.conn.reader, &none));
        try testing.expectEqualSlices(u8, expected[3..7], h.conn.reader.buffered());
    }
}

test "handshake: a plaintext alert from the client is still accepted before Finished" {
    const gpa = testing.allocator;
    var pki = try x509.TestPki.init(gpa, 1_790_000_000, &.{x509.ip4(127, 0, 0, 1)});
    defer pki.deinit(gpa);
    var chain: [2][]const u8 = undefined;
    const creds = testCredentials(&pki, &chain);
    const entropy: [server.entropy_len]u8 = @splat(0x33);
    const h = try gpa.create(Harness);
    defer gpa.destroy(h);
    // ClientHello, then (instead of Finished) a plaintext bad_certificate
    // alert, as a client that rejects our chain may send.
    const input = rfc_ch_record ++ [_]u8{ 21, 3, 3, 0, 2, 2, 42 };
    var in = try FixedInput.init(gpa, &input);
    defer in.deinit(gpa);
    var out: Io.Writer = .fixed(&h.out_buf);
    try testing.expectError(error.TlsAlertReceived, h.conn.handshake(&in.reader, &out, .{
        .credentials = &creds,
        .entropy = &entropy,
        .read_buffer = &h.rbuf,
        .write_buffer = &h.wbuf,
    }));
    try testing.expectEqual(server.AlertDescription.bad_certificate, h.conn.diag.received_alert.?);
    try testing.expectEqual(@as(?server.AlertDescription, null), h.conn.diag.sent_alert);
    h.conn.wipe();
}

// ---------------------------------------------------------- loopback tests

const Bufs = struct {
    conn: Connection,
    in: [server.min_input_buffer]u8,
    out: [server.min_output_buffer]u8,
    /// std.crypto.tls.Client needs a whole max-size record of output space.
    cout: [crypto.tls.max_ciphertext_record_len]u8,
    rbuf: [8192]u8,
    wbuf: [8192]u8,
};

const LoopServer = struct {
    listener: net.Server,
    pki: *const x509.TestPki,
    err: ?anyerror = null,
    diag: server.Diagnostics = .{},
    echoed: usize = 0,

    fn run(s: *LoopServer) void {
        const io = testing.io;
        const gpa = testing.allocator;
        const stream = s.listener.accept(io) catch |e| {
            s.err = e;
            return;
        };
        defer stream.close(io);
        const b = gpa.create(Bufs) catch return;
        defer gpa.destroy(b);
        var sr = stream.reader(io, &b.in);
        var sw = stream.writer(io, &b.out);
        var entropy: [server.entropy_len]u8 = undefined;
        io.random(&entropy);
        var chain: [2][]const u8 = undefined;
        const creds = testCredentials(s.pki, &chain);
        defer b.conn.wipe();
        b.conn.handshake(&sr.interface, &sw.interface, .{
            .credentials = &creds,
            .entropy = &entropy,
            .read_buffer = &b.rbuf,
            .write_buffer = &b.wbuf,
        }) catch |e| {
            s.err = e;
            s.diag = b.conn.diag;
            return;
        };
        var buf: [20000]u8 = undefined;
        while (true) {
            const n = b.conn.readSome(&buf) catch |e| {
                s.err = e;
                break;
            };
            if (n == 0) break;
            s.echoed += n;
            b.conn.writer.writeAll(buf[0..n]) catch break;
            b.conn.writer.flush() catch break;
        }
        s.diag = b.conn.diag;
        b.conn.close();
    }
};

fn startServer(pki: *const x509.TestPki, s: *LoopServer) !std.Thread {
    const io = testing.io;
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    s.* = .{ .listener = try addr.listen(io, .{ .reuse_address = false }), .pki = pki };
    return std.Thread.spawn(.{}, LoopServer.run, .{s});
}

test "interop: std.crypto.tls.Client verifies our chain against the Portal CA" {
    const io = testing.io;
    const gpa = testing.allocator;
    const now = Io.Timestamp.now(io, .real).toSeconds();
    var pki = try x509.TestPki.init(gpa, now, &.{x509.ip4(127, 0, 0, 1)});
    defer pki.deinit(gpa);

    var ls: LoopServer = undefined;
    const t = try startServer(&pki, &ls);
    defer ls.listener.deinit(io);

    var bundle: crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(gpa);
    try bundle.bytes.appendSlice(gpa, pki.ca_der);
    try bundle.parseCert(gpa, 0, now);
    var lock: Io.RwLock = .init;

    const stream = try ls.listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    const cb = try gpa.create(Bufs);
    defer gpa.destroy(cb);
    var sr = stream.reader(io, &cb.in);
    var sw = stream.writer(io, &cb.cout);
    var client_in: [crypto.tls.max_ciphertext_record_len]u8 = undefined;
    var client_out: [crypto.tls.max_ciphertext_record_len]u8 = undefined;
    var entropy: [crypto.tls.Client.Options.entropy_len]u8 = undefined;
    io.random(&entropy);
    var client = try crypto.tls.Client.init(&sr.interface, &sw.interface, .{
        .host = .{ .explicit = "127.0.0.1" },
        .ca = .{ .bundle = .{ .gpa = gpa, .io = io, .lock = &lock, .bundle = &bundle } },
        .write_buffer = &client_out,
        .read_buffer = &client_in,
        .entropy = &entropy,
        .realtime_now = Io.Timestamp.now(io, .real),
    });
    // A message larger than one record, then a small one.
    var big: [20000]u8 = undefined;
    for (&big, 0..) |*b, i| b.* = @truncate(i *% 7);
    try client.writer.writeAll(&big);
    try client.writer.flush();
    try sw.interface.flush();
    var back: [20000]u8 = undefined;
    try client.reader.readSliceAll(&back);
    try testing.expectEqualSlices(u8, &big, &back);
    try client.writer.writeAll("ping");
    try client.writer.flush();
    try sw.interface.flush();
    try client.reader.readSliceAll(back[0..4]);
    try testing.expectEqualStrings("ping", back[0..4]);
    try client.end();
    try sw.interface.flush();
    t.join();
    try testing.expectEqual(@as(?anyerror, null), ls.err);
    try testing.expectEqual(server.Suite.aes_128_gcm_sha256, ls.diag.suite.?);
    try testing.expect(!ls.diag.hello_retry);
    try testing.expectEqual(@as(usize, 20004), ls.echoed);
}

test "interop: std client refuses a leaf from a different CA" {
    const io = testing.io;
    const gpa = testing.allocator;
    const now = Io.Timestamp.now(io, .real).toSeconds();
    var pki = try x509.TestPki.init(gpa, now, &.{x509.ip4(127, 0, 0, 1)});
    defer pki.deinit(gpa);
    // A different CA in the client's bundle.
    const other_key = try x509.KeyPair.generateDeterministic(@splat(0x77));
    var c: x509.Constraints = .{};
    c.subnets[0] = try x509.Subnet.parse("127.0.0.1/32");
    c.n_subnets = 1;
    const other_ca = try x509.buildCa(gpa, .{ .key = &other_key, .tag = "ffffffff".*, .serial = @splat(3), .now = now, .constraints = &c });
    defer gpa.free(other_ca);

    var ls: LoopServer = undefined;
    const t = try startServer(&pki, &ls);
    defer ls.listener.deinit(io);
    var bundle: crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(gpa);
    try bundle.bytes.appendSlice(gpa, other_ca);
    try bundle.parseCert(gpa, 0, now);
    var lock: Io.RwLock = .init;
    const stream = try ls.listener.socket.address.connect(io, .{ .mode = .stream });
    const cb = try gpa.create(Bufs);
    defer gpa.destroy(cb);
    var sr = stream.reader(io, &cb.in);
    var sw = stream.writer(io, &cb.cout);
    var client_in: [crypto.tls.max_ciphertext_record_len]u8 = undefined;
    var client_out: [crypto.tls.max_ciphertext_record_len]u8 = undefined;
    var entropy: [crypto.tls.Client.Options.entropy_len]u8 = undefined;
    io.random(&entropy);
    // Note: on Windows std's client falls back to the OS chain engine when
    // the bundle has no issuer; the Portal CA is not in the OS store, so
    // that fails too.
    if (crypto.tls.Client.init(&sr.interface, &sw.interface, .{
        .host = .{ .explicit = "127.0.0.1" },
        .ca = .{ .bundle = .{ .gpa = gpa, .io = io, .lock = &lock, .bundle = &bundle } },
        .write_buffer = &client_out,
        .read_buffer = &client_in,
        .entropy = &entropy,
        .realtime_now = Io.Timestamp.now(io, .real),
    })) |_| {
        return error.UnexpectedSuccess;
    } else |_| {}
    stream.close(io);
    t.join();
    try testing.expect(ls.err != null);
}

// ------------------------------------------- minimal test client (HRR etc.)

const MiniSpec = struct {
    hello: HelloSpec = .{},
    /// Ask the server to update its key during the session.
    key_update: bool = false,
};

const Mini = struct {
    in: *Io.Reader,
    out: *Io.Writer,
    read: Traffic = undefined,
    write: Traffic = undefined,
    suite: Suite = undefined,
    hrr: bool = false,
    alpn_selected: bool = false,
    alert: ?u8 = null,
    saw_key_update: bool = false,
    buf: [server.max_inner]u8 = undefined,
    sbuf: [server.min_output_buffer]u8 = undefined,

    fn sendPlain(m: *Mini, ct: u8, data: []const u8) !void {
        var hdr = [5]u8{ ct, 3, 3, 0, 0 };
        std.mem.writeInt(u16, hdr[3..5], @intCast(data.len), .big);
        try m.out.writeAll(&hdr);
        try m.out.writeAll(data);
        try m.out.flush();
    }

    fn sendProtected(m: *Mini, ct: u8, data: []const u8) !void {
        var inner: [server.max_inner]u8 = undefined;
        @memcpy(inner[0..data.len], data);
        inner[data.len] = ct;
        const n = try m.write.seal(&m.sbuf, inner[0 .. data.len + 1]);
        try m.out.writeAll(m.sbuf[0..n]);
        try m.out.flush();
    }

    const Rec = struct { ct: u8, data: []const u8 };

    fn recvPlain(m: *Mini) !Rec {
        var hdr = (try m.in.takeArray(5)).*;
        var len = std.mem.readInt(u16, hdr[3..5], .big);
        var body = try m.in.take(len);
        if (hdr[0] == 20) { // compatibility-mode CCS: skip
            hdr = (try m.in.takeArray(5)).*;
            len = std.mem.readInt(u16, hdr[3..5], .big);
            body = try m.in.take(len);
        }
        @memcpy(m.buf[0..len], body);
        if (hdr[0] == 21 and len == 2) m.alert = body[1];
        return .{ .ct = hdr[0], .data = m.buf[0..len] };
    }

    fn recvProtected(m: *Mini) !Rec {
        while (true) {
            const hdr = (try m.in.takeArray(5)).*;
            const len = std.mem.readInt(u16, hdr[3..5], .big);
            const body = try m.in.take(len);
            if (hdr[0] == 20) continue;
            if (hdr[0] == 21) {
                if (len == 2) m.alert = body[1];
                return error.AlertReceived;
            }
            const o = try m.read.open(&hdr, body, &m.buf);
            if (o.content_type == 21 and o.len == 2) {
                m.alert = m.buf[1];
                return error.AlertReceived;
            }
            return .{ .ct = o.content_type, .data = m.buf[0..o.len] };
        }
    }

    const ServerHello = struct { hrr: bool, suite: Suite, share: ?[32]u8, sid: [32]u8, sid_len: usize };

    fn parseServerHello(data: []const u8) !ServerHello {
        var c: server.Cursor = .{ .b = data };
        if (try c.int(u8) != 2) return error.NotServerHello;
        _ = try c.int(u24);
        if (try c.int(u16) != 0x0303) return error.BadVersion;
        const random = try c.bytes(32);
        var sh: ServerHello = .{ .hrr = std.mem.eql(u8, random, &crypto.tls.hello_retry_request_sequence), .suite = undefined, .share = null, .sid = undefined, .sid_len = 0 };
        const sid = try c.vec(u8);
        @memcpy(sh.sid[0..sid.len], sid);
        sh.sid_len = sid.len;
        sh.suite = switch (try c.int(u16)) {
            0x1301 => .aes_128_gcm_sha256,
            0x1303 => .chacha20_poly1305_sha256,
            else => return error.BadSuite,
        };
        if (try c.int(u8) != 0) return error.BadCompression;
        var e: server.Cursor = .{ .b = try c.vec(u16) };
        var version_ok = false;
        while (!e.done()) {
            const et = try e.int(u16);
            var d: server.Cursor = .{ .b = try e.vec(u16) };
            switch (et) {
                43 => version_ok = try d.int(u16) == 0x0304,
                51 => {
                    if (try d.int(u16) != 0x001d) return error.BadGroup;
                    if (!sh.hrr) sh.share = (try d.bytes(try d.int(u16)))[0..32].*;
                },
                else => return error.UnexpectedExtension,
            }
        }
        if (!version_ok) return error.BadVersion;
        return sh;
    }

    fn handshake(m: *Mini, spec: MiniSpec, ca_der: []const u8) !void {
        const kp = X25519.KeyPair.generateDeterministic(@splat(0x42));
        var hello = spec.hello;
        if (hello.x25519_share != null) hello.x25519_share = kp.public_key;
        var transcript: Sha256 = .init(.{});
        var ch_buf: [2048]u8 = undefined;
        var o: Out = .{ .buf = &ch_buf };
        try buildHello(&o, hello);
        transcript.update(o.written());
        try m.sendPlain(22, o.written());

        var rec = try m.recvPlain();
        if (rec.ct == 21) return error.AlertReceived;
        var sh = try parseServerHello(rec.data);
        if (!std.mem.eql(u8, sh.sid[0..sh.sid_len], hello.session_id)) return error.SessionIdNotEchoed;
        if (sh.hrr) {
            m.hrr = true;
            var h1: [32]u8 = undefined;
            Sha256.hash(o.written(), &h1, .{});
            transcript = .init(.{});
            transcript.update(&.{ 254, 0, 0, 32 });
            transcript.update(&h1);
            transcript.update(rec.data);
            try m.sendPlain(20, &.{1}); // middlebox-compat CCS, as browsers send
            hello.x25519_share = kp.public_key;
            o = .{ .buf = &ch_buf };
            try buildHello(&o, hello);
            transcript.update(o.written());
            try m.sendPlain(22, o.written());
            rec = try m.recvPlain();
            if (rec.ct == 21) return error.AlertReceived;
            sh = try parseServerHello(rec.data);
            if (sh.hrr) return error.SecondRetry;
        }
        transcript.update(rec.data);
        m.suite = sh.suite;
        const shared = try X25519.scalarmult(kp.secret_key, sh.share orelse return error.NoShare);
        var ks = KeySchedule.init(&shared, transcript.peek());
        m.read = .init(m.suite, ks.server_handshake);
        m.write = .init(m.suite, ks.client_handshake);

        const ca = try x509.parse(ca_der);
        var hs: [16 * 1024]u8 = undefined;
        var have: usize = 0;
        var leaf_pk: ?Ecdsa.PublicKey = null;
        var done = false;
        while (!done) {
            const r = try m.recvProtected();
            if (r.ct != 22) return error.UnexpectedRecord;
            @memcpy(hs[have..][0..r.data.len], r.data);
            have += r.data.len;
            var off: usize = 0;
            while (have - off >= 4) {
                const typ = hs[off];
                const len = std.mem.readInt(u24, hs[off + 1 ..][0..3], .big);
                if (have - off < 4 + len) break;
                const msg = hs[off .. off + 4 + len];
                var b: server.Cursor = .{ .b = msg[4..] };
                switch (typ) {
                    8 => m.alpn_selected = std.mem.indexOf(u8, msg, "http/1.1") != null,
                    11 => {
                        if (try b.int(u8) != 0) return error.BadContext;
                        var list: server.Cursor = .{ .b = try b.vec(u24) };
                        const leaf_der = try list.vec(u24);
                        _ = try list.vec(u16);
                        const leaf = try x509.parse(leaf_der);
                        try x509.verifySignedBy(leaf, ca);
                        leaf_pk = try Ecdsa.PublicKey.fromSec1(leaf.public_key);
                    },
                    15 => {
                        if (try b.int(u16) != 0x0403) return error.BadScheme;
                        const sig = try Ecdsa.Signature.fromDer(try b.vec(u16));
                        const content = server.certificateVerifyContent(transcript.peek());
                        try sig.verify(&content, leaf_pk orelse return error.NoCertificate);
                    },
                    20 => {
                        const want = server.finishedVerifyData(ks.server_handshake, transcript.peek());
                        if (!std.mem.eql(u8, &want, try b.bytes(32))) return error.BadFinished;
                        done = true;
                    },
                    else => return error.UnexpectedHandshake,
                }
                transcript.update(msg);
                off += 4 + len;
            }
            std.mem.copyForwards(u8, hs[0 .. have - off], hs[off..have]);
            have -= off;
        }
        const fin_hash = transcript.peek();
        const app = ks.application(fin_hash);
        const fin = [_]u8{ 20, 0, 0, 32 } ++ server.finishedVerifyData(ks.client_handshake, fin_hash);
        try m.sendPlain(20, &.{1});
        try m.sendProtected(22, &fin);
        m.read = .init(m.suite, app.server);
        m.write = .init(m.suite, app.client);
    }

    fn recvApp(m: *Mini) ![]const u8 {
        while (true) {
            const r = try m.recvProtected();
            if (r.ct == 22 and r.data.len == 5 and r.data[0] == 24) {
                m.saw_key_update = true;
                m.read.update();
                continue;
            }
            if (r.ct != 23) return error.UnexpectedRecord;
            return r.data;
        }
    }
};

const MiniResult = struct { server_err: ?anyerror, diag: server.Diagnostics, mini: *Mini, client_err: ?anyerror };

fn runMini(gpa: std.mem.Allocator, pki: *const x509.TestPki, spec: MiniSpec, mini: *Mini, cb: *Bufs) !MiniResult {
    const io = testing.io;
    var ls: LoopServer = undefined;
    const t = try startServer(pki, &ls);
    defer ls.listener.deinit(io);
    _ = gpa;
    const stream = try ls.listener.socket.address.connect(io, .{ .mode = .stream });
    var sr = stream.reader(io, &cb.in);
    var sw = stream.writer(io, &cb.out);
    mini.* = .{ .in = &sr.interface, .out = &sw.interface };
    var client_err: ?anyerror = null;
    blk: {
        mini.handshake(spec, pki.ca_der) catch |e| {
            client_err = e;
            break :blk;
        };
        if (spec.key_update) {
            mini.sendProtected(22, &.{ 24, 0, 0, 1, 1 }) catch |e| {
                client_err = e;
                break :blk;
            };
            mini.write.update();
        }
        mini.sendProtected(23, "over the wire") catch |e| {
            client_err = e;
            break :blk;
        };
        const back = mini.recvApp() catch |e| {
            client_err = e;
            break :blk;
        };
        if (!std.mem.eql(u8, back, "over the wire")) client_err = error.BadEcho;
        mini.sendProtected(21, &.{ 1, 0 }) catch {};
    }
    stream.close(io);
    t.join();
    return .{ .server_err = ls.err, .diag = ls.diag, .mini = mini, .client_err = client_err };
}

test "loopback: HelloRetryRequest, ChaCha20, KeyUpdate and ALPN with the test client" {
    const gpa = testing.allocator;
    const now = Io.Timestamp.now(testing.io, .real).toSeconds();
    var pki = try x509.TestPki.init(gpa, now, &.{x509.ip4(127, 0, 0, 1)});
    defer pki.deinit(gpa);
    const mini = try gpa.create(Mini);
    defer gpa.destroy(mini);
    const cb = try gpa.create(Bufs);
    defer gpa.destroy(cb);

    // Plain AES-GCM with ALPN http/1.1.
    var r = try runMini(gpa, &pki, .{ .hello = .{ .alpn = "\x02h2\x08http/1.1" } }, mini, cb);
    try testing.expectEqual(@as(?anyerror, null), r.client_err);
    try testing.expectEqual(@as(?anyerror, null), r.server_err);
    try testing.expectEqual(Suite.aes_128_gcm_sha256, mini.suite);
    try testing.expect(mini.alpn_selected and !mini.hrr);

    // ChaCha20-Poly1305 only.
    r = try runMini(gpa, &pki, .{ .hello = .{ .suites = &.{0x1303} } }, mini, cb);
    try testing.expectEqual(@as(?anyerror, null), r.client_err);
    try testing.expectEqual(Suite.chacha20_poly1305_sha256, mini.suite);
    try testing.expect(!mini.alpn_selected);

    // No x25519 share but x25519 listed: HelloRetryRequest.
    r = try runMini(gpa, &pki, .{ .hello = .{ .x25519_share = null } }, mini, cb);
    try testing.expectEqual(@as(?anyerror, null), r.client_err);
    try testing.expectEqual(@as(?anyerror, null), r.server_err);
    try testing.expect(mini.hrr and r.diag.hello_retry);

    // KeyUpdate(update_requested): the server switches its read key and
    // answers with its own KeyUpdate before the echoed data.
    r = try runMini(gpa, &pki, .{ .key_update = true }, mini, cb);
    try testing.expectEqual(@as(?anyerror, null), r.client_err);
    try testing.expect(mini.saw_key_update);

    // h2-only ALPN is refused.
    r = try runMini(gpa, &pki, .{ .hello = .{ .alpn = "\x02h2" } }, mini, cb);
    try testing.expectEqual(@as(?anyerror, error.AlertReceived), r.client_err);
    try testing.expectEqual(@as(?u8, @backingInt(server.AlertDescription.no_application_protocol)), mini.alert);

    // No usable group at all.
    r = try runMini(gpa, &pki, .{ .hello = .{ .x25519_share = null, .groups = &.{0x0017} } }, mini, cb);
    try testing.expectEqual(@as(?anyerror, error.AlertReceived), r.client_err);
    try testing.expectEqual(@as(?u8, @backingInt(server.AlertDescription.handshake_failure)), mini.alert);
}
