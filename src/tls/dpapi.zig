//! Windows DPAPI (CryptProtectData / CryptUnprotectData), current-user
//! scope: the blob can only be decrypted by this Windows account (the key
//! is derived from the user's logon credentials). Used for the CA and
//! server private keys at rest. Declared by hand, like win32.zig, so std
//! binding churn cannot break the build.

const std = @import("std");
const Allocator = std.mem.Allocator;

const DATA_BLOB = extern struct {
    cbData: u32,
    pbData: ?[*]u8,
};

const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

extern "crypt32" fn CryptProtectData(
    pDataIn: *const DATA_BLOB,
    szDataDescr: ?[*:0]const u16,
    pOptionalEntropy: ?*const DATA_BLOB,
    pvReserved: ?*anyopaque,
    pPromptStruct: ?*anyopaque,
    dwFlags: u32,
    pDataOut: *DATA_BLOB,
) callconv(.winapi) c_int;

extern "crypt32" fn CryptUnprotectData(
    pDataIn: *const DATA_BLOB,
    ppszDataDescr: ?*?[*:0]u16,
    pOptionalEntropy: ?*const DATA_BLOB,
    pvReserved: ?*anyopaque,
    pPromptStruct: ?*anyopaque,
    dwFlags: u32,
    pDataOut: *DATA_BLOB,
) callconv(.winapi) c_int;

extern "kernel32" fn LocalFree(hMem: ?*anyopaque) callconv(.winapi) ?*anyopaque;

fn blob(bytes: []const u8) DATA_BLOB {
    return .{ .cbData = @intCast(bytes.len), .pbData = @constCast(bytes.ptr) };
}

/// Encrypts `plain` for the current user. `purpose` is mixed in as DPAPI's
/// optional entropy, so a blob made for one purpose (the CA key) cannot be
/// substituted for another (the server key). Caller frees the result.
pub fn protect(gpa: Allocator, plain: []const u8, purpose: []const u8) ![]u8 {
    if (plain.len > 1 << 20 or purpose.len > 1 << 10) return error.TooLarge;
    const in = blob(plain);
    const ent = blob(purpose);
    var out: DATA_BLOB = .{ .cbData = 0, .pbData = null };
    const desc = std.unicode.utf8ToUtf16LeStringLiteral("Portal TLS private key");
    if (CryptProtectData(&in, desc, &ent, null, null, CRYPTPROTECT_UI_FORBIDDEN, &out) == 0) return error.DpapiProtectFailed;
    defer _ = LocalFree(out.pbData);
    const p = out.pbData orelse return error.DpapiProtectFailed;
    return gpa.dupe(u8, p[0..out.cbData]);
}

/// Decrypts a blob made by `protect` with the same `purpose`. Caller must
/// secureZero and free the result.
pub fn unprotect(gpa: Allocator, data: []const u8, purpose: []const u8) ![]u8 {
    if (data.len == 0 or data.len > 1 << 20) return error.DpapiUnprotectFailed;
    const in = blob(data);
    const ent = blob(purpose);
    var out: DATA_BLOB = .{ .cbData = 0, .pbData = null };
    if (CryptUnprotectData(&in, null, &ent, null, null, CRYPTPROTECT_UI_FORBIDDEN, &out) == 0) return error.DpapiUnprotectFailed;
    const p = out.pbData orelse return error.DpapiUnprotectFailed;
    defer {
        std.crypto.secureZero(u8, p[0..out.cbData]);
        _ = LocalFree(out.pbData);
    }
    return gpa.dupe(u8, p[0..out.cbData]);
}

test "dpapi round trip and purpose binding" {
    const gpa = std.testing.allocator;
    const secret = "0123456789abcdef0123456789abcdef";
    const sealed = try protect(gpa, secret, "purpose A");
    defer gpa.free(sealed);
    try std.testing.expect(std.mem.indexOf(u8, sealed, secret) == null);
    const opened = try unprotect(gpa, sealed, "purpose A");
    defer gpa.free(opened);
    try std.testing.expectEqualStrings(secret, opened);
    try std.testing.expectError(error.DpapiUnprotectFailed, unprotect(gpa, sealed, "purpose B"));
    var tampered = try gpa.dupe(u8, sealed);
    defer gpa.free(tampered);
    tampered[tampered.len - 5] ^= 0xff;
    try std.testing.expectError(error.DpapiUnprotectFailed, unprotect(gpa, tampered, "purpose A"));
}
