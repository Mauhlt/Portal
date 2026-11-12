//! Long-lived device credential storage in the OS credential store only:
//!
//!   Windows  Credential Manager (CredWriteW / CredReadW / CredDeleteW,
//!            CRED_TYPE_GENERIC, persisted for this user on this machine)
//!   macOS    Keychain generic password via Security.framework, loaded with
//!            dlopen (no SDK needed to build)
//!   Linux    Secret Service over D-Bus via libsecret-1.so.0 (dlopen); if
//!            it is not installed or no keyring is running, this fails with
//!            error.Unavailable and the client refuses to pair rather than
//!            fall back to a file.
//!
//! The secret is never written to plain files, argv or logs. Buffers that
//! held it are zeroed by the caller (see net/client.zig).

const std = @import("std");
const builtin = @import("builtin");

pub const Error = error{ Unavailable, Failed, TooLong };

pub const max_secret = 256;
pub const max_target = 128;

/// "Portal/<server host>"
pub fn targetName(host: []const u8, buf: *[max_target]u8) []const u8 {
    return std.fmt.bufPrint(buf, "Portal/{s}", .{host}) catch buf[0..0];
}

const impl = switch (builtin.os.tag) {
    .windows => windows,
    .macos => macos,
    else => linux,
};

/// Copies the stored secret into `out` and returns it, or null if none.
pub fn load(target: []const u8, out: []u8) Error!?[]u8 {
    return impl.load(target, out);
}

/// Creates or replaces the secret.
pub fn save(target: []const u8, secret: []const u8) Error!void {
    if (secret.len > max_secret) return error.TooLong;
    return impl.save(target, secret);
}

/// Deletes the secret; succeeds if there was none.
pub fn delete(target: []const u8) Error!void {
    return impl.delete(target);
}

// ------------------------------------------------------------------ Windows

const windows = struct {
    const WINAPI: std.builtin.CallingConvention = .winapi;
    const FILETIME = extern struct { lo: u32, hi: u32 };
    const CREDENTIALW = extern struct {
        Flags: u32 = 0,
        Type: u32,
        TargetName: [*:0]u16,
        Comment: ?[*:0]u16 = null,
        LastWritten: FILETIME = .{ .lo = 0, .hi = 0 },
        CredentialBlobSize: u32,
        CredentialBlob: ?[*]u8,
        Persist: u32,
        AttributeCount: u32 = 0,
        Attributes: ?*anyopaque = null,
        TargetAlias: ?[*:0]u16 = null,
        UserName: ?[*:0]u16 = null,
    };
    const CRED_TYPE_GENERIC = 1;
    const CRED_PERSIST_LOCAL_MACHINE = 2;
    const ERROR_NOT_FOUND = 1168;

    extern "advapi32" fn CredWriteW(*const CREDENTIALW, u32) callconv(WINAPI) i32;
    extern "advapi32" fn CredReadW([*:0]const u16, u32, u32, *?*CREDENTIALW) callconv(WINAPI) i32;
    extern "advapi32" fn CredDeleteW([*:0]const u16, u32, u32) callconv(WINAPI) i32;
    extern "advapi32" fn CredFree(*anyopaque) callconv(WINAPI) void;
    extern "kernel32" fn GetLastError() callconv(WINAPI) u32;

    fn wide(s: []const u8, buf: *[max_target + 1:0]u16) Error![*:0]u16 {
        const n = std.unicode.utf8ToUtf16Le(buf[0..max_target], s) catch return error.Failed;
        buf[n] = 0;
        return buf[0..n :0].ptr;
    }

    fn load(target: []const u8, out: []u8) Error!?[]u8 {
        var tbuf: [max_target + 1:0]u16 = undefined;
        var cred: ?*CREDENTIALW = null;
        if (CredReadW(try wide(target, &tbuf), CRED_TYPE_GENERIC, 0, &cred) == 0) {
            if (GetLastError() == ERROR_NOT_FOUND) return null;
            return error.Failed;
        }
        const c = cred orelse return null;
        defer CredFree(c);
        const n = c.CredentialBlobSize;
        const blob = c.CredentialBlob orelse return null;
        defer std.crypto.secureZero(u8, blob[0..n]);
        if (n > out.len) return error.TooLong;
        @memcpy(out[0..n], blob[0..n]);
        return out[0..n];
    }

    fn save(target: []const u8, secret: []const u8) Error!void {
        var tbuf: [max_target + 1:0]u16 = undefined;
        var user = std.unicode.utf8ToUtf16LeStringLiteral("portal-client").*;
        var copy: [max_secret]u8 = undefined;
        defer std.crypto.secureZero(u8, &copy);
        @memcpy(copy[0..secret.len], secret);
        const cred: CREDENTIALW = .{
            .Type = CRED_TYPE_GENERIC,
            .TargetName = try wide(target, &tbuf),
            .CredentialBlobSize = @intCast(secret.len),
            .CredentialBlob = &copy,
            .Persist = CRED_PERSIST_LOCAL_MACHINE,
            .UserName = &user,
        };
        if (CredWriteW(&cred, 0) == 0) return error.Failed;
    }

    fn delete(target: []const u8) Error!void {
        var tbuf: [max_target + 1:0]u16 = undefined;
        if (CredDeleteW(try wide(target, &tbuf), CRED_TYPE_GENERIC, 0) == 0) {
            if (GetLastError() == ERROR_NOT_FOUND) return;
            return error.Failed;
        }
    }
};

// ------------------------------------------------------------------ macOS

const macos = struct {
    const CFTypeRef = *anyopaque;
    const OSStatus = i32;
    const errSecItemNotFound: OSStatus = -25300;
    const errSecDuplicateItem: OSStatus = -25299;
    const kCFStringEncodingUTF8: u32 = 0x08000100;

    const Api = struct {
        CFStringCreateWithBytes: *const fn (?*anyopaque, [*]const u8, isize, u32, u8) callconv(.c) ?CFTypeRef,
        CFDataCreate: *const fn (?*anyopaque, [*]const u8, isize) callconv(.c) ?CFTypeRef,
        CFDataGetBytePtr: *const fn (CFTypeRef) callconv(.c) [*]const u8,
        CFDataGetLength: *const fn (CFTypeRef) callconv(.c) isize,
        CFDictionaryCreate: *const fn (?*anyopaque, [*]const CFTypeRef, [*]const CFTypeRef, isize, *const anyopaque, *const anyopaque) callconv(.c) ?CFTypeRef,
        CFRelease: *const fn (CFTypeRef) callconv(.c) void,
        SecItemCopyMatching: *const fn (CFTypeRef, *?CFTypeRef) callconv(.c) OSStatus,
        SecItemAdd: *const fn (CFTypeRef, ?*?CFTypeRef) callconv(.c) OSStatus,
        SecItemUpdate: *const fn (CFTypeRef, CFTypeRef) callconv(.c) OSStatus,
        SecItemDelete: *const fn (CFTypeRef) callconv(.c) OSStatus,
        key_callbacks: *const anyopaque,
        value_callbacks: *const anyopaque,
        kSecClass: CFTypeRef,
        kSecClassGenericPassword: CFTypeRef,
        kSecAttrService: CFTypeRef,
        kSecAttrAccount: CFTypeRef,
        kSecValueData: CFTypeRef,
        kSecReturnData: CFTypeRef,
        kSecMatchLimit: CFTypeRef,
        kSecMatchLimitOne: CFTypeRef,
        kCFBooleanTrue: CFTypeRef,
    };

    var api: ?Api = null;
    var libs: [2]?std.DynLib = .{ null, null };

    fn get() Error!*const Api {
        if (api) |*a| return a;
        var cf = std.DynLib.open("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation") catch return error.Unavailable;
        var sec = std.DynLib.open("/System/Library/Frameworks/Security.framework/Security") catch return error.Unavailable;
        libs = .{ cf, sec };
        var a: Api = undefined;
        inline for (@typeInfo(Api).@"struct".field_names, @typeInfo(Api).@"struct".field_types) |f_name, f_type| {
            const is_cf = comptime std.mem.startsWith(u8, f_name, "CF") or std.mem.startsWith(u8, f_name, "kCF") or
                std.mem.endsWith(u8, f_name, "callbacks");
            const lib = if (is_cf) &cf else &sec;
            if (comptime std.mem.startsWith(u8, f_name, "k")) {
                // Data symbols: the CFStringRef/CFBooleanRef variable.
                const p = lib.lookup(*const CFTypeRef, f_name) orelse return error.Unavailable;
                @field(a, f_name) = p.*;
            } else if (comptime std.mem.eql(u8, f_name, "key_callbacks")) {
                a.key_callbacks = lib.lookup(*const anyopaque, "kCFTypeDictionaryKeyCallBacks") orelse return error.Unavailable;
            } else if (comptime std.mem.eql(u8, f_name, "value_callbacks")) {
                a.value_callbacks = lib.lookup(*const anyopaque, "kCFTypeDictionaryValueCallBacks") orelse return error.Unavailable;
            } else {
                @field(a, f_name) = lib.lookup(f_type, f_name) orelse return error.Unavailable;
            }
        }
        api = a;
        return &api.?;
    }

    fn str(a: *const Api, s: []const u8) Error!CFTypeRef {
        return a.CFStringCreateWithBytes(null, s.ptr, @intCast(s.len), kCFStringEncodingUTF8, 0) orelse error.Failed;
    }

    fn query(a: *const Api, service: CFTypeRef, account: CFTypeRef, extra_k: []const CFTypeRef, extra_v: []const CFTypeRef) Error!CFTypeRef {
        var ks: [6]CFTypeRef = undefined;
        var vs: [6]CFTypeRef = undefined;
        ks[0] = a.kSecClass;
        vs[0] = a.kSecClassGenericPassword;
        ks[1] = a.kSecAttrService;
        vs[1] = service;
        ks[2] = a.kSecAttrAccount;
        vs[2] = account;
        for (extra_k, extra_v, 0..) |k, v, i| {
            ks[3 + i] = k;
            vs[3 + i] = v;
        }
        const n = 3 + extra_k.len;
        return a.CFDictionaryCreate(null, &ks, &vs, @intCast(n), a.key_callbacks, a.value_callbacks) orelse error.Failed;
    }

    fn load(target: []const u8, out: []u8) Error!?[]u8 {
        const a = try get();
        const service = try str(a, target);
        defer a.CFRelease(service);
        const account = try str(a, "portal-client");
        defer a.CFRelease(account);
        const q = try query(a, service, account, &.{ a.kSecReturnData, a.kSecMatchLimit }, &.{ a.kCFBooleanTrue, a.kSecMatchLimitOne });
        defer a.CFRelease(q);
        var result: ?CFTypeRef = null;
        const st = a.SecItemCopyMatching(q, &result);
        if (st == errSecItemNotFound) return null;
        if (st != 0) return error.Failed;
        const data = result orelse return null;
        defer a.CFRelease(data);
        const len: usize = @intCast(@max(0, a.CFDataGetLength(data)));
        if (len > out.len) return error.TooLong;
        @memcpy(out[0..len], a.CFDataGetBytePtr(data)[0..len]);
        return out[0..len];
    }

    fn save(target: []const u8, secret: []const u8) Error!void {
        const a = try get();
        const service = try str(a, target);
        defer a.CFRelease(service);
        const account = try str(a, "portal-client");
        defer a.CFRelease(account);
        const data = a.CFDataCreate(null, secret.ptr, @intCast(secret.len)) orelse return error.Failed;
        defer a.CFRelease(data);
        const add = try query(a, service, account, &.{a.kSecValueData}, &.{data});
        defer a.CFRelease(add);
        var st = a.SecItemAdd(add, null);
        if (st == errSecDuplicateItem) {
            const q = try query(a, service, account, &.{}, &.{});
            defer a.CFRelease(q);
            var ks = [_]CFTypeRef{a.kSecValueData};
            var vs = [_]CFTypeRef{data};
            const attrs = a.CFDictionaryCreate(null, &ks, &vs, 1, a.key_callbacks, a.value_callbacks) orelse return error.Failed;
            defer a.CFRelease(attrs);
            st = a.SecItemUpdate(q, attrs);
        }
        if (st != 0) return error.Failed;
    }

    fn delete(target: []const u8) Error!void {
        const a = try get();
        const service = try str(a, target);
        defer a.CFRelease(service);
        const account = try str(a, "portal-client");
        defer a.CFRelease(account);
        const q = try query(a, service, account, &.{}, &.{});
        defer a.CFRelease(q);
        const st = a.SecItemDelete(q);
        if (st != 0 and st != errSecItemNotFound) return error.Failed;
    }
};

// ------------------------------------------------------------------ Linux

const linux = struct {
    const SchemaAttribute = extern struct { name: ?[*:0]const u8, type: c_int };
    const Schema = extern struct {
        name: [*:0]const u8,
        flags: c_int,
        attributes: [32]SchemaAttribute,
        reserved: c_int = 0,
        reserved1: ?*anyopaque = null,
        reserved2: ?*anyopaque = null,
        reserved3: ?*anyopaque = null,
        reserved4: ?*anyopaque = null,
        reserved5: ?*anyopaque = null,
        reserved6: ?*anyopaque = null,
        reserved7: ?*anyopaque = null,
    };
    const GError = extern struct { domain: u32, code: c_int, message: ?[*:0]const u8 };
    const HashFn = *const fn (?*const anyopaque) callconv(.c) c_uint;
    const EqFn = *const fn (?*const anyopaque, ?*const anyopaque) callconv(.c) c_int;

    const Api = struct {
        secret_password_storev_sync: *const fn (*const Schema, *anyopaque, ?[*:0]const u8, [*:0]const u8, [*:0]const u8, ?*anyopaque, *?*GError) callconv(.c) c_int,
        secret_password_lookupv_sync: *const fn (*const Schema, *anyopaque, ?*anyopaque, *?*GError) callconv(.c) ?[*:0]u8,
        secret_password_clearv_sync: *const fn (*const Schema, *anyopaque, ?*anyopaque, *?*GError) callconv(.c) c_int,
        secret_password_free: *const fn (?[*:0]u8) callconv(.c) void,
        g_hash_table_new: *const fn (HashFn, EqFn) callconv(.c) ?*anyopaque,
        g_hash_table_insert: *const fn (*anyopaque, ?*anyopaque, ?*anyopaque) callconv(.c) c_int,
        g_hash_table_unref: *const fn (*anyopaque) callconv(.c) void,
        g_error_free: *const fn (*GError) callconv(.c) void,
        g_str_hash: HashFn,
        g_str_equal: EqFn,
    };

    var api: ?Api = null;

    const schema: Schema = blk: {
        var s: Schema = .{ .name = "org.portal.client.Device", .flags = 0, .attributes = undefined };
        for (&s.attributes) |*a| a.* = .{ .name = null, .type = 0 };
        s.attributes[0] = .{ .name = "target", .type = 0 }; // SECRET_SCHEMA_ATTRIBUTE_STRING
        break :blk s;
    };

    fn get() Error!*const Api {
        if (api) |*a| return a;
        var secret = std.DynLib.open("libsecret-1.so.0") catch return error.Unavailable;
        var glib = std.DynLib.open("libglib-2.0.so.0") catch return error.Unavailable;
        var a: Api = undefined;
        inline for (@typeInfo(Api).@"struct".field_names, @typeInfo(Api).@"struct".field_types) |f_name, f_type| {
            const lib = if (comptime std.mem.startsWith(u8, f_name, "secret_")) &secret else &glib;
            @field(a, f_name) = lib.lookup(f_type, f_name) orelse return error.Unavailable;
        }
        api = a;
        return &api.?;
    }

    fn attrs(a: *const Api, target_z: [*:0]const u8) Error!*anyopaque {
        const t = a.g_hash_table_new(a.g_str_hash, a.g_str_equal) orelse return error.Failed;
        _ = a.g_hash_table_insert(t, @constCast(@ptrCast("target")), @constCast(@ptrCast(target_z)));
        return t;
    }

    fn check(a: *const Api, err: ?*GError) Error!void {
        if (err) |e| {
            a.g_error_free(e);
            return error.Unavailable; // usually: no Secret Service running
        }
    }

    fn load(target: []const u8, out: []u8) Error!?[]u8 {
        const a = try get();
        var tz: [max_target + 1]u8 = undefined;
        const t = std.fmt.bufPrintSentinel(&tz, "{s}", .{target}, 0) catch return error.TooLong;
        const table = try attrs(a, t);
        defer a.g_hash_table_unref(table);
        var err: ?*GError = null;
        const pw = a.secret_password_lookupv_sync(&schema, table, null, &err);
        try check(a, err);
        const p = pw orelse return null;
        defer a.secret_password_free(p);
        const s = std.mem.span(p);
        defer std.crypto.secureZero(u8, s);
        if (s.len > out.len) return error.TooLong;
        @memcpy(out[0..s.len], s);
        return out[0..s.len];
    }

    fn save(target: []const u8, secret: []const u8) Error!void {
        const a = try get();
        var tz: [max_target + 1]u8 = undefined;
        const t = std.fmt.bufPrintSentinel(&tz, "{s}", .{target}, 0) catch return error.TooLong;
        var sz: [max_secret + 1]u8 = undefined;
        defer std.crypto.secureZero(u8, &sz);
        const s = std.fmt.bufPrintSentinel(&sz, "{s}", .{secret}, 0) catch return error.TooLong;
        const table = try attrs(a, t);
        defer a.g_hash_table_unref(table);
        var err: ?*GError = null;
        const okv = a.secret_password_storev_sync(&schema, table, null, t, s, null, &err);
        try check(a, err);
        if (okv == 0) return error.Failed;
    }

    fn delete(target: []const u8) Error!void {
        const a = try get();
        var tz: [max_target + 1]u8 = undefined;
        const t = std.fmt.bufPrintSentinel(&tz, "{s}", .{target}, 0) catch return error.TooLong;
        const table = try attrs(a, t);
        defer a.g_hash_table_unref(table);
        var err: ?*GError = null;
        _ = a.secret_password_clearv_sync(&schema, table, null, &err);
        try check(a, err);
    }
};

test "credential store round trip" {
    if (builtin.os.tag != .windows) return error.SkipZigTest; // needs a desktop keyring
    const target = "Portal-client-unittest/127.0.0.1:1";
    try delete(target);
    var buf: [max_secret]u8 = undefined;
    try std.testing.expect((try load(target, &buf)) == null);
    try save(target, "dev.first");
    try std.testing.expectEqualStrings("dev.first", (try load(target, &buf)).?);
    try save(target, "dev.second"); // replace
    try std.testing.expectEqualStrings("dev.second", (try load(target, &buf)).?);
    try delete(target);
    try std.testing.expect((try load(target, &buf)) == null);
    try delete(target); // idempotent
}
